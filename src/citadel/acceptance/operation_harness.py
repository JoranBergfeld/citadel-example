"""Actual planner-identity durable fault drivers and independent storage observation."""

import hashlib
import time
from uuid import UUID, uuid4

from azure.core.exceptions import AzureError

from citadel.operations import OperationError, identity
from citadel.operator.state import Blocked
from .operation_oracle import OPERATION_CHECKS, evaluate_operation, operation_snapshot
from .oracle import hash_value
from .revision import RevisionProbe
from .storage_probes import StorageControls


def bind_operation_result(result, *, run_id, principal, account):
    if (not isinstance(result, dict) or type(result.get("schema_version")) is not int
            or result["schema_version"] != 1 or result.get("run_id") != run_id
            or result.get("state") not in ("complete", "blocked")
            or not isinstance(result.get("observations"), list) or len(result["observations"]) > 6):
        raise Blocked("operation_worker_result_shape_conflict")
    ids, checks = [], set()
    for row in result["observations"]:
        if not isinstance(row, dict) or not isinstance(row.get("actual"), dict):
            raise Blocked("operation_worker_result_shape_conflict")
        operation = identity(row.get("operation_id"))
        check = row.get("check_id")
        if (not isinstance(check, str) or check not in OPERATION_CHECKS or check in checks
                or row.get("probe_id") != check or row.get("run_id") != run_id
                or row.get("caller") != "candidate-planner" or row.get("runtime_identity") != principal
                or row["actual"].get("operation_id") != operation
                or row.get("target") != hashlib.sha256(
                    f"{account}/planner-operations/acceptance/{run_id}/observations/{operation}.json".encode()).hexdigest()):
            raise Blocked("operation_worker_authority_or_target_conflict")
        ids.append(operation)
        checks.add(check)
    if len(ids) != len(set(ids)) or result["state"] == "complete" and checks != set(OPERATION_CHECKS):
        raise Blocked("operation_worker_coverage_conflict")
    return ids


class FaultAcceptance:
    def __init__(self, lifecycle):
        self.lifecycle = lifecycle

    def execute(self, report):
        if "operation_phase" in report:
            raise Blocked("operation_probe_intent_requires_reconciliation")
        accounts = [resource for resource in self.lifecycle.value["inventory"]
            if "/providers/Microsoft.Storage/storageAccounts/" in resource and "/blobServices/" not in resource]
        apps = [app for app in self.lifecycle.value["outputs"]["appInventory"]
                if app["app"].rsplit("/", 1)[-1] == self.lifecycle.id + "-candidate-planner"]
        if len(accounts) != 1 or len(apps) != 1:
            raise Blocked("exact_operation_probe_inventory_required")
        phase = {"state": "dispatching", "deadline": time.time() + 900, "read_attempts": 0,
                 "observations": [], "snapshots": {}}
        report["operation_phase"] = phase
        self.lifecycle.state.save()

        def admit():
            if phase["read_attempts"] >= 512 or time.time() >= phase["deadline"]:
                raise OperationError("exhausted", "Operation probe controls exhausted")
            phase["read_attempts"] += 1
            self.lifecycle.state.save()

        native = self.lifecycle.native
        previous = getattr(native, "deadline", None)
        native.deadline = min(previous or float("inf"), time.monotonic() + 900)
        try:
            app, run_id = apps[0], uuid4().hex
            principal = hashlib.sha256(str(UUID(app["identityPrincipalId"])).encode()).hexdigest()
            account = "https://" + accounts[0].rsplit("/", 1)[-1] + ".blob.core.windows.net"
            report["operation_ids"].append(run_id)
            self.lifecycle.state.save()
            result = RevisionProbe(self.lifecycle, admit=admit).execute(
                app, "candidate-planner", run_id, mode="operation-faults", deadline=phase["deadline"])
            operations = bind_operation_result(result, run_id=run_id, principal=principal, account=account)
            if set(operations) & set(report["operation_ids"]):
                raise Blocked("operation_probe_identity_reused")
            report["operation_ids"].extend(operations)
            phase["observations"] = result["observations"]
            self.lifecycle.state.save()
            controls = StorageControls(native, account=account, suite_id=report["run_id"], admit=admit)
            snapshot, document = controls.operation_state(run_id)
            report["operation_ids"].append(snapshot["operation_id"])
            for row in phase["observations"]:
                phase["snapshots"][row["operation_id"]] = snapshot | operation_snapshot(
                    document, "candidate-planner", row["actual"])
            phase["state"] = "observed" if result["state"] == "complete" else "blocked"
        except (AzureError, OperationError, Blocked, ValueError, KeyError, TypeError, TimeoutError):
            phase["state"] = "blocked"
            raise Blocked("operation_probe_phase_incomplete") from None
        finally:
            native.deadline = previous
            self.lifecycle.state.save()

    @staticmethod
    def evaluate(report, evidence):
        phase = report.get("operation_phase", {})
        snapshots = phase.get("snapshots", {})
        output = []
        for row in phase.get("observations", []):
            snapshot = snapshots.get(row.get("operation_id"), {})
            observers = {record.get("runtime_identity") for record in evidence
                if record.get("source") == "storage" and hash_value(record.get("runtime_identity"))
                and record.get("request_id") == snapshot.get("request_id")
                and record.get("client_request_id") == snapshot.get("operation_id")
                and record.get("target") == snapshot.get("target")}
            observer = next(iter(observers)) if len(observers) == 1 else None
            snapshot = snapshot | {"runtime_identity": observer}
            for check in sorted(OPERATION_CHECKS.get(row.get("probe_id"), set())):
                observation = row | {"check_id": check}
                result = evaluate_operation(observation, snapshot, evidence,
                    runtime_identity=report.get("runtime_identities", {}).get("candidate-planner"),
                    observer_identity=observer)
                output.append(result | {"expected": "fault",
                    "actual": {"observation": observation, "control": snapshot}})
        return output
