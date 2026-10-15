"""Controller dispatches only the allocated reviewer and independently observes effects."""

import hashlib
import time
from uuid import UUID, uuid4

from azure.core.exceptions import AzureError

from citadel.operations import OperationError, identity
from citadel.operator.state import Blocked
from .oracle import hash_value
from .release_oracle import evaluate_release, release_snapshot
from .release_probes import RELEASE_CHECKS
from .revision import RevisionProbe
from .storage_probes import StorageControls


def bind_release_result(result, *, run_id, principal, account):
    if (not isinstance(result, dict) or type(result.get("schema_version")) is not int
            or result["schema_version"] != 1 or result.get("run_id") != run_id
            or result.get("state") not in ("complete", "blocked")
            or not isinstance(result.get("observations"), list) or len(result["observations"]) > len(RELEASE_CHECKS)):
        raise Blocked("release_worker_result_shape_conflict")
    identifiers, checks = [], set()
    for row in result["observations"]:
        if not isinstance(row, dict) or not isinstance(row.get("actual"), dict):
            raise Blocked("release_worker_result_shape_conflict")
        operation, check = identity(row.get("operation_id")), row.get("check_id")
        if (not isinstance(check, str) or check not in RELEASE_CHECKS or check in checks
                or row.get("probe_id") != check or row.get("run_id") != run_id
                or row.get("caller") != "release-reviewer" or row.get("runtime_identity") != principal
                or row["actual"].get("operation_id") != operation
                or row.get("target") != hashlib.sha256(
                    f"{account}/reviewer-operations/acceptance/{run_id}/observations/{operation}.json".encode()).hexdigest()):
            raise Blocked("release_worker_authority_or_target_conflict")
        identifiers.append(operation)
        if check == "fault.concurrent-different-operation-release":
            children = [identity(operation + "-a"), identity(operation + "-b")]
            if row["actual"].get("operation_ids") != children:
                raise Blocked("release_worker_child_identity_conflict")
            identifiers.extend(children)
        if check == "fault.draft-hash-binding":
            rejected = identity(operation + "-bad")
            if row["actual"].get("rejected_operation_id") != rejected:
                raise Blocked("release_worker_rejected_identity_conflict")
            identifiers.append(rejected)
        checks.add(check)
    if len(identifiers) != len(set(identifiers)) or result["state"] == "complete" and checks != RELEASE_CHECKS:
        raise Blocked("release_worker_coverage_conflict")
    return identifiers


class ReleaseAcceptance:
    def __init__(self, lifecycle):
        self.lifecycle = lifecycle

    def execute(self, report):
        if "release_phase" in report:
            raise Blocked("release_probe_intent_requires_reconciliation")
        accounts = [resource for resource in self.lifecycle.value["inventory"]
            if "/providers/Microsoft.Storage/storageAccounts/" in resource and "/blobServices/" not in resource]
        apps = [app for app in self.lifecycle.value["outputs"]["appInventory"]
                if app["app"].rsplit("/", 1)[-1] == self.lifecycle.id + "-release-reviewer"]
        comparison = report.get("scenarios", {}).get("comparison", {}).get("operation_id")
        if len(accounts) != 1 or len(apps) != 1 or comparison not in report["operation_ids"]:
            raise Blocked("exact_completed_release_source_and_inventory_required")
        phase = {"state": "dispatching", "deadline": time.time() + 900, "read_attempts": 0,
                 "observations": [], "snapshots": {}}
        report["release_phase"] = phase
        self.lifecycle.state.save()

        def admit():
            if phase["read_attempts"] >= 512 or time.time() >= phase["deadline"]:
                raise OperationError("exhausted", "Release control deadline or read allowance exhausted")
            phase["read_attempts"] += 1
            self.lifecycle.state.save()

        native = self.lifecycle.native
        previous = getattr(native, "deadline", None)
        native.deadline = min(previous or float("inf"), time.monotonic() + 900)
        try:
            app, run_id = apps[0], uuid4().hex
            account = "https://" + accounts[0].rsplit("/", 1)[-1] + ".blob.core.windows.net"
            principal = hashlib.sha256(str(UUID(app["identityPrincipalId"])).encode()).hexdigest()
            controls = StorageControls(native, account=account, suite_id=report["run_id"], admit=admit)
            phase["source"] = controls.release_source([comparison])
            phase["before"] = controls.products()
            report["operation_ids"].extend([run_id, phase["source"]["observation"]["operation_id"],
                                           *[row["operation_id"] for row in phase["before"].values()]])
            self.lifecycle.state.save()
            result = RevisionProbe(self.lifecycle, admit=admit).execute(app, "release-reviewer", run_id,
                mode="release-faults", release=phase["source"]["release_source"], deadline=phase["deadline"])
            operations = bind_release_result(result, run_id=run_id, principal=principal, account=account)
            if set(operations) & set(report["operation_ids"]):
                raise Blocked("release_probe_identity_reused")
            report["operation_ids"].extend(operations)
            phase["observations"] = result["observations"]
            self.lifecycle.state.save()
            for row in phase["observations"]:
                snapshot, document = controls.release_state(run_id, row["operation_id"])
                phase["snapshots"][row["operation_id"]] = snapshot | release_snapshot(document, row["actual"])
                report["operation_ids"].append(snapshot["operation_id"])
            phase["after"] = controls.products()
            report["operation_ids"].extend(row["operation_id"] for row in phase["after"].values())
            phase["state"] = "observed" if result["state"] == "complete" else "blocked"
        except (AzureError, OperationError, Blocked, ValueError, KeyError, TypeError, TimeoutError):
            phase["state"] = "blocked"
            raise Blocked("release_probe_phase_incomplete") from None
        finally:
            native.deadline = previous
            self.lifecycle.state.save()

    @staticmethod
    def evaluate(report, evidence):
        phase, output = report.get("release_phase", {}), []
        for row in phase.get("observations", []):
            snapshot = phase.get("snapshots", {}).get(row.get("operation_id"), {})
            observers = {record.get("runtime_identity") for record in evidence
                if record.get("source") == "storage" and hash_value(record.get("runtime_identity"))
                and record.get("request_id") == snapshot.get("request_id")
                and record.get("client_request_id") == snapshot.get("operation_id")
                and record.get("target") == snapshot.get("target")}
            observer = next(iter(observers)) if len(observers) == 1 else None
            snapshot = snapshot | {"runtime_identity": observer}
            source = phase.get("source", {})
            result = evaluate_release(row, snapshot, source,
                {side: phase.get(side, {}) for side in ("before", "after")}, evidence,
                runtime_identity=report.get("runtime_identities", {}).get("release-reviewer"),
                reference_identity=report.get("runtime_identities", {}).get("reference-data"),
                observer_identity=observer, subscription=report.get("subscription_bindings", {}).get("release-reviewer"))
            output.append(result | {"expected": "fault", "actual": {
                "observation": row, "control": snapshot, "source": source,
                **{side: list(phase.get(side, {}).values()) for side in ("before", "after")}}})
        return output
