"""Actual planner-identity durable fault drivers and independent storage observation."""

import hashlib
import time
from uuid import UUID, uuid4

from azure.core.exceptions import AzureError

from citadel.operations import OperationError, identity
from citadel.evidence.manifests import sha256
from citadel.operator.state import Blocked
from .operation_oracle import OPERATION_CHECKS, evaluate_operation, operation_snapshot
from .oracle import hash_value
from .revision import RevisionProbe
from .storage_probes import StorageControls
from .admission_limits import ADMISSION_CHECKS, admission_snapshot, evaluate_admission
from .read_limit import read_snapshot, evaluate_read_boundary
from .model_limits import MODEL_BOUNDARY_CHECKS, evaluate_model_boundaries
from .model_counters import COUNTER_MODES, COUNTER_CHECKS, COUNTER_GROUPS, evaluate_model_counter


def _groups(mode):
    if mode in COUNTER_MODES:
        key = COUNTER_CHECKS[COUNTER_MODES[mode]]
        return {key: COUNTER_GROUPS[COUNTER_MODES[mode]]}
    if mode == "model-limits":
        return {"limit.input_tokens_attempt": MODEL_BOUNDARY_CHECKS}
    if mode == "read-limit":
        return {"limit.read_attempts_run": {"limit.read_attempts_run"}}
    if mode == "admission-limits":
        return {"limit.agent_executions": ADMISSION_CHECKS}
    if mode == "operation-faults":
        return OPERATION_CHECKS
    raise ValueError("Only fixed operation, read and bounded admission modes are supported")


def bind_operation_result(result, *, run_id, principal, account, mode="operation-faults"):
    groups = _groups(mode)
    if (not isinstance(result, dict) or type(result.get("schema_version")) is not int
            or result["schema_version"] != 1 or result.get("run_id") != run_id
            or result.get("state") not in ("complete", "blocked")
            or not isinstance(result.get("observations"), list) or len(result["observations"]) > len(groups)):
        raise Blocked("operation_worker_result_shape_conflict")
    ids, checks = [], set()
    for row in result["observations"]:
        if not isinstance(row, dict) or not isinstance(row.get("actual"), dict):
            raise Blocked("operation_worker_result_shape_conflict")
        operation = identity(row.get("operation_id"))
        check = row.get("check_id")
        if (not isinstance(check, str) or check not in groups or check in checks
                or row.get("probe_id") != check or row.get("run_id") != run_id
                or row.get("caller") != "candidate-planner" or row.get("runtime_identity") != principal
                or row["actual"].get("operation_id") != operation
                or row.get("target") != hashlib.sha256(
                    f"{account}/planner-operations/acceptance/{run_id}/observations/{operation}.json".encode()).hexdigest()):
            raise Blocked("operation_worker_authority_or_target_conflict")
        ids.append(operation)
        if check == "limit.safe_read_timeout_seconds":
            steps = row["actual"].get("steps")
            if (not isinstance(steps, list) or len(steps) != 3 or any(not isinstance(step, dict)
                    or step.get("operation_id") != operation + f"-read{index}" for index, step in enumerate(steps))):
                raise Blocked("read_timeout_physical_binding_conflict")
            ids.extend(identity(step["operation_id"]) for step in steps)
        if mode == "read-limit":
            steps = row["actual"].get("steps")
            if (not isinstance(steps, list) or not 0 <= len(steps) <= 513
                    or any(not isinstance(step, dict) or step.get("operation_id") != operation + f"-read{index:03}"
                        or step.get("target") != hashlib.sha256(
                            f"{account}/planner-operations/acceptance/{run_id}/ledger-v1.json".encode()).hexdigest()
                        for index, step in enumerate(steps))):
                raise Blocked("read_boundary_physical_binding_conflict")
            ids.extend(identity(step["operation_id"]) for step in steps)
        if mode == "admission-limits":
            slot = row["actual"].get("slot")
            if (not isinstance(slot, dict) or slot.get("scope_sha256") != sha256("acceptance/" + run_id)
                    or not isinstance(slot.get("steps"), list) or len(slot["steps"]) != 3
                    or any(not isinstance(step, dict) or step.get("operation_id") != operation + f"-slot{index}"
                        or step.get("target") != hashlib.sha256(
                            f"{account}/planner-operations/active-run-slot.json".encode()).hexdigest()
                        for index, step in enumerate(slot["steps"]))):
                raise Blocked("admission_global_slot_binding_conflict")
            ids.extend(identity(step["operation_id"]) for step in slot["steps"])
        if mode in ("model-limits", *COUNTER_MODES):
            slots = row["actual"].get("slot")
            if not isinstance(slots, dict) or set(slots) != {"before", "after"}:
                raise Blocked("model_boundary_global_slot_binding_conflict")
            for side, prefix in (("before", operation), ("after", operation + "-end")):
                slot = slots[side]
                if (not isinstance(slot, dict) or slot.get("scope_sha256") != sha256("acceptance/" + run_id)
                        or not isinstance(slot.get("steps"), list) or len(slot["steps"]) != 3
                        or any(not isinstance(step, dict) or step.get("operation_id") != prefix + f"-slot{index}"
                            or step.get("target") != hashlib.sha256(
                                f"{account}/planner-operations/active-run-slot.json".encode()).hexdigest()
                            for index, step in enumerate(slot["steps"]))):
                    raise Blocked("model_boundary_global_slot_binding_conflict")
                ids.extend(identity(step["operation_id"]) for step in slot["steps"])
        checks.add(check)
    if len(ids) != len(set(ids)) or result["state"] == "complete" and checks != set(groups):
        raise Blocked("operation_worker_coverage_conflict")
    return ids


class FaultAcceptance:
    def __init__(self, lifecycle):
        self.lifecycle = lifecycle

    def execute(self, report, *, mode="operation-faults"):
        _groups(mode)
        admission = mode == "admission-limits"
        phase_key = ("model_counter_" + COUNTER_MODES[mode] + "_phase" if mode in COUNTER_MODES else
                     "model_boundary_phase" if mode == "model-limits" else "read_phase" if mode == "read-limit"
                     else "admission_phase" if admission else "operation_phase")
        if phase_key in report:
            raise Blocked("operation_probe_intent_requires_reconciliation")
        accounts = [resource for resource in self.lifecycle.value["inventory"]
            if "/providers/Microsoft.Storage/storageAccounts/" in resource and "/blobServices/" not in resource]
        apps = [app for app in self.lifecycle.value["outputs"]["appInventory"]
                if app["app"].rsplit("/", 1)[-1] == self.lifecycle.id + "-candidate-planner"]
        if len(accounts) != 1 or len(apps) != 1:
            raise Blocked("exact_operation_probe_inventory_required")
        phase = {"state": "dispatching", "deadline": time.time() + 900, "read_attempts": 0,
                 "observations": [], "snapshots": {}}
        report[phase_key] = phase
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
            if mode in COUNTER_MODES and COUNTER_MODES[mode] != "execution":
                from .model_counters import observe_model_quota
                phase["quota"] = observe_model_quota(self.lifecycle, admit=admit, run_id=run_id)
                self.lifecycle.state.save()
            result = RevisionProbe(self.lifecycle, admit=admit).execute(
                app, "candidate-planner", run_id, mode=mode, deadline=phase["deadline"])
            operations = bind_operation_result(result, run_id=run_id, principal=principal, account=account, mode=mode)
            if set(operations) & set(report["operation_ids"]):
                raise Blocked("operation_probe_identity_reused")
            report["operation_ids"].extend(operations)
            phase["observations"] = result["observations"]
            self.lifecycle.state.save()
            controls = StorageControls(native, account=account, suite_id=report["run_id"], admit=admit)
            snapshot, document = controls.operation_state(run_id)
            report["operation_ids"].append(snapshot["operation_id"])
            for row in phase["observations"]:
                phase["snapshots"][row["operation_id"]] = snapshot | (
                    read_snapshot(document) if mode == "read-limit" else
                    admission_snapshot(document, row["actual"]) if admission or mode in ("model-limits", *COUNTER_MODES) else
                    operation_snapshot(document, "candidate-planner", row["actual"]))
                if "quota" in phase:
                    phase["snapshots"][row["operation_id"]]["quota"] = phase["quota"]
            phase["state"] = "observed" if result["state"] == "complete" else "blocked"
        except (AzureError, OperationError, Blocked, ValueError, KeyError, TypeError, TimeoutError):
            phase["state"] = "blocked"
            raise Blocked("operation_probe_phase_incomplete") from None
        finally:
            native.deadline = previous
            self.lifecycle.state.save()

    @staticmethod
    def evaluate(report, evidence, *, mode="operation-faults"):
        groups = _groups(mode)
        admission = mode == "admission-limits"
        phase = report.get("model_counter_" + COUNTER_MODES[mode] + "_phase" if mode in COUNTER_MODES else
                           "model_boundary_phase" if mode == "model-limits" else "read_phase" if mode == "read-limit" else
                           "admission_phase" if admission else "operation_phase", {})
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
            for check in sorted(groups.get(row.get("probe_id"), set())):
                observation = row | {"check_id": check}
                evaluator = (evaluate_model_counter if mode in COUNTER_MODES else
                             evaluate_model_boundaries if mode == "model-limits" else
                             evaluate_read_boundary if mode == "read-limit" else evaluate_admission if admission else evaluate_operation)
                result = evaluator(observation, snapshot, evidence,
                    runtime_identity=report.get("runtime_identities", {}).get("candidate-planner"),
                    observer_identity=observer, **({
                        "subscription": report.get("subscription_bindings", {}).get("candidate-planner"),
                        "target": report.get("gateway_targets", {}).get("model"),
                        "slot_target": report.get("storage_targets", {}).get("active-run-slot")}
                        if mode in ("model-limits", *COUNTER_MODES) else {}),
                    **({"tokens_per_minute": report.get("model_tokens_per_minute"),
                        "quota_binding": report.get("quota_inputs")} if mode in COUNTER_MODES else {}))
                output.append(result | {"expected": "boundary" if check.startswith("limit.") else "fault",
                    "actual": {"observation": observation, "control": snapshot}})
        return output
