"""Deployed storage controls, immutable probe intents and independent correlation."""

import hashlib
import time
from uuid import UUID, uuid4

from azure.core.exceptions import AzureError

from citadel.operations import OperationError, identity
from citadel.operator.state import Blocked
from .coverage import CONTAINERS
from .oracle import hash_value
from .revision import RevisionProbe
from .storage_probes import StorageControls, evaluate_storage, storage_target


def bind_storage_result(result, *, actor, run_id, suite_id, principal, account):
    if (not isinstance(result, dict) or type(result.get("schema_version")) is not int
            or result["schema_version"] != 1 or result.get("run_id") != run_id
            or result.get("state") not in ("complete", "blocked")
            or not isinstance(result.get("observations"), list) or len(result["observations"]) > 36):
        raise Blocked("storage_worker_result_shape_conflict")
    ids, checks = [], set()
    for row in result["observations"]:
        if not isinstance(row, dict):
            raise Blocked("storage_worker_result_shape_conflict")
        container, action = row.get("container"), row.get("action")
        expected = f"storage.{actor}.{container}.{action}"
        if (container not in CONTAINERS or action not in ("read", "write")
                or row.get("caller") != actor or row.get("runtime_identity") != principal
                or row.get("run_id") != run_id or row.get("suite_id") != suite_id
                or row.get("check_id") != expected or row.get("target") != hashlib.sha256(
                    f"{account}/{container}/{storage_target(suite_id)}".encode()).hexdigest()):
            raise Blocked("storage_worker_identity_or_target_binding_conflict")
        ids.append(identity(row.get("operation_id")))
        if row.get("control") is not True:
            if expected in checks:
                raise Blocked("storage_worker_duplicate_check")
            checks.add(expected)
    if (len(ids) != len(set(ids)) or result["state"] == "complete" and checks != {
            f"storage.{actor}.{container}.{action}" for container in CONTAINERS for action in ("read", "write")}):
        raise Blocked("storage_worker_coverage_binding_conflict")
    return ids


class StorageAcceptance:
    def __init__(self, lifecycle):
        self.lifecycle = lifecycle

    def execute(self, report):
        if "storage_phase" in report:
            raise Blocked("storage_probe_intent_requires_reconciliation")
        accounts = [rid for rid in self.lifecycle.value["inventory"]
                    if "/providers/Microsoft.Storage/storageAccounts/" in rid and "/blobServices/" not in rid]
        if len(accounts) != 1:
            raise Blocked("exact_storage_account_required")
        phase = {"state": "dispatching", "deadline": time.time() + 900, "read_attempts": 0,
                 "seeds": {}, "snapshots": {}, "observations": [], "identities": {}}
        report["storage_phase"] = phase
        self.lifecycle.state.save()

        def admit():
            if phase["read_attempts"] >= 512 or time.time() >= phase["deadline"]:
                raise OperationError("exhausted", "Storage controls exhausted their fixed envelope")
            phase["read_attempts"] += 1
            self.lifecycle.state.save()

        account = "https://" + accounts[0].split("/")[-1] + ".blob.core.windows.net"
        controls = StorageControls(self.lifecycle.native, account=account, suite_id=report["run_id"], admit=admit)
        native = self.lifecycle.native
        previous = getattr(native, "deadline", None)
        native.deadline = min(previous or float("inf"), time.monotonic() + 900)
        try:
            phase["seeds"] = controls.prepare()
            self.lifecycle.state.save()
            driver = RevisionProbe(self.lifecycle, admit=admit)
            for app in self.lifecycle.value["outputs"]["appInventory"]:
                actor = app["app"].split("/")[-1].removeprefix(self.lifecycle.id + "-")
                phase["identities"][actor] = hashlib.sha256(str(UUID(app["identityPrincipalId"])).encode()).hexdigest()
                if actor == "reference-data":
                    continue
                before = controls.snapshot()
                if any(before[name]["sha256"] != phase["seeds"][name]["sha256"] for name in CONTAINERS):
                    raise Blocked("disposable_storage_target_changed")
                operation = uuid4().hex
                report["operation_ids"].append(operation)
                phase["snapshots"][operation] = {"before": before}
                self.lifecycle.state.save()
                result = driver.execute(app, actor, operation, mode="storage-boundaries",
                    deadline=phase["deadline"], storage={"suite_id": report["run_id"], "targets": {
                        name: {"sha256": before[name]["sha256"], "etag": before[name]["etag"]}
                        for name in CONTAINERS}})
                physical_ids = bind_storage_result(result, actor=actor, run_id=operation,
                    suite_id=report["run_id"], principal=phase["identities"][actor], account=account)
                if set(physical_ids) & set(report["operation_ids"]):
                    raise Blocked("storage_worker_operation_identity_reused")
                report["operation_ids"].extend(physical_ids)
                phase["observations"].extend(result["observations"])
                phase["snapshots"][operation]["after"] = controls.snapshot()
                self.lifecycle.state.save()
                if result.get("state") != "complete":
                    raise Blocked("storage_worker_partial_requires_reconciliation")
            phase["state"] = "observed"
        except (AzureError, OperationError, ValueError, TimeoutError, Blocked):
            phase["state"] = "blocked"
            raise Blocked("storage_probe_phase_incomplete") from None
        finally:
            native.deadline = previous
            self.lifecycle.state.save()

    @staticmethod
    def evaluate(report, evidence):
        phase = report.get("storage_phase", {})
        identities = dict(phase.get("identities", {}))
        observer = list(phase.get("seeds", {}).values())
        for snapshots in phase.get("snapshots", {}).values():
            for side in ("before", "after"):
                observer.extend(snapshots.get(side, {}).values())
        bindings = {(r.get("request_id"), r.get("operation_id"), r.get("target")) for r in observer}
        operators = {row.get("runtime_identity") for row in evidence if row.get("source") == "storage"
                     and (row.get("request_id"), row.get("client_request_id"), row.get("target")) in bindings
                     and hash_value(row.get("runtime_identity"))}
        if len(operators) == 1:
            identities["operator"] = next(iter(operators))
        observed = phase.get("observations", [])
        output = []
        for row in observed:
            if row.get("control") is True:
                continue
            container, action = row.get("container"), row.get("action")
            snapshots = phase.get("snapshots", {}).get(row.get("run_id"), {})
            before = snapshots.get("before", {}).get(container, {})
            after = snapshots.get("after", {}).get(container, {})
            candidates = [r for r in observed if r.get("control") is True
                          and r.get("container") == container and r.get("action") == action]
            if container == "reference":
                candidates += ([phase.get("seeds", {}).get("reference", {})] if action == "write"
                               else [before])
            evaluations = [(evaluate_storage(row, control, {"before": before, "after": after},
                                             evidence, identities), control) for control in candidates]
            selected = next((pair for pair in evaluations if pair[0]["status"] == "pass"),
                            next((pair for pair in evaluations if pair[0]["status"] == "fail"), None))
            if selected is None:
                result = {"check_id": row.get("check_id"), "status": "blocked",
                          "reason": "storage_service_control_or_no_effect_proof_missing"}
                control = {}
            else:
                result, control = selected
            result["actual"] = {"observation": row, "control": control,
                               "before": before | {"runtime_identity": identities.get("operator")},
                               "after": after | {"runtime_identity": identities.get("operator")}}
            output.append(result)
        return output
