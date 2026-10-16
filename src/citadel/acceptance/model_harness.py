"""Globally excluded direct-model controls, with no workload authority substitution."""

import hashlib
import re
import time
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from azure.core.exceptions import AzureError

from citadel.operations import OperationError
from citadel.operator.state import Blocked
from .console import ConsoleProbe
from .coverage import STORAGE
from .model_admission import ModelAdmission
from .model_probes import INPUT_BOUND, OUTPUT_BOUND, model_origin
from .revision import RevisionProbe
from .storage_probes import StorageControls


def bind_model_result(result, *, workload, worker_id, run_id, principal, origin):
    if (not isinstance(result, dict) or type(result.get("schema_version")) is not int
            or result["schema_version"] != 1 or result.get("run_id") != worker_id
            or result.get("state") not in ("complete", "blocked")
            or not isinstance(result.get("observations"), list) or len(result["observations"]) != 1):
        raise Blocked("model_worker_result_shape_conflict")
    row = result["observations"][0]
    expected = {"check_id": f"model.{workload}.direct-denied", "caller": workload,
        "operation_id": worker_id, "run_id": run_id, "runtime_identity": principal,
        "target": hashlib.sha256((model_origin(origin) + "/openai/v1/chat/completions").encode()).hexdigest(),
        "model_attempts": 1, "input_tokens": INPUT_BOUND, "output_tokens": OUTPUT_BOUND}
    if (not isinstance(row, dict) or any(row.get(key) != value for key, value in expected.items())
            or any(type(row.get(key)) is not int for key in ("model_attempts", "input_tokens", "output_tokens"))):
        raise Blocked("model_worker_authority_or_reservation_conflict")
    return row


class ModelAcceptance:
    def __init__(self, lifecycle, *, sleep=time.sleep):
        self.lifecycle, self.sleep = lifecycle, sleep

    def execute(self, report):
        if "model_phase" in report:
            raise Blocked("model_probe_intent_requires_reconciliation")
        value = self.lifecycle.value
        if any(row["state"] not in ("succeeded", "failed_no_commit") for row in value["runs"].values()):
            raise Blocked("model_controls_require_quiescent_runs")
        run_id = uuid4().hex
        phase = {"run_id": run_id, "state": "preparing", "deadline": time.time() + 900,
                 "read_attempts": 0, "observations": [], "slot": [], "snapshots": {}}
        report["model_phase"] = phase
        report["operation_ids"].append(run_id)
        self.lifecycle.state.save()

        def admit(count=1):
            if (type(count) is not int or count < 1 or phase["read_attempts"] + count > 512
                    or time.time() >= phase["deadline"]):
                raise OperationError("exhausted", "Model controller reads or deadline exhausted")
            phase["read_attempts"] += count
            self.lifecycle.state.save()

        def cooldown(until):
            while time.time() < until:
                if time.time() >= phase["deadline"]:
                    raise OperationError("deadline", "Model rate isolation window expired")
                self.sleep(min(5, until - time.time(), phase["deadline"] - time.time()))

        native = self.lifecycle.native
        previous = getattr(native, "deadline", None)
        native.deadline = min(previous or float("inf"), time.monotonic() + 900)
        try:
            accounts = [rid for rid in value["inventory"]
                if "/Microsoft.CognitiveServices/accounts/" in rid and "/deployments/" not in rid]
            deployments = [rid for rid in value["inventory"] if len(accounts) == 1
                           and rid == accounts[0] + "/deployments/citadel-gpt-41-mini"]
            storage = [rid for rid in value["inventory"]
                if "/Microsoft.Storage/storageAccounts/" in rid and "/blobServices/" not in rid]
            apps = {app["app"].rsplit("/", 1)[-1].removeprefix(self.lifecycle.id + "-"): app
                    for app in value["outputs"]["appInventory"]}
            quota = self.lifecycle.config["modelTokensPerMinute"]
            if (len(accounts) != 1 or len(deployments) != 1 or len(storage) != 1
                    or set(apps) != set(STORAGE) or len(value["outputs"]["appInventory"]) != 5
                    or type(quota) is not int or not INPUT_BOUND + OUTPUT_BOUND <= quota <= 120000
                    or quota > value["preflight"]["verifiedTokensPerMinute"]):
                raise Blocked("actual_model_control_inventory_or_quota_required")
            admit()
            actual = native.rest("get", accounts[0], "2024-10-01")
            origin = model_origin(actual["properties"]["endpoint"])
            admit()
            deployed = native.rest("get", deployments[0], "2024-10-01")
            if (deployed["sku"].get("name") != "Standard"
                    or deployed["sku"].get("capacity") != self.lifecycle.config["modelCapacity"]
                    or deployed["properties"]["model"].get("name") != "gpt-4.1-mini"
                    or deployed["properties"]["model"].get("version") != "2025-04-14"
                    or deployed["properties"].get("versionUpgradeOption") != "NoAutoUpgrade"):
                raise Blocked("actual_model_control_deployment_conflict")
            admission = ModelAdmission(phase, save=self.lifecycle.state.save, tokens_per_minute=quota)
            account = "https://" + storage[0].rsplit("/", 1)[-1] + ".blob.core.windows.net"
            controls = StorageControls(native, account=account, suite_id=report["run_id"], admit=admit)
            phase["state"] = "acquiring"
            self.lifecycle.state.save()
            with native.blob(account, "planner-operations", "active-run-slot.json") as blob:
                lease_id = str(uuid5(NAMESPACE_URL, "citadel-ticket-pool:acceptance/" + run_id))

                def exchange(action, callback):
                    operation = uuid4().hex
                    row = {"operation_id": operation, "action": action, "started": time.time(),
                           "target": hashlib.sha256(blob.url.encode()).hexdigest()}
                    phase["slot"].append(row)
                    report["operation_ids"].append(operation)
                    self.lifecycle.state.save()
                    sent = False

                    def once(request):
                        nonlocal sent
                        if sent or time.time() >= phase["deadline"]:
                            raise Blocked("late_or_repeated_model_slot_dispatch")
                        sent = True
                        request.http_request.headers["x-ms-client-request-id"] = operation

                    def received(response):
                        row.update(status_code=response.http_response.status_code,
                                   request_id=response.http_response.headers.get("x-ms-request-id"))

                    result = callback(timeout=5, raw_request_hook=once, raw_response_hook=received)
                    row["finished"] = time.time()
                    self.lifecycle.state.save()
                    if row.get("status_code") != (201 if action == "acquire" else 200) or not row.get("request_id"):
                        raise Blocked("actual_model_slot_receipt_missing")
                    return result

                lease = exchange("acquire", lambda **options: blob.acquire_lease(
                    lease_duration=-1, lease_id=lease_id, **options))
                cooldown(phase["slot"][0]["finished"] + 60)
                phase["state"] = "dispatching"
                phase["snapshots"]["before"] = controls.products()
                report["operation_ids"].extend(row["operation_id"] for row in phase["snapshots"]["before"].values())
                self.lifecycle.state.save()
                for workload in STORAGE:
                    worker_id = uuid4().hex
                    while True:
                        try:
                            permit = admission.reserve(workload, operation_id=worker_id)
                            break
                        except OperationError as exc:
                            if exc.code != "rate_limited":
                                raise
                            self.sleep(min(5, max(0, phase["deadline"] - time.time())))
                    report["operation_ids"].append(worker_id)
                    self.lifecycle.state.save()
                    driver = ConsoleProbe if workload == "reference-data" else RevisionProbe
                    result = driver(self.lifecycle, admit=admit).execute(
                        apps[workload], workload, worker_id, mode="direct-model",
                        model={"run_id": run_id, "origin": origin, "deployment": "citadel-gpt-41-mini"},
                        deadline=phase["deadline"])
                    row = bind_model_result(result, workload=workload, worker_id=worker_id, run_id=run_id,
                        origin=origin, principal=hashlib.sha256(
                            str(UUID(apps[workload]["identityPrincipalId"])).encode()).hexdigest())
                    phase["observations"].append(row)
                    self.lifecycle.state.save()
                    admission.settle(permit, row)
                phase["snapshots"]["after"] = controls.products()
                report["operation_ids"].extend(row["operation_id"] for row in phase["snapshots"]["after"].values())
                self.lifecycle.state.save()
                cooldown(phase["model_history"][-1]["at"] + 60)
                exchange("release", lease.release)
            phase["state"] = "observed"
        except (AzureError, OperationError, Blocked, ValueError, KeyError, TypeError, TimeoutError):
            # Infinite lease and private model ticket deliberately survive ambiguity.
            phase["state"] = "blocked"
            raise Blocked("model_control_phase_requires_reconciliation") from None
        finally:
            native.deadline = previous
            self.lifecycle.state.save()

    @staticmethod
    def evaluate(report, evidence):
        from .model_oracle import evaluate_model
        from .oracle import hash_value
        phase = report.get("model_phase", {})
        snapshots = phase.get("snapshots", {})
        observers = {row.get("runtime_identity") for row in evidence
            if row.get("source") == "storage" and hash_value(row.get("runtime_identity"))
            and any(row.get("request_id") == snapshot.get("request_id")
                    and row.get("client_request_id") == snapshot.get("operation_id")
                    and row.get("target") == snapshot.get("target")
                    for side in snapshots.values() for snapshot in side.values())}
        observer = next(iter(observers)) if len(observers) == 1 else None
        results = []
        for observation in phase.get("observations", []):
            caller = observation["caller"]
            allowed_caller = "candidate-planner" if caller == "reference-data" else caller
            candidates = [row for row in evidence if row.get("source") == "application"
                and row.get("method") == "chat.completions" and row.get("caller") == allowed_caller
                and row.get("status_code") == 200 and row.get("run_id") in report["operation_ids"]
                and isinstance(row.get("operation_id"), str)
                and re.fullmatch("[A-Za-z0-9_-]{1,64}", row["operation_id"])
                and isinstance(row.get("facts"), dict)
                and type(row["facts"].get("finished")) in (int, float)]
            latest = max(candidates, key=lambda row: row["facts"]["finished"], default={})
            allowed = {key: latest.get(key) for key in (
                "run_id", "operation_id", "caller", "request_id", "status_code", "target", "runtime_identity")}
            allowed.update({key: latest.get("facts", {}).get(key) for key in (
                "input_tokens", "output_tokens", "tokens", "started", "finished")})
            if latest and allowed["operation_id"] not in report["operation_ids"]:
                report["operation_ids"].append(allowed["operation_id"])
            control = {"allowed": allowed, "slot": phase.get("slot", []), "runtime_identity": observer}
            result = evaluate_model(observation, control, snapshots, evidence,
                identities=report.get("runtime_identities", {}),
                subscription=report.get("subscription_bindings", {}).get(allowed_caller),
                observer_identity=observer)
            results.append(result | {"expected": "deny", "actual": {
                "observation": observation, "control": control,
                "before": list(snapshots.get("before", {}).values()),
                "after": list(snapshots.get("after", {}).values())}})
        return results
