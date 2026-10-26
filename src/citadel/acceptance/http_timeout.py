"""Actual cached A2A traffic held at the client, never a new execution or allowance."""

import asyncio
import hashlib
import json
import math
import time
from uuid import uuid4

import httpx
from azure.core.exceptions import AzureError

from citadel.evidence.manifests import sha256
from citadel.operations import OperationError
from citadel.operator.state import Blocked
from .storage_accounts import storage_accounts
from .oracle import hash_value
from .telemetry import gateway_request_id


CHECK = "limit.a2a_http_timeout_seconds"
ACCEPTANCE_CHECK = "limit.acceptance_seconds"


class HttpTimeoutAcceptance:
    def __init__(self, lifecycle, *, acceptance=False):
        self.lifecycle = lifecycle
        self.acceptance = acceptance
        self.phase_key = "acceptance_timeout_phase" if acceptance else "http_timeout_phase"

    def execute(self, report):
        if self.phase_key in report:
            raise Blocked("http_timeout_intent_requires_reconciliation")
        run_id = report["scenarios"]["comparison"]["operation_id"]
        run = self.lifecycle.value["runs"][run_id]
        from citadel.operator.quiescence import runs_quiescent
        if (run["state"] != "succeeded" or run["fixture"] != "base-source"
                or not runs_quiescent(self.lifecycle)
                or run["deadline"] - time.time() < 185):
            raise Blocked("completed_quiescent_comparison_with_original_time_required")
        accounts = storage_accounts(self.lifecycle)
        operation = uuid4().hex
        phase = {"state": "observing", "run_id": run_id, "operation_id": operation,
            "started": time.time(), "deadline": run["deadline"], "read_attempts": 0,
            "before": [], "after": [], "observations": []}
        report[self.phase_key] = phase
        report["operation_ids"].append(operation)
        run["state"] = "control_intent"
        self.lifecycle.state.save()

        def admit():
            if phase["read_attempts"] >= (94 if self.acceptance else 12) or time.time() >= phase["deadline"]:
                raise OperationError("exhausted", "Finite HTTP timeout observations exhausted")
            phase["read_attempts"] += 1
            self.lifecycle.state.save()

        native = self.lifecycle.native
        previous = getattr(native, "deadline", None)
        native.deadline = min(previous or float("inf"), time.monotonic() + phase["deadline"] - time.time())
        try:
            from .storage_probes import StorageControls
            from citadel.runtime.configuration import OPERATIONS
            from citadel.operator.scenarios import PlannerClient
            controls = StorageControls(native, account=accounts, suite_id=report["run_id"], admit=admit)

            def snapshot(side):
                for container in (*OPERATIONS.values(), "drafts", "findings"):
                    row, document = controls._read(container, "ledger-v1.json")
                    if container == "planner-operations":
                        root = json.loads(document)["operations"]["operator/invoke/" + run_id]
                        if root["state"] != "succeeded" or root["run_id"] != run_id:
                            raise Blocked("independently_completed_root_required")
                        row["control_reference"] = {key: root[key] for key in
                            ("input_hash", "deadline", "operation_id", "run_id")}
                        row["control_reference"]["result_sha256"] = sha256(root["result"])
                    phase[side].append(row)
                    report["operation_ids"].append(row["operation_id"])
                    self.lifecycle.state.save()

            snapshot("before")
            credentials = self.lifecycle.credentials()
            if credentials["callerStates"]["operator"] != "active":
                raise Blocked("operator_credential_suspended")

            async def probes():
                async with httpx.AsyncClient(follow_redirects=False, trust_env=False, timeout=30) as http:
                    client = PlannerClient(self.lifecycle.value["outputs"]["gatewayUrl"],
                        credentials["callerKeys"]["operator"]["primary"], http=http)
                    cancelled = []

                    async def received(response):
                        await response.aread()
                        receipt = client.invocation_receipt
                        if self.acceptance and len(phase["observations"]) == 1:
                            body = response.json()["result"]["message"]
                            error = json.loads(body["parts"][0]["text"])
                            if response.status_code != 200 or error != {"error": "indeterminate", "complete": False}:
                                raise Blocked("actual_cached_acceptance_expiry_response_required")
                            phase["observations"].append(phase["observations"][0] | {
                                "request_id": gateway_request_id(response.headers), "started": client.started,
                                "finished": time.time(), "business_state": "indeterminate", "sha256": sha256(error)})
                            self.lifecycle.state.save()
                            return
                        if (response.status_code != 200 or receipt is None
                                or receipt["facts"]["business_state"] != "TASK_STATE_COMPLETED"
                                or receipt["facts"]["accepted_operation_id"] != run_id):
                            raise Blocked("definite_completed_cached_response_required")
                        phase["observations"].append({
                            "run_id": run_id, "operation_id": run_id, "caller": "operator",
                            "request_id": gateway_request_id(response.headers), "status_code": 200,
                            "target": hashlib.sha256(str(response.request.url).encode()).hexdigest(),
                            "started": receipt["facts"]["started"], "finished": receipt["facts"]["finished"],
                            "business_state": receipt["facts"]["business_state"],
                            "accepted_operation_id": run_id, "sha256": receipt["facts"]["task_sha256"],
                            "input_hash": sha256({"operation_id": run_id, "run_id": run_id, "fixture": run["fixture"]})})
                        self.lifecycle.state.save()
                        if len(phase["observations"]) == 2:
                            try:
                                await asyncio.sleep(200)
                            except asyncio.CancelledError:
                                cancelled.append(True)
                                raise

                    http.event_hooks["response"].append(received)
                    await client.invoke(run_id, run["fixture"], phase["deadline"])
                    phase["before_sha256"] = sha256(run)
                    if self.acceptance:
                        from .acceptance_timeout import CachedAcceptanceRevision
                        revision = CachedAcceptanceRevision(self.lifecycle, operation_id=operation,
                            run_id=run_id, deadline=phase["deadline"], admit=admit)
                        revision.start()
                        try:
                            await client.invoke(run_id, run["fixture"], phase["deadline"])
                            phase["response"] = "indeterminate"
                            phase["after_sha256"] = sha256(run)
                        finally:
                            revision.restore()
                        return
                    try:
                        await client.invoke(run_id, run["fixture"], phase["deadline"])
                    except Blocked as exc:
                        phase["response"] = exc.code
                    else:
                        raise Blocked("actual_http_guard_did_not_expire")
                    phase["after_sha256"] = sha256(run)
                    phase["timer"] = client.timeout_receipt
                    if (len(phase["observations"]) != 2 or cancelled != [True]
                            or phase["timer"] is None or phase["response"] != "invocation_ambiguous_reconcile_only"):
                        raise Blocked("definite_received_response_and_actual_http_expiry_required")

            asyncio.run(probes())
            snapshot("after")
            if ({row["container"]: row["sha256"] for row in phase["before"]}
                    != {row["container"]: row["sha256"] for row in phase["after"]}):
                raise Blocked("cached_http_control_changed_business_state")
            phase["state"], run["state"] = "observed", "succeeded"
        except (AzureError, OperationError, Blocked, ValueError, KeyError, TypeError, TimeoutError):
            phase["state"] = "blocked"
            raise Blocked("http_timeout_phase_incomplete") from None
        finally:
            phase["finished"] = time.time()
            native.deadline = previous
            self.lifecycle.state.save()

    @staticmethod
    def evaluate(report, *, acceptance=False):
        phase = report.get("acceptance_timeout_phase" if acceptance else "http_timeout_phase", {})
        check = {"check_id": ACCEPTANCE_CHECK if acceptance else CHECK, "expected": "boundary", "status": "blocked",
                 "reason": "actual_http_timeout_driver_required"}
        if phase.get("state") != "observed":
            return check
        bindings = {(row["request_id"], row["operation_id"], row["target"])
                    for side in ("before", "after") for row in phase[side]}
        observers = {row.get("runtime_identity") for row in report["evidence"] if row.get("source") == "storage"
            and hash_value(row.get("runtime_identity"))
            and (row.get("request_id"), row.get("client_request_id"), row.get("target")) in bindings}
        check["actual"] = {key: value for key, value in phase.items() if key not in ("state", "read_attempts")}
        check["actual"]["runtime_identity"] = next(iter(observers)) if len(observers) == 1 else None
        if acceptance:
            events = [row for row in report["evidence"] if row.get("source") == "application"
                and row.get("method") == "acceptance.timeout"
                and row.get("request_id") == phase["observations"][-1]["request_id"]]
            check["actual"]["timer"] = events[0]["facts"] if len(events) == 1 else None
        return check | evaluate_http_timeout(check, report)


def evaluate_http_timeout(check, report):
    acceptance = check["check_id"] == ACCEPTANCE_CHECK
    blocked = {"check_id": ACCEPTANCE_CHECK if acceptance else CHECK, "status": "blocked",
               "reason": "actual_http_timer_cached_receipts_and_independent_no_effect_required"}
    try:
        actual, records = check["actual"], report["evidence"]
        run, observer = actual["run_id"], actual["runtime_identity"]
        if (run != report["scenarios"]["comparison"]["operation_id"]
                or run not in report["operation_ids"] or actual["operation_id"] not in report["operation_ids"]
                or not hash_value(observer) or observer in report["runtime_identities"].values()
                or any(type(actual[key]) not in (int, float) or not math.isfinite(actual[key])
                       for key in ("started", "finished", "deadline"))
                or not actual["started"] <= actual["finished"] <= actual["deadline"] <= actual["started"] + 900):
            return blocked
        observations, timer = actual["observations"], actual["timer"]
        if (len(observations) != 2 or len({row["request_id"] for row in observations}) != 2
                or any(type(timer[key]) not in (int, float) or not math.isfinite(timer[key]) for key in
                    ("started", "finished", "deadline", "monotonic_started", "monotonic_deadline", "monotonic_finished"))
                or not acceptance and timer["deadline"] != actual["deadline"]
                or not actual["started"] <= observations[0]["started"] <= observations[0]["finished"]
                    <= observations[1]["started"] <= observations[1]["finished"] <= actual["finished"]):
            return blocked
        if acceptance:
            if not observations[1]["started"] <= timer["started"] <= timer["finished"] <= observations[1]["finished"]:
                return blocked
            events = [row for row in records if row.get("source") == "application"
                and row.get("method") == "acceptance.timeout" and row.get("request_id") == observations[1]["request_id"]]
            if (len(events) != 1 or events[0].get("facts") != timer
                    or events[0].get("runtime_identity") != report["runtime_identities"]["candidate-planner"]
                    or events[0].get("caller") != "operator" or events[0].get("run_id") != run
                    or events[0].get("operation_id") != run or events[0].get("status_code") != 0
                    or not timer["finished"] - 5 <= events[0]["observed"] <= timer["finished"] + 5):
                return blocked
        elif not observations[0]["finished"] <= timer["started"] <= observations[1]["started"] <= observations[1]["finished"] <= timer["finished"]:
            return blocked
        target, subscription = report["gateway_targets"]["candidate-planner"], report["subscription_bindings"]["operator"]
        if not hash_value(target) or not hash_value(subscription):
            return blocked
        roots = [row["control_reference"] for side in ("before", "after")
                 for row in actual[side] if row["container"] == "planner-operations"]
        if (len(roots) != 2 or roots[0] != roots[1] or roots[0]["operation_id"] != run
                or roots[0]["run_id"] != run or not hash_value(roots[0]["result_sha256"])
                or roots[0]["input_hash"] != sha256({"inputs": {
                    "operation_id": run, "run_id": run, "fixture": "base-source"},
                    "run_id": run, "deadline": roots[0]["deadline"]})):
            return blocked
        for index, row in enumerate(observations):
            if (row["target"] != target or row["status_code"] != 200 or row["caller"] != "operator"
                    or row["run_id"] != run or row["operation_id"] != run or row["accepted_operation_id"] != run
                    or row["business_state"] != ("indeterminate" if acceptance and index == 1 else "TASK_STATE_COMPLETED")
                    or not hash_value(row["sha256"])
                    or row["input_hash"] != sha256({"operation_id": run, "run_id": run, "fixture": "base-source"})
                    or not 0 <= row["finished"] - row["started"] <= 180):
                return blocked
            gateways = [event for event in records if event.get("source") == "gateway"
                        and event.get("request_id") == row["request_id"]]
            backends = [event for event in records if event.get("source") == "application"
                        and event.get("request_id") == row["request_id"] and event.get("method") == "SendMessage.cached"]
            if (not gateways or not backends
                    or any(event.get("target") != target or event.get("caller") != "operator"
                        or event.get("credential_sha256") != subscription or event.get("method") != "POST"
                        or event.get("facts", {}).get("backend_dispatched") is not True for event in gateways)
                    or any(event.get("runtime_identity") != report["runtime_identities"]["candidate-planner"]
                        or event.get("caller") != "operator" or event.get("run_id") != run
                        or event.get("operation_id") != run for event in backends)
                    or not any(event.get("facts", {}).get("business_state") == "succeeded"
                        and event["facts"].get("accepted_operation_id") == run
                        and event["facts"].get("deadline") == roots[0]["deadline"]
                        and event["facts"].get("input_hash") == roots[0]["input_hash"] for event in backends)
                    or any(event.get("status_code") != 200 or type(event.get("observed")) not in (int, float)
                        or not row["started"] - 5 <= event["observed"] <= row["finished"] + 5
                        for event in (*gateways, *backends))):
                return blocked
        census = {row.get("request_id") for row in records if row.get("source") == "gateway"
            and row.get("target") == target and row.get("caller") == "operator"
            and type(row.get("observed")) in (int, float)
            and observations[0]["started"] - 5 <= row["observed"] <= timer["finished"] + 5}
        if census != {row["request_id"] for row in observations}:
            return blocked
        snapshots = {}
        from .operation_oracle import _matched
        containers = {"planner-operations", "assessor-operations", "reviewer-operations",
                      "author-operations", "drafts", "findings"}
        for side in ("before", "after"):
            rows = actual[side]
            if len(rows) != 6 or {row["container"] for row in rows} != containers:
                return blocked
            snapshots[side] = {}
            for row in rows:
                if (row["suite_id"] != report["run_id"] or row["operation_id"] not in report["operation_ids"]
                        or row["caller"] != "operator" or row["action"] != "read"
                        or row["target"] != report["storage_targets"][row["container"]]
                        or not hash_value(row["sha256"]) or row["status_code"] not in (200, 206)
                        or not actual["started"] <= row["started"] <= row["finished"] <= actual["finished"]
                        or side == "before" and row["finished"] > observations[0]["started"]
                        or side == "after" and row["started"] < timer["finished"]
                        or not _matched(row, records, "storage", observer, "GetBlob",
                            client_request_id=row["operation_id"])):
                    return blocked
                snapshots[side][row["container"]] = row["sha256"]
        valid = (timer["monotonic_deadline"] - timer["monotonic_started"] == (10 if acceptance else 180)
            and timer["monotonic_finished"] >= timer["monotonic_deadline"]
            and actual["response"] == ("indeterminate" if acceptance else "invocation_ambiguous_reconcile_only")
            and hash_value(actual["before_sha256"]) and actual["before_sha256"] == actual["after_sha256"]
            and (observations[1]["sha256"] == sha256({"error": "indeterminate", "complete": False}) if acceptance
                 else observations[0]["sha256"] == observations[1]["sha256"])
            and snapshots["before"] == snapshots["after"])
        return blocked | {"status": "pass" if valid else "fail",
            "reason": "actual_http_expiry_without_replay_verified" if valid else "http_timeout_or_no_effect_failed"}
    except (KeyError, TypeError, ValueError, AttributeError, IndexError):
        return blocked
