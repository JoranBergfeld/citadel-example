"""Actual owner-poll cadence and durable operator refusal, without new work grants."""

import hashlib
import math
import asyncio
import time

import httpx
from azure.core.exceptions import AzureError

from citadel.evidence.manifests import sha256
from citadel.gateway.trust import INVOCATION_CALLERS
from citadel.operations import identity
from .telemetry import correlate, emit, gateway_request_id
from .oracle import hash_value
from citadel.operator.state import Blocked
from citadel.operations import OperationError


def observe_poll(response, *, caller, target, run_id, operation_id, started, finished):
    try:
        body = response.json()
        if (caller == "operator" or caller not in INVOCATION_CALLERS.get(target, ())
                or response.request.method != "GET" or response.status_code != 200
                or body["run_id"] != run_id
                or body["state"] not in ("pending", "running", "succeeded", "failed_no_commit", "indeterminate")
                or any(type(value) not in (int, float) or not math.isfinite(value) for value in (started, finished))
                or not 0 <= finished - started <= 30):
            return None
        for value in (run_id, operation_id, body["operation_id"]):
            identity(value)
        record = {"method": "poll.observed", "run_id": run_id, "operation_id": operation_id,
            "caller": caller, "request_id": gateway_request_id(response.headers), "status_code": 200,
            "target": hashlib.sha256(str(response.request.url).encode()).hexdigest(),
            "facts": {"probe_id": f"route.{caller}.{target}.status", "read_operation_id": body["operation_id"],
                "business_state": body["state"], "started": started, "finished": finished}}
        record["facts"]["sha256"] = sha256(record)
    except (ValueError, TypeError, KeyError, AttributeError):
        return None
    with correlate(run_id, operation_id, caller):
        emit("poll.observed", request_id=record["request_id"], status_code=200,
             target=record["target"], facts=record["facts"])
    return record


class PollAcceptance:
    def __init__(self, lifecycle):
        self.lifecycle = lifecycle

    def execute(self, report):
        if "poll_phase" in report:
            raise Blocked("poll_probe_intent_requires_reconciliation")
        run_id = report["scenarios"]["comparison"]["operation_id"]
        run = self.lifecycle.value["runs"][run_id]
        if run["state"] != "succeeded" or any(row["state"] not in ("succeeded", "failed_no_commit")
                                            for row in self.lifecycle.value["runs"].values()):
            raise Blocked("completed_quiescent_comparison_required")
        accounts = [resource for resource in self.lifecycle.value["inventory"]
                    if "/providers/Microsoft.Storage/storageAccounts/" in resource and "/blobServices/" not in resource]
        if len(accounts) != 1:
            raise Blocked("exact_poll_observer_inventory_required")
        phase = {"state": "observing", "run_id": run_id, "started": time.time(), "deadline": run["deadline"],
                 "read_attempts": 0, "before": [], "after": [], "observations": []}
        report["poll_phase"] = phase
        self.lifecycle.state.save()

        def admit():
            if phase["read_attempts"] >= 12 or time.time() >= phase["deadline"]:
                raise OperationError("exhausted", "Finite poll no-effect observations exhausted")
            phase["read_attempts"] += 1
            self.lifecycle.state.save()

        native = self.lifecycle.native
        previous = getattr(native, "deadline", None)
        native.deadline = min(previous or float("inf"), time.monotonic() + max(0, phase["deadline"] - time.time()))
        try:
            from .storage_probes import StorageControls
            from citadel.runtime.configuration import OPERATIONS
            from citadel.operator.scenarios import PlannerClient
            controls = StorageControls(native, account="https://" + accounts[0].rsplit("/", 1)[-1]
                + ".blob.core.windows.net", suite_id=report["run_id"], admit=admit)

            def snapshot(side):
                for container in (*OPERATIONS.values(), "drafts", "findings"):
                    row, _ = controls._read(container, "ledger-v1.json")
                    phase[side].append(row)
                    report["operation_ids"].append(row["operation_id"])
                    self.lifecycle.state.save()

            snapshot("before")
            credentials = self.lifecycle.credentials()
            if credentials["callerStates"]["operator"] != "active":
                raise Blocked("operator_credential_suspended")

            async def probes():
                async def wait(until):
                    while time.time() < until:
                        if time.time() >= phase["deadline"]:
                            raise Blocked("poll_probe_inherited_deadline")
                        await asyncio.sleep(min(5, until - time.time(), phase["deadline"] - time.time()))

                async with httpx.AsyncClient(follow_redirects=False, timeout=30) as http:
                    client = PlannerClient(self.lifecycle.value["outputs"]["gatewayUrl"],
                                           credentials["callerKeys"]["operator"]["primary"], http=http)
                    await wait(run.get("lastRead", 0) + 15)
                    await client.poll(run_id, run, phase["deadline"], save=self.lifecycle.state.save)
                    phase["observations"].append(client.status_receipt)
                    phase["before_sha256"], phase["refusal_started"] = sha256(run), time.time()
                    try:
                        await client.poll(run_id, run, phase["deadline"], save=self.lifecycle.state.save)
                        phase["response"] = "allowed"
                    except Blocked as exc:
                        phase["response"] = exc.code
                    phase["refusal_finished"], phase["after_sha256"] = time.time(), sha256(run)
                    self.lifecycle.state.save()
                    if phase["response"] == "allowed":
                        phase["observations"].append(client.status_receipt)
                        return
                    if phase["response"] != "poll_interval_15_seconds_required":
                        raise Blocked("actual_poll_refusal_not_observed")
                    await wait(phase["observations"][0]["finished"] + 15)
                    await client.poll(run_id, run, phase["deadline"], save=self.lifecycle.state.save)
                    phase["observations"].append(client.status_receipt)

            asyncio.run(probes())
            snapshot("after")
            phase["state"] = "observed"
        except (AzureError, OperationError, Blocked, ValueError, KeyError, TypeError, TimeoutError):
            phase["state"] = "blocked"
            raise Blocked("poll_probe_phase_incomplete") from None
        finally:
            phase["finished"] = time.time()
            native.deadline = previous
            self.lifecycle.state.save()

    @staticmethod
    def evaluate(report):
        phase = report.get("poll_phase", {})
        check = {"check_id": "limit.poll_seconds", "expected": "boundary", "status": "blocked",
                 "reason": "actual_poll_driver_required"}
        if phase.get("state") != "observed":
            return check
        bindings = {(row["request_id"], row["operation_id"], row["target"])
                    for side in ("before", "after") for row in phase[side]}
        observers = {row.get("runtime_identity") for row in report["evidence"] if row.get("source") == "storage"
            and hash_value(row.get("runtime_identity"))
            and (row.get("request_id"), row.get("client_request_id"), row.get("target")) in bindings}
        check["actual"] = {key: value for key, value in phase.items() if key not in ("state", "read_attempts")}
        check["actual"]["runtime_identity"] = next(iter(observers)) if len(observers) == 1 else None
        return check | evaluate_poll(check, report)


def evaluate_poll(check, report):
    blocked = {"check_id": "limit.poll_seconds", "status": "blocked",
               "reason": "actual_poll_refusal_cadence_and_independent_no_effect_required"}
    try:
        actual, evidence = check["actual"], report["evidence"]
        identities, subscriptions = report["runtime_identities"], report["subscription_bindings"]
        run_id, observer = actual["run_id"], actual["runtime_identity"]
        if (run_id != report["scenarios"]["comparison"]["operation_id"] or run_id not in report["operation_ids"]
                or not hash_value(observer) or observer in identities.values()
                or any(type(actual[key]) not in (int, float) or not math.isfinite(actual[key]) for key in
                       ("started", "finished", "deadline", "refusal_started", "refusal_finished"))
                or not actual["started"] <= actual["finished"] <= actual["deadline"] <= actual["started"] + 900):
            return blocked

        def matches(receipt, source, method, **binding):
            selected = [row for row in evidence if row.get("source") == source
                and row.get("request_id") == receipt["request_id"] and
                (source != "application" or row.get("method") == method)]
            return bool(selected) and all(row.get("method") == method
                and row.get("status_code") == receipt["status_code"]
                and type(row.get("observed")) in (int, float) and math.isfinite(row["observed"])
                and receipt["started"] - 5 <= row["observed"] <= receipt["finished"] + 5
                and all(row.get(key) == value for key, value in binding.items())
                and (source != "gateway" or row.get("facts", {}).get("backend_dispatched") is True)
                for row in selected)

        def wire(receipt, caller, target, operation, *, method="GET", action="status"):
            return (receipt["status_code"] == 200 and hash_value(receipt["target"])
                and all(type(receipt[key]) in (int, float) and math.isfinite(receipt[key])
                        for key in ("started", "finished"))
                and 0 <= receipt["finished"] - receipt["started"] <= (180 if method == "POST" else 30)
                and hash_value(subscriptions[caller])
                and matches(receipt, "gateway", method, target=receipt["target"], caller=caller,
                            credential_sha256=subscriptions[caller])
                and matches(receipt, "application", action, runtime_identity=identities[target],
                            caller=caller, run_id=run_id, operation_id=operation))

        observations = actual["observations"]
        if not isinstance(observations, list) or len(observations) != 2:
            return blocked
        first, last = observations
        for row in observations:
            if (row["run_id"] != run_id or row["operation_id"] != run_id or row["caller"] != "operator"
                    or row["business_state"] != "succeeded" or not hash_value(row["sha256"])
                    or not wire(row, "operator", "candidate-planner", run_id)):
                return blocked
        if (first["target"] != last["target"] or first["sha256"] != last["sha256"]
                or first["request_id"] == last["request_id"]):
            return blocked
        census = {row["request_id"] for row in evidence if row.get("source") == "gateway"
            and row.get("target") == first["target"] and type(row.get("observed")) in (int, float)
            and first["started"] - 5 <= row["observed"] <= last["finished"] + 5}
        if census != {first["request_id"], last["request_id"]}:
            return blocked
        containers = {"planner-operations", "assessor-operations", "reviewer-operations",
                      "author-operations", "drafts", "findings"}
        snapshots = {}
        for side in ("before", "after"):
            rows = actual[side]
            if len(rows) != 6 or {row["container"] for row in rows} != containers:
                return blocked
            snapshots[side] = {}
            for row in rows:
                if (row["operation_id"] not in report["operation_ids"] or row["suite_id"] != report["run_id"]
                        or row["caller"] != "operator" or row["action"] != "read" or not hash_value(row["sha256"])
                        or row["target"] != report["storage_targets"][row["container"]]
                        or row["status_code"] not in (200, 206)
                        or not actual["started"] <= row["started"] <= row["finished"] <= actual["finished"]
                        or side == "before" and row["finished"] > first["started"]
                        or side == "after" and row["started"] < last["finished"]
                        or not matches(row, "storage", "GetBlob", target=row["target"],
                                       runtime_identity=observer, client_request_id=row["operation_id"])):
                    return blocked
                snapshots[side][row["container"]] = row["sha256"]
        peer = _peer_polls(evidence, run_id, identities, actual["started"], wire)
        if peer is None:
            return blocked
        valid = (peer and actual["response"] == "poll_interval_15_seconds_required"
            and hash_value(actual["before_sha256"]) and actual["before_sha256"] == actual["after_sha256"]
            and snapshots["before"] == snapshots["after"]
            and first["finished"] <= actual["refusal_started"] <= actual["refusal_finished"] < first["started"] + 15
            and last["started"] >= max(first["started"] + 15, actual["refusal_finished"]))
        return blocked | {"status": "pass" if valid else "fail",
            "reason": "actual_poll_cadence_and_refusal_verified" if valid else "actual_poll_limit_or_no_effect_failed"}
    except (KeyError, TypeError, ValueError, AttributeError, IndexError):
        return blocked


def _peer_polls(evidence, run_id, identities, end, wire):
    from .workflow_routes import _invocation
    records = [row for row in evidence if row.get("source") == "application"
               and row.get("method") == "poll.observed" and row.get("run_id") == run_id]
    server = {row.get("request_id") for row in evidence if row.get("source") == "application"
              and row.get("method") == "status" and row.get("run_id") == run_id and row.get("caller") != "operator"}
    if (not records or len({row["request_id"] for row in records}) != len(records)
            or {row["request_id"] for row in records} != server):
        return None
    groups = {}
    for record in records:
        facts, caller = record["facts"], record["caller"]
        parts = facts["probe_id"].split(".")
        if len(parts) != 4 or parts[:2] != ["route", caller] or parts[3] != "status":
            return None
        target = parts[2]
        original = {key: record[key] for key in
                    ("method", "run_id", "operation_id", "caller", "request_id", "status_code", "target")}
        original["facts"] = {key: value for key, value in facts.items() if key != "sha256"}
        row = record | {"started": facts["started"], "finished": facts["finished"]}
        if (caller not in INVOCATION_CALLERS.get(target, ()) or record["runtime_identity"] != identities[caller]
                or facts["sha256"] != sha256(original) or row["finished"] > end
                or not wire(row, caller, target, record["operation_id"])):
            return None
        groups.setdefault((caller, target, record["operation_id"], facts["read_operation_id"]), []).append(row)
    valid = True
    for (caller, target, parent, child), rows in groups.items():
        invocations = [record for record in evidence if record.get("source") == "application"
            and record.get("method") == "invocation.observed" and record.get("run_id") == run_id
            and record.get("operation_id") == parent and record.get("caller") == caller
            and record.get("runtime_identity") == identities[caller]
            and record.get("facts", {}).get("accepted_operation_id") == child]
        if len(invocations) != 1:
            return None
        invocation = _invocation(invocations[0])
        if (invocations[0]["facts"]["sha256"] != sha256(invocation)
                or not wire(invocation, caller, target, parent, method="POST", action="SendMessage")):
            return None
        previous = invocation["finished"]
        for row in sorted(rows, key=lambda item: item["started"]):
            valid &= row["started"] >= previous + 15
            previous = row["finished"]
    return valid
