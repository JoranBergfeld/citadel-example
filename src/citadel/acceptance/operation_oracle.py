"""Durable fault proof binds actual workload publication and independent state."""

import math
import re

from citadel.evidence.manifests import sha256
from citadel.operations import operation_key
from .oracle import hash_value


OPERATION_CHECKS = {
    "fault.dropped-committed-write": {"fault.dropped-committed-write", "fault.identical-input-reuse"},
    "fault.pending-incomplete": {"fault.pending-incomplete", "fault.running-incomplete",
        "fault.indeterminate-incomplete", "fault.missing-incomplete",
        "fault.changed-input-conflict", "fault.partial-not-completed"},
    "fault.fenced-explicit-retry": {"fault.fenced-explicit-retry", "fault.stale-generation-denied"},
    "fault.deadline-no-late-effect": {"fault.deadline-no-late-effect"},
    "fault.safe-read-recovery": {"fault.safe-read-recovery"},
    "fault.safe-read-exhaustion": {"fault.safe-read-exhaustion", "limit.safe_read_retries"},
}


def operation_snapshot(document, actor, result):
    record = document["operations"].get(operation_key(actor, "acceptance", result["operation_id"]))
    projection = {"operation_state": {
        "state": record["state"] if record else "missing",
        "generation": record["generation"] if record else None,
        "input_hash": record["input_hash"] if record else None,
        "deadline": record["deadline"] if record else None,
        "artifact_count": int(record is not None and "product" in record),
        "product_sha256": sha256(record["product"]) if record is not None and "product" in record else None,
        "sha256": sha256(record) if record is not None else None,
    }}
    if "missing_operation_id" in result:
        missing = operation_key(actor, "acceptance", result["missing_operation_id"])
        projection["missing_state"] = "missing" if missing not in document["operations"] else "present"
    if "steps" in result:
        budget = document["budgets"].get(result["operation_id"], {})
        projection["budget_state"] = {"closed": budget.get("closed"), "deadline": budget.get("deadline"),
                                      "remaining_reads": budget.get("remaining", {}).get("reads")}
        projection["business_sha256"] = sha256({
            key: document[key] for key in ("operations", "drafts", "findings")})
    return projection


def _matched(record, evidence, source, identity, method, **bindings):
    if (not hash_value(identity) or not isinstance(record.get("request_id"), str)
            or not record["request_id"] or not hash_value(record.get("target"))
            or type(record.get("status_code")) is not int
            or any(type(record.get(key)) not in (int, float) or not math.isfinite(record[key])
                   for key in ("started", "finished"))
            or not 0 <= record["finished"] - record["started"] <= 900):
        return False
    return any(row.get("source") == source and row.get("request_id") == record["request_id"]
        and row.get("status_code") == record["status_code"] and row.get("runtime_identity") == identity
        and row.get("method") == method and row.get("target") == record["target"]
        and type(row.get("observed")) in (int, float)
        and record["started"] - 5 <= row["observed"] <= record["finished"] + 5
        and all(row.get(key) == value for key, value in bindings.items()) for row in evidence)


def evaluate_operation(observation, snapshot, evidence, *, runtime_identity, observer_identity):
    blocked = {"check_id": observation.get("check_id"), "status": "blocked",
               "reason": "durable_fault_state_or_service_correlation_missing"}
    actual, state = observation.get("actual"), snapshot.get("operation_state")
    group = observation.get("probe_id")
    if (not isinstance(group, str) or group not in OPERATION_CHECKS
            or not isinstance(observation.get("check_id"), str)
            or observation.get("check_id") not in OPERATION_CHECKS[group]
            or any(not isinstance(observation.get(key), str)
                   or re.fullmatch("[A-Za-z0-9_-]{1,64}", observation[key]) is None
                   for key in ("operation_id", "run_id"))
            or observation.get("caller") != "candidate-planner"
            or observation.get("runtime_identity") != runtime_identity
            or runtime_identity == observer_identity
            or not isinstance(actual, dict) or not isinstance(state, dict)
            or actual.get("operation_id") != observation.get("operation_id")
            or snapshot.get("status_code") not in (200, 206)
            or observation.get("status_code") != 201
            or not hash_value(snapshot.get("sha256"))
            or not _matched(observation, evidence, "storage", runtime_identity, "PutBlob",
                            client_request_id=observation.get("operation_id"))
            or not _matched(snapshot, evidence, "storage", observer_identity, "GetBlob",
                            client_request_id=snapshot.get("operation_id"))
            or snapshot["started"] < observation["finished"]):
        return blocked
    events = [row for row in evidence if isinstance(row.get("facts"), dict)
              and row["facts"].get("sha256") == sha256(actual)
              and row["facts"].get("probe_id") == group]
    if not _matched(observation, events, "application", runtime_identity, "execution",
        run_id=observation.get("run_id"), operation_id=observation.get("operation_id"),
        caller=observation["caller"]):
        return blocked
    if group in ("fault.safe-read-recovery", "fault.safe-read-exhaustion"):
        steps, budget = actual.get("steps"), snapshot.get("budget_state")
        recovered = group == "fault.safe-read-recovery"
        valid = (isinstance(steps, list) and len(steps) == 3 and isinstance(budget, dict)
            and all(isinstance(step, dict) and hash_value(step.get("sha256"))
                and all(type(step.get(key)) in (int, float) and math.isfinite(step[key])
                        for key in ("started", "finished"))
                and observation["started"] <= step["started"] <= step["finished"] <= observation["finished"]
                and step["finished"] - step["started"] <= 30 for step in steps)
            and [step.get("state") for step in steps] == ["dropped", "dropped", "received" if recovered else "dropped"]
            and all(steps[index]["started"] - steps[index - 1]["finished"] >= index for index in (1, 2))
            and actual.get("state") == ("recovered" if recovered else "unavailable")
            and type(actual.get("read_attempts")) is int and actual["read_attempts"] == 3
            and type(actual.get("retry")) is int and actual["retry"] == 2
            and type(actual.get("remaining_reads")) is int and actual["remaining_reads"] == 509
            and budget.get("closed") is True and type(budget.get("remaining_reads")) is int
            and budget["remaining_reads"] == 509 and budget.get("deadline") == actual.get("deadline")
            and state.get("state") == "missing" and state.get("artifact_count") == 0
            and hash_value(actual.get("before_sha256"))
            and actual["before_sha256"] == actual.get("after_sha256") == snapshot.get("business_sha256")
            and all(step["sha256"] == actual["before_sha256"] for step in steps))
    elif group == "fault.deadline-no-late-effect":
        valid = (actual.get("response") == "fenced" and actual.get("state") == state.get("state") == "running"
            and type(actual.get("artifact_count")) is int and actual["artifact_count"] == 0
            and type(state.get("artifact_count")) is int and state["artifact_count"] == 0
            and state.get("product_sha256") is None
            and all(type(actual.get(key)) in (int, float) and math.isfinite(actual[key])
                    for key in ("observed", "deadline"))
            and actual["deadline"] == state.get("deadline")
            and observation["started"] < actual["deadline"] < actual["observed"] <= observation["finished"]
            and hash_value(actual.get("before_sha256"))
            and actual["before_sha256"] == actual.get("after_sha256") == state.get("sha256"))
    elif group == "fault.fenced-explicit-retry":
        valid = (actual.get("fenced") == "failed_no_commit" and actual.get("stale") == "fenced"
            and actual.get("retried") == "pending" and actual.get("state") == state.get("state") == "succeeded"
            and type(actual.get("generation")) is int and actual["generation"] == 3
            and type(state.get("generation")) is int and state["generation"] == 3
            and type(actual.get("artifact_count")) is int and actual["artifact_count"] == 1
            and type(state.get("artifact_count")) is int and state["artifact_count"] == 1
            and state.get("product_sha256") == sha256({"probe": "explicit-retry"}))
    elif group == "fault.pending-incomplete":
        valid = (actual.get("states") == ["pending", "running", "indeterminate", "missing"]
            and actual.get("completed_states") == ["incomplete", "incomplete", "incomplete", "missing"]
            and actual.get("changed_input") == "conflict" and actual.get("retry") == "conflict"
            and actual.get("completed") is False and state.get("state") == "indeterminate"
            and type(state.get("artifact_count")) is int and state["artifact_count"] == 0
            and state.get("product_sha256") is None and snapshot.get("missing_state") == "missing")
    else:
        valid = (actual.get("state") == state.get("state") == "succeeded"
            and actual.get("response") == "indeterminate" and actual.get("replay") == "conflict"
            and actual.get("identical_input") is True
            and type(actual.get("artifact_count")) is int and actual["artifact_count"] == 1
            and type(state.get("artifact_count")) is int and state["artifact_count"] == 1
            and hash_value(actual.get("sha256")) and actual["sha256"] == state.get("product_sha256"))
    return blocked | {"status": "pass" if valid else "fail",
        "business_state": state.get("state"),
        "reason": "verified_durable_fault" if valid else "durable_fault_invariant_failed"}
