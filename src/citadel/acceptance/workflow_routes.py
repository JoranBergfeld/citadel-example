"""Reuse actual workflow receipts; never reinvoke work or replenish operation tickets."""

import hashlib
import json
import math

from citadel.evidence.manifests import sha256
from citadel.operations import identity
from .oracle import hash_value
from .telemetry import correlate, emit, gateway_request_id


PAIRS = {"evidence-assessor": "candidate-planner", "release-reviewer": "evidence-assessor"}


def _observation(record):
    facts = record["facts"]
    target = facts["probe_id"].split(".")[2]
    if (PAIRS.get(target) != record["caller"] or facts["probe_id"] != f"route.{record['caller']}.{target}.status"
            or record["status_code"] != 200 or not hash_value(record["target"])
            or not hash_value(facts["input_hash"]) or not hash_value(facts["result_sha256"])
            or any(type(facts[key]) not in (int, float) or not math.isfinite(facts[key])
                   for key in ("started", "finished"))
            or not 0 <= facts["finished"] - facts["started"] <= 30):
        raise ValueError("Invalid observed owner-read metadata")
    for value in (record["run_id"], record["operation_id"], facts["read_operation_id"]):
        identity(value)
    reference = {"operation_id": facts["read_operation_id"], "run_id": record["run_id"],
        "input_hash": facts["input_hash"], "result_sha256": facts["result_sha256"],
        "task_sha256": facts["result_sha256"]}
    return {key: record[key] for key in ("run_id", "operation_id", "caller", "request_id", "status_code", "target")} | {
        "check_id": facts["probe_id"], "started": facts["started"], "finished": facts["finished"],
        "sources": ["gateway"], "reason": "observed", "actual": "owned_status", "sha256": facts["result_sha256"],
        "control_reference": reference, "observation_kind": "workflow"}


def observe_status(response, *, caller, target, run_id, operation_id, started, finished):
    if target not in PAIRS or caller != PAIRS[target] or response.status_code != 200:
        return None
    body = response.json()
    if not isinstance(body, dict) or body.get("state") != "succeeded" or body.get("run_id") != run_id:
        return None
    record = {"method": "status.observed", "run_id": run_id, "operation_id": operation_id,
        "caller": caller, "request_id": gateway_request_id(response.headers), "status_code": response.status_code,
        "target": hashlib.sha256(str(response.request.url).encode()).hexdigest(),
        "facts": {"probe_id": f"route.{caller}.{target}.status", "read_operation_id": body["operation_id"],
            "input_hash": body["input_hash"], "result_sha256": sha256(body["result"]),
            "started": started, "finished": finished}}
    observation = _observation(record)
    record["facts"]["sha256"] = sha256(observation)
    with correlate(run_id, operation_id, caller):
        emit("status.observed", request_id=record["request_id"], status_code=record["status_code"],
             target=record["target"], facts=record["facts"])
    return record


def status_controls(evidence, context):
    from .route_context import validate_route_context
    validate_route_context(context)
    selected = {}
    for record in evidence:
        if not isinstance(record, dict) or record.get("source") != "application" or record.get("method") != "status.observed":
            continue
        try:
            row = _observation(record)
            target = row["check_id"].split(".")[2]
            if (record["facts"]["sha256"] == sha256(row)
                    and row["control_reference"] == context["operations"][target]
                    and isinstance(row["request_id"], str) and row["request_id"]):
                selected.setdefault(row["check_id"], row)
        except (ValueError, TypeError, KeyError, IndexError):
            continue
    return list(selected.values())


def _invocation(record):
    from citadel.gateway.trust import INVOCATION_CALLERS
    facts = record["facts"]
    parts = facts["probe_id"].split(".")
    if (len(parts) != 4 or parts[0] != "route" or parts[3] != "invoke"
            or parts[2] == "reference-data" or record["caller"] not in INVOCATION_CALLERS.get(parts[2], ())
            or parts[1] != record["caller"] or record["status_code"] != 200
            or not hash_value(record["target"]) or not hash_value(facts["task_sha256"])
            or facts["business_state"] not in ("TASK_STATE_SUBMITTED", "TASK_STATE_WORKING", "TASK_STATE_COMPLETED")
            or not isinstance(record["request_id"], str) or not record["request_id"]
            or any(type(facts[key]) not in (int, float) or not math.isfinite(facts[key])
                   for key in ("started", "finished"))
            or not 0 <= facts["finished"] - facts["started"] <= 180):
        raise ValueError("Invalid actual invocation receipt")
    for value in (record["run_id"], record["operation_id"], facts["accepted_operation_id"]):
        identity(value)
    return {key: record[key] for key in
        ("run_id", "operation_id", "caller", "request_id", "status_code", "target")} | {
        "check_id": facts["probe_id"], "started": facts["started"], "finished": facts["finished"],
        "sources": ["gateway"], "reason": "observed", "actual": "accepted_invocation",
        "accepted_operation_id": facts["accepted_operation_id"], "business_state": facts["business_state"],
        "sha256": facts["task_sha256"], "observation_kind": "workflow"}


def observe_invocation(response, *, caller, target, run_id, operation_id, started, finished):
    """Hash the actual protocol task; never export task artifacts, inputs or prose."""
    try:
        request, body = json.loads(response.request.content), response.json()
        task = body["result"]["task"]
        if (response.request.method != "POST" or request.get("method") != "SendMessage"
                or not isinstance(request.get("id"), (str, int)) or body.get("id") != request["id"]
                or body.get("jsonrpc") != "2.0" or "error" in body or task["contextId"] != run_id):
            return None
        record = {"method": "invocation.observed", "run_id": run_id, "operation_id": operation_id,
            "caller": caller, "request_id": gateway_request_id(response.headers), "status_code": response.status_code,
            "target": hashlib.sha256(str(response.request.url).encode()).hexdigest(),
            "facts": {"probe_id": f"route.{caller}.{target}.invoke", "accepted_operation_id": task["id"],
                "task_sha256": sha256(task), "business_state": task["status"]["state"],
                "started": started, "finished": finished}}
        observation = _invocation(record)
    except (ValueError, TypeError, KeyError, AttributeError):
        return None
    record["facts"]["sha256"] = sha256(observation)
    if caller != "operator":
        with correlate(run_id, operation_id, caller):
            emit("invocation.observed", request_id=record["request_id"], status_code=record["status_code"],
                 target=record["target"], facts=record["facts"])
    return record


def invocation_controls(evidence, context, *, operator=None):
    from .route_context import validate_route_context
    validate_route_context(context)
    selected = {}
    for record in [*evidence, *([operator] if operator is not None else [])]:
        if not isinstance(record, dict) or record.get("method") != "invocation.observed":
            continue
        if record is not operator and record.get("source") != "application":
            continue
        if record is operator and record.get("caller") != "operator":
            continue
        try:
            row = _invocation(record)
            reference = context["operations"][row["check_id"].split(".")[2]]
            if (record["facts"]["sha256"] == sha256(row) and row["run_id"] == reference["run_id"]
                    and row["accepted_operation_id"] == reference["operation_id"]):
                selected.setdefault(row["check_id"], row)
        except (ValueError, TypeError, KeyError, IndexError):
            continue
    return list(selected.values())
