"""Correlate actual model receipts, allocated APIM controls and independent storage."""

import math
import re

from .model_probes import AUTH_ERRORS, INPUT_BOUND, OUTPUT_BOUND
from .operation_oracle import _matched
from .oracle import hash_value
from .storage_probes import _correlated


def evaluate_allowed_model(observation, evidence, *, runtime_identity, subscription):
    blocked = {"check_id": observation.get("check_id") if isinstance(observation, dict) else None,
               "status": "blocked", "reason": "allocated_model_route_or_actual_usage_missing"}
    if (not isinstance(observation, dict) or not isinstance(evidence, list)
            or any(not isinstance(row, dict) for row in evidence) or not hash_value(subscription)
            or not hash_value(runtime_identity)):
        return blocked
    caller = observation.get("caller")
    if (caller not in ("candidate-planner", "evidence-assessor", "release-reviewer", "briefing-author")
            or observation.get("check_id") != f"route.{caller}.model.inference"
            or observation.get("runtime_identity") != runtime_identity or observation.get("status_code") != 200
            or any(not isinstance(observation.get(key), str)
                   or re.fullmatch("[A-Za-z0-9_-]{1,64}", observation[key]) is None
                   for key in ("run_id", "operation_id"))):
        return blocked
    facts = {key: observation.get(key) for key in (
        "input_tokens", "output_tokens", "tokens", "started", "finished")}
    if (any(type(facts[key]) is not int or not 0 <= facts[key] <= bound for key, bound in (
                ("input_tokens", 16000), ("output_tokens", 2000), ("tokens", 18000)))
            or facts["tokens"] != facts["input_tokens"] + facts["output_tokens"]
            or not _matched(observation, evidence, "application", runtime_identity, "chat.completions",
                caller=caller, run_id=observation["run_id"], operation_id=observation["operation_id"], facts=facts)
            or observation["finished"] - observation["started"] > 60):
        return blocked
    if not any(row.get("source") == "gateway" and row.get("method") == "POST"
            and row.get("request_id") == observation["request_id"] and row.get("status_code") == 200
            and row.get("caller") == caller and row.get("target") == observation["target"]
            and row.get("credential_sha256") == subscription and isinstance(row.get("facts"), dict)
            and row["facts"].get("backend_dispatched") is True and type(row.get("observed")) in (int, float)
            and observation["started"] - 5 <= row["observed"] <= observation["finished"] + 5 for row in evidence):
        return blocked
    return blocked | {"status": "pass", "reason": "verified_allocated_model_route_and_actual_usage"}


def evaluate_operator_model(observation, control, snapshots, evidence, *, identities, subscriptions, observer_identity):
    blocked = {"check_id": "route.operator.model.inference", "status": "blocked",
               "reason": "operator_model_denial_control_or_no_effect_missing"}
    if (any(not isinstance(value, dict) for value in (observation, control, snapshots, identities, subscriptions))
            or not isinstance(evidence, list) or any(not isinstance(row, dict) for row in evidence)
            or not hash_value(observer_identity) or observer_identity in identities.values()
            or observation.get("check_id") != blocked["check_id"] or observation.get("caller") != "operator"
            or observation.get("runtime_identity") is not None or observation.get("state") != "observed"
            or not hash_value(subscriptions.get("operator")) or not hash_value(observation.get("target"))
            or type(observation.get("status_code")) is not int
            or any(not isinstance(observation.get(key), str) or not re.fullmatch("[A-Za-z0-9_.:-]{1,128}", observation[key])
                   for key in ("run_id", "operation_id", "request_id"))
            or any(type(observation.get(key)) not in (int, float) or not math.isfinite(observation[key])
                   for key in ("started", "finished"))
            or not 0 <= observation["finished"] - observation["started"] <= 60):
        return blocked
    gateway = [row for row in evidence if row.get("source") == "gateway" and row.get("method") == "POST"
        and row.get("request_id") == observation["request_id"]
        and row.get("status_code") == observation["status_code"] and row.get("caller") == "operator"
        and row.get("target") == observation["target"] and row.get("credential_sha256") == subscriptions["operator"]
        and type(row.get("observed")) in (int, float)
        and observation["started"] - 5 <= row["observed"] <= observation["finished"] + 5]
    if not gateway:
        return blocked
    if observation["status_code"] == 200 and observation.get("reason") == "unauthorized_model_succeeded":
        return blocked | {"status": "fail", "reason": "operator_model_inference_succeeded"}
    if (observation["status_code"] != 403 or observation.get("reason") != "model_caller_denied"
            or not any(isinstance(row.get("facts"), dict) and row["facts"].get("backend_dispatched") is False
                       for row in gateway)
            or any(type(observation.get(key)) is not int or observation[key] != value for key, value in (
                ("model_attempts", 1), ("input_tokens", INPUT_BOUND), ("output_tokens", OUTPUT_BOUND)))):
        return blocked
    allowed, slot = control.get("allowed"), control.get("slot")
    if (not isinstance(allowed, dict) or not isinstance(allowed.get("caller"), str)
            or not isinstance(slot, list) or len(slot) != 2 or any(not isinstance(row, dict) for row in slot)
            or allowed.get("target") != observation["target"]
            or allowed.get("request_id") == observation["request_id"]):
        return blocked
    caller = allowed["caller"]
    if (evaluate_allowed_model(allowed | {"check_id": f"route.{caller}.model.inference"}, evidence,
            runtime_identity=identities.get(caller), subscription=subscriptions.get(caller))["status"] != "pass"
            or max(allowed["finished"], observation["finished"])
               - min(allowed["started"], observation["started"]) > 900):
        return blocked
    if ([row.get("action") for row in slot] != ["acquire", "release"]
            or [row.get("status_code") for row in slot] != [201, 200]
            or slot[0].get("target") != slot[1].get("target")
            or slot[0].get("request_id") == slot[1].get("request_id")
            or any(not _matched(row, evidence, "storage", observer_identity, "LeaseBlob",
                client_request_id=row.get("operation_id")) for row in slot)
            or not slot[0]["finished"] + 60 <= observation["started"] <= observation["finished"] <= slot[1]["started"] - 60
            or slot[1]["finished"] - slot[0]["started"] > 900):
        return blocked
    for container in ("drafts", "findings"):
        if any(not isinstance(snapshots.get(side), dict) for side in ("before", "after")):
            return blocked
        before, after = (snapshots[side].get(container) for side in ("before", "after"))
        for row in (before, after):
            if (not isinstance(row, dict) or row.get("container") != container or row.get("action") != "read"
                    or row.get("status_code") not in (200, 206) or not hash_value(row.get("sha256"))
                    or type(row.get("count")) is not int or row["count"] < 0
                    or not _correlated(row, evidence, observer_identity)):
                return blocked
        if (not before.get("suite_id") or before["suite_id"] != after.get("suite_id")
                or before.get("target") != after.get("target")
                or not slot[0]["finished"] <= before["started"] <= before["finished"] <= observation["started"]
                or not observation["finished"] <= after["started"] <= after["finished"] <= slot[1]["started"]):
            return blocked
        if before["sha256"] != after["sha256"] or before["count"] != after["count"]:
            return blocked | {"status": "fail", "reason": "operator_model_control_changed_business_products"}
    return blocked | {"status": "pass", "reason": "verified_operator_model_denial_and_no_effect"}


def evaluate_model(observation, control, snapshots, evidence, *, identities, subscription, observer_identity):
    blocked = {"check_id": observation.get("check_id") if isinstance(observation, dict) else None,
               "status": "blocked", "reason": "model_receipt_control_or_no_effect_missing"}
    if (not isinstance(observation, dict) or not isinstance(control, dict)
            or not isinstance(evidence, list) or any(not isinstance(row, dict) for row in evidence)
            or not isinstance(identities, dict) or not hash_value(observer_identity)
            or observer_identity in identities.values()):
        return blocked
    actor = observation.get("caller")
    if (not isinstance(actor, str) or actor not in identities
            or observation.get("check_id") != f"model.{actor}.direct-denied"
            or observation.get("runtime_identity") != identities[actor]
            or observation.get("state") != "observed"
            or any(not isinstance(observation.get(key), str)
                   or re.fullmatch("[A-Za-z0-9_-]{1,64}", observation[key]) is None
                   for key in ("run_id", "operation_id"))
            or any(type(observation.get(key)) is not int or observation[key] != value for key, value in (
                ("model_attempts", 1), ("input_tokens", INPUT_BOUND), ("output_tokens", OUTPUT_BOUND)))):
        return blocked
    facts = {"model_attempts": 1, "input_tokens": INPUT_BOUND, "output_tokens": OUTPUT_BOUND,
             "reason": observation.get("reason")}
    if (not _matched(observation, evidence, "application", identities[actor], "model.direct",
            run_id=observation["run_id"], operation_id=observation["operation_id"], caller=actor, facts=facts)
            or observation["finished"] - observation["started"] > 60):
        return blocked
    if observation.get("status_code") == 200 and observation.get("reason") == "unauthorized_model_succeeded":
        return blocked | {"status": "fail", "reason": "unauthorized_model_inference_succeeded"}
    if (observation.get("status_code") not in (401, 403) or observation.get("reason") not in AUTH_ERRORS
            or observation.get("actual") is not None):
        return blocked
    allowed, slot = control.get("allowed"), control.get("slot")
    if (not isinstance(allowed, dict) or not isinstance(slot, list) or len(slot) != 2
            or any(not isinstance(row, dict) for row in slot) or not hash_value(subscription)):
        return blocked
    caller = allowed.get("caller")
    if not isinstance(caller, str) or caller not in identities or (
            actor != "reference-data" and caller != actor) or caller == "reference-data":
        return blocked
    usage = {key: allowed.get(key) for key in ("input_tokens", "output_tokens", "tokens", "started", "finished")}
    if (any(type(usage[key]) is not int or not 0 <= usage[key] <= bound for key, bound in (
                ("input_tokens", 16000), ("output_tokens", 2000), ("tokens", 18000)))
            or usage["tokens"] != usage["input_tokens"] + usage["output_tokens"]
            or allowed.get("status_code") != 200
            or allowed.get("request_id") == observation["request_id"]
            or not _matched(allowed, evidence, "application", identities[caller], "chat.completions",
                run_id=allowed.get("run_id"), operation_id=allowed.get("operation_id"),
                caller=caller, facts=usage)
            or allowed["finished"] - allowed["started"] > 60
            or max(allowed["finished"], observation["finished"])
               - min(allowed["started"], observation["started"]) > 900
            or not any(row.get("source") == "gateway" and row.get("method") == "POST"
                and row.get("request_id") == allowed["request_id"] and row.get("status_code") == 200
                and row.get("caller") == caller and row.get("target") == allowed["target"]
                and row.get("credential_sha256") == subscription and isinstance(row.get("facts"), dict)
                and row["facts"].get("backend_dispatched") is True
                and type(row.get("observed")) in (int, float)
                and allowed["started"] - 5 <= row["observed"] <= allowed["finished"] + 5 for row in evidence)):
        return blocked
    if ([row.get("action") for row in slot] != ["acquire", "release"]
            or [row.get("status_code") for row in slot] != [201, 200]
            or slot[0].get("target") != slot[1].get("target")
            or slot[0].get("request_id") == slot[1].get("request_id")
            or any(not _matched(row, evidence, "storage", observer_identity, "LeaseBlob",
                client_request_id=row.get("operation_id")) for row in slot)
            or not slot[0]["finished"] + 60 <= observation["started"] <= observation["finished"] <= slot[1]["started"] - 60
            or slot[1]["finished"] - slot[0]["started"] > 900):
        return blocked
    if not isinstance(snapshots, dict):
        return blocked
    for container in ("drafts", "findings"):
        if any(not isinstance(snapshots.get(side), dict) for side in ("before", "after")):
            return blocked
        before, after = (snapshots[side].get(container) for side in ("before", "after"))
        if any(not isinstance(row, dict) for row in (before, after)):
            return blocked
        for row in (before, after):
            if (row.get("container") != container or row.get("action") != "read"
                    or row.get("status_code") not in (200, 206)
                    or type(row.get("count")) is not int or row["count"] < 0 or not hash_value(row.get("sha256"))
                    or not _correlated(row, evidence, observer_identity)):
                return blocked
        if (not before.get("suite_id") or before["suite_id"] != after.get("suite_id")
                or before.get("target") != after.get("target")
                or not slot[0]["finished"] <= before["started"] <= before["finished"] <= observation["started"]
                or not observation["finished"] <= after["started"] <= after["finished"] <= slot[1]["started"]):
            return blocked
        if before["sha256"] != after["sha256"] or before["count"] != after["count"]:
            return blocked | {"status": "fail", "reason": "model_control_changed_business_products"}
    return blocked | {"status": "pass", "reason": "verified_model_denial_allowed_route_and_no_effect"}
