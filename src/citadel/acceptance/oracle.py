"""Deterministic proof evaluation. An expected business failure is not success."""

import math
import re


DENIALS = {"AuthorizationPermissionMismatch", "AuthorizationFailure", "PermissionDenied",
           "Forbidden", "Unauthorized", "Route denied", "Method denied",
           "invalid_gateway_context", "certificate_required", "certificate_rejected",
           "AccessDenied", "invalid_subscription"}
SOURCES = {"application", "gateway", "storage", "model", "ingress"}


def hash_value(value):
    return isinstance(value, str) and re.fullmatch("[a-f0-9]{64}", value) is not None


def evaluate_control(observation, evidence):
    result = {"check_id": observation.get("check_id"), "status": "blocked",
              "business_state": observation.get("business_state", "unobserved"),
              "reason": "required_proof_missing"}
    required = {"run_id", "operation_id", "caller", "runtime_identity", "started", "finished",
                "expected", "status_code", "request_id", "control_request_id", "control_status",
                "before_sha256", "after_sha256", "before_count", "after_count", "sources",
                "control_identity"}
    if not required <= observation.keys():
        return result
    o = observation
    if (not all(hash_value(o[key]) for key in (
                "runtime_identity", "control_identity", "before_sha256", "after_sha256"))
            or any(not isinstance(o[key], str) or not re.fullmatch("[A-Za-z0-9_.:-]{1,128}", o[key])
                   for key in ("request_id", "control_request_id"))
            or any(type(o[key]) is not int or not 100 <= o[key] <= 599
                   for key in ("status_code", "control_status"))
            or o["request_id"] == o["control_request_id"]
            or not isinstance(o["sources"], list) or not o["sources"]
            or any(not isinstance(source, str) or source not in SOURCES for source in o["sources"])
            or any(type(o[key]) not in (int, float) or not math.isfinite(o[key])
                   for key in ("started", "finished"))
            or not 0 <= o["finished"] - o["started"] <= 900
            or any(type(o[key]) is not int or o[key] < 0 for key in ("before_count", "after_count"))):
        return result
    if o["expected"] == "deny":
        if (o["status_code"] not in (401, 403) or o.get("reason") not in DENIALS
                or o["before_sha256"] != o["after_sha256"] or o["before_count"] != o["after_count"]):
            return result | {"status": "fail", "reason": "denial_or_no_effect_not_established"}
    elif o["expected"] == "allow":
        if not 200 <= o["status_code"] < 300:
            return result | {"status": "fail", "reason": "permitted_control_failed"}
    else:
        return result
    if not 200 <= o["control_status"] < 300:
        return result | {"status": "fail", "reason": "working_control_missing"}
    for source in o["sources"]:
        for request_id, status, identity in (
                (o["request_id"], o["status_code"], o["runtime_identity"]),
                (o["control_request_id"], o["control_status"], o["control_identity"])):
            matches = [e for e in evidence
                       if e.get("source") == source and e.get("request_id") == request_id
                       and e.get("status_code") == status
                       and type(e.get("observed")) in (int, float)
                       and o["started"] - 5 <= e["observed"] <= o["finished"] + 5
                       and (identity is None or e.get("runtime_identity") == identity)]
            if not matches:
                return result | {"reason": "required_service_correlation_missing"}
    return result | {"status": "pass", "reason": "verified_control"}
