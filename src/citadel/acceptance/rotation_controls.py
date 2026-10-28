"""Fixed caller-owned read controls; private signing material never enters a workload."""

import asyncio
import hashlib
import re
import time
from uuid import uuid4

from citadel.evidence.manifests import sha256
from citadel.gateway.trust import INVOCATION_CALLERS
from citadel.operations import OperationError, identity
from .oracle import hash_value
from .telemetry import correlate, emit, gateway_request_id


KINDS = ("subscription", "certificate", "context")
LEDGERS = ("planner-operations", "assessor-operations", "reviewer-operations",
           "author-operations", "drafts", "findings")
TARGETS = {"candidate-planner": "evidence-assessor", "evidence-assessor": "release-reviewer",
           "release-reviewer": "reference-data", "operator": "candidate-planner",
           "briefing-author": "release-reviewer", "operator-web": "candidate-planner"}


def validate_rotation(value, workload):
    keys = {"kind", "target", "credential_sha256", "secret_version"}
    operator_read = workload == "operator-web"
    if operator_read:
        keys.add("projection")
    finding_read = workload == "briefing-author" and isinstance(value, dict) and value.get("kind") == "subscription"
    if finding_read:
        keys |= {"finding", "read_scope"}
    if (not isinstance(value, dict) or set(value) != keys or value["kind"] not in KINDS
            or value["target"] not in INVOCATION_CALLERS
            or operator_read and (value["kind"] != "subscription" or value["target"] != "candidate-planner"
                                  or value["projection"] != "run-list")
            or not operator_read and (value["target"] != "release-reviewer" if finding_read
                                      else workload not in INVOCATION_CALLERS[value["target"]])
            or not hash_value(value["credential_sha256"])
            or value["secret_version"] is not None and (
                value["kind"] != "subscription" or not isinstance(value["secret_version"], str)
                or re.fullmatch("[a-f0-9]{32}", value["secret_version"]) is None)):
        raise ValueError("Exact allocated read-only rotation control required")
    if finding_read:
        finding, scope = value["finding"], value["read_scope"]
        if (not isinstance(finding, dict) or set(finding) != {"artifact_id", "version", "sha256"}
                or type(finding["version"]) is not int or not 1 <= finding["version"] <= 2147483647
                or not hash_value(finding["sha256"]) or not isinstance(scope, dict)
                or set(scope) != {"operation_id", "run_id"}):
            raise ValueError("Exact existing funded finding required")
        for identifier in (finding["artifact_id"], scope["operation_id"], scope["run_id"]):
            identity(identifier)
    return value


def rotation_path(control):
    if control.get("projection") == "run-list":
        return "/operator/runs"
    if "finding" in control:
        return f"/findings/{control['finding']['artifact_id']}/versions/{control['finding']['version']}"
    return "/mcp" if control["target"] == "reference-data" else "/.well-known/agent-card.json"


def rotation_method(actor, target):
    if actor == "operator-web":
        return "operator-observe"
    return "findings-read" if actor == "briefing-author" else "initialize" if target == "reference-data" else "discovery"


async def rotation_read(*, workload, gateway, key, request, client, admit, principal_id=None):
    control = validate_rotation(request["rotation"], workload)
    if hashlib.sha256(key.encode()).hexdigest() != control["credential_sha256"]:
        raise ValueError("Allocated secret version differs from the pending rotation")
    await admit()
    deadline, started, operation = request["deadline"], time.time(), uuid4().hex
    target = control["target"]
    path = rotation_path(control)
    url = gateway + "/" + target + path
    method = "POST" if path == "/mcp" else "GET"
    payload = ({"jsonrpc": "2.0", "id": operation, "method": "initialize",
        "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                   "clientInfo": {"name": "citadel-rotation", "version": "1"}}} if method == "POST" else None)
    if time.time() >= deadline:
        raise OperationError("deadline", "Rotation read expired before dispatch")
    async with asyncio.timeout(max(0, min(30, deadline - time.time()))):
        response = await client.request(method, url, json=payload, follow_redirects=False, headers={
            "Ocp-Apim-Subscription-Key": key, "x-citadel-run-id": request["run_id"],
            "x-citadel-operation-id": operation, "Accept": "application/json, text/event-stream",
            **({"x-citadel-read-pool": control["read_scope"]["operation_id"]} if "finding" in control else {})})
        content = await response.aread()
    if len(content) > 1024 * 1024:
        raise ValueError("Rotation response exceeds the fixed bound")
    allowed = False
    if response.status_code == 200:
        body = response.json()
        if method == "POST":
            allowed = (body.get("jsonrpc") == "2.0" and body.get("id") == operation
                and body.get("result", {}).get("protocolVersion") == "2025-11-25" and "error" not in body)
        elif "finding" in control:
            allowed = sha256(body) == control["finding"]["sha256"]
        elif workload == "operator-web":
            allowed = (body.get("state") in ("ok", "empty") and isinstance(body.get("runs"), list)
                       and len(body["runs"]) <= 20 and "next_cursor" in body)
        else:
            interfaces = body.get("supportedInterfaces", [])
            allowed = (len(interfaces) == 1 and interfaces[0].get("url") == gateway + "/" + target + "/a2a"
                and interfaces[0].get("protocolBinding") == "JSONRPC"
                and interfaces[0].get("protocolVersion") == "1.0")
    row = {"run_id": request["run_id"], "operation_id": operation, "caller": workload,
        "check_id": "rotation." + control["kind"] + "-allowed-and-revoked",
        "target": hashlib.sha256(url.encode()).hexdigest(), "started": started, "finished": time.time(),
        "request_id": gateway_request_id(response.headers), "status_code": response.status_code,
        "origin_request_id": response.headers.get("x-citadel-origin-request-id"),
        "actual": "read_only_control" if allowed else "unverified_response",
        "credential_sha256": control["credential_sha256"]}
    if principal_id is not None:
        from uuid import UUID
        row["runtime_identity"] = hashlib.sha256(str(UUID(principal_id)).encode()).hexdigest()
    with correlate(request["run_id"], operation, workload):
        emit("rotation.probe", request_id=row["request_id"], status_code=row["status_code"],
            target=row["target"], facts={"sha256": sha256(row), "probe_id": row["check_id"]})
    return row


def evaluate_rotation(check, report):
    from .storage_probes import _correlated
    blocked = {"check_id": check["check_id"], "status": "blocked",
               "reason": "rotation_service_controls_restoration_and_no_effect_required"}
    try:
        value, evidence = check["actual"], report["evidence"]
        kind = check["check_id"].split(".")[1].removesuffix("-allowed-and-revoked")
        actor, target = value["caller"], value["name"]
        identities, operations = report["runtime_identities"], report["operation_ids"]
        rows = value["observations"]
        if (kind not in KINDS
                or not (actor in INVOCATION_CALLERS[target]
                        or kind == "subscription" and (
                            actor == "briefing-author" and target == "release-reviewer"
                            or actor == "operator-web" and target == "candidate-planner"))
                or len(rows) != 3
                or value["run_id"] not in operations or value["state"] != "restored"
                or not hash_value(value["before_sha256"])
                or value["before_sha256"] != value["after_sha256"]):
            return blocked
        for index, row in enumerate(rows):
            if (row["operation_id"] not in operations or row["run_id"] not in operations
                    or row["caller"] != actor or row["check_id"] != check["check_id"]
                    or not hash_value(row["target"]) or not hash_value(row["credential_sha256"])
                    or not 0 <= row["finished"] - row["started"] <= 30
                    or index and row["started"] < rows[index - 1]["finished"]
                    or row["target"] != rows[0]["target"]):
                return blocked
            if actor not in ("operator", "operator-web"):
                if row.get("runtime_identity") != identities[actor]:
                    return blocked
                if not any(e.get("source") == "application" and e.get("method") == "rotation.probe"
                        and e.get("request_id") == row["request_id"] and e.get("status_code") == row["status_code"]
                        and e.get("runtime_identity") == identities[actor]
                        and e.get("run_id") == row["run_id"] and e.get("operation_id") == row["operation_id"]
                        and e.get("caller") == actor and e.get("target") == row["target"]
                        and e.get("facts", {}).get("sha256") == sha256(row)
                        and e.get("facts", {}).get("probe_id") == check["check_id"]
                        and row["started"] - 5 <= e.get("observed", -1) <= row["finished"] + 5
                        for e in evidence):
                    return blocked
            gateway = [e for e in evidence if e.get("source") == "gateway"
                and e.get("request_id") == row["request_id"] and e.get("target") == row["target"]
                and e.get("status_code") == row["status_code"]
                and row["started"] - 5 <= e.get("observed", -1) <= row["finished"] + 5]
            if len(gateway) != 1:
                return blocked
            service = gateway[0]
            if index == 1 and any(e.get("source") == "application"
                    and e.get("method") in ("initialize", "discovery", "findings-read", "operator-observe")
                    and e.get("request_id") == row["request_id"] for e in evidence):
                return blocked
            if index != 1:
                method = rotation_method(actor, target)
                if (row["status_code"] != 200 or row["actual"] != "read_only_control"
                        or service.get("credential_sha256") != report["subscription_bindings"][actor]
                        or service.get("caller") != actor
                        or service.get("facts", {}).get("backend_dispatched") is not True
                        or not any(e.get("source") == "application" and e.get("method") == method
                            and e.get("request_id") == row["request_id"] and e.get("status_code") == 200
                            and e.get("runtime_identity") == identities[target] and e.get("caller") == actor
                            and row["started"] - 5 <= e.get("observed", -1) <= row["finished"] + 5
                            for e in evidence)):
                    return blocked
            elif kind == "subscription":
                if (row["status_code"] != 401 or service.get("facts", {}).get("backend_dispatched") is not False
                        or service.get("facts", {}).get("reason") != "SubscriptionKeyInvalid"
                        or row["credential_sha256"] == rows[0]["credential_sha256"]):
                    return blocked
            else:
                reason = "certificate_rejected" if kind == "certificate" else "invalid_gateway_context"
                if (row["status_code"] != 403 or service.get("facts", {}).get("backend_dispatched") is not True
                        or service.get("facts", {}).get("backend_status") != 403
                        or service.get("credential_sha256") != report["subscription_bindings"][actor]
                        or service.get("caller") != actor or not row.get("origin_request_id")
                        or not any(e.get("source") == "application"
                            and e.get("method") == "authorization.denied"
                            and e.get("request_id") == row["origin_request_id"]
                            and e.get("status_code") == 403 and e.get("runtime_identity") == identities[target]
                            and e.get("facts", {}).get("reason") == reason
                            and e.get("facts", {}).get("business_state") == "not_dispatched"
                            and row["started"] - 5 <= e.get("observed", -1) <= row["finished"] + 5
                            for e in evidence)):
                    return blocked
        if rows[0]["credential_sha256"] != rows[2]["credential_sha256"]:
            return blocked
        for side in ("before", "after"):
            if (len(value[side]) != len(LEDGERS)
                    or {row["container"] for row in value[side]} != set(LEDGERS)):
                return blocked
        for container in LEDGERS:
            before, after = (next(row for row in value[side] if row["container"] == container)
                             for side in ("before", "after"))
            observers = {e.get("runtime_identity") for e in evidence if e.get("source") == "storage"
                         and e.get("request_id") == before["request_id"]}
            if len(observers) != 1:
                return blocked
            observer = observers.pop()
            for row in (before, after):
                if (not hash_value(observer) or observer in identities.values()
                        or row["operation_id"] not in operations or row["suite_id"] != report["run_id"]
                        or row["caller"] != "operator" or row["status_code"] not in (200, 206)
                        or row["target"] != report["storage_targets"][container]
                        or not _correlated(row, evidence, observer)):
                    return blocked
            if (before["finished"] > rows[1]["started"] or after["started"] < rows[2]["finished"]
                    or before["target"] != after["target"]
                    or before["sha256"] != after["sha256"] or before["count"] != after["count"]):
                return blocked
        return blocked | {"status": "pass", "reason": "actual_rotation_and_unchanged_business_state_verified"}
    except (KeyError, TypeError, ValueError, StopIteration, IndexError):
        return blocked
