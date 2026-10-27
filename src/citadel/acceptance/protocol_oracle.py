"""Protocol proofs reconstructed from actual hash-bound successful wire controls."""

from .coverage import required_checks
from .probes import AGENTS
from .oracle import hash_value


DEPENDENCIES = {
    "protocol.mcp-2025-11-25": tuple(sorted(key for key, expected in required_checks().items()
        if key.startswith("route.") and ".reference-data." in key and expected == "allow")),
    "protocol.a2a-1.0": tuple(sorted(key for key, expected in required_checks().items()
        if key.startswith("route.") and key.split(".")[2] in AGENTS
        and key.split(".")[3] in ("discovery", "invoke", "task") and expected == "allow")),
    "protocol.model-v1": tuple(sorted(key for key, expected in required_checks().items()
        if key.startswith("model.") or key.startswith("route.") and ".model." in key and expected == "allow")),
}
MCP = {"mcp": "2025-11-25", "mcp_transport": "Streamable HTTP"}
A2A = {"a2a": "1.0", "a2a_binding": "JSONRPC"}


def evaluate_protocol(check, report):
    from .proof_gate import evaluate_check
    result = {"check_id": check.get("check_id"), "status": "blocked",
              "reason": "complete_observed_protocol_receipts_required"}
    required = DEPENDENCIES.get(check.get("check_id"))
    a2a = check.get("check_id") == "protocol.a2a-1.0"
    model = check.get("check_id") == "protocol.model-v1"
    expected = ({"model_path": "/openai/v1/chat/completions"} if model else
                {"a2a": "1.0.0", "a2a_binding": "JSONRPC"} if a2a else MCP)
    children, pins = report.get("checks"), report.get("protocols")
    if (required is None or check.get("actual") != {"required_checks": list(required)}
            or not isinstance(children, list) or any(not isinstance(child, dict) for child in children)
            or not isinstance(pins, dict) or any(pins.get(key) != value for key, value in expected.items())):
        return result
    selected = []
    for identifier in required:
        matches = [child for child in children if child.get("check_id") == identifier]
        if len(matches) != 1:
            return result
        selected.append(matches[0])
    if any(child.get("status") == "fail" for child in selected):
        return result | {"status": "fail", "reason": "required_protocol_control_failed"}
    observations = []
    for child in selected:
        if child.get("status") != "pass":
            return result
        verified = evaluate_check(child, report)
        if verified["status"] != "pass":
            return result | {"status": verified["status"]}
        row = child["actual"]["observation"]
        if not model and (not a2a or not child["check_id"].endswith(".invoke")):
            if not isinstance(row.get("protocols"), dict):
                return result
            if row["protocols"] != (A2A if a2a else MCP):
                return result | {"status": "fail", "reason": "observed_protocol_version_mismatch"}
        observations.append(row)
    if model:
        return result | _model_backend(observations, report)
    if a2a:
        targets = {actor: {row["check_id"].split(".")[3]: row["target"] for row in observations
                          if row["check_id"].split(".")[2] == actor} for actor in AGENTS}
        if (any(values["task"] != values["invoke"] or values["discovery"] == values["task"]
                for values in targets.values())
                or any(len({values[capability] for values in targets.values()}) != 4
                       for capability in ("discovery", "task"))):
            return result
    elif len({row["target"] for row in observations}) != 1:
        return result
    return result | {"status": "pass", "reason": "negotiated_versions_and_real_protocol_operations_verified"}


def _model_backend(observations, report):
    blocked = {"status": "blocked", "reason": "actual_model_backend_protocol_receipt_required"}
    origins = {row["target"] for row in observations if row["check_id"].startswith("model.")}
    allowed = [row for row in observations if row["check_id"].startswith("route.")]
    frontends = {row["target"] for row in allowed}
    if len(origins) != 1 or len(frontends) != 1 or origins == frontends:
        return blocked
    for row in allowed:
        receipts = [record for record in report["evidence"]
            if record.get("source") == "gateway" and record.get("request_id") == row["request_id"]
            and record.get("status_code") == 200 and record.get("caller") == row["caller"]
            and record.get("target") == row["target"] and record.get("method") == "POST"
            and record.get("credential_sha256") == report["subscription_bindings"][row["caller"]]
            and type(record.get("observed")) in (int, float)
            and row["started"] - 5 <= record["observed"] <= row["finished"] + 5]
        if not receipts:
            return blocked
        for receipt in receipts:
            facts = receipt.get("facts")
            if (not isinstance(facts, dict) or not hash_value(facts.get("backend_target"))
                    or not isinstance(facts.get("backend_method"), str) or not facts["backend_method"]
                    or type(facts.get("backend_status")) is not int):
                return blocked
            if (facts.get("backend_dispatched") is not True or facts["backend_target"] not in origins
                    or facts["backend_method"] != "POST" or facts["backend_status"] != 200):
                return {"status": "fail", "reason": "actual_model_backend_protocol_mismatch"}
    return {"status": "pass", "reason": "actual_v1_backend_and_each_framework_usage_receipt_verified"}


def collect_protocols(report):
    for identifier, required in DEPENDENCIES.items():
        check = {"check_id": identifier, "expected": "evidence",
                 "actual": {"required_checks": list(required)}}
        yield check | evaluate_protocol(check, report)
