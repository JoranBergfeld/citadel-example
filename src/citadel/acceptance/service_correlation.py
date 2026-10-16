"""Count exact queried service receipts after independently rechecking every control."""

from citadel.evidence.manifests import sha256
from .coverage import required_checks


DEPENDENCIES = {"telemetry.storage-correlation": tuple(sorted(
    key for key in required_checks() if key.startswith("storage."))),
    "telemetry.gateway-correlation": tuple(sorted(
        key for key in required_checks() if key.startswith("route.")))}


def _correlation(identifier, report):
    from .proof_gate import evaluate_check
    blocked = {"status": "blocked", "reason": "complete_exact_service_receipt_census_required"}
    try:
        required = DEPENDENCIES[identifier]
        source = "storage" if identifier == "telemetry.storage-correlation" else "gateway"
        children, evidence = report["checks"], report["evidence"]
        by_request = {}
        for row in evidence:
            if row.get("source") == source:
                by_request.setdefault(row.get("request_id"), []).append(row)
        receipts = {}
        for name in required:
            matches = [row for row in children if row.get("check_id") == name]
            if len(matches) != 1:
                return blocked
            child = matches[0]
            if child.get("status") == "fail":
                return blocked | {"status": "fail", "reason": "required_service_control_failed"}
            verified = evaluate_check(child, report)
            if verified["status"] != "pass":
                return blocked | {"status": verified["status"]}
            actual = child["actual"]
            if source == "storage":
                observations = [actual[key] for key in ("observation", "control", "before", "after")]
            else:
                observations = [actual["observation"]]
                control = actual["control"].get("allowed", actual["control"])
                if control:
                    observations.append(control)
            for row in observations:
                expected = {"source": source, "request_id": row["request_id"],
                            "target": row["target"], "status_code": row["status_code"]}
                if source == "storage":
                    principal = row.get("runtime_identity")
                    if principal is None and row.get("caller") == "operator":
                        principal = actual["before"]["runtime_identity"]
                    expected.update(client_request_id=row["operation_id"], runtime_identity=principal,
                                    method="GetBlob" if row["action"] == "read" else "PutBlob")
                else:
                    capability = row.get("check_id", "route.model.inference").rsplit(".", 1)[-1]
                    expected.update(caller=row["caller"],
                        credential_sha256=report["subscription_bindings"][row["caller"]],
                        method="GET" if capability in ("discovery", "status", "findings") else "POST")
                records = by_request.get(row["request_id"], [])
                if not records or any(
                        any(record.get(key) != value for key, value in expected.items())
                        or type(record.get("observed")) not in (int, float)
                        or not row["started"] - 5 <= record["observed"] <= row["finished"] + 5
                        or source == "gateway" and record.get("facts", {}).get("backend_dispatched")
                            is not (row["status_code"] == 200)
                        for record in records):
                    return blocked
                digest = sha256(expected)
                if row["request_id"] in receipts and receipts[row["request_id"]] != digest:
                    return blocked
                receipts[row["request_id"]] = digest
        return {"status": "pass", "reason": "all_actual_service_receipts_and_controls_reverified",
                "actual": {"required_checks": list(required), "sources": [source, "application"],
                           "count": len(receipts), "sha256": sha256(sorted(receipts.values()))}}
    except (KeyError, ValueError, TypeError, AttributeError):
        return blocked


def evaluate_correlation(check, report):
    result = _correlation(check["check_id"], report)
    actual = result.pop("actual", None)
    if result["status"] == "pass" and actual != check.get("actual"):
        result = {"status": "blocked", "reason": "actual_service_receipt_count_binding_missing"}
    return {"check_id": check["check_id"]} | result


def collect_correlations(report):
    for identifier in DEPENDENCIES:
        yield {"check_id": identifier, "expected": "evidence"} | _correlation(identifier, report)
