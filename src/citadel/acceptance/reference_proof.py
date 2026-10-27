"""Bind three real MCP reads to the allocated caller and Reference Data runtime."""

import math

from .oracle import hash_value


def reference_reads_proven(observation, evidence, *, caller, reference_identity, subscription):
    receipts = observation.get("actual", {}).get("reference_reads")
    if (not hash_value(reference_identity) or not hash_value(subscription)
            or not isinstance(receipts, list) or len(receipts) != 3
            or any(not isinstance(row, dict) or not isinstance(row.get("method"), str)
                   or not isinstance(row.get("request_id"), str) or not row["request_id"] for row in receipts)
            or {row["method"] for row in receipts} != {"initialize", "lookup_airport", "list_runways"}
            or len({row["request_id"] for row in receipts}) != 3):
        return False
    for receipt in receipts:
        if (receipt.get("status_code") != 200 or not hash_value(receipt.get("target"))
                or receipt.get("run_id") != observation["run_id"]
                or receipt.get("operation_id") != observation["run_id"]
                or any(type(receipt.get(key)) not in (int, float) or not math.isfinite(receipt[key])
                       for key in ("started", "finished"))
                or not 0 <= receipt["finished"] - receipt["started"] <= 30
                or receipt["finished"] > observation["started"]
                or observation["finished"] - receipt["started"] > 900):
            return False
        def matches(row):
            return (row.get("request_id") == receipt["request_id"] and row.get("status_code") == 200
                and type(row.get("observed")) in (int, float)
                and receipt["started"] - 5 <= row["observed"] <= receipt["finished"] + 5
                and row.get("caller") == caller)
        if (not any(matches(row) and row.get("source") == "gateway" and row.get("method") == "POST"
                and row.get("target") == receipt["target"] and row.get("credential_sha256") == subscription
                for row in evidence)
                or not any(matches(row) and row.get("source") == "application"
                    and row.get("runtime_identity") == reference_identity and row.get("method") == receipt["method"]
                    and row.get("run_id") == observation["run_id"]
                    and row.get("operation_id") == observation["run_id"] for row in evidence)):
            return False
    return True
