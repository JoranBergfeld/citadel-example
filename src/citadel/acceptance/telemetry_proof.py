"""Queried event-prefix proofs; exporter acknowledgement never substitutes for ingestion."""

import hashlib
import math
import re

from .coverage import STORAGE
from .oracle import hash_value


def _requests(checks):
    pending, result, count = [checks], set(), 0
    while pending:
        value = pending.pop()
        count += 1
        if count > 100000:
            raise ValueError("Proof metadata exceeds its finite traversal bound")
        if isinstance(value, dict):
            if isinstance(value.get("request_id"), str):
                result.add(value["request_id"])
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    return result


def _application(report):
    blocked = {"status": "blocked", "reason": "complete_queried_application_event_prefixes_required"}
    try:
        identities, records = report["runtime_identities"], report["evidence"]
        if set(identities) != set(STORAGE) or len(set(identities.values())) != 5:
            return blocked
        owned, operations, requests = set(identities.values()), set(report["operation_ids"]), _requests(report["checks"])
        selected = [row for row in records if row.get("source") in ("application", "console")
            and row.get("runtime_identity") in owned and row.get("method") != "exporter.health"
            and (row.get("run_id") in operations or row.get("request_id") in requests)]
        if not selected:
            return blocked
        streams = set()
        for row in selected:
            stream = row.get("stream_id")
            if not isinstance(stream, str) or re.fullmatch("[a-f0-9]{32}", stream) is None:
                return blocked
            streams.add((row["runtime_identity"], stream))
        if {identity for identity, _ in streams} != owned:
            return blocked
        ingested, emitted = {}, {}
        for row in records:
            key = (row.get("runtime_identity"), row.get("stream_id"))
            if key in streams and row.get("source") == "application":
                ingested.setdefault(key, []).append(row)
        for row in selected:
            emitted.setdefault((row["runtime_identity"], row["stream_id"]), set()).add(row.get("event_id"))
        total = 0
        for identity, stream in streams:
            rows = ingested.get((identity, stream), [])
            if (not rows or any(type(row.get("sequence")) is not int or row["sequence"] < 1
                    or not isinstance(row.get("event_id"), str)
                    or re.fullmatch("[a-f0-9]{32}", row["event_id"]) is None
                    or type(row.get("observed")) not in (int, float) or not math.isfinite(row["observed"])
                    or not report["started"] - 5 <= row["observed"] <= report["finished"] + (
                        20 if row.get("method") == "exporter.health" else 5) for row in rows)
                    or len({row["sequence"] for row in rows}) != len(rows)
                    or len({row["event_id"] for row in rows}) != len(rows)):
                return blocked
            health_rows = [row for row in rows if row.get("method") == "exporter.health"]
            if not health_rows:
                return blocked
            health = max(health_rows, key=lambda row: row["sequence"])
            facts = health["facts"]
            counters = ("stream_count", "submitted_records", "acknowledged_records", "failed_records",
                        "dropped_records", "delivery_attempts", "queued_records")
            if (any(type(facts.get(key)) is not int or facts[key] < 0 for key in counters)
                    or type(facts.get("inflight")) is not bool or facts.get("ingestion_verified") is not False
                    or not hash_value(facts.get("stream_sha256"))):
                return blocked
            if facts["failed_records"] or facts["dropped_records"]:
                return {"status": "fail", "reason": "actual_exporter_record_loss"}
            size = facts["stream_count"]
            if (not 0 < size <= 100000 or health["sequence"] != size + 1 or health.get("status_code") != 200
                    or facts["queued_records"] or facts["inflight"]
                    or facts["submitted_records"] != facts["acknowledged_records"]
                    or facts["submitted_records"] < size or facts["delivery_attempts"] < 1):
                return blocked
            prefix = sorted([row for row in rows if row["sequence"] <= size], key=lambda row: row["sequence"])
            if ([row["sequence"] for row in prefix] != list(range(1, size + 1))
                    or any(row["method"] != "exporter.health" and row["sequence"] > size for row in rows)):
                return blocked
            digest = hashlib.sha256("".join(row["event_id"] for row in prefix).encode()).hexdigest()
            if digest != facts["stream_sha256"]:
                return {"status": "fail", "reason": "actual_ingested_event_prefix_hash_mismatch"}
            observed_ids = {row["event_id"] for row in prefix}
            if not emitted[identity, stream] <= observed_ids:
                return blocked
            total += sum(row["method"] != "exporter.health" for row in prefix)
        return {"status": "pass", "reason": "every_emitted_owned_event_queried_and_exporter_loss_counters_zero",
                "count": total, "stream_count": len(streams)}
    except (KeyError, ValueError, TypeError, AttributeError):
        return blocked


def evaluate_application(check, report):
    result = _application(report)
    summary = {"sources": ["application"], "count": result.pop("count", 0),
               "stream_count": result.pop("stream_count", 0)}
    if result["status"] == "pass" and check.get("actual") != summary:
        result = {"status": "blocked", "reason": "actual_application_count_binding_missing"}
    return {"check_id": "telemetry.application-ingestion"} | result


def collect_application(report):
    result = _application(report)
    actual = {"sources": ["application"], "count": result.pop("count", 0),
              "stream_count": result.pop("stream_count", 0)}
    return {"check_id": "telemetry.application-ingestion", "expected": "evidence", "actual": actual} | result
