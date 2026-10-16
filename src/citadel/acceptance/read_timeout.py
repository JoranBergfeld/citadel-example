"""Independently match real scheduled/expired read timers to all three Blob receipts."""

import math

from .oracle import hash_value


def evaluate_timeout_reads(observation, snapshot, evidence, *, runtime_identity):
    from .operation_oracle import _matched
    blocked = {"check_id": "limit.safe_read_timeout_seconds", "status": "blocked",
               "reason": "three_actual_expired_timers_and_read_receipts_required"}
    try:
        actual, budget, state = observation["actual"], snapshot["budget_state"], snapshot["operation_state"]
        steps = actual["steps"]
        events = [row for row in evidence if row.get("source") == "application"
            and row.get("method") == "safe_read.timeout" and row.get("run_id") == observation["run_id"]
            and row.get("operation_id") == observation["operation_id"]]
        if (len(steps) != 3 or len(events) != 3
                or any(not isinstance(row.get("facts"), dict) or type(row["facts"].get("retry")) is not int for row in events)
                or {row["facts"]["retry"] for row in events} != {0, 1, 2}):
            return blocked
        valid = True
        for index, step in enumerate(steps):
            identifier = observation["operation_id"] + f"-read{index}"
            if (step["operation_id"] != identifier or not hash_value(step["sha256"])
                    or any(type(step[key]) not in (int, float) or not math.isfinite(step[key]) for key in
                           ("started", "received", "finished", "accepted", "deadline",
                            "monotonic_started", "monotonic_finished"))
                    or not observation["started"] <= step["accepted"] <= step["started"] <= step["received"]
                           < step["deadline"]
                    or not step["received"] <= step["finished"] <= observation["finished"]):
                return blocked
            reads = [row for row in evidence if row.get("source") == "application"
                and row.get("method") == "storage.read" and row.get("run_id") == observation["run_id"]
                and row.get("operation_id") == identifier and row.get("target") == snapshot["target"]]
            if len(reads) != 1 or reads[0].get("status_code") not in (200, 206):
                return blocked
            receipt = {key: reads[0][key] for key in ("request_id", "status_code", "target")}
            receipt.update(started=step["started"], finished=step["received"])
            if (not _matched(receipt, reads, "application", runtime_identity, "storage.read",
                             caller="candidate-planner", run_id=observation["run_id"], operation_id=identifier)
                    or not _matched(receipt, evidence, "storage", runtime_identity, "GetBlob")):
                return blocked
            event = next(row for row in events if row["facts"]["retry"] == index)
            timer = event["facts"]
            if (event.get("runtime_identity") != runtime_identity or event.get("caller") != "candidate-planner"
                    or event.get("status_code") != 0 or timer.get("read_operation_id") != observation["operation_id"]
                    or any(type(timer.get(key)) not in (int, float) or not math.isfinite(timer[key]) for key in
                           ("started", "finished", "deadline", "monotonic_started", "monotonic_deadline",
                            "monotonic_finished"))
                    or type(event.get("observed")) not in (int, float)
                    or not timer["finished"] - 5 <= event["observed"] <= timer["finished"] + 5
                    or not step["accepted"] <= timer["started"] <= step["started"]
                    or not step["finished"] <= timer["finished"] <= observation["finished"]
                    or timer["deadline"] != step["deadline"]
                    or not timer["monotonic_started"] <= step["monotonic_started"] < timer["monotonic_deadline"]
                           <= step["monotonic_finished"] <= timer["monotonic_finished"]):
                return blocked
            valid &= (step["state"] == "timed_out" and step["deadline"] - step["accepted"] == 30
                and math.isclose(timer["monotonic_deadline"] - timer["monotonic_started"],
                                 timer["deadline"] - timer["started"], rel_tol=0, abs_tol=1e-6)
                and 0 < timer["monotonic_deadline"] - timer["monotonic_started"] <= 30
                and (not index or step["monotonic_started"] - steps[index - 1]["monotonic_finished"] >= index))
        valid &= (actual["state"] == "unavailable" and actual["read_attempts"] == 3 and actual["retry"] == 2
            and type(actual["remaining_reads"]) is int and actual["remaining_reads"] == 509
            and budget["closed"] is True and type(budget["remaining_reads"]) is int and budget["remaining_reads"] == 509
            and budget["deadline"] == actual["deadline"] and state["state"] == "missing"
            and type(state["artifact_count"]) is int and state["artifact_count"] == 0
            and hash_value(actual["before_sha256"])
            and actual["before_sha256"] == actual["after_sha256"] == snapshot["business_sha256"]
            and all(step["sha256"] == actual["before_sha256"] for step in steps))
        return blocked | {"status": "pass" if valid else "fail",
            "reason": "actual_thirty_second_expiry_verified" if valid else "actual_read_timeout_invariant_failed"}
    except (KeyError, TypeError, ValueError, AttributeError, IndexError, StopIteration):
        return blocked
