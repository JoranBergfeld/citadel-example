"""Release proofs require reviewer receipts, an independent snapshot and real MCP controls."""

import math
import re

from citadel.evidence.manifests import sha256
from citadel.operations import OperationError, operation_key
from .operation_oracle import _matched
from .oracle import hash_value
from .release_probes import RELEASE_CHECKS, validate_source
from .storage_probes import _correlated


def release_snapshot(document, result):
    identifiers = result.get("operation_ids", [result["operation_id"]])
    if (not isinstance(identifiers, list) or not 1 <= len(identifiers) <= 2
            or any(not isinstance(item, str) for item in identifiers)):
        raise ValueError("Bounded release operation identities required")
    records = [document["operations"].get(operation_key("evidence-assessor", "release", identifier), {})
               for identifier in identifiers]
    if any(not isinstance(row, dict) or row.get("result") is not None
           and not isinstance(row["result"], dict) for row in records):
        raise ValueError("Persisted release operation is malformed")
    findings = [finding for versions in document["findings"].values() for finding in versions.values()]
    finding = findings[0] if len(findings) == 1 else {}
    projection = {"operation_state": {
        "operation_ids": identifiers, "states": [row.get("state", "missing") for row in records],
        "input_hashes": [row.get("input_hash") for row in records],
        "deadlines": [row.get("deadline") for row in records],
        "run_ids": [row.get("run_id") for row in records],
        "result_hashes": [row["result"].get("sha256") if isinstance(row.get("result"), dict) else None
                          for row in records],
        "count": len(document["operations"]), "artifact_count": len(findings),
        "sha256": sha256(document["findings"]), "product_sha256": sha256(finding),
        "draft_sha256": finding.get("draft", {}).get("sha256"),
        "projection_sha256": sha256({key: value for key, value in finding.items() if key != "operation_id"})}}
    if "rejected_operation_id" in result:
        rejected = document["operations"].get(
            operation_key("evidence-assessor", "release", result["rejected_operation_id"]), {})
        projection["rejected_state"] = {
            key: rejected.get(key) for key in ("state", "run_id", "input_hash", "deadline", "operation_id")}
        projection["rejected_state"]["result_sha256"] = (
            sha256(rejected["result"]) if rejected.get("result") is not None else None)
    return projection


def evaluate_release(observation, snapshot, source, snapshots, evidence, *,
                     runtime_identity, observer_identity, reference_identity, subscription):
    blocked = {"check_id": observation.get("check_id") if isinstance(observation, dict) else None,
               "status": "blocked", "reason": "release_state_or_service_correlation_missing"}
    if (any(not isinstance(value, dict) for value in (observation, snapshot, source, snapshots))
            or any(not isinstance(snapshots.get(side), dict) for side in ("before", "after"))
            or not isinstance(evidence, list) or any(not isinstance(row, dict) for row in evidence)
            or not all(hash_value(value) for value in
                       (runtime_identity, observer_identity, reference_identity, subscription))
            or len({runtime_identity, observer_identity, reference_identity}) != 3):
        return blocked
    try:
        context = validate_source(source.get("release_source"))
    except (OperationError, ValueError, TypeError):
        return blocked
    check, actual, state = observation.get("check_id"), observation.get("actual"), snapshot.get("operation_state")
    source_read = source.get("observation")
    if (not isinstance(check, str) or check not in RELEASE_CHECKS or observation.get("probe_id") != check
            or observation.get("caller") != "release-reviewer" or observation.get("runtime_identity") != runtime_identity
            or not isinstance(actual, dict) or not isinstance(state, dict) or not isinstance(source_read, dict)
            or any(not isinstance(observation.get(key), str)
                   or not re.fullmatch("[A-Za-z0-9_-]{1,64}", observation[key]) for key in ("run_id", "operation_id"))
            or actual.get("operation_id") != observation["operation_id"]
            or observation.get("status_code") != 201 or snapshot.get("status_code") not in (200, 206)
            or not hash_value(source.get("projection_sha256"))
            or not _matched(observation, evidence, "storage", runtime_identity, "PutBlob",
                            client_request_id=observation["operation_id"])
            or not _matched(snapshot, evidence, "storage", observer_identity, "GetBlob",
                            client_request_id=snapshot.get("operation_id"))
            or not _correlated(source_read, evidence, observer_identity)
            or source_read.get("container") != "findings" or source_read.get("action") != "read"
            or source_read.get("status_code") not in (200, 206)
            or not hash_value(source_read.get("sha256"))
            or source_read["finished"] > observation["started"]
            or observation["finished"] - source_read["started"] > 900
            or snapshot["started"] < observation["finished"]):
        return blocked
    events = [row for row in evidence if isinstance(row.get("facts"), dict)
              and row["facts"].get("sha256") == sha256(actual) and row["facts"].get("probe_id") == check]
    if not _matched(observation, events, "application", runtime_identity, "execution",
        run_id=observation["run_id"], operation_id=observation["operation_id"], caller="release-reviewer"):
        return blocked
    receipts = actual.get("reference_reads")
    if (not isinstance(receipts, list) or len(receipts) != 3
            or any(not isinstance(row, dict) or not isinstance(row.get("method"), str)
                   or not isinstance(row.get("request_id"), str) or not row["request_id"] for row in receipts)
            or {row["method"] for row in receipts} != {"initialize", "lookup_airport", "list_runways"}
            or len({row["request_id"] for row in receipts}) != 3):
        return blocked
    for receipt in receipts:
        if (receipt.get("status_code") != 200 or not hash_value(receipt.get("target"))
                or receipt.get("run_id") != observation["run_id"]
                or receipt.get("operation_id") != observation["run_id"]
                or any(type(receipt.get(key)) not in (int, float) or not math.isfinite(receipt[key])
                       for key in ("started", "finished"))
                or not 0 <= receipt["finished"] - receipt["started"] <= 30
                or receipt["finished"] > observation["started"]
                or observation["finished"] - receipt["started"] > 900):
            return blocked
        def matches(row):
            return (row.get("request_id") == receipt["request_id"] and row.get("status_code") == 200
                and type(row.get("observed")) in (int, float)
                and receipt["started"] - 5 <= row["observed"] <= receipt["finished"] + 5
                and row.get("caller") == "release-reviewer")
        if (not any(matches(row) and row.get("source") == "gateway" and row.get("method") == "POST"
                and row.get("target") == receipt["target"] and row.get("credential_sha256") == subscription
                for row in evidence)
                or not any(matches(row) and row.get("source") == "application"
                    and row.get("runtime_identity") == reference_identity and row.get("method") == receipt["method"]
                    and row.get("run_id") == observation["run_id"]
                    and row.get("operation_id") == observation["run_id"] for row in evidence)):
            return blocked
    changed = False
    for container in ("drafts", "findings"):
        before, after = (snapshots.get(side, {}).get(container) for side in ("before", "after"))
        for row in (before, after):
            if (not isinstance(row, dict) or row.get("container") != container or row.get("action") != "read"
                    or row.get("status_code") not in (200, 206) or not hash_value(row.get("sha256"))
                    or type(row.get("count")) is not int or row["count"] < 0
                    or row.get("suite_id") != source_read.get("suite_id")
                    or not _correlated(row, evidence, observer_identity)):
                return blocked
        if (before["finished"] > observation["started"] or after["started"] < observation["finished"]
                or before.get("target") != after.get("target") or not source_read.get("suite_id")
                or container == "findings" and (before["target"] != source_read.get("target")
                                                or snapshot.get("target") == before["target"])):
            return blocked
        changed |= before["sha256"] != after["sha256"] or before["count"] != after["count"]
    identifiers = ([observation["operation_id"] + "-a", observation["operation_id"] + "-b"]
                   if check == "fault.concurrent-different-operation-release" else
                   [observation["operation_id"]] * (2 if "concurrent" in check else 1))
    valid = (not changed and state.get("operation_ids") == identifiers
        and state.get("states") == ["succeeded"] * len(identifiers)
        and state.get("run_ids") == [context["run_id"]] * len(identifiers)
        and isinstance(state.get("deadlines"), list) and len(state["deadlines"]) == len(identifiers)
        and all(type(deadline) in (int, float) and math.isfinite(deadline)
                and observation["finished"] <= deadline <= observation["started"] + 900
                for deadline in state["deadlines"])
        and state.get("input_hashes") == [sha256({"inputs": {"draft": context["draft"]},
            "run_id": context["run_id"], "deadline": deadline}) for deadline in state["deadlines"]]
        and type(state.get("count")) is int
        and state["count"] == len(set(identifiers)) + int(check == "fault.draft-hash-binding")
        and type(actual.get("artifact_count")) is int and actual["artifact_count"] == 1
        and type(state.get("artifact_count")) is int and state["artifact_count"] == 1
        and actual.get("draft_sha256") == state.get("draft_sha256") == context["draft"]["sha256"]
        and state.get("projection_sha256") == source["projection_sha256"]
        and hash_value(state.get("product_sha256"))
        and state.get("result_hashes") == [state["product_sha256"]] * len(identifiers)
        and type(actual.get("before_count")) is int and actual["before_count"] == 0
        and actual.get("before_sha256") == sha256({})
        and hash_value(actual.get("after_sha256")) and actual["after_sha256"] == state.get("sha256"))
    if check == "fault.dropped-committed-release":
        valid &= (actual.get("response") == "indeterminate" and actual.get("replay") == "conflict"
                  and actual.get("state") == "succeeded" and actual.get("sha256") == state.get("product_sha256"))
    elif check == "fault.draft-hash-binding":
        rejected = snapshot.get("rejected_state")
        invalid = context["draft"] | {"sha256": actual.get("rejected_draft_sha256")}
        valid = valid and (isinstance(rejected, dict) and hash_value(invalid["sha256"])
            and invalid["sha256"] != context["draft"]["sha256"]
            and actual.get("response") == "conflict" and actual.get("state") == "succeeded"
            and actual.get("sha256") == state.get("product_sha256")
            and type(actual.get("rejected_count")) is int and actual["rejected_count"] == 0
            and actual.get("rejected_sha256") == actual.get("before_sha256") == sha256({})
            and rejected.get("state") == "running" and rejected.get("result_sha256") is None
            and rejected.get("operation_id") == actual.get("rejected_operation_id") == observation["operation_id"] + "-bad"
            and rejected.get("run_id") == context["run_id"]
            and rejected.get("deadline") == state["deadlines"][0]
            and rejected.get("input_hash") == sha256({"inputs": {"draft": invalid},
                "run_id": context["run_id"], "deadline": rejected["deadline"]}))
    else:
        valid &= (actual.get("states") == ["succeeded", "succeeded"]
            and actual.get("operation_ids") == identifiers and actual.get("result_hashes") == state.get("result_hashes")
            and type(actual.get("simultaneous_commits")) is int and actual["simultaneous_commits"] == 2
            and type(actual.get("conditional_conflicts")) is int and 1 <= actual["conditional_conflicts"] <= 4)
    return blocked | {"status": "pass" if valid else "fail", "business_state": "unchanged" if not changed else "changed",
                      "reason": "verified_release_fault" if valid else "release_fault_invariant_failed"}
