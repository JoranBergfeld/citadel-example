"""Version contention proof from actual assessor publication and independent state."""

import math
import re

from citadel.evidence.manifests import sha256
from citadel.operations import OperationError, operation_key
from .operation_oracle import _matched
from .oracle import hash_value
from .reference_proof import reference_reads_proven
from .release_probes import validate_source
from .storage_probes import _correlated


def content_hash(draft):
    return sha256({key: value for key, value in draft.items()
                   if key not in ("artifact_id", "version", "run_id", "operation_id")})


def version_snapshot(document, result):
    operation = result["operation_id"]
    identifiers = [operation + suffix for suffix in ("-v1", "-a", "-b")]
    versions = document["drafts"].get(operation, {})
    first = versions.get("1")
    if not isinstance(first, dict):
        raise ValueError("Original immutable draft is absent")
    records = [document["operations"].get(operation_key("candidate-planner", "submit-draft", name), {})
               for name in identifiers]
    if (any(not isinstance(row, dict) or row.get("result") is not None
            and not isinstance(row["result"], dict) for row in records)
            or any(not isinstance(row, dict) for row in versions.values())):
        raise ValueError("Persisted draft-version state is malformed")
    return {"drafts": [{"artifact_id": row["artifact_id"], "version": row["version"],
        "sha256": sha256(row), "content_sha256": content_hash(row),
        "operation_id": row["operation_id"], "run_id": row["run_id"]}
        for _, row in sorted(versions.items())],
        "artifact_count": sum(len(rows) for rows in document["drafts"].values()),
        "operation_state": {"operation_ids": identifiers, "states": [row.get("state", "missing") for row in records],
            "run_ids": [row.get("run_id") for row in records], "deadlines": [row.get("deadline") for row in records],
            "count": len(document["operations"]), "input_hashes": [row.get("input_hash") for row in records],
            "result_hashes": [row["result"].get("sha256") if row.get("result") else None for row in records],
            "result_kinds": [row["result"].get("kind") if row.get("result") else None for row in records],
            "expected_input_hashes": [sha256({"inputs": {
                "draft": first | {"version": 1 if index == 0 else 2, "operation_id": identifiers[index]},
                "expected_version": 0 if index == 0 else 1},
                "run_id": row.get("run_id"), "deadline": row.get("deadline")})
                for index, row in enumerate(records)]}}


def evaluate_version(observation, snapshot, source, snapshots, evidence, *,
                     runtime_identity, observer_identity, reference_identity, subscription):
    blocked = {"check_id": "fault.concurrent-version-conflict", "status": "blocked",
               "reason": "version_state_or_service_correlation_missing"}
    if (any(not isinstance(row, dict) for row in (observation, snapshot, source, snapshots))
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
    actual, state = observation.get("actual"), snapshot.get("operation_state")
    if (observation.get("check_id") != blocked["check_id"] or observation.get("probe_id") != blocked["check_id"]
            or observation.get("caller") != "evidence-assessor" or observation.get("runtime_identity") != runtime_identity
            or not isinstance(actual, dict) or not isinstance(state, dict)
            or any(not isinstance(observation.get(key), str)
                   or not re.fullmatch("[A-Za-z0-9_-]{1,64}", observation[key]) for key in ("run_id", "operation_id"))
            or actual.get("operation_id") != observation["operation_id"]
            or observation.get("status_code") != 201 or snapshot.get("status_code") not in (200, 206)
            or not hash_value(snapshot.get("sha256")) or not hash_value(source.get("content_sha256"))
            or not _matched(observation, evidence, "storage", runtime_identity, "PutBlob",
                            client_request_id=observation["operation_id"])
            or not _matched(snapshot, evidence, "storage", observer_identity, "GetBlob",
                            client_request_id=snapshot.get("operation_id"))
            or snapshot["started"] < observation["finished"]):
        return blocked
    events = [row for row in evidence if isinstance(row.get("facts"), dict)
              and row["facts"].get("sha256") == sha256(actual)
              and row["facts"].get("probe_id") == blocked["check_id"]]
    if (not _matched(observation, events, "application", runtime_identity, "execution",
                     run_id=observation["run_id"], operation_id=observation["operation_id"], caller="evidence-assessor")
            or not reference_reads_proven(observation, evidence, caller="evidence-assessor",
                                          reference_identity=reference_identity, subscription=subscription)):
        return blocked
    changed = False
    for container, key in (("findings", "observation"), ("drafts", "draft_read")):
        read = source.get(key)
        if (not isinstance(read, dict) or read.get("container") != container or read.get("action") != "read"
                or read.get("status_code") not in (200, 206) or not hash_value(read.get("sha256"))
                or not _correlated(read, evidence, observer_identity)
                or read["finished"] > observation["started"] or observation["finished"] - read["started"] > 900):
            return blocked
        before, after = (snapshots[side].get(container) for side in ("before", "after"))
        for row in (before, after):
            if (not isinstance(row, dict) or row.get("container") != container or row.get("action") != "read"
                    or row.get("status_code") not in (200, 206) or not hash_value(row.get("sha256"))
                    or type(row.get("count")) is not int or row["count"] < 0
                    or row.get("suite_id") != read.get("suite_id")
                    or not _correlated(row, evidence, observer_identity)):
                return blocked
        if (before["finished"] > observation["started"] or after["started"] < observation["finished"]
                or before["target"] != after["target"] or read["target"] != before["target"]
                or not read.get("suite_id") or container == "drafts" and snapshot["target"] == before["target"]):
            return blocked
        changed |= before["sha256"] != after["sha256"] or before["count"] != after["count"]
    versions, attempts = snapshot.get("drafts"), actual.get("attempts")
    identifiers = [observation["operation_id"] + suffix for suffix in ("-v1", "-a", "-b")]
    valid = (not changed and actual.get("source_sha256") == context["draft"]["sha256"]
        and actual.get("operation_ids") == state.get("operation_ids") == identifiers
        and actual.get("states") == ["running", "succeeded"] and actual.get("responses") == ["conflict", "succeeded"]
        and isinstance(state.get("states"), list) and len(state["states"]) == 3
        and state["states"][0] == "succeeded" and sorted(state["states"][1:]) == ["running", "succeeded"]
        and state.get("run_ids") == [observation["run_id"]] * 3
        and type(state.get("count")) is int and state["count"] == 3
        and isinstance(state.get("deadlines"), list) and len(state["deadlines"]) == 3
        and all(type(value) in (int, float) and math.isfinite(value)
                and observation["finished"] <= value <= observation["started"] + 900 for value in state["deadlines"])
        and isinstance(state.get("input_hashes"), list) and len(state["input_hashes"]) == 3
        and all(hash_value(value) for value in state["input_hashes"])
        and state["input_hashes"] == state.get("expected_input_hashes")
        and type(actual.get("artifact_count")) is int and actual["artifact_count"] == 2
        and type(snapshot.get("artifact_count")) is int and snapshot["artifact_count"] == 2
        and type(actual.get("simultaneous_commits")) is int and actual["simultaneous_commits"] == 2
        and type(actual.get("conditional_conflicts")) is int and actual["conditional_conflicts"] == 1
        and isinstance(versions, list) and len(versions) == 2 and all(isinstance(row, dict) for row in versions)
        and [row.get("version") for row in versions] == [1, 2]
        and all(row.get("artifact_id") == observation["operation_id"] and row.get("run_id") == observation["run_id"]
                and hash_value(row.get("sha256")) and row.get("content_sha256") == source["content_sha256"]
                for row in versions)
        and versions[0].get("operation_id") == identifiers[0]
        and actual.get("before_sha256") == actual.get("after_sha256") == versions[0]["sha256"]
        and actual.get("drafts") == [{key: row[key] for key in ("artifact_id", "version", "sha256")} for row in versions]
        and isinstance(attempts, list) and len(attempts) == 2 and all(isinstance(row, dict) for row in attempts))
    if valid:
        winner = state["states"][1:].index("succeeded") + 1
        hashes = [versions[0]["sha256"], None, None]
        kinds = ["draft", None, None]
        hashes[winner], kinds[winner] = versions[1]["sha256"], "draft"
        valid = (state.get("result_hashes") == hashes and state.get("result_kinds") == kinds
            and versions[1].get("operation_id") == identifiers[winner]
            and all(row.get("operation_id") == identifiers[index]
                and row.get("state") == state["states"][index]
                and row.get("response") == ("succeeded" if index == winner else "conflict")
                and hash_value(row.get("sha256"))
                and (index != winner or row["sha256"] == versions[1]["sha256"])
                for index, row in enumerate(attempts, 1)))
    return blocked | {"status": "pass" if valid else "fail",
        "reason": "verified_version_conflict" if valid else "version_conflict_invariant_failed"}
