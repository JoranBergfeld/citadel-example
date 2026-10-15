"""Cross-authority proof that two exact drafts yield immutable public findings."""

import math
import re

from citadel.evidence.manifests import sha256
from citadel.operations import OperationError, operation_key
from .operation_oracle import _matched
from .oracle import hash_value
from .reference_proof import reference_reads_proven
from .release_probes import validate_versions
from .storage_probes import _correlated
from .version_oracle import evaluate_version, public_content_hash


FINDING_FIELDS = frozenset(("schema_version", "run_id", "operation_id", "airport_ident", "draft",
    "evidence", "classification", "gap_reasons", "caveats", "provenance", "artifact_id", "version", "reviewer"))


def immutable_snapshot(document, result):
    identifiers = [result["operation_id"] + suffix for suffix in ("-v1", "-v2")]
    records = [document["operations"].get(operation_key("evidence-assessor", "release", identifier), {})
               for identifier in identifiers]
    findings = []
    for _, versions in sorted(document["findings"].items()):
        for _, row in sorted(versions.items()):
            if (not isinstance(row, dict) or not isinstance(row.get("draft"), dict)
                    or row["draft"].keys() != {"artifact_id", "version", "sha256"}):
                raise ValueError("Persisted immutable finding is malformed")
            findings.append({key: row.get(key) for key in
                ("artifact_id", "version", "operation_id", "run_id", "reviewer", "draft")} | {
                    "sha256": sha256(row), "projection_sha256": public_content_hash(row),
                    "fields_sha256": sha256(sorted(row))})
    if any(not isinstance(row, dict) or row.get("result") is not None
           and not isinstance(row["result"], dict) for row in records):
        raise ValueError("Persisted immutable release operation is malformed")
    return {"findings": findings, "artifact_count": len(findings), "operation_state": {
        "operation_ids": identifiers, "states": [row.get("state", "missing") for row in records],
        "run_ids": [row.get("run_id") for row in records], "deadlines": [row.get("deadline") for row in records],
        "input_hashes": [row.get("input_hash") for row in records], "count": len(document["operations"]),
        "result_hashes": [row["result"].get("sha256") if row.get("result") else None for row in records],
        "result_kinds": [row["result"].get("kind") if row.get("result") else None for row in records]}}


def evaluate_immutable(observation, snapshot, source, snapshots, evidence, *,
                       identities, subscriptions, observer_identity):
    blocked = {"check_id": "fault.immutable-versions", "status": "blocked",
               "reason": "immutable_version_source_or_correlation_missing"}
    if (any(not isinstance(value, dict) for value in
            (observation, snapshot, source, snapshots, identities, subscriptions))
            or any(not isinstance(snapshots.get(side), dict) for side in ("before", "after"))
            or not isinstance(evidence, list) or any(not isinstance(row, dict) for row in evidence)
            or not hash_value(observer_identity) or observer_identity in identities.values()
            or any(not hash_value(identities.get(actor)) for actor in
                   ("evidence-assessor", "release-reviewer", "reference-data"))
            or len({identities[actor] for actor in ("evidence-assessor", "release-reviewer", "reference-data")}) != 3):
        return blocked
    try:
        descriptor = validate_versions(source.get("versions"))
    except (OperationError, ValueError, TypeError):
        return blocked
    proof = source.get("version_proof")
    if not isinstance(proof, dict) or any(not isinstance(proof.get(key), dict) for key in ("observation", "control", "source")):
        return blocked
    source_snapshots = {}
    for side in ("before", "after"):
        rows = proof.get(side)
        if (not isinstance(rows, list) or len(rows) != 2
                or any(not isinstance(row, dict) or not isinstance(row.get("container"), str) for row in rows)
                or {row["container"] for row in rows} != {"drafts", "findings"}):
            return blocked
        source_snapshots[side] = {row["container"]: row for row in rows}
    verified = evaluate_version(proof["observation"], proof["control"], proof["source"], source_snapshots, evidence,
        runtime_identity=identities["evidence-assessor"], observer_identity=observer_identity,
        reference_identity=identities["reference-data"], subscription=subscriptions.get("evidence-assessor"))
    if (verified["status"] != "pass" or descriptor["run_id"] != proof["observation"]["run_id"]
            or descriptor["operation_id"] != proof["observation"]["operation_id"]
            or descriptor["drafts"] != proof["observation"]["actual"].get("drafts")):
        return blocked
    actual, state, findings = observation.get("actual"), snapshot.get("operation_state"), snapshot.get("findings")
    reviewer = identities["release-reviewer"]
    if (observation.get("check_id") != blocked["check_id"] or observation.get("probe_id") != blocked["check_id"]
            or observation.get("caller") != "release-reviewer" or observation.get("runtime_identity") != reviewer
            or not isinstance(actual, dict) or not isinstance(state, dict)
            or any(not isinstance(observation.get(key), str)
                   or not re.fullmatch("[A-Za-z0-9_-]{1,64}", observation[key]) for key in ("run_id", "operation_id"))
            or observation["run_id"] == descriptor["run_id"] or actual.get("operation_id") != observation["operation_id"]
            or observation.get("status_code") != 201 or snapshot.get("status_code") not in (200, 206)
            or not hash_value(snapshot.get("sha256"))
            or not _matched(observation, evidence, "storage", reviewer, "PutBlob",
                            client_request_id=observation["operation_id"])
            or not _matched(snapshot, evidence, "storage", observer_identity, "GetBlob",
                            client_request_id=snapshot.get("operation_id"))
            or snapshot["started"] < observation["finished"]):
        return blocked
    events = [row for row in evidence if isinstance(row.get("facts"), dict)
              and row["facts"].get("sha256") == sha256(actual) and row["facts"].get("probe_id") == blocked["check_id"]]
    if (not _matched(observation, events, "application", reviewer, "execution",
                     run_id=observation["run_id"], operation_id=observation["operation_id"], caller="release-reviewer")
            or not reference_reads_proven(observation, evidence, caller="release-reviewer",
                reference_identity=identities["reference-data"], subscription=subscriptions.get("release-reviewer"))):
        return blocked
    changed = False
    pairs = [(container, snapshots["before"].get(container), snapshots["after"].get(container))
             for container in ("drafts", "findings")]
    pairs.append(("drafts", source.get("draft_before"), source.get("draft_after")))
    for container, before, after in pairs:
        for row in (before, after):
            if (not isinstance(row, dict) or row.get("container") != container or row.get("action") != "read"
                    or row.get("status_code") not in (200, 206) or not hash_value(row.get("sha256"))
                    or type(row.get("count")) is not int or row["count"] < 0
                    or row.get("suite_id") != proof["control"].get("suite_id")
                    or not _correlated(row, evidence, observer_identity)):
                return blocked
        if (not before.get("suite_id") or before["target"] != after["target"]
                or before["finished"] > observation["started"] or after["started"] < observation["finished"]):
            return blocked
        changed |= before["sha256"] != after["sha256"] or before["count"] != after["count"]
    if (source["draft_before"]["target"] != proof["control"]["target"]
            or source["draft_before"]["sha256"] != proof["control"]["sha256"]
            or source["draft_before"]["started"] < proof["control"]["finished"]
            or snapshot["target"] == snapshots["before"]["findings"]["target"]):
        return blocked
    identifiers = [observation["operation_id"] + suffix for suffix in ("-v1", "-v2")]
    source_deadline = min(proof["control"]["operation_state"]["deadlines"])
    valid = (not changed and actual.get("source_run") == descriptor["run_id"]
        and actual.get("operation_ids") == state.get("operation_ids") == identifiers
        and actual.get("states") == state.get("states") == ["succeeded", "succeeded"]
        and state.get("run_ids") == [descriptor["run_id"]] * 2
        and type(state.get("count")) is int and state["count"] == 2
        and isinstance(state.get("deadlines"), list) and len(state["deadlines"]) == 2
        and all(type(value) in (int, float) and math.isfinite(value)
                and observation["finished"] <= value <= source_deadline for value in state["deadlines"])
        and state.get("input_hashes") == [sha256({"inputs": {"draft": ref}, "run_id": descriptor["run_id"],
            "deadline": deadline}) for ref, deadline in zip(descriptor["drafts"], state["deadlines"])]
        and actual.get("drafts") == descriptor["drafts"]
        and type(actual.get("artifact_count")) is int and actual["artifact_count"] == 2
        and type(snapshot.get("artifact_count")) is int and snapshot["artifact_count"] == 2
        and isinstance(findings, list) and len(findings) == 2
        and all(isinstance(row, dict) and type(row.get("version")) is int for row in findings)
        and [row.get("version") for row in findings] == [1, 2])
    if valid:
        expected_id = sha256({"draft_id": descriptor["operation_id"]})
        valid = (all(row.get("artifact_id") == expected_id and row.get("run_id") == descriptor["run_id"]
            and row.get("operation_id") == identifiers[index] and row.get("reviewer") == "release-reviewer"
            and row.get("draft") == descriptor["drafts"][index] and hash_value(row.get("sha256"))
            and row.get("projection_sha256") == proof["control"]["drafts"][index].get("projection_sha256")
            and hash_value(row.get("projection_sha256")) and row.get("fields_sha256") == sha256(sorted(FINDING_FIELDS))
            for index, row in enumerate(findings))
            and actual.get("findings") == [{key: row[key] for key in ("artifact_id", "version", "sha256")} for row in findings]
            and state.get("result_hashes") == [row["sha256"] for row in findings]
            and state.get("result_kinds") == ["finding", "finding"]
            and actual.get("before_sha256") == actual.get("after_sha256") == findings[0]["sha256"])
    return blocked | {"status": "pass" if valid else "fail",
        "reason": "verified_immutable_findings" if valid else "immutable_finding_invariant_failed"}
