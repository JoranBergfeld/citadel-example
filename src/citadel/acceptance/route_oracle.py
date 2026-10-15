"""Independent read-route authorization proofs, never HTTP-status-only approval."""

import math
import re

from citadel.evidence.manifests import sha256
from .coverage import required_checks
from .oracle import hash_value
from .storage_probes import _correlated


READ_CAPABILITIES = {"discovery", "initialize", "search_airports", "lookup_airport", "list_runways"}


def evaluate_route(observation, control, snapshots, evidence, *, identities, subscriptions, observer_identity):
    blocked = {"check_id": observation.get("check_id") if isinstance(observation, dict) else None, "status": "blocked",
               "reason": "route_authority_control_or_no_effect_missing"}
    if (not isinstance(evidence, list) or any(not isinstance(row, dict) for row in evidence)
            or not isinstance(identities, dict) or not all(hash_value(value) for value in identities.values())
            or not isinstance(subscriptions, dict) or not isinstance(snapshots, dict)
            or any(not isinstance(snapshots.get(side), dict) for side in ("before", "after"))
            or not hash_value(observer_identity) or observer_identity in identities.values()):
        return blocked

    def shape(row):
        if not isinstance(row, dict) or not isinstance(row.get("check_id"), str):
            return False
        parts = row["check_id"].split(".")
        return (len(parts) == 4 and parts[0] == "route" and row["check_id"] in required_checks()
            and parts[1] == row.get("caller") and parts[2] in identities
            and parts[3] in READ_CAPABILITIES and hash_value(row.get("target"))
            and hash_value(subscriptions.get(parts[1]))
            and all(isinstance(row.get(key), str) and re.fullmatch("[A-Za-z0-9_.:-]{1,128}", row[key])
                    for key in ("run_id", "operation_id", "request_id"))
            and type(row.get("status_code")) is int and 100 <= row["status_code"] <= 599
            and all(type(row.get(key)) in (int, float) and math.isfinite(row[key])
                    for key in ("started", "finished"))
            and 0 <= row["finished"] - row["started"] <= 30)

    def matches(record, source, **fields):
        return any(row.get("source") == source and row.get("request_id") == record["request_id"]
            and row.get("status_code") == record["status_code"]
            and type(row.get("observed")) in (int, float)
            and record["started"] - 5 <= row["observed"] <= record["finished"] + 5
            and all(row.get(key) == value for key, value in fields.items()) for row in evidence)

    def gateway(row, **fields):
        capability = row["check_id"].split(".")[3]
        return matches(row, "gateway", caller=row["caller"], target=row["target"],
            method="GET" if capability == "discovery" else "POST",
            credential_sha256=subscriptions[row["caller"]], **fields)

    def client(row):
        if row["caller"] == "operator":
            return True
        return any(isinstance(item.get("facts"), dict)
            and item["facts"].get("sha256") == sha256(row)
            and item["facts"].get("probe_id") == row["check_id"]
            and matches(row, "application", method="probe", runtime_identity=identities.get(row["caller"]),
                caller=row["caller"], run_id=row["run_id"], operation_id=row["operation_id"],
                target=row["target"], facts=item["facts"]) for item in evidence)

    def positive(row):
        _, caller, target, capability = row["check_id"].split(".")
        actual = ("gateway_card" if capability == "discovery" else
                  "mcp_initialized" if capability == "initialize" else "reference_data")
        return (required_checks()[row["check_id"]] == "allow" and row["status_code"] == 200
            and row.get("status") != "blocked" and row.get("actual") == actual
            and (capability in ("discovery", "initialize") or hash_value(row.get("sha256")))
            and gateway(row) and client(row)
            and matches(row, "application", runtime_identity=identities[target], method=capability,
                        caller=caller, run_id=row["run_id"], operation_id=row["operation_id"]))

    if not shape(observation) or not shape(control) or not gateway(observation) or not client(observation):
        return blocked
    expected = required_checks()[observation["check_id"]]
    if expected == "deny" and 200 <= observation["status_code"] < 300:
        return blocked | {"status": "fail", "reason": "forbidden_route_succeeded"}
    if (observation["target"] != control["target"]
            or observation["check_id"].split(".")[2:] != control["check_id"].split(".")[2:]
            or not positive(control)
            or max(observation["finished"], control["finished"])
               - min(observation["started"], control["started"]) > 900):
        return blocked
    if expected == "allow":
        if not positive(observation):
            return blocked
    elif (observation["status_code"] != 403 or observation.get("reason") != "route_denied"
            or observation["request_id"] == control["request_id"]
            or not any(isinstance(row.get("facts"), dict)
                and row["facts"].get("backend_dispatched") is False
                and gateway(observation, facts=row["facts"]) for row in evidence)):
        return blocked
    for container in ("drafts", "findings"):
        before, after = (snapshots.get(side, {}).get(container, {}) for side in ("before", "after"))
        for record in (before, after):
            if (record.get("container") != container or record.get("action") != "read"
                    or record.get("status_code") not in (200, 206)
                    or type(record.get("count")) is not int or record["count"] < 0
                    or not hash_value(record.get("sha256"))
                    or not _correlated(record, evidence, observer_identity)):
                return blocked
        if (not before.get("suite_id") or before["suite_id"] != after.get("suite_id")
                or before.get("target") != after.get("target")
                or before["finished"] > observation["started"] or after["started"] < observation["finished"]):
            return blocked
        if before["sha256"] != after["sha256"] or before["count"] != after["count"]:
            return blocked | {"status": "fail", "reason": "read_route_changed_business_products"}
    return blocked | {"status": "pass", "reason": "verified_route_authorization_and_no_effect"}
