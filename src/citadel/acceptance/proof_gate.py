"""Re-evaluate exported observations; labels and generic source rows are not proof."""

from .coverage import STORAGE, required_checks
from .oracle import hash_value
from .origin_probes import evaluate_origin
from .storage_probes import evaluate_storage


def evaluate_check(check, report):
    blocked = {"check_id": check.get("check_id"), "status": "blocked",
               "reason": "independent_check_proof_missing"}
    actual, records = check.get("actual"), report.get("evidence")
    identities = report.get("runtime_identities")
    if (not isinstance(check.get("check_id"), str)
            or check.get("expected") != required_checks().get(check["check_id"])
            or not isinstance(actual, dict) or not isinstance(records, list)
            or any(not isinstance(row, dict) for row in records)
            or not isinstance(identities, dict) or set(identities) != set(STORAGE)
            or not all(hash_value(value) for value in identities.values())
            or len(set(identities.values())) != len(identities)):
        return blocked
    observation, control = actual.get("observation"), actual.get("control")
    operations = report.get("operation_ids", [])
    if (not isinstance(observation, dict) or not isinstance(control, dict)
            or not isinstance(operations, list)
            or observation.get("check_id") != check["check_id"]
            or observation.get("operation_id") not in operations
            or observation.get("run_id") not in operations and not (
                check["check_id"].startswith("route.operator.")
                and observation.get("run_id") == report.get("run_id"))):
        return blocked
    if check["check_id"].startswith("fault."):
        from .operation_oracle import evaluate_operation
        if (control.get("suite_id") != report.get("run_id")
                or control.get("caller") != "operator" or control.get("container") != "planner-operations"
                or control.get("action") != "read" or not hash_value(control.get("runtime_identity"))
                or control["runtime_identity"] in identities.values()
                or control.get("operation_id") not in operations):
            return blocked
        return evaluate_operation(observation, control, records,
            runtime_identity=identities["candidate-planner"], observer_identity=control["runtime_identity"])
    if check["check_id"].startswith("storage."):
        before, after = actual.get("before"), actual.get("after")
        if (not isinstance(before, dict) or not isinstance(after, dict)
                or observation.get("suite_id") != report.get("run_id")
                or not hash_value(before.get("runtime_identity"))
                or before["runtime_identity"] != after.get("runtime_identity")
                or before["runtime_identity"] in identities.values()
                or control.get("caller") != "operator" and (
                    control.get("operation_id") not in operations
                    or control.get("run_id") not in operations)):
            return blocked
        identities = identities | {"operator": before["runtime_identity"]}
        return evaluate_storage(observation, control, {"before": before, "after": after},
                                records, identities)
    if check["check_id"].startswith(("origin.", "route.")):
        route = check["check_id"].startswith("route.")
        actor, caller = observation.get("caller"), control.get("caller")
        bindings = report.get("subscription_bindings")
        if (not isinstance(actor, str) or actor not in identities and not (route and actor == "operator")
                or not isinstance(caller, str) or not isinstance(bindings, dict)
                or not hash_value(bindings.get(caller))
                or control.get("operation_id") not in operations
                or control.get("run_id") not in [report.get("run_id"), *operations]):
            return blocked
        snapshots = {}
        for side in ("before", "after"):
            rows = actual.get(side)
            if (not isinstance(rows, list) or len(rows) != 2
                    or any(not isinstance(row, dict) or not isinstance(row.get("container"), str)
                           or row.get("suite_id") != report.get("run_id") for row in rows)
                    or {row["container"] for row in rows} != {"drafts", "findings"}):
                return blocked
            snapshots[side] = {row["container"]: row for row in rows}
        observers = {row.get("runtime_identity") for row in records
            if row.get("source") == "storage" and hash_value(row.get("runtime_identity"))
            and any(row.get("request_id") == snapshot.get("request_id")
                    and row.get("client_request_id") == snapshot.get("operation_id")
                    and row.get("target") == snapshot.get("target")
                    for values in snapshots.values() for snapshot in values.values())}
        if len(observers) != 1 or observers & set(identities.values()):
            return blocked
        correlated = [row for row in records if not (
            row.get("source") == "application" and row.get("request_id") == control.get("request_id")
            and (row.get("operation_id") != control.get("operation_id")
                 or row.get("run_id") != control.get("run_id")))]
        if route:
            from .route_oracle import evaluate_route
            return evaluate_route(observation, control, snapshots, correlated, identities=identities,
                                  subscriptions=bindings, observer_identity=next(iter(observers)))
        return evaluate_origin(observation, control, snapshots, correlated,
            runtime_identity=identities[actor], observer_identity=next(iter(observers)),
            credential_sha256=bindings[caller])
    return blocked
