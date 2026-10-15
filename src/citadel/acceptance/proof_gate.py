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
    from .release_probes import RELEASE_CHECKS, validate_source
    if check["check_id"] in RELEASE_CHECKS or check["check_id"] == "fault.concurrent-version-conflict":
        from citadel.operations import OperationError
        from .release_oracle import evaluate_release
        from .version_oracle import evaluate_version
        versions = check["check_id"] == "fault.concurrent-version-conflict"
        source = actual.get("source")
        if not isinstance(source, dict) or not isinstance(source.get("observation"), dict):
            return blocked
        try:
            context = validate_source(source.get("release_source"))
        except (OperationError, ValueError, TypeError):
            return blocked
        comparison = report.get("scenarios", {}).get("comparison", {})
        snapshot_rows = [control, source["observation"]]
        if versions:
            if not isinstance(source.get("draft_read"), dict):
                return blocked
            snapshot_rows.append(source["draft_read"])
        snapshots = {}
        for side in ("before", "after"):
            rows = actual.get(side)
            if (not isinstance(rows, list) or len(rows) != 2
                    or any(not isinstance(row, dict) or not isinstance(row.get("container"), str) for row in rows)
                    or {row["container"] for row in rows} != {"drafts", "findings"}):
                return blocked
            snapshots[side] = {row["container"]: row for row in rows}
            snapshot_rows.extend(rows)
        observer = control.get("runtime_identity")
        nested = observation.get("actual")
        if (not isinstance(comparison, dict) or context["run_id"] != comparison.get("operation_id")
                or context["run_id"] not in operations or not isinstance(nested, dict)
                or not isinstance(nested.get("operation_ids", []), list)
                or any(identifier not in operations for identifier in nested.get("operation_ids", []))
                or check["check_id"] == "fault.draft-hash-binding" and nested.get("rejected_operation_id") not in operations
                or any(row.get("suite_id") != report["run_id"] or row.get("caller") != "operator"
                       or row.get("action") != "read" or row.get("operation_id") not in operations
                       for row in snapshot_rows)
                or control.get("container") != ("drafts" if versions else "findings")
                or not isinstance(report.get("subscription_bindings"), dict)
                or not hash_value(observer) or observer in identities.values()):
            return blocked
        actor = "evidence-assessor" if versions else "release-reviewer"
        return (evaluate_version if versions else evaluate_release)(observation, control, source, snapshots, records,
            runtime_identity=identities[actor], reference_identity=identities["reference-data"],
            observer_identity=observer, subscription=report["subscription_bindings"].get(actor))
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
            context, reads = actual.get("route_context"), actual.get("context_reads")
            if check["check_id"].split(".")[-1] in ("status", "task", "findings"):
                from .route_context import validate_route_context
                try:
                    validate_route_context(context)
                except (ValueError, TypeError):
                    return blocked
                comparison = report.get("scenarios", {}).get("comparison", {})
                if (not isinstance(comparison, dict) or comparison.get("operation_id") != context["read_scope"]["run_id"]
                        or not isinstance(reads, list)
                        or any(not isinstance(row, dict) or row.get("operation_id") not in operations
                               or row.get("suite_id") != report.get("run_id") for row in reads)
                        or any(row["operation_id"] not in operations
                               for row in [*context["operations"].values(), *[
                                   item["read_scope"] for item in context["finding_controls"].values()]])):
                    return blocked
            return evaluate_route(observation, control, snapshots, correlated, identities=identities,
                subscriptions=bindings, observer_identity=next(iter(observers)),
                route_context=context, context_observations=reads)
        return evaluate_origin(observation, control, snapshots, correlated,
            runtime_identity=identities[actor], observer_identity=next(iter(observers)),
            credential_sha256=bindings[caller])
    return blocked
