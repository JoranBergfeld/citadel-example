"""Independent private-product/source observations, exporting hashes rather than payloads."""

import math

from citadel.evidence.manifests import sha256
from citadel.gateway.trust import INVOCATION_CALLERS
from citadel.operations import identity
from citadel.runtime.configuration import OPERATIONS
from .scenarios import FIXTURES, expected_scenario, evaluate_scenario
from .oracle import hash_value


SEMANTIC = ("airport_ident", "classification", "gap_reasons", "caveats", "evidence", "provenance")
PRODUCT_FIELDS = {"status", "selected_identifiers", "pool_count", "assessed",
                  "provenance", "caveats", "planner_commentary"}
BRIEF_FIELDS = {"status", "fictional", "narrative", "citations", "read_scopes",
                "findings", "provenance", "caveats"}
FINDING_FIELDS = {*SEMANTIC, "schema_version", "run_id", "operation_id", "draft",
                  "artifact_id", "version", "reviewer"}


def _source(source, scenario):
    fixture = FIXTURES[scenario]
    return source if fixture == "base-source" else source.with_overlay(source.fixture_manifests()[fixture])


def scenario_inputs(source):
    result = {}
    for scenario in FIXTURES:
        data, expected = _source(source, scenario), expected_scenario(source, scenario)
        result[scenario] = {"semantics_sha256": sha256(expected), "source_sha256": sha256(data.provenance),
            "pool_sha256": sha256(data.search_airports()), "status": expected["status"],
            "selected_identifiers": expected["selected_identifiers"], "pool_count": expected["pool_count"],
            "assessed": [{"airport_ident": row["airport_ident"], "sha256": sha256(row),
                         "lookup_sha256": sha256(data.lookup_airport(row["airport_ident"])),
                         "runways_sha256": sha256(data.list_runways(row["airport_ident"]))}
                        for row in expected["assessed"]]}
    return result


def scenario_snapshot(source, scenario, product, documents, *, run_id):
    """Called only on actual private products and independently read six ledgers."""
    try:
        return _snapshot(source, scenario, product, documents, identity(run_id))
    except (KeyError, TypeError, IndexError):
        raise ValueError("Incomplete actual scenario state") from None


def _snapshot(source, scenario, product, documents, run_id):
    if evaluate_scenario(source, scenario, product)["status"] != "pass":
        raise ValueError("Actual product differs from independent pinned source")
    complete = product["status"] == "complete"
    if (set(product) != PRODUCT_FIELDS | ({"brief"} if complete else set())
            or not isinstance(product["planner_commentary"], str) or not product["planner_commentary"]
            or set(documents) != {*OPERATIONS, "drafts", "findings"}):
        raise ValueError("Unexpected public product fields or missing independent ledgers")
    data, operations = _source(source, scenario), {}
    for actor in OPERATIONS:
        owner = next(iter(INVOCATION_CALLERS[actor]))
        rows = []
        for key, row in documents[actor]["operations"].items():
            if row.get("run_id") != run_id:
                continue
            if (key != owner + "/invoke/" + identity(row["operation_id"])
                    or row["state"] != "succeeded" or not isinstance(row["result"], dict)):
                raise ValueError("Scenario contains uncompleted or incorrectly owned work")
            result = row["result"]
            observed = {"operation_id": row["operation_id"], "run_id": run_id, "caller": owner,
                "state": row["state"], "input_hash": row["input_hash"], "result_sha256": sha256(result)}
            if actor in ("candidate-planner", "briefing-author"):
                expected = product if actor == "candidate-planner" else product.get("brief")
                if row.get("product") != expected or result.get("sha256") != sha256(expected):
                    raise ValueError("Actual completed task differs from returned product")
                observed["product_sha256"] = sha256(expected)
            else:
                observed.update(finding=result["finding"], read_scope=result["read_scope"])
            rows.append(observed)
        required = 1 if actor == "candidate-planner" else int(complete) if actor == "briefing-author" else len(product["assessed"])
        if len(rows) != required:
            raise ValueError("Not every exact scenario invocation completed")
        operations[actor] = sorted(rows, key=lambda row: row["operation_id"])
    if operations["candidate-planner"][0]["operation_id"] != run_id:
        raise ValueError("Root product belongs to another invocation")
    findings = []
    for finding in product["assessed"]:
        if set(finding) != FINDING_FIELDS or finding["run_id"] != run_id:
            raise ValueError("Finding contains nonshareable fields or belongs to another run")
        ref = {key: finding[key] for key in ("artifact_id", "version")} | {"sha256": sha256(finding)}
        if documents["findings"]["findings"][ref["artifact_id"]][str(ref["version"])] != finding:
            raise ValueError("Returned finding is not the exact persisted release")
        draft_ref = finding["draft"]
        draft = documents["drafts"]["drafts"][draft_ref["artifact_id"]][str(draft_ref["version"])]
        if sha256(draft) != draft_ref["sha256"]:
            raise ValueError("Released draft hash does not match independently read bytes")
        projected = data.shareable_projection(draft) | {
            key: finding[key] for key in ("operation_id", "artifact_id", "version", "reviewer")}
        if projected != finding:
            raise ValueError("Returned finding differs from the independent private-field projection")
        matched = {}
        for actor in ("evidence-assessor", "release-reviewer"):
            matches = [row for row in operations[actor] if row["finding"] == ref]
            if len(matches) != 1:
                raise ValueError("Finding lacks its exact actual collaboration result")
            matched[actor] = matches[0]
        scope = {"run_id": run_id, "operation_id": matched["release-reviewer"]["operation_id"]}
        if any(row["read_scope"] != scope for row in matched.values()):
            raise ValueError("Finding read scope is not the completed reviewer execution")
        findings.append({"airport_ident": finding["airport_ident"], "finding": ref, "draft": draft_ref,
            "read_scope": scope, "operations": {actor: row["operation_id"] for actor, row in matched.items()},
            "assessment_sha256": sha256({key: finding[key] for key in SEMANTIC}),
            "projection_sha256": sha256(projected), "fields_sha256": sha256(sorted(finding))})
    semantics = {key: product[key] for key in ("status", "selected_identifiers", "pool_count", "provenance", "caveats")}
    semantics["assessed"] = [{key: row[key] for key in SEMANTIC} for row in product["assessed"]]
    snapshot = {"run_id": run_id, "product_sha256": sha256(product), "semantics_sha256": sha256(semantics),
                "fields_sha256": sha256(sorted(product)), "operations": operations, "findings": findings}
    if complete:
        brief = product["brief"]
        if set(brief) != BRIEF_FIELDS:
            raise ValueError("Brief contains nonshareable fields")
        selected = [row for row in findings if row["airport_ident"] in product["selected_identifiers"]]
        if (brief["citations"] != [row["finding"] for row in selected]
                or brief["read_scopes"] != [row["read_scope"] for row in selected]):
            raise ValueError("Brief citations or funded read scopes do not match exact released findings")
        snapshot["brief"] = {"product_sha256": sha256(brief), "fields_sha256": sha256(sorted(brief)),
            "findings": brief["citations"], "read_scopes": brief["read_scopes"]}
    return snapshot


def evaluate_scenario_proof(check, report):
    result = {"check_id": check.get("check_id"), "status": "blocked",
              "reason": "independent_scenario_source_product_and_service_proof_required"}
    try:
        return result | _evaluate(check, report)
    except (KeyError, TypeError, ValueError, IndexError, AttributeError):
        return result


def _evaluate(check, report):
    from .storage_probes import _correlated
    blocked = {"status": "blocked", "reason": "scenario_service_correlation_missing"}
    failed = {"status": "fail", "reason": "scenario_independent_source_or_projection_mismatch"}
    scenario = check["check_id"].removeprefix("scenario.")
    if scenario not in FIXTURES:
        return blocked
    expected = report["scenario_inputs"][scenario]
    if sha256(report["scenario_inputs"]) != report["inputs"]["scenario_oracles"]:
        return blocked
    actual = check["actual"]
    snapshot, control = actual["observation"], actual["control"]
    run_id, records = snapshot["run_id"], report["evidence"]
    saved = report["scenarios"][scenario]
    if (saved["operation_id"] != run_id or run_id not in report["operation_ids"]
            or not hash_value(snapshot["product_sha256"])
            or snapshot["product_sha256"] != saved["product_sha256"]
            or snapshot["semantics_sha256"] != saved["semantics_sha256"]
            or any(type(actual[k]) not in (int, float) or not math.isfinite(actual[k])
                   for k in ("started", "finished"))
            or not 0 <= actual["finished"] - actual["started"] <= 900):
        return blocked
    if snapshot["semantics_sha256"] != expected["semantics_sha256"]:
        return failed
    complete = expected["status"] == "complete"
    if (expected["pool_count"] != 20 or not 0 < len(expected["assessed"]) <= 20
            or snapshot["fields_sha256"] != sha256(sorted(PRODUCT_FIELDS | ({"brief"} if complete else set())))
            or len(snapshot["findings"]) != len(expected["assessed"])
            or set(snapshot["operations"]) != set(OPERATIONS)
            or not hash_value(control["runtime_identity"])
            or control["runtime_identity"] in report["runtime_identities"].values()):
        return blocked
    reads = control["observations"]
    containers = {*OPERATIONS.values(), "drafts", "findings"}
    if (len(reads) != 6 or {row["container"] for row in reads} != containers
            or len({row["request_id"] for row in reads}) != 6):
        return blocked
    for row in reads:
        if (row["caller"] != "operator" or row["suite_id"] != report["run_id"]
                or row["action"] != "read" or row["status_code"] not in (200, 206)
                or row["operation_id"] not in report["operation_ids"] or not hash_value(row["sha256"])
                or row["target"] != report["storage_targets"][row["container"]]
                or not actual["started"] <= row["started"] <= row["finished"] <= actual["finished"]
                or not _correlated(row, records, control["runtime_identity"])):
            return blocked

    def gateway(row, actor):
        return any(g.get("source") == "gateway" and g.get("request_id") == row["request_id"]
            and g.get("caller") == row["caller"] and g.get("status_code") == 200
            and g.get("credential_sha256") == report["subscription_bindings"][row["caller"]]
            and g.get("target") == report["gateway_targets"][actor] and g.get("method") == "POST"
            and g.get("facts", {}).get("backend_dispatched") is True
            and type(g.get("observed")) in (int, float)
            and actual["started"] - 5 <= g["observed"] <= actual["finished"] + 5
            and abs(g["observed"] - row["observed"]) <= 5 for g in records)

    def application(actor, caller, operation, method):
        return [row for row in records if row.get("source") == "application"
            and row.get("runtime_identity") == report["runtime_identities"][actor]
            and row.get("caller") == caller and row.get("run_id") == run_id
            and row.get("operation_id") == operation and row.get("method") == method
            and row.get("status_code") == 200 and isinstance(row.get("request_id"), str)
            and row["request_id"] and isinstance(row.get("facts"), dict)
            and type(row.get("observed")) in (int, float)
            and actual["started"] - 5 <= row["observed"] <= actual["finished"] + 5]

    all_ids = set()
    for actor, operations in snapshot["operations"].items():
        size = 1 if actor == "candidate-planner" else int(complete) if actor == "briefing-author" else len(snapshot["findings"])
        if len(operations) != size:
            return blocked
        for operation in operations:
            key = operation["operation_id"]
            if (key in all_ids or key not in report["operation_ids"] or operation["run_id"] != run_id
                    or operation["caller"] not in INVOCATION_CALLERS[actor] or operation["state"] != "succeeded"
                    or not all(hash_value(operation[k]) for k in ("input_hash", "result_sha256"))):
                return blocked
            all_ids.add(key)
            accepted = [row for row in application(actor, operation["caller"], key, "SendMessage")
                if row["facts"].get("accepted_operation_id") == key
                and row["facts"].get("input_hash") == operation["input_hash"]]
            if not accepted or not any(gateway(row, actor) for row in accepted):
                return blocked
    root = snapshot["operations"]["candidate-planner"][0]
    if root["operation_id"] != run_id or root["product_sha256"] != snapshot["product_sha256"]:
        return failed
    needed = [("candidate-planner", run_id, "search_airports", expected["pool_sha256"])]
    for finding, wanted in zip(snapshot["findings"], expected["assessed"]):
        if (finding["airport_ident"] != wanted["airport_ident"]
                or finding["assessment_sha256"] != wanted["sha256"]
                or finding["projection_sha256"] != finding["finding"]["sha256"]
                or finding["fields_sha256"] != sha256(sorted(FINDING_FIELDS))):
            return failed
        for ref in (finding["finding"], finding["draft"]):
            if (set(ref) != {"artifact_id", "version", "sha256"} or not hash_value(ref["sha256"])
                    or type(ref["version"]) is not int or ref["version"] < 1):
                return blocked
            identity(ref["artifact_id"])
        if finding["finding"]["version"] != finding["draft"]["version"]:
            return failed
        if finding["read_scope"] != {"run_id": run_id, "operation_id": finding["operations"]["release-reviewer"]}:
            return failed
        for actor in ("evidence-assessor", "release-reviewer"):
            key = finding["operations"][actor]
            matches = [row for row in snapshot["operations"][actor] if row["operation_id"] == key]
            if len(matches) != 1 or matches[0]["finding"] != finding["finding"] or matches[0]["read_scope"] != finding["read_scope"]:
                return failed
            needed.extend((actor, key, method, wanted[field]) for method, field in
                          (("lookup_airport", "lookup_sha256"), ("list_runways", "runways_sha256")))
    source_requests = set()
    for caller, operation, tool, digest in needed:
        observed = [row for row in application("reference-data", caller, operation, "reference.observed")
                    if row["facts"].get("probe_id") == tool]
        if len(observed) != 1 or not gateway(observed[0], "reference-data"):
            return blocked
        row = observed[0]
        if row["request_id"] in source_requests:
            return blocked
        source_requests.add(row["request_id"])
        if row["facts"].get("sha256") != digest or row["facts"].get("source_sha256") != expected["source_sha256"]:
            return failed
    if complete:
        brief = snapshot["brief"]
        selected = [row for row in snapshot["findings"] if row["airport_ident"] in expected["selected_identifiers"]]
        if (len(selected) != 3 or brief["fields_sha256"] != sha256(sorted(BRIEF_FIELDS))
                or brief["findings"] != [row["finding"] for row in selected]
                or brief["read_scopes"] != [row["read_scope"] for row in selected]
                or brief["product_sha256"] != snapshot["operations"]["briefing-author"][0]["product_sha256"]):
            return failed
    elif "brief" in snapshot:
        return failed
    if scenario == "denied-bypass":
        from .bypass import bypass_status
        bypass = actual["bypass"]
        if (bypass["run_id"] != run_id or bypass["fingerprint"] != report["fingerprint"]
                or bypass["runtime_identities"] != report["runtime_identities"]
                or bypass["finished"] > actual["started"]):
            return blocked
        status = bypass_status(bypass)
        if status != "pass":
            return {"status": status, "reason": "prior_four_denials_and_no_effects_not_verified"}
    return {"status": "pass", "reason": "independent_sources_exact_released_products_and_service_correlations_verified"}


def evaluate_projection(check, report):
    from .proof_gate import evaluate_check
    blocked = {"check_id": "projection.private-fields-absent", "status": "blocked",
               "reason": "all_actual_scenario_projections_required"}
    required = ["scenario." + name for name in sorted(FIXTURES)]
    if check.get("actual") != {"required_checks": required}:
        return blocked
    children = report.get("checks")
    if not isinstance(children, list) or any(not isinstance(row, dict) for row in children):
        return blocked
    run_ids = set()
    for identifier in required:
        matches = [row for row in children if row.get("check_id") == identifier]
        if len(matches) != 1:
            return blocked
        child = matches[0]
        if child.get("status") == "fail":
            return blocked | {"status": "fail", "reason": "scenario_projection_failed"}
        if child.get("status") != "pass":
            return blocked
        outcome = evaluate_check(child, report)
        if outcome["status"] != "pass":
            return blocked | {"status": outcome["status"]}
        run_ids.add(child["actual"]["observation"]["run_id"])
    if len(run_ids) != 4:
        return blocked
    return blocked | {"status": "pass", "reason": "all_exact_source_and_draft_bound_shareable_field_sets_verified"}


def collect_projection(report):
    check = {"check_id": "projection.private-fields-absent", "expected": "evidence",
             "actual": {"required_checks": ["scenario." + name for name in sorted(FIXTURES)]}}
    return check | evaluate_projection(check, report)
