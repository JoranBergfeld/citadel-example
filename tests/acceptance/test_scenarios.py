import copy
import os
import unittest

from citadel.acceptance.scenarios import expected_scenario, evaluate_scenario
from citadel.evidence import ReferenceData


@unittest.skipUnless(os.environ.get("CITADEL_EVIDENCE_DATA"), "Retained pinned evidence not selected")
class ScenarioOracleTests(unittest.TestCase):
    def setUp(self):
        self.source = ReferenceData.from_directory(os.environ["CITADEL_EVIDENCE_DATA"])

    def test_exact_pinned_scenario_outcomes_are_independent_of_prose(self):
        for scenario, expected in (
            ("comparison", ["BE-0052", "EBAM", "EBAR"]),
            ("replacement", ["EBAM", "EBAR", "EBAW"]),
            ("exhaustion", []),
        ):
            with self.subTest(scenario=scenario):
                value = expected_scenario(self.source, scenario)
                self.assertEqual(value["selected_identifiers"], expected)
                self.assertEqual(value["pool_count"], 20)

    def test_exhaustion_with_a_fabricated_complete_brief_fails(self):
        product = expected_scenario(self.source, "exhaustion")
        self.assertEqual(evaluate_scenario(self.source, "exhaustion", product)["status"], "blocked")
        product["brief"] = {"status": "complete"}
        self.assertEqual(evaluate_scenario(self.source, "exhaustion", product)["status"], "fail")

    def test_missing_caveat_changed_fixture_or_reordered_candidates_fail(self):
        product = expected_scenario(self.source, "exhaustion")
        for altered in (
            product | {"caveats": []},
            product | {"provenance": {}},
            product | {"assessed": list(reversed(product["assessed"]))},
        ):
            self.assertEqual(evaluate_scenario(self.source, "exhaustion", altered)["status"], "fail")

    def test_complete_comparison_requires_exact_released_versions_not_just_three_names(self):
        product = expected_scenario(self.source, "comparison")
        self.assertEqual(evaluate_scenario(self.source, "comparison", product)["status"], "blocked")


@unittest.skipUnless(os.environ.get("CITADEL_EVIDENCE_DATA"), "Retained pinned evidence not selected")
class ProtocolScenarioOracleTests(unittest.IsolatedAsyncioTestCase):
    async def test_independent_snapshot_binds_every_real_draft_finding_and_completed_invocation(self):
        import sys
        from pathlib import Path
        runtime_tests = str(Path(__file__).resolve().parents[1] / "runtime")
        sys.path.insert(0, runtime_tests)
        try:
            import test_workflow
            from citadel.acceptance.scenario_proof import scenario_inputs, scenario_snapshot
            from citadel.evidence.manifests import sha256
            source = ReferenceData.from_directory(os.environ["CITADEL_EVIDENCE_DATA"])
            documents = {}
            product, _, _ = await test_workflow.WorkflowTests().run_case(
                "missing-width-replacement", data_source=source, persisted=documents)
            result = scenario_snapshot(source, "replacement", product, documents, run_id="run1")
            expected = scenario_inputs(source)["replacement"]
            self.assertEqual(result["semantics_sha256"], expected["semantics_sha256"])
            self.assertEqual(result["product_sha256"], sha256(product))
            self.assertEqual(len(result["findings"]), 5)
            self.assertEqual(len(result["operations"]["release-reviewer"]), 5)
            self.assertEqual(result["brief"]["product_sha256"], sha256(product["brief"]))
            self.assertNotIn("private_notes", str(result))
            import json
            import time
            from types import SimpleNamespace
            from citadel.acceptance.scenario_harness import ScenarioAcceptance
            from citadel.operator.state import Blocked
            from citadel.runtime.configuration import OPERATIONS
            from tests.acceptance.test_storage_controls import BlobProvider
            provider, saves = BlobProvider(), []
            for actor, container in {**OPERATIONS, "drafts": "drafts", "findings": "findings"}.items():
                provider.objects[container, "ledger-v1.json"] = json.dumps(documents[actor]).encode()
            original = dict(provider.objects)
            lifecycle = SimpleNamespace(native=provider, state=SimpleNamespace(save=lambda: saves.append(1)),
                value={"inventory": ["/subscriptions/s/resourceGroups/g/providers/Microsoft.Storage/storageAccounts/allocated"],
                       "runs": {"run1": {"state": "succeeded", "deadline": time.time() + 600}}})
            captured = {"run_id": "suite1", "operation_ids": ["run1"]}
            ScenarioAcceptance(lifecycle).execute(captured, "replacement", product, source=source, run_id="run1")
            self.assertEqual(len(provider.requests), 6)
            self.assertTrue(all(method == "GET" and name == "ledger-v1.json" for method, _, name in provider.requests))
            self.assertEqual(provider.objects, original)
            with self.assertRaises(Blocked):
                ScenarioAcceptance(lifecycle).execute(captured, "replacement", product, source=source, run_id="run1")
            self.assertEqual(len(provider.requests), 6)
            from citadel.acceptance.proof_gate import evaluate_check
            from citadel.acceptance.reports import sanitize
            check, report = scenario_query_fixture(result, scenario_inputs(source), "replacement")
            self.assertEqual(evaluate_check(check, report)["status"], "pass")
            exported = sanitize(report | {"checks": [check]})
            self.assertEqual(evaluate_check(exported["checks"][0], exported)["status"], "pass")
            self.assertNotIn("Fictional reference-data comparison", str(exported))
            for source_name in ("application", "gateway", "storage"):
                missing = report | {"evidence": [r for r in report["evidence"] if r["source"] != source_name]}
                self.assertEqual(evaluate_check(check, missing)["status"], "blocked")
            altered = copy.deepcopy(report)
            next(row for row in altered["evidence"] if row.get("method") == "reference.observed")["facts"]["sha256"] = "f" * 64
            self.assertEqual(evaluate_check(check, altered)["status"], "fail")
            for mutate in (
                lambda p, d: p.update(private_notes="leaked"),
                lambda p, d: p["brief"].update(reviewer_deliberation="leaked"),
                lambda p, d: p["assessed"][0]["evidence"].update(credentials="leaked"),
                lambda p, d: d["findings"]["findings"].clear(),
                lambda p, d: d["drafts"]["drafts"].clear(),
                lambda p, d: d["evidence-assessor"]["operations"].clear(),
            ):
                altered, observed = copy.deepcopy(product), copy.deepcopy(documents)
                mutate(altered, observed)
                with self.assertRaises(ValueError):
                    scenario_snapshot(source, "replacement", altered, observed, run_id="run1")
        finally:
            sys.path.remove(runtime_tests)


    async def test_oracle_accepts_real_protocol_workflow_outputs_not_expected_value_fixtures(self):
        import sys
        from pathlib import Path
        runtime_tests = str(Path(__file__).resolve().parents[1] / "runtime")
        sys.path.insert(0, runtime_tests)
        try:
            import test_workflow
            fixture = test_workflow.WorkflowTests()
            source = ReferenceData.from_directory(os.environ["CITADEL_EVIDENCE_DATA"])
            from citadel.acceptance.scenario_proof import scenario_inputs, scenario_snapshot
            from citadel.acceptance.proof_gate import evaluate_check
            from citadel.acceptance.reports import sanitize
            expected = scenario_inputs(source)
            combined = None
            for scenario, overlay in (("comparison", "base-source"),
                                      ("replacement", "missing-width-replacement"),
                                      ("exhaustion", "no-alternative"),
                                      ("denied-bypass", "base-source")):
                documents = {}
                product, _, _ = await fixture.run_case(overlay, data_source=source, persisted=documents, run_id=scenario)
                result = evaluate_scenario(source, scenario, product)
                self.assertEqual(result["status"], "pass", result)
                snapshot = scenario_snapshot(source, scenario, product, documents, run_id=scenario)
                check, report = scenario_query_fixture(snapshot, expected, scenario)
                if scenario == "denied-bypass":
                    self.assertEqual(evaluate_check(check, report)["status"], "blocked")
                    attach_bypass(check, report)
                    missing = copy.deepcopy(check)
                    missing["actual"]["bypass"]["evidence"] = []
                    self.assertEqual(evaluate_check(missing, report)["status"], "blocked")
                    failed = copy.deepcopy(check)
                    failed["actual"]["bypass"]["checks"][0]["actual"]["after"]["sha256"] = "0" * 64
                    self.assertEqual(evaluate_check(failed, report)["status"], "fail")
                exported = sanitize(report | {"checks": [check]})
                self.assertEqual(evaluate_check(exported["checks"][0], exported)["status"], "pass")
                if combined is None:
                    combined = report | {"checks": [check]}
                else:
                    combined["checks"].append(check)
                    combined["scenarios"].update(report["scenarios"])
                    combined["evidence"].extend(report["evidence"])
                    combined["operation_ids"].extend(report["operation_ids"])
                altered = copy.deepcopy(product)
                altered["assessed"][0]["draft"]["sha256"] = "invalid-hash"
                self.assertEqual(evaluate_scenario(source, scenario, altered)["status"], "fail")
            from citadel.acceptance.scenario_proof import collect_projection
            projection = collect_projection(combined)
            self.assertEqual(evaluate_check(sanitize(projection), sanitize(combined))["status"], "pass")
            missing = combined | {"checks": combined["checks"][:-1]}
            self.assertEqual(evaluate_check(projection, missing)["status"], "blocked")
        finally:
            sys.path.remove(runtime_tests)


def scenario_query_fixture(snapshot, expected, scenario):
    """External query boundary data; never a cloud evidence or exporter stand-in."""
    from citadel.evidence.manifests import sha256
    from citadel.runtime.configuration import OPERATIONS
    identities = {role: sha256(role) for role in (*OPERATIONS, "reference-data")}
    subscriptions = {role: sha256("subscription-" + role) for role in (*OPERATIONS, "operator")}
    targets = {role: sha256("gateway-" + role) for role in identities}
    storage = {container: sha256("blob-" + container) for container in (*OPERATIONS.values(), "drafts", "findings")}
    rows, reads = [], []
    for container, target in storage.items():
        operation = snapshot["run_id"] + "-read-" + container
        read = {"operation_id": operation, "request_id": "service-" + operation,
            "status_code": 206, "target": target, "container": container, "action": "read", "caller": "operator",
            "suite_id": "suite1", "started": 109, "finished": 110, "sha256": sha256(container), "count": 1}
        reads.append(read)
        rows.append(read | {"source": "storage", "method": "GetBlob", "observed": 109,
            "runtime_identity": sha256("operator"), "client_request_id": operation})

    def application(caller, actor, operation, method, facts):
        request_id = snapshot["run_id"] + "-service-" + str(len(rows))
        rows.append({"source": "application", "request_id": request_id, "status_code": 200,
            "runtime_identity": identities[actor], "caller": caller, "run_id": snapshot["run_id"],
            "operation_id": operation, "method": method, "observed": 100, "facts": facts})
        rows.append({"source": "gateway", "request_id": request_id, "status_code": 200,
            "caller": caller, "credential_sha256": subscriptions[caller], "method": "POST",
            "target": targets[actor], "observed": 100, "facts": {"backend_dispatched": True}})

    for actor, operations in snapshot["operations"].items():
        for operation in operations:
            application(operation["caller"], actor, operation["operation_id"], "SendMessage", {
                "accepted_operation_id": operation["operation_id"], "input_hash": operation["input_hash"]})
    inputs = expected[scenario]
    application("candidate-planner", "reference-data", snapshot["run_id"], "reference.observed", {
        "probe_id": "search_airports", "sha256": inputs["pool_sha256"], "source_sha256": inputs["source_sha256"]})
    for finding, wanted in zip(snapshot["findings"], inputs["assessed"]):
        for actor, operation in finding["operations"].items():
            for tool, field in (("lookup_airport", "lookup_sha256"), ("list_runways", "runways_sha256")):
                application(actor, "reference-data", operation, "reference.observed", {
                    "probe_id": tool, "sha256": wanted[field], "source_sha256": inputs["source_sha256"]})
    report = {"run_id": "suite1", "mode": "cloud", "runtime_identities": identities, "fingerprint": "9" * 64,
        "subscription_bindings": subscriptions, "gateway_targets": targets, "storage_targets": storage,
        "scenario_inputs": expected, "inputs": {"scenario_oracles": sha256(expected)}, "evidence": rows,
        "scenarios": {scenario: {"operation_id": snapshot["run_id"], "product_sha256": snapshot["product_sha256"],
                                "semantics_sha256": snapshot["semantics_sha256"]}},
        "operation_ids": sorted({snapshot["run_id"], *[r["operation_id"] for r in reads],
                                *[r["operation_id"] for group in snapshot["operations"].values() for r in group]})}
    check = {"check_id": "scenario." + scenario, "expected": "semantic", "status": "pass",
        "actual": {"observation": snapshot, "control": {"runtime_identity": sha256("operator"), "observations": reads},
                   "started": 90, "finished": 110}}
    return check, report


def attach_bypass(check, report):
    from tests.acceptance.test_bypass import proof
    bypass = proof()
    translations = {old: report["runtime_identities"][actor]
                    for actor, old in bypass["runtime_identities"].items()}

    def translate(value):
        if isinstance(value, list):
            return [translate(item) for item in value]
        if isinstance(value, dict):
            result = {key: translate(item) for key, item in value.items()}
            for key in ("started", "finished", "observed"):
                if key in result:
                    result[key] -= 50
            if "runtime_identity" in result:
                result["runtime_identity"] = translations.get(result["runtime_identity"], result["runtime_identity"])
            if "suite_id" in result:
                result["suite_id"] = check["actual"]["observation"]["run_id"]
            return result
        return value

    bypass = translate(bypass)
    bypass.update(run_id=check["actual"]["observation"]["run_id"], fingerprint=report["fingerprint"],
                  runtime_identities=report["runtime_identities"], started=48, finished=54)
    check["actual"]["bypass"] = bypass
