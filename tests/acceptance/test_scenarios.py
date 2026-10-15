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
    async def test_oracle_accepts_real_protocol_workflow_outputs_not_expected_value_fixtures(self):
        import sys
        from pathlib import Path
        runtime_tests = str(Path(__file__).resolve().parents[1] / "runtime")
        sys.path.insert(0, runtime_tests)
        try:
            import test_workflow
            fixture = test_workflow.WorkflowTests()
            source = ReferenceData.from_directory(os.environ["CITADEL_EVIDENCE_DATA"])
            for scenario, overlay in (("comparison", "base-source"),
                                      ("replacement", "missing-width-replacement"),
                                      ("exhaustion", "no-alternative")):
                product, _, _ = await fixture.run_case(overlay, data_source=source)
                result = evaluate_scenario(source, scenario, product)
                self.assertEqual(result["status"], "pass", result)
                altered = copy.deepcopy(product)
                altered["assessed"][0]["draft"]["sha256"] = "invalid-hash"
                self.assertEqual(evaluate_scenario(source, scenario, altered)["status"], "fail")
        finally:
            sys.path.remove(runtime_tests)
