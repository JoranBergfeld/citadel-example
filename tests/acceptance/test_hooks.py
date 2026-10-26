import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from citadel.acceptance.operator_hooks import Harness, run
from citadel.operator.state import Blocked


class NoCloud:
    value = {"phase": "initialized"}

    def require_plan_observation(self):
        raise Blocked("api_center_foundation_required")


class HookTests(unittest.TestCase):
    def test_collection_selects_workspace_without_its_role_assignment_or_table_children(self):
        workspace = "/subscriptions/fixture/resourceGroups/fixture/providers/Microsoft.OperationalInsights/workspaces/logs"
        lifecycle = SimpleNamespace(
            value={"inventory": [workspace, workspace + "/tables/AppTraces",
                                workspace + "/providers/Microsoft.Authorization/roleAssignments/collector"]},
            state=SimpleNamespace(save=Mock()), native=SimpleNamespace(deadline=None))
        harness = object.__new__(Harness)
        harness.lifecycle = lifecycle
        harness.attempts = {"run1": {"fingerprint": "same", "collection_deadline": 0,
                                   "checks": [{"check_id": "telemetry.application-ingestion"}]}}
        harness.save = Mock(return_value={"status": "blocked", "reason": "evidence_collection_deadline"})
        with patch("citadel.acceptance.operator_hooks.fingerprints", return_value={"fingerprint": "same"}):
            result = harness.collect("run1")
        self.assertEqual(result["reason"], "evidence_collection_deadline")
        self.assertEqual(harness.attempts["run1"]["checks"][0]["reason"], "evidence_collection_deadline")

    def test_public_hook_never_accepts_local_or_unobserved_deployment(self):
        for check in ("full-acceptance", "denied-bypass-controls", "rotation-new-material-allowed",
                      "rotation-old-material-denied", "collect-evidence"):
            with self.subTest(check=check):
                with self.assertRaises(Blocked) as error:
                    run(lifecycle=NoCloud(), check_id=check, run_id="r1")
                self.assertEqual(error.exception.code, "api_center_foundation_required")

    def test_unknown_hook_and_malformed_run_do_not_reach_any_provider(self):
        for check, run_id in (("arbitrary-privileged-proxy", "r1"), ("full-acceptance", "../private")):
            with self.assertRaises((Blocked, ValueError)):
                run(lifecycle=object(), check_id=check, run_id=run_id)
