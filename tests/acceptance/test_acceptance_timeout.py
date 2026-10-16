import json
import copy
import time
import unittest


class AcceptanceTimeoutTests(unittest.TestCase):
    def test_export_requires_actual_backend_ten_second_expiry_not_a_client_timeout_label(self):
        from test_http_timeout import fixture
        from citadel.acceptance.proof_gate import evaluate_check
        from citadel.acceptance.reports import sanitize
        from citadel.evidence.manifests import sha256
        check, report = fixture()
        check["check_id"] = "limit.acceptance_seconds"
        actual = check["actual"]
        actual["response"] = "indeterminate"
        actual["timer"] = {"started": 120, "finished": 130.01, "deadline": 130,
            "monotonic_started": 50, "monotonic_deadline": 60, "monotonic_finished": 60.01}
        actual["observations"][1].update(finished=130.02, business_state="indeterminate",
            sha256=sha256({"error": "indeterminate", "complete": False}))
        report["evidence"].append({"source": "application", "method": "acceptance.timeout",
            "request_id": actual["observations"][1]["request_id"], "caller": "operator",
            "run_id": actual["run_id"], "operation_id": actual["run_id"], "status_code": 0,
            "runtime_identity": report["runtime_identities"]["candidate-planner"],
            "observed": 130.01, "facts": actual["timer"]})
        self.assertEqual(evaluate_check(sanitize(check), sanitize(report))["status"], "pass")
        changed = report | {"evidence": report["evidence"][:-1]}
        self.assertEqual(evaluate_check(check, changed)["status"], "blocked")
        changed = copy.deepcopy(check)
        changed["actual"]["timer"]["monotonic_deadline"] -= 1
        self.assertNotEqual(evaluate_check(changed, report)["status"], "pass")

    def test_hold_is_disabled_normally_and_accepts_only_private_fixed_cached_root_configuration(self):
        from citadel.acceptance.acceptance_timeout import CachedAcceptanceHold
        request = {"run_id": "completed", "deadline": time.time() + 600, "mode": "cached-acceptance"}
        self.assertIsNone(CachedAcceptanceHold.from_environment({}, workload="candidate-planner"))
        enabled = {"CITADEL_ACCEPTANCE_ENABLED": "true", "CITADEL_ACCEPTANCE_HOLD": json.dumps(request)}
        hold = CachedAcceptanceHold.from_environment(enabled, workload="candidate-planner")
        self.assertEqual(hold.run_id, "completed")
        for environment, workload in (
            (enabled, "release-reviewer"),
            (enabled | {"CITADEL_ACCEPTANCE_ENABLED": "false"}, "candidate-planner"),
            (enabled | {"CITADEL_ACCEPTANCE_HOLD": json.dumps(request | {"seconds": 20})}, "candidate-planner"),
            (enabled | {"CITADEL_ACCEPTANCE_HOLD": json.dumps(request | {"deadline": time.time() - 1})}, "candidate-planner"),
        ):
            with self.assertRaises(ValueError):
                CachedAcceptanceHold.from_environment(environment, workload=workload)
