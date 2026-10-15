import unittest

from citadel.acceptance.operator_hooks import run
from citadel.operator.state import Blocked


class NoCloud:
    value = {"phase": "initialized"}

    def require_plan_observation(self):
        raise Blocked("api_center_foundation_required")


class HookTests(unittest.TestCase):
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
