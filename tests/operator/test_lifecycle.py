import copy
import json

import test_cli


class CloudFixture:
    """External native boundary; unknown commands fail, never blanket-success."""
    def __init__(self):
        self.calls = []
        self.groups = []

    def az(self, *args, **kwargs):
        self.calls.append(args)
        if args[:2] == ("group", "list"):
            return copy.deepcopy(self.groups)
        raise AssertionError("Unexpected native command: " + str(args[:2]))


class LifecycleTests(test_cli.CliCase):
    def initialize(self):
        self.assertEqual(self.cli("init", "--config", str(self.config),
                                 "--state-dir", str(self.state))[0], 0)

    def test_paid_deploy_requires_explicit_confirmation_and_real_preflight(self):
        self.initialize()
        fixture = CloudFixture()
        code, result = self.cli("deploy", "--state-dir", str(self.state), adapter=fixture)
        self.assertEqual((code, result["code"]), (2, "explicit_paid_provisioning_confirmation_required"))
        self.assertEqual(fixture.calls, [])

    def test_inventory_rejects_preexisting_foreign_group_even_with_expected_name(self):
        self.initialize()
        fixture = CloudFixture()
        fixture.groups = [{"name": "citadel-test19-platform", "tags": {"citadel-deployment": "other"},
                           "id": "/subscriptions/test/resourceGroups/citadel-test19-platform"}]
        code, result = self.cli("inventory", "--state-dir", str(self.state), adapter=fixture)
        self.assertEqual((code, result["code"]), (2, "resource_group_ownership_conflict"))
        self.assertFalse(any("delete" in call for call in fixture.calls))

    def test_acceptance_hook_is_honestly_blocked_not_a_canned_pass(self):
        self.initialize()
        code, result = self.cli("acceptance", "--state-dir", str(self.state), adapter=CloudFixture())
        self.assertEqual((code, result["code"]), (2, "task20_acceptance_harness_required"))

    def test_rotation_cannot_retire_credentials_without_live_control_evidence(self):
        self.initialize()
        code, result = self.cli("rotate", "certificate", "--stage", "finalize",
                                "--state-dir", str(self.state), adapter=CloudFixture())
        self.assertEqual((code, result["code"]), (2, "runtime_deployment_required"))

    def test_manual_teardown_requires_exact_identity_before_any_cloud_action(self):
        self.initialize()
        fixture = CloudFixture()
        code, result = self.cli("teardown", "--state-dir", str(self.state),
                                "--confirm-deployment", "other", adapter=fixture)
        self.assertEqual((code, result["code"]), (2, "manual_exact_deployment_confirmation_required"))
        self.assertEqual(fixture.calls, [])

    def test_unexpected_child_error_cannot_echo_sensitive_private_target(self):
        self.initialize()
        fixture = CloudFixture()
        def error(*args, **kwargs):
            raise RuntimeError(self.values["subscriptionId"] + " private-credential")
        fixture.az = error
        code, result = self.cli("inventory", "--state-dir", str(self.state), adapter=fixture)
        self.assertEqual(code, 1)
        self.assertNotIn(self.values["subscriptionId"], json.dumps(result))
        self.assertNotIn("private-credential", json.dumps(result))
