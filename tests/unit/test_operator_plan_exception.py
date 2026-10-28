from types import SimpleNamespace
import unittest
from unittest.mock import patch

from citadel.operator.plan import BINDING_FIELDS, observation_summary, require_observation
from citadel.operator.state import Blocked, digest


class SandboxPlanExceptionTests(unittest.TestCase):
    def setUp(self):
        self.request = {
            "requestId": "request1", "deploymentId": "demo1",
            "resourceId": "/subscriptions/example/resourceGroups/demo/providers/Microsoft.ApiCenter/services/demo",
            "resourceCreatedAt": "2026-10-28T12:00:00+00:00",
        }
        self.lifecycle = SimpleNamespace(
            config={"subscriptionId": "example", "deploymentId": "demo1"},
            value={},
        )

    def authorize(self):
        exception = {
            "source": "explicit-operator-sandbox-exception",
            "binding": {key: self.request[key] for key in BINDING_FIELDS},
            "configurationFingerprint": digest(self.lifecycle.config),
            "planVerified": False,
        }
        self.lifecycle.value["sandboxPlanException"] = exception

    def test_explicit_exact_bound_exception_never_claims_verified_plan(self):
        self.authorize()
        with patch("citadel.operator.plan.current_request", return_value=self.request):
            proof = require_observation(self.lifecycle)
            self.assertIs(proof["planVerified"], False)
            summary = observation_summary(self.lifecycle)
            self.assertEqual(summary["status"], "operator_exception_plan_unverified")
            self.assertNotIn("observedAt", summary)

    def test_absence_or_changed_resource_or_configuration_does_not_authorize(self):
        with patch("citadel.operator.plan.current_request", return_value=self.request):
            with self.assertRaises(Blocked):
                require_observation(self.lifecycle)
            self.authorize()
            self.request["resourceCreatedAt"] = "2026-10-29T12:00:00+00:00"
            with self.assertRaises(Blocked):
                require_observation(self.lifecycle)
            self.authorize()
            self.lifecycle.config["subscriptionId"] = "another-subscription"
            with self.assertRaises(Blocked):
                require_observation(self.lifecycle)
