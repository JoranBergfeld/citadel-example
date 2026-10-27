import copy
import time
import unittest
from types import SimpleNamespace

from citadel.acceptance.model_admission import ModelAdmission
from citadel.operations import OperationError
from citadel.operator.state import Blocked


class ModelAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.saved = []
        self.clock = [time.time()]
        self.phase = {"run_id": "models1", "deadline": self.clock[0] + 900}
        self.state = SimpleNamespace(save=lambda: self.saved.append(copy.deepcopy(self.phase)))

    def admission(self):
        return ModelAdmission(self.phase, save=self.state.save, tokens_per_minute=6000,
                              clock=lambda: self.clock[0])

    def test_durable_reservation_survives_restart_and_never_releases_an_ambiguous_call(self):
        admission = self.admission()
        permit = admission.reserve("evidence-assessor", operation_id="direct1")
        self.assertEqual(len(self.saved), 1)
        self.assertEqual(self.saved[-1]["model_active"]["operation_id"], "direct1")
        self.assertEqual(self.phase["remaining"]["models"], 127)
        for actor in ("release-reviewer", "evidence-assessor"):
            with self.assertRaises(OperationError):
                self.admission().reserve(actor, operation_id="other1")
        for observation in (
            {"state": "indeterminate"},
            {"state": "observed", "status_code": 403, "reason": "PermissionDenied"},
            {"state": "observed", "status_code": 403, "reason": "PermissionDenied",
             "request_id": "real-service-id", "operation_id": "wrong"},
        ):
            with self.assertRaises(Blocked):
                self.admission().settle(permit, observation)
        self.assertIsNotNone(self.phase["model_active"])
        self.assertEqual(self.phase["remaining"]["models"], 127)

    def test_definite_receipt_preserves_spend_and_enforces_shared_spacing_and_actual_quota(self):
        admission = self.admission()
        permit = admission.reserve("evidence-assessor", operation_id="direct1")
        observation = {"state": "observed", "status_code": 403, "reason": "PermissionDenied",
            "request_id": "actual-model-receipt", "operation_id": "direct1",
            "caller": "evidence-assessor", "run_id": "models1",
            "started": self.clock[0], "finished": self.clock[0]}
        admission.settle(permit, observation)
        self.assertIsNone(self.phase["model_active"])
        self.assertEqual(self.phase["remaining"]["models"], 127)
        with self.assertRaises(OperationError) as error:
            self.admission().reserve("release-reviewer", operation_id="direct2")
        self.assertEqual(error.exception.code, "rate_limited")
        self.clock[0] += 5
        with self.assertRaises(OperationError) as error:
            self.admission().reserve("release-reviewer", operation_id="direct2")
        self.assertEqual(error.exception.code, "rate_limited")
        self.clock[0] += 60
        self.admission().reserve("release-reviewer", operation_id="direct2")
        self.assertEqual(self.phase["remaining"]["models"], 126)
        with self.assertRaises(OperationError):
            self.admission().reserve("evidence-assessor", operation_id="direct1")


if __name__ == "__main__":
    unittest.main()
