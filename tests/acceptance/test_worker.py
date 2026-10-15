import time
import unittest

from citadel.acceptance.worker import validate_request


class WorkerTests(unittest.TestCase):
    def request(self):
        return {"schema_version": 1, "run_id": "probe1", "workload": "candidate-planner",
                "client_id": "11111111-1111-1111-1111-111111111111",
                "deadline": time.time() + 100, "mode": "gateway-matrix"}

    def test_disabled_normal_mode_and_wrong_actual_identity_refused_before_sdk_access(self):
        request = self.request()
        with self.assertRaises(ValueError):
            validate_request(request, enabled=False, workload=request["workload"],
                             client_id=request["client_id"])
        with self.assertRaises(ValueError):
            validate_request(request, enabled=True, workload="evidence-assessor",
                             client_id=request["client_id"])

    def test_probe_manifest_cannot_contain_credentials_urls_or_unbounded_timing(self):
        request = self.request()
        for change in ({"operator_key": "stolen"}, {"url": "https://other.example"},
                       {"deadline": time.time() + 901}, {"deadline": time.time() - 1},
                       {"mode": "arbitrary-python"}):
            with self.subTest(change=change):
                with self.assertRaises(ValueError):
                    validate_request(request | change, enabled=True, workload=request["workload"],
                                     client_id=request["client_id"])

    def test_fixed_purpose_request_binds_allocated_identity_and_deadline(self):
        request = self.request()
        self.assertEqual(validate_request(request, enabled=True, workload=request["workload"],
                                          client_id=request["client_id"]), request)
