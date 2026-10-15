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
                       {"mode": "arbitrary-python"}, {"schema_version": True}):
            with self.subTest(change=change):
                with self.assertRaises(ValueError):
                    validate_request(request | change, enabled=True, workload=request["workload"],
                                     client_id=request["client_id"])

    def test_fixed_purpose_request_binds_allocated_identity_and_deadline(self):
        request = self.request()
        self.assertEqual(validate_request(request, enabled=True, workload=request["workload"],
                                          client_id=request["client_id"]), request)

    def test_storage_mode_accepts_only_fixed_disposable_target_bindings(self):
        from citadel.acceptance.coverage import CONTAINERS
        request = self.request() | {"mode": "storage-boundaries",
            "storage": {"suite_id": "suite1", "targets": {
                name: {"sha256": "a" * 64, "etag": '"known"'} for name in CONTAINERS}}}
        self.assertEqual(validate_request(request, enabled=True, workload=request["workload"],
                                          client_id=request["client_id"]), request)
        for bad in ({"suite_id": "../other", "targets": request["storage"]["targets"]},
                    {"suite_id": "suite1", "targets": {}},
                    request["storage"] | {"credential": "not-allowed"}):
            with self.assertRaises((ValueError, RuntimeError)):
                validate_request(request | {"storage": bad}, enabled=True,
                                 workload=request["workload"], client_id=request["client_id"])

    def test_direct_model_dispatch_requires_integrated_global_admission_not_an_asserted_control_id(self):
        request = self.request() | {"mode": "model-boundary", "control_id": "suite1",
                                   "model_origin": "https://allocated.openai.azure.com"}
        with self.assertRaises(ValueError):
            validate_request(request, enabled=True, workload=request["workload"], client_id=request["client_id"])
