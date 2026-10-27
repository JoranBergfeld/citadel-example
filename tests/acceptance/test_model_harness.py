import unittest
from tests.acceptance.storage_fixture import storage_inventory
from types import SimpleNamespace

from citadel.acceptance.model_harness import ModelAcceptance, bind_model_result
from citadel.operator.state import Blocked


class ModelHarnessTests(unittest.TestCase):
    def test_ambiguous_controller_read_retains_real_global_slot_and_cannot_start_a_second_phase(self):
        import time
        from unittest.mock import patch
        from citadel.acceptance.coverage import STORAGE
        now, calls = [time.time()], []
        model = "/subscriptions/s/resourceGroups/g/providers/Microsoft.CognitiveServices/accounts/model"

        class Blob:
            url = "https://allocated.blob.core.windows.net/planner-operations/active-run-slot.json"

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def acquire_lease(self, **options):
                calls.append(("acquire", options["lease_duration"]))
                options["raw_request_hook"](SimpleNamespace(http_request=SimpleNamespace(headers={})))
                options["raw_response_hook"](SimpleNamespace(http_response=SimpleNamespace(
                    status_code=201, headers={"x-ms-request-id": "actual-slot-receipt"})))
                return self

            def release(self, **options):
                calls.append(("release", None))

            def download_blob(self, **options):
                calls.append(("read", None))
                raise Blocked("ambiguous_external_storage_response")

        def rest(method, resource, version):
            if resource == model:
                return {"properties": {"endpoint": "https://allocated.openai.azure.com"}}
            return {"sku": {"name": "Standard", "capacity": 6}, "properties": {
                "model": {"name": "gpt-4.1-mini", "version": "2025-04-14"},
                "versionUpgradeOption": "NoAutoUpgrade"}}

        lifecycle = SimpleNamespace(id="d", config={"modelTokensPerMinute": 6000, "modelCapacity": 6},
            value={"runs": {}, "preflight": {"verifiedTokensPerMinute": 6000},
                "inventory": [model, model + "/deployments/citadel-gpt-41-mini", *storage_inventory()],
                "outputs": {"appInventory": [{"app": "/d-" + actor} for actor in STORAGE]}},
            native=SimpleNamespace(rest=rest, blob=lambda *args: Blob()),
            state=SimpleNamespace(save=lambda: None))
        report = {"run_id": "suite1", "operation_ids": []}
        with patch("time.time", lambda: now[0]):
            for _ in range(2):
                with self.assertRaises(Blocked):
                    ModelAcceptance(lifecycle, sleep=lambda seconds: now.__setitem__(0, now[0] + seconds)).execute(report)
        self.assertEqual(calls, [("acquire", -1), ("read", None)])
        self.assertEqual(report["model_phase"]["state"], "blocked")
        self.assertEqual(report["model_phase"]["observations"], [])
        self.assertEqual(len(report["model_phase"]["slot"]), 1)

    def test_interrupted_model_phase_is_never_automatically_dispatched_again(self):
        calls, saves = [], []
        account = "/subscriptions/s/resourceGroups/g/providers/Microsoft.CognitiveServices/accounts/model"

        def rest(*args):
            calls.append(args)
            raise Blocked("provider_unavailable")

        lifecycle = SimpleNamespace(id="d", config={"modelTokensPerMinute": 6000, "modelCapacity": 6},
            value={"runs": {}, "preflight": {"verifiedTokensPerMinute": 6000}, "inventory": [
                account, account + "/deployments/citadel-gpt-41-mini",
                *storage_inventory()],
                "outputs": {"appInventory": [{"app": "/d-" + actor} for actor in (
                    "candidate-planner", "evidence-assessor", "release-reviewer",
                    "briefing-author", "reference-data")]}},
            state=SimpleNamespace(save=lambda: saves.append(True)),
            native=SimpleNamespace(rest=rest))
        report = {"run_id": "suite1", "operation_ids": []}
        for _ in range(2):
            with self.assertRaises(Blocked):
                ModelAcceptance(lifecycle).execute(report)
        self.assertEqual(len(calls), 1)
        self.assertTrue(saves)
        self.assertEqual(report["model_phase"]["state"], "blocked")

    def test_worker_result_requires_exact_prepaid_actor_operation_and_inventoried_target(self):
        import hashlib
        observation = {"check_id": "model.reference-data.direct-denied",
            "caller": "reference-data", "run_id": "phase1", "operation_id": "worker1",
            "runtime_identity": "a" * 64,
            "target": hashlib.sha256(
                b"https://allocated.openai.azure.com/openai/v1/chat/completions").hexdigest(),
            "model_attempts": 1, "input_tokens": 1081, "output_tokens": 2000}
        from citadel.acceptance.model_probes import INPUT_BOUND
        observation["input_tokens"] = INPUT_BOUND
        result = {"schema_version": 1, "run_id": "worker1", "state": "complete",
                  "observations": [observation]}
        options = dict(workload="reference-data", worker_id="worker1", run_id="phase1",
                       principal="a" * 64, origin="https://allocated.openai.azure.com")
        self.assertEqual(bind_model_result(result, **options), observation)
        for key, value in (("caller", "operator"), ("operation_id", "other"),
                           ("target", "b" * 64), ("runtime_identity", "b" * 64),
                           ("model_attempts", 2)):
            with self.subTest(key=key), self.assertRaises(Blocked):
                bind_model_result(result | {"observations": [observation | {key: value}]}, **options)
