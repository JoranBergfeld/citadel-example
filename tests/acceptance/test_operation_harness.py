import hashlib
import unittest
from types import SimpleNamespace

from citadel.acceptance.operation_harness import FaultAcceptance, bind_operation_result
from citadel.operator.state import Blocked
from tests.acceptance.storage_fixture import storage_inventory


class OperationHarnessTests(unittest.TestCase):
    def test_each_fixed_mode_reads_its_own_phase_and_keeps_missing_independent_proof_blocked(self):
        for mode, phase, probe in (
            ("operation-faults", "operation_phase", "fault.dropped-committed-write"),
            ("process-restart", "restart_phase", "fault.restart-no-replay"),
            ("admission-limits", "admission_phase", "limit.agent_executions"),
            ("read-limit", "read_phase", "limit.read_attempts_run"),
            ("model-limits", "model_boundary_phase", "limit.input_tokens_attempt"),
            ("model-timeout", "model_timeout_phase", "limit.model_timeout_seconds"),
            ("model-execution-limit", "model_counter_execution_phase", "limit.model_attempts_execution"),
            ("model-run-limit", "model_counter_run_phase", "limit.model_attempts_run"),
            ("model-token-limit", "model_counter_tokens_phase", "limit.tokens_run"),
        ):
            with self.subTest(mode=mode):
                report = {phase: {"observations": [{"probe_id": probe, "check_id": probe, "actual": {}}]}}
                result = FaultAcceptance.evaluate(report, [], mode=mode)
                self.assertIn(probe, {row["check_id"] for row in result})
                self.assertTrue(all(row["status"] == "blocked" for row in result))
        with self.assertRaises(ValueError):
            FaultAcceptance.evaluate({}, [], mode="arbitrary")

    def result(self):
        return {"schema_version": 1, "run_id": "worker1", "state": "complete", "observations": [
            {"check_id": check, "probe_id": check, "run_id": "worker1", "operation_id": "op" + str(index),
             "caller": "candidate-planner", "runtime_identity": "a" * 64,
             "target": hashlib.sha256(("https://allocated.blob.core.windows.net/planner-operations/"
                 f"acceptance/worker1/observations/op{index}.json").encode()).hexdigest(),
             "actual": {"operation_id": "op" + str(index), **(
                 {"steps": [{"operation_id": f"op{index}-read{retry}"} for retry in range(3)]}
                 if check == "limit.safe_read_timeout_seconds" else {})}}
            for index, check in enumerate(("fault.dropped-committed-write", "fault.pending-incomplete",
                "fault.fenced-explicit-retry", "fault.deadline-no-late-effect",
                "fault.safe-read-recovery", "fault.safe-read-exhaustion", "limit.safe_read_timeout_seconds"))]}

    def bind(self, result):
        return bind_operation_result(result, run_id="worker1", principal="a" * 64,
                                     account="https://allocated.blob.core.windows.net")

    def test_worker_fault_results_bind_all_fixed_drivers_and_actual_identity_targets(self):
        self.assertEqual(len(self.bind(self.result())), 10)
        for change in ({"caller": "operator"}, {"runtime_identity": "b" * 64},
                       {"run_id": "other"}, {"target": "b" * 64}, {"actual": {"operation_id": "other"}}):
            result = self.result()
            result["observations"][0].update(change)
            with self.subTest(change=change), self.assertRaises(Blocked):
                self.bind(result)
        result = self.result()
        result["observations"].pop()
        with self.assertRaises(Blocked):
            self.bind(result)

    def test_provider_failure_is_recorded_before_dispatch_and_never_automatically_replayed(self):
        calls = []

        def rest(*args):
            calls.append(args)
            raise Blocked("external_provider_unavailable")

        lifecycle = SimpleNamespace(id="d", value={"inventory": storage_inventory(),
            "outputs": {"appInventory": [{"app": "/d-candidate-planner",
                "identityPrincipalId": "11111111-1111-1111-1111-111111111111"}]}},
            state=SimpleNamespace(save=lambda: None), native=SimpleNamespace(rest=rest))
        report = {"run_id": "suite1", "operation_ids": []}
        for _ in range(2):
            with self.assertRaises(Blocked):
                FaultAcceptance(lifecycle).execute(report)
        self.assertEqual(len(calls), 1)
        self.assertEqual(report["operation_phase"]["state"], "blocked")
