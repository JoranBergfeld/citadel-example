import unittest

from citadel.acceptance.faults import OperationProbes
from citadel.operations.testing import MemoryLedger


class FaultTests(unittest.IsolatedAsyncioTestCase):
    async def test_committed_response_loss_reconciles_without_duplicate_product(self):
        probe = OperationProbes(MemoryLedger(), workload="candidate-planner",
                                enabled=True, run_id="loss1")
        result = await probe.committed_response_loss()
        self.assertEqual(result["state"], "succeeded")
        self.assertEqual(result["artifact_count"], 1)
        self.assertEqual(result["response"], "indeterminate")

    async def test_changed_input_and_incomplete_status_never_allow_replay_or_completed_product(self):
        probe = OperationProbes(MemoryLedger(), workload="candidate-planner",
                                enabled=True, run_id="status1")
        result = await probe.identity_and_incomplete_status()
        self.assertEqual(result["changed_input"], "conflict")
        self.assertEqual(result["states"], ["pending", "running", "indeterminate", "missing"])
        self.assertEqual(result["completed"], False)

    async def test_fault_facility_disabled_in_normal_mode(self):
        with self.assertRaises(ValueError):
            OperationProbes(MemoryLedger(), workload="candidate-planner",
                            enabled=False, run_id="disabled")
