import unittest

from citadel.operations import OperationError, Operations
from citadel.operations.limits import Accounting
from citadel.operations.testing import MemoryLedger


class CollaborationCompletionTests(unittest.IsolatedAsyncioTestCase):
    async def test_closed_budget_and_public_finding_commit_atomically_without_artifact_authority(self):
        ledger = MemoryLedger()
        ops = Operations(ledger, workload="evidence-assessor")
        parent = Accounting(MemoryLedger(), workload="candidate-planner")
        await parent.start_run("run1")
        grant = await parent.delegate("run1", "child1", "evidence-assessor",
                                      {"agents": 2, "models": 2, "tokens": 36000, "reads": 64})
        accounting = Accounting(ledger, workload="evidence-assessor")
        await accounting.adopt(grant, authenticated_issuer="candidate-planner")
        await ops.accept("candidate-planner", "invoke", "child1", {"grant": grant},
                         run_id="run1", deadline=grant["deadline"])
        owner = await ops.claim("candidate-planner", "invoke", "child1", worker="worker")
        finding = {"artifact_id": "finding1", "version": 1, "sha256": "a" * 64}
        with self.assertRaises(OperationError):
            await ops.complete(owner, finding=finding, receipt={"closed": True})
        receipt = await accounting.close("child1")
        with self.assertRaises(OperationError):
            await ops.complete(owner, finding=finding | {"private_notes": "secret"}, receipt=receipt)
        ledger.lose_response = True
        with self.assertRaises(OperationError):
            await ops.complete(owner, finding=finding, receipt=receipt)
        status = await ops.status("candidate-planner", "invoke", "child1")
        self.assertEqual(status["state"], "succeeded")
        self.assertEqual(status["result"]["finding"], finding)
        self.assertEqual(status["result"]["receipt"], receipt)
        self.assertEqual((await ops.status("operator", "invoke", "child1"))["state"], "missing")
        with self.assertRaises(OperationError):
            await ops.get_finding("finding1", 1)
