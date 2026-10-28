import asyncio
import unittest
import httpx2

from citadel.operations import OperationError, Operations
from citadel.operations.limits import Accounting
from citadel.operations.testing import MemoryLedger
from citadel.runtime.agents import Runtime
from citadel.runtime.model import GovernedModel


class RuntimeRecoveryTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.now = [1000.0]
        self.ledger = MemoryLedger(clock=lambda: self.now[0])

    async def crashed(self):
        payload = {"operation_id": "crashed", "run_id": "crashed", "fixture": "base-source"}
        await self.ledger.ticket_store.open_pool("operator/invoke/crashed", exclusive=True)
        accounting = Accounting(self.ledger, workload="candidate-planner", clock=lambda: self.now[0])
        budget = await accounting.start_run("crashed")
        ops = Operations(self.ledger, workload="candidate-planner", clock=lambda: self.now[0])
        await ops.accept("operator", "invoke", "crashed", payload, run_id="crashed", deadline=budget["deadline"])
        owner = await ops.claim("operator", "invoke", "crashed", worker="abandoned", lease_seconds=180)
        await accounting.start_agent("crashed", "crashed")
        self.now[0] += 181
        runtime = Runtime("candidate-planner", self.ledger, model=None, peers=None,
                          clock=lambda: self.now[0], gateway_url="https://gateway.test")
        return runtime, payload, accounting, ops, owner

    async def test_definite_fenced_recovery_releases_global_exclusion_without_refunding_old_budget(self):
        runtime, payload, accounting, ops, owner = await self.crashed()
        before = await accounting.status("crashed")
        recovered = await runtime.accept("operator", payload, recover=True)
        self.assertEqual(recovered["state"], "failed_no_commit")
        self.assertEqual(await accounting.status("crashed"), before)
        with self.assertRaises(OperationError):
            await ops.complete(owner, product={"late": True})
        try:
            accepted = await runtime.accept("operator", {
                "operation_id": "fresh", "run_id": "fresh", "fixture": "base-source"})
            self.assertEqual(accepted["state"], "pending")
            self.assertEqual(await accounting.status("crashed"), before)
        finally:
            await runtime.shutdown()

    async def test_explicit_retry_reuses_fenced_identity_and_budget_but_reacquires_generation_owned_exclusion(self):
        previous, payload, accounting, ops, owner = await self.crashed()
        recovered = await previous.accept("operator", payload, recover=True)
        self.assertEqual(recovered["state"], "failed_no_commit")
        before = await accounting.status("crashed")
        markers = set(self.ledger.ticket_store.markers)
        entered, hold, calls = asyncio.Event(), asyncio.Event(), []

        async def response(request):
            calls.append(request)
            entered.set()
            await hold.wait()

        async with httpx2.AsyncClient(transport=httpx2.MockTransport(response)) as http:
            model = GovernedModel("candidate-planner", "https://gateway.test", "owned", "approved",
                                  http_client=http, clock=lambda: self.now[0])
            runtime = Runtime("candidate-planner", self.ledger, model=model, peers=None,
                              clock=lambda: self.now[0], gateway_url="https://gateway.test")
            try:
                accepted = await runtime.accept("operator", payload, retry=True)
                self.assertEqual(accepted["operation_id"], "crashed")
                self.assertEqual(accepted["deadline"], before["deadline"])
                await asyncio.wait_for(entered.wait(), 2)
                budget = await accounting.status("crashed")
                self.assertEqual(budget["deadline"], 1900)
                self.assertEqual(budget["remaining"]["agents"], 40)
                self.assertLess(budget["remaining"]["models"], before["remaining"]["models"])
                self.assertTrue(markers <= self.ledger.ticket_store.markers)
                await self.ledger.ticket_store.release_run("operator/invoke/crashed", generation=0)
                for arguments in ((payload, {"retry": True}), (
                        {"operation_id": "other", "run_id": "other", "fixture": "base-source"}, {})):
                    with self.assertRaises(OperationError):
                        await runtime.accept("operator", arguments[0], **arguments[1])
                self.assertEqual(len(calls), 1, "Duplicate retry must not dispatch a second execution")
                self.assertEqual((await runtime.accept("operator", payload))["state"], "running")
                with self.assertRaises(OperationError):
                    await ops.complete(owner, product={"late": True})
            finally:
                await runtime.shutdown()
                await model.close()

    async def test_ambiguous_model_admission_retains_exclusion_and_cannot_authorize_retry(self):
        runtime, payload, accounting, ops, owner = await self.crashed()
        await accounting.model("crashed", "crashed", input_tokens=100, output_tokens=100)
        before = await accounting.status("crashed")
        recovered = await runtime.accept("operator", payload, recover=True)
        self.assertEqual(recovered["state"], "indeterminate")
        for candidate, options in (
            (payload, {"retry": True}),
            ({"operation_id": "other", "run_id": "other", "fixture": "base-source"}, {}),
        ):
            with self.assertRaises(OperationError):
                await runtime.accept("operator", candidate, **options)
        self.assertEqual(await accounting.status("crashed"), before)

    async def test_retry_cannot_change_owner_inputs_or_original_deadline(self):
        runtime, payload, accounting, ops, owner = await self.crashed()
        await runtime.accept("operator", payload, recover=True)
        for caller, candidate in (("briefing-author", payload),
                                  ("operator", payload | {"fixture": "no-alternative"})):
            with self.assertRaises(OperationError):
                await runtime.accept(caller, candidate, retry=True)
        self.now[0] = 1901
        with self.assertRaises(OperationError) as caught:
            await runtime.accept("operator", payload, retry=True)
        self.assertEqual(caught.exception.code, "deadline")
        self.assertEqual((await accounting.status("crashed"))["remaining"]["agents"], 41)
        self.assertEqual(runtime.tasks, set())

    async def test_owner_recovery_reconciles_definite_no_effect_without_accepting_claimed_service_status(self):
        runtime, payload, accounting, ops, owner = await self.crashed()
        self.now[0] = 1100
        await ops.mark_incomplete(owner, "cancelled")
        self.now[0] = 1181
        before = await accounting.status("crashed")
        recovered = await runtime.accept("operator", payload, recover=True)
        self.assertEqual(recovered["state"], "failed_no_commit")
        self.assertEqual(await accounting.status("crashed"), before)
        with self.assertRaises(OperationError):
            await ops.complete(owner, product={"late": True})
