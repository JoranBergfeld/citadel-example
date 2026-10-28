import asyncio
import json
import unittest

import httpx
import httpx2
from agent_framework_a2a import A2AAgent

from citadel.operations.testing import MemoryLedger
from citadel.operations import OperationError
from citadel.runtime.agents import Runtime, agent_application
from citadel.runtime.model import GovernedModel
from citadel.runtime.state import ScopedLedger, read_scope
from citadel.runtime.tickets import TicketPool
from tests.unit.gateway_fixtures import signed, trust


class CountingLedger(MemoryLedger):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.read_attempts = 0

    async def read(self):
        self.read_attempts += 1
        return await super().read()


class SharedReadTicketTests(unittest.IsolatedAsyncioTestCase):
    async def test_reconstructed_concurrent_pools_cannot_spend_conditional_markers_twice(self):
        ledger = CountingLedger(clock=lambda: 1000)
        store = ledger.ticket_store
        await store.open_pool("operator/invoke/run1")

        async def spend():
            store.cursors.clear()
            pool = TicketPool(store, "operator/invoke/run1", 8, clock=lambda: 1000)
            with read_scope(pool, deadline=1900):
                try:
                    await ScopedLedger(ledger).read()
                    return True
                except OperationError as exc:
                    self.assertEqual(exc.code, "exhausted")
                    return False

        results = await asyncio.gather(*(spend() for _ in range(16)))
        self.assertEqual(sum(results), 8)
        self.assertEqual(ledger.read_attempts, 8)

    async def test_lost_marker_response_never_dispatches_a_read_or_refunds_its_slot(self):
        ledger = CountingLedger(clock=lambda: 1000)
        store = ledger.ticket_store
        await store.open_pool("operator/invoke/run1")
        create = store.create_marker

        async def lost_marker(*args):
            await create(*args)
            raise OperationError("indeterminate", "Unit-fixture committed response loss")

        store.create_marker = lost_marker
        pool = TicketPool(store, "operator/invoke/run1", 1, clock=lambda: 1000)
        with read_scope(pool, deadline=1900):
            with self.assertRaises(OperationError) as caught:
                await ScopedLedger(ledger).read()
        self.assertEqual(caught.exception.code, "indeterminate")
        store.create_marker = create
        store.cursors.clear()
        restarted = TicketPool(store, "operator/invoke/run1", 1, clock=lambda: 1000)
        with read_scope(restarted, deadline=1900):
            with self.assertRaises(OperationError) as caught:
                await ScopedLedger(ledger).read()
        self.assertEqual(caught.exception.code, "exhausted")
        self.assertEqual(ledger.read_attempts, 0)


class ExternalReadBudgetTests(unittest.IsolatedAsyncioTestCase):
    def make_ledger(self):
        return CountingLedger()

    async def test_owner_status_admission_and_recovery_share_finite_durable_tickets_after_restart(self):
        entered = asyncio.Event()
        never = asyncio.Event()

        async def model_response(request):
            entered.set()
            await never.wait()

        ledger = self.make_ledger()
        async with httpx2.AsyncClient(transport=httpx2.MockTransport(model_response)) as model_http:
            model = GovernedModel("candidate-planner", "https://gateway.test", "test",
                                  "approved", http_client=model_http)
            first = Runtime("candidate-planner", ledger, model=model, peers=None,
                            gateway_url="https://gateway.test")

            async def sign(request):
                request.url = request.url.copy_with(path=request.url.path.removeprefix("/candidate-planner"))
                request.headers.update(signed(request.content, "candidate-planner",
                                               request.url.path, "operator", request.method))

            payload = {"operation_id": "run1", "run_id": "run1", "fixture": "base-source"}
            async with httpx.AsyncClient(transport=httpx.ASGITransport(
                    app=agent_application(first, trust("candidate-planner"))),
                    event_hooks={"request": [sign]}) as client:
                async with A2AAgent(agent_card=first.card, http_client=client) as agent:
                    await agent.run(json.dumps(payload), background=True)
                    await asyncio.wait_for(entered.wait(), 2)
            await first.shutdown()
            ledger.ticket_store.cursors.clear()

            # Separate processes/revisions must share only durable storage, not a
            # live Runtime, in-memory ticket counter, HTTP session, or task cache.
            resumed = [Runtime("candidate-planner", ledger, model=model, peers=None,
                              gateway_url="https://gateway.test") for _ in range(2)]
            clients = [httpx.AsyncClient(transport=httpx.ASGITransport(
                app=agent_application(runtime, trust("candidate-planner"))),
                event_hooks={"request": [sign]}) for runtime in resumed]
            reads_served = 0
            try:
                for _ in range(140):
                    responses = await asyncio.gather(*[
                        client.get("https://gateway.test/candidate-planner/operations/run1")
                        for client in clients
                    ])
                    reads_served += sum(response.status_code == 200 for response in responses)
                    if all(response.status_code == 429 for response in responses):
                        break
                self.assertLess(reads_served, 256, "Owner polling escaped the run's 512-read total")
                before = ledger.read_attempts
                body = json.dumps({"jsonrpc": "2.0", "id": "retry", "method": "SendMessage", "params": {
                    "message": {"messageId": "retry", "role": "ROLE_USER",
                                "parts": [{"text": json.dumps(payload)}]},
                    "configuration": {"returnImmediately": True},
                    "metadata": {"citadel_recovery": True},
                }})
                for client in clients:
                    for recovery in (True, False):
                        retry = json.loads(body)
                        retry["params"]["metadata"]["citadel_recovery"] = recovery
                        response = await client.post("https://gateway.test/candidate-planner/a2a",
                            json=retry, headers={"a2a-version": "1.0"})
                        self.assertIn("exhausted", response.text)
                self.assertEqual(ledger.read_attempts, before,
                                 "Exhausted admission/recovery must not perform uncharged storage reads")
                self.assertLessEqual(ledger.read_attempts + reads_served, 512)
            finally:
                for client in clients:
                    await client.aclose()
                for runtime in resumed:
                    await runtime.shutdown()
                await model.close()
