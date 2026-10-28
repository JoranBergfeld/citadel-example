import unittest

import httpx

from agent_fixtures import Clock, PeerResponses, reference
from citadel.operations import OperationError
from citadel.operations.testing import MemoryLedger
from citadel.runtime.network import GatewayPeers
from citadel.runtime.state import read_scope
from citadel.runtime.tickets import TicketPool


class ExactFindingReadTests(unittest.IsolatedAsyncioTestCase):
    async def test_exact_finding_is_read_at_its_bound_version_with_funded_scope(self):
        fixture = PeerResponses(reference())
        requests = []

        async def response(request):
            requests.append(request)
            return httpx.Response(200, json=fixture.findings["finding1"])

        clock = Clock()
        ledger = MemoryLedger(clock=clock)
        pool = TicketPool(ledger.ticket_store, "planner/invoke/run1", 1, clock=clock)
        async with httpx.AsyncClient(transport=httpx.MockTransport(response)) as http:
            peers = GatewayPeers("candidate-planner", "https://gateway.test", "fixture-key",
                                 http_client=http, clock=clock)
            self.addAsyncCleanup(peers.close)
            with read_scope(pool, deadline=1900):
                result = await peers.finding(fixture.references[0], 1900, read_scope=fixture.scopes[0])
        self.assertEqual(result["airport_ident"], "EB01")
        self.assertEqual(requests[0].url.path, "/release-reviewer/findings/finding1/versions/1")
        self.assertEqual(requests[0].headers["x-citadel-read-pool"], "review1")
        self.assertEqual(len(ledger.ticket_store.markers), 1)

    async def test_changed_finding_is_denied_and_failed_read_does_not_restore_allowance(self):
        fixture = PeerResponses(reference())
        fixture.findings["finding1"]["caveats"] = []
        requests = []

        async def response(request):
            requests.append(request)
            return httpx.Response(200, json=fixture.findings["finding1"])

        clock = Clock()
        ledger = MemoryLedger(clock=clock)
        pool = TicketPool(ledger.ticket_store, "planner/invoke/run1", 1, clock=clock)
        async with httpx.AsyncClient(transport=httpx.MockTransport(response)) as http:
            peers = GatewayPeers("briefing-author", "https://gateway.test", "fixture-key",
                                 http_client=http, clock=clock)
            self.addAsyncCleanup(peers.close)
            with read_scope(pool, deadline=1900):
                with self.assertRaises(OperationError) as caught:
                    await peers.finding(fixture.references[0], 1900, read_scope=fixture.scopes[0])
                self.assertEqual(caught.exception.code, "conflict")
                with self.assertRaises(OperationError) as caught:
                    await peers.finding(fixture.references[0], 1900, read_scope=fixture.scopes[0])
                self.assertEqual(caught.exception.code, "exhausted")
        self.assertEqual(len(requests), 1)
