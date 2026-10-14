import json
import time
import unittest

import httpx

from citadel.operator.scenarios import PlannerClient
from citadel.operator.state import Blocked


class ScenarioTests(unittest.IsolatedAsyncioTestCase):
    async def test_official_nonblocking_send_has_no_discovery_or_hidden_retry(self):
        calls = []

        async def transport(request):
            calls.append(request)
            raise httpx.ReadTimeout("credential-material-must-not-escape", request=request)

        async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as http:
            client = PlannerClient("https://gateway.test", "private-test-key", http=http)
            with self.assertRaises(Blocked) as caught:
                await client.invoke("run19", "base-source", time.time() + 900)
            self.assertEqual(caught.exception.code, "invocation_ambiguous_reconcile_only")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].url.path, "/candidate-planner/a2a")
        body = json.loads(calls[0].content)
        self.assertEqual(body["method"], "SendMessage")
        self.assertTrue(body["params"]["configuration"]["returnImmediately"])

    async def test_authorized_status_exhaustion_is_not_missing_state_or_success(self):
        calls = []

        async def transport(request):
            calls.append(request)
            return httpx.Response(429, json={"error": "exhausted"})

        async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as http:
            client = PlannerClient("https://gateway.test", "private-test-key", http=http)
            with self.assertRaises(Blocked) as caught:
                await client.status("run19", time.time() + 900)
            self.assertEqual(caught.exception.code, "run_read_tickets_exhausted")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].headers["Ocp-Apim-Subscription-Key"], "private-test-key")
        self.assertEqual(calls[0].url.path, "/candidate-planner/operations/run19")
