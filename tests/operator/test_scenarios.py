import json
import time
import unittest

import httpx

from citadel.operator.scenarios import PlannerClient
from citadel.operator.state import Blocked


class ScenarioTests(unittest.IsolatedAsyncioTestCase):
    async def test_poll_refusal_precedes_dispatch_and_preserves_durable_read_accounting(self):
        calls, saves = [], []
        now = [1000.0]

        async def transport(request):
            calls.append(request)
            return httpx.Response(200, headers={"apim-request-id": f"actual-status-{len(calls)}"},
                json={"state": "running", "run_id": "run19", "operation_id": "run19",
                      "input_hash": "a" * 64, "result": None})

        state = {"reads": 0}
        async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as http:
            client = PlannerClient("https://gateway.test", "private-test-key", http=http, clock=lambda: now[0])
            result = await client.poll("run19", state, 1900, save=lambda: saves.append(state.copy()))
            self.assertEqual(result["state"], "running")
            self.assertEqual(state["reads"], 1)
            self.assertEqual(state["poll_receipts"][0]["request_id"], "actual-status-1")
            self.assertEqual(calls[0].headers["x-citadel-run-id"], "run19")
            with self.assertRaises(Blocked) as caught:
                await client.poll("run19", state, 1900, save=lambda: saves.append(state.copy()))
            self.assertEqual(caught.exception.code, "poll_interval_15_seconds_required")
            self.assertEqual(len(calls), 1)
            self.assertEqual(state["reads"], 1)
            now[0] += 15
            await client.poll("run19", state, 1900, save=lambda: saves.append(state.copy()))
            self.assertEqual(len(calls), 2)
            self.assertEqual(state["reads"], 2)
            self.assertNotIn("private-test-key", str(state))

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
