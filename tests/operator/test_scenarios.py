import json
import time
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import httpx

from citadel.operator.scenarios import PlannerClient, scenario_command
from citadel.operator.state import Blocked


class ScenarioCommandTests(unittest.TestCase):
    def test_exhaustion_demo_waits_without_dispatching_after_original_deadline(self):
        now, sleeps = [0], []
        run = {"fixture": "no-alternative", "scenario": "exhaustion",
               "deadline": 900, "state": "accepted", "reads": 0}
        lifecycle = SimpleNamespace(
            value={"phase": "deployed_unverified", "runs": {"run19": run},
                   "outputs": {"gatewayUrl": "https://gateway.test"}},
            state=SimpleNamespace(save=Mock()),
            credentials=lambda: {"callerStates": {"operator": "active"},
                                 "callerKeys": {"operator": {"primary": "private-test-key"}}})

        async def advance(delay):
            sleeps.append(delay)
            now[0] += delay

        with patch("citadel.operator.scenarios.time.time", side_effect=lambda: now[0]), \
                patch("citadel.operator.scenarios.asyncio.sleep", side_effect=advance), \
                patch.object(PlannerClient, "poll", new_callable=AsyncMock,
                             return_value={"state": "running"}) as poll:
            with self.assertRaises(Blocked) as caught:
                scenario_command(lifecycle, SimpleNamespace(command="demo", scenario="exhaustion", run_id="run19"))
        self.assertEqual(caught.exception.code, "run_absolute_deadline_expired")
        self.assertEqual(poll.await_count, 4)
        self.assertEqual(sleeps, [240, 240, 240, 165, 15])
        self.assertEqual(now[0], run["deadline"])


class ScenarioTests(unittest.IsolatedAsyncioTestCase):
    async def test_exhaustion_polling_observes_four_times_within_original_deadline(self):
        from citadel.operator.scenarios import demo_poll_delay
        elapsed, polls = 0, []
        while elapsed < 900:
            delay = demo_poll_delay("exhaustion", 900 - elapsed)
            self.assertGreaterEqual(delay, 15)
            elapsed += delay
            if elapsed < 900:
                polls.append(elapsed)
        self.assertEqual(polls, [240, 480, 720, 885])
        for scenario in ("comparison", "replacement", "denied-bypass"):
            self.assertEqual(demo_poll_delay(scenario, 900), 15)

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
