import asyncio
import json
import time
import unittest

import httpx
import httpx2
from agent_framework_a2a import A2AAgent

from citadel.operations.testing import MemoryLedger
from citadel.runtime.agents import Runtime, agent_application
from citadel.runtime.model import GovernedModel
from test_reference import signed, trust


class LifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_late_model_response_does_not_release_admission_or_complete_work(self):
        entered, release = asyncio.Event(), asyncio.Event()
        now = [time.time()]

        async def response(request):
            entered.set()
            await release.wait()
            return httpx2.Response(200, json={
                "id": "late-test", "object": "chat.completion", "created": 0, "model": "approved",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "Late fixture"},
                             "finish_reason": "stop"}],
            })

        async with httpx2.AsyncClient(transport=httpx2.MockTransport(response)) as model_http:
            model = GovernedModel("candidate-planner", "https://gateway.test", "test-key",
                                  "approved", http_client=model_http, clock=lambda: now[0])
            runtime = Runtime("candidate-planner", MemoryLedger(clock=lambda: now[0]),
                model=model, peers=None, gateway_url="https://gateway.test", clock=lambda: now[0])
            app = agent_application(runtime, trust("candidate-planner"))

            async def gateway(request):
                request.url = request.url.copy_with(path=request.url.path.removeprefix("/candidate-planner"))
                request.headers.update(signed(request.content, "candidate-planner",
                                               request.url.path, "operator", request.method))

            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                        event_hooks={"request": [gateway]}) as client:
                async with A2AAgent(agent_card=runtime.card, http_client=client) as agent:
                    await agent.run(json.dumps({"operation_id": "run1", "run_id": "run1",
                                                "fixture": "base-source"}), background=True)
                    await asyncio.wait_for(entered.wait(), 2)
                    now[0] += 61
                    release.set()
                    async with asyncio.timeout(2):
                        while True:
                            status = await client.get("https://gateway.test/candidate-planner/operations/run1")
                            if status.json()["state"] == "indeterminate":
                                break
                            await asyncio.sleep(.01)
                    self.assertEqual(status.json()["result"]["code"], "deadline")
                    self.assertNotIn("brief", status.text)
            await runtime.shutdown()
            await model.close()

    async def test_actual_model_failure_is_not_retried_or_relabelled_as_missing_evidence(self):
        attempts = []

        async def response(request):
            attempts.append(json.loads(request.content))
            return httpx2.Response(503, json={"error": {"message": "test-only model failure"}})

        async with httpx2.AsyncClient(transport=httpx2.MockTransport(response)) as model_http:
            model = GovernedModel("candidate-planner", "https://gateway.test", "test-key",
                                  "approved-deployment", http_client=model_http)
            runtime = Runtime("candidate-planner", MemoryLedger(), model=model, peers=None,
                              gateway_url="https://gateway.test")
            app = agent_application(runtime, trust("candidate-planner"))
            body = json.dumps({"jsonrpc": "2.0", "id": "one", "method": "SendMessage", "params": {
                "message": {"messageId": "message1", "role": "ROLE_USER", "parts": [{"text": json.dumps({
                    "operation_id": "run1", "run_id": "run1", "fixture": "base-source"})}]},
                "configuration": {"returnImmediately": True},
            }}).encode()
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                        base_url="https://backend.test") as client:
                headers = signed(body, "candidate-planner", "/a2a", "operator") | {"a2a-version": "1.0"}
                accepted = await client.post("/a2a", content=body, headers=headers)
                self.assertIn("task", accepted.json()["result"])
                async with asyncio.timeout(2):
                    while True:
                        status = await client.get("/operations/run1", headers=signed(
                            b"", "candidate-planner", "/operations/run1", "operator", "GET"))
                        if status.json()["state"] == "indeterminate":
                            break
                        await asyncio.sleep(.01)
                self.assertEqual(len(attempts), 1)
                self.assertEqual(attempts[0]["max_completion_tokens"], 2000)
                self.assertNotIn("tools", attempts[0])
                self.assertEqual(status.json()["result"]["kind"], "incomplete")
                self.assertNotIn("brief", status.text)
                replay = await client.post("/a2a", content=body, headers=headers)
                self.assertIn("task", replay.json()["result"])
                self.assertEqual(len(attempts), 1)
            await runtime.shutdown()
            await model.close()

    async def test_acceptance_is_durable_owner_bound_and_restart_does_not_replay(self):
        held = asyncio.Event()
        attempts = []

        async def model_response(request):
            attempts.append(request)
            await held.wait()
            return httpx2.Response(503, json={"error": {"message": "test unavailable"}})

        async with httpx2.AsyncClient(transport=httpx2.MockTransport(model_response)) as model_http:
            model = GovernedModel("candidate-planner", "https://gateway.test", "test-key",
                                  "approved-deployment", http_client=model_http)
            ledger = MemoryLedger()
            runtime = Runtime("candidate-planner", ledger, model=model, peers=None,
                              gateway_url="https://gateway.test")
            app = agent_application(runtime, trust("candidate-planner"))

            async def gateway(request):
                if request.url.path.startswith("/candidate-planner/"):
                    request.url = request.url.copy_with(path=request.url.path.removeprefix("/candidate-planner"))
                request.headers.update(signed(request.content, "candidate-planner",
                                              request.url.path, "operator", request.method))

            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                        event_hooks={"request": [gateway]},
                                        base_url="https://gateway.test") as client:
                async with A2AAgent(agent_card=runtime.card, http_client=client) as agent:
                    payload = {"operation_id": "run1", "run_id": "run1", "fixture": "base-source"}
                    accepted = await asyncio.wait_for(agent.run(json.dumps(payload), background=True), 2)
                    self.assertIsNotNone(accepted.continuation_token)
                    status = await client.get("/operations/run1")
                    self.assertIn(status.json()["state"], {"pending", "running"})
                    self.assertNotIn("product", status.json())
                    self.assertFalse(held.is_set())
                    again = await agent.run(json.dumps(payload), background=True)
                    self.assertIsNotNone(again.continuation_token)
                    for _ in range(30):
                        if attempts:
                            break
                        await asyncio.sleep(.01)
                    self.assertEqual(len(attempts), 1)
                    concurrent = await agent.run(json.dumps(payload | {
                        "operation_id": "run2", "run_id": "run2"}), background=True)
                    self.assertIn("conflict", concurrent.text)
                    changed = await agent.run(json.dumps(payload | {"fixture": "no-alternative"}),
                                              background=True)
                    self.assertIn("conflict", changed.text)
                    await runtime.shutdown()
                    restarted = Runtime("candidate-planner", ledger, model=model, peers=None,
                                        gateway_url="https://gateway.test")
                    restarted_app = agent_application(restarted, trust("candidate-planner"))
                    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=restarted_app),
                                                event_hooks={"request": [gateway]},
                                                base_url="https://gateway.test") as other:
                        current = await other.get("/operations/run1")
                        self.assertEqual(current.json()["state"], "running")
                        self.assertEqual(len(attempts), 1)
                    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=restarted_app),
                                                base_url="https://gateway.test") as other:
                        denied = await other.get("/operations/run1", headers=signed(
                            b"", "candidate-planner", "/operations/run1", "briefing-author", "GET"))
                        self.assertEqual(denied.status_code, 403)
                    await restarted.shutdown()
            await model.close()
