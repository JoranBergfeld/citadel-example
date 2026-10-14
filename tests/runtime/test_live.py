"""Operator-owned opt-in real APIM probes; never enabled by ordinary local tests."""

import asyncio
import json
import os
import time
import unittest
from uuid import uuid4

import httpx
from a2a.types import AgentCard
from agent_framework_a2a import A2AAgent
from google.protobuf.json_format import ParseDict

from citadel.evidence import CAVEATS


@unittest.skipUnless(os.environ.get("CITADEL_RUNTIME_LIVE") == "1",
                     "Real APIM/model/storage probe requires explicit operator opt-in")
class LiveRuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_gateway_workflow_accepts_then_returns_exact_caveated_brief(self):
        gateway = os.environ["CITADEL_LIVE_GATEWAY"].rstrip("/")
        headers = {"Ocp-Apim-Subscription-Key": os.environ["CITADEL_OPERATOR_KEY"]}
        async with httpx.AsyncClient(headers=headers, timeout=30, follow_redirects=False) as client:
            response = await client.get(gateway + "/candidate-planner/.well-known/agent-card.json")
            response.raise_for_status()
            card = ParseDict(response.json(), AgentCard())
            self.assertEqual(card.supported_interfaces[0].url, gateway + "/candidate-planner/a2a")
            run = uuid4().hex
            async with A2AAgent(agent_card=card, http_client=client) as agent:
                start = time.monotonic()
                result = await asyncio.wait_for(agent.run(json.dumps({
                    "operation_id": run, "run_id": run, "fixture": "base-source",
                }), background=True), 10)
                self.assertLess(time.monotonic() - start, 10)
                self.assertIsNotNone(result.continuation_token)
                async with asyncio.timeout(900 - (time.monotonic() - start)):
                    while True:
                        await asyncio.sleep(15)
                        response = await client.get(gateway + "/candidate-planner/operations/" + run)
                        response.raise_for_status()
                        status = response.json()
                        if status["state"] not in ("pending", "running"):
                            break
                self.assertEqual(status["state"], "succeeded")
                result = await agent.poll_task(result.continuation_token)
                self.assertIsNone(result.continuation_token)
                product = json.loads(result.text)
                self.assertEqual(product["status"], "complete")
                self.assertEqual(len(product["brief"]["citations"]), 3)
                self.assertTrue(set(CAVEATS).issubset(product["brief"]["caveats"]))
                self.assertEqual(product["provenance"]["source"]["kind"], "pinned-source")

    async def test_real_operator_allowed_discovery_does_not_grant_assessor_invocation(self):
        gateway = os.environ["CITADEL_LIVE_GATEWAY"].rstrip("/")
        async with httpx.AsyncClient(headers={
            "Ocp-Apim-Subscription-Key": os.environ["CITADEL_OPERATOR_KEY"]}, timeout=30) as client:
            allowed = await client.get(gateway + "/candidate-planner/.well-known/agent-card.json")
            self.assertEqual(allowed.status_code, 200)
            denied = await client.post(gateway + "/evidence-assessor/a2a",
                json={"jsonrpc": "2.0", "id": "denial", "method": "SendMessage", "params": {}})
            self.assertIn(denied.status_code, (401, 403))
