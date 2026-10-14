import asyncio
import json
import unittest
from contextlib import AsyncExitStack

import httpx
import httpx2
from agent_framework_a2a import A2AAgent

from citadel.evidence.manifests import sha256
from citadel.operations import Operations
from citadel.operations.limits import Accounting
from citadel.operations.testing import MemoryLedger
from citadel.runtime.agents import Runtime, agent_application
from citadel.runtime.model import GovernedModel
from citadel.runtime.network import GatewayPeers
from citadel.runtime.reference import reference_application
from test_reference import reference, trust
from test_workflow import FixtureGateway


class ReviewProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def test_review_rejects_exact_draft_that_does_not_match_rechecked_fixture(self):
        base = reference()
        overlay = base.with_overlay(base.fixture_manifests()["missing-width-replacement"])
        parent = Accounting(MemoryLedger(), workload="candidate-planner")
        root = await parent.start_run("run1")
        assessor_grant = await parent.delegate("run1", "assess1", "evidence-assessor",
            {"agents": 2, "models": 2, "tokens": 36000, "reads": 72})
        assessor = Accounting(MemoryLedger(), workload="evidence-assessor")
        await assessor.adopt(assessor_grant, authenticated_issuer="candidate-planner")
        grant = await assessor.delegate("assess1", "review1", "release-reviewer",
            {"agents": 1, "models": 1, "tokens": 18000, "reads": 32})
        drafts, findings = MemoryLedger(), MemoryLedger()
        writer = Operations(drafts, workload="evidence-assessor")
        draft = {"schema_version": 1, "artifact_id": "draft1", "version": 1,
                 "run_id": "run1", "operation_id": "draft-op", "airport_ident": "EB01",
                 **base.assess_airport("EB01"), "private_notes": "Never released"}
        await writer.accept("evidence-assessor", "submit-draft", "draft-op",
            {"draft": draft, "expected_version": 0}, run_id="run1", deadline=root["deadline"])
        owner = await writer.claim("evidence-assessor", "submit-draft", "draft-op", worker="worker")
        await writer.submit_draft(owner, draft, expected_version=0, reference=base)
        calls = []

        async def model_response(request):
            calls.append(request)
            return httpx2.Response(200, json={
                "id": "test", "object": "chat.completion", "created": 0, "model": "approved",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "Recheck differs."},
                             "finish_reason": "stop"}],
            })

        gateway = FixtureGateway()
        mcp = reference_application(overlay, trust("reference-data"))
        gateway.apps["reference-data"] = mcp
        async with AsyncExitStack() as stack:
            await stack.enter_async_context(mcp.app.router.lifespan_context(mcp.app))
            http = await stack.enter_async_context(httpx.AsyncClient(transport=gateway))
            model_http = await stack.enter_async_context(httpx2.AsyncClient(transport=httpx2.MockTransport(model_response)))
            model = GovernedModel("release-reviewer", "https://gateway.test", "release-reviewer",
                                  "approved", http_client=model_http)
            stack.push_async_callback(model.close)
            peers = GatewayPeers("release-reviewer", "https://gateway.test", "release-reviewer", http_client=http)
            stack.push_async_callback(peers.close)
            runtime = Runtime("release-reviewer", MemoryLedger(), model=model, peers=peers,
                              gateway_url="https://gateway.test", artifacts=findings, drafts=drafts)
            stack.push_async_callback(runtime.shutdown)
            gateway.apps["release-reviewer"] = agent_application(runtime, trust("release-reviewer"))
            client = await stack.enter_async_context(httpx.AsyncClient(transport=gateway,
                headers={"Ocp-Apim-Subscription-Key": "evidence-assessor"}))
            async with A2AAgent(agent_card=runtime.card, http_client=client) as agent:
                accepted = await agent.run(json.dumps({
                    "operation_id": "review1", "run_id": "run1", "grant": grant,
                    "fixture": "missing-width-replacement",
                    "draft": {"artifact_id": "draft1", "version": 1, "sha256": sha256(draft)},
                }), background=True)
                async with asyncio.timeout(2):
                    while True:
                        response = await client.get("https://gateway.test/release-reviewer/operations/review1")
                        if response.json()["state"] == "succeeded":
                            break
                        await asyncio.sleep(.01)
                self.assertEqual(response.json()["result"]["kind"], "rejected")
                result = await agent.poll_task(accepted.continuation_token)
                self.assertEqual(json.loads(result.text)["reason"], "draft_evidence_mismatch")
                self.assertEqual(len(calls), 1)
                self.assertNotIn("Never released", result.text)
                missing = await client.get(
                    f"https://gateway.test/release-reviewer/findings/{sha256({'draft_id': 'draft1'})}/versions/1",
                    headers={"Ocp-Apim-Subscription-Key": "briefing-author"})
                self.assertEqual(missing.status_code, 404)
