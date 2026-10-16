import asyncio
import json
import os
import time
import unittest
from contextlib import AsyncExitStack

import httpx
import httpx2
from agent_framework_a2a import A2AAgent

from citadel.evidence import CAVEATS, ReferenceData
from citadel.operations.testing import MemoryLedger
from citadel.runtime.agents import Runtime, agent_application
from citadel.runtime.model import GovernedModel
from citadel.runtime.network import GatewayPeers
from citadel.runtime.reference import reference_application
from test_reference import reference, signed, trust
from test_read_tickets import CountingLedger


class FixtureGateway(httpx.AsyncBaseTransport):
    """Test-only APIM transport; real GatewayTrust remains outside every backend."""
    def __init__(self):
        self.apps, self.exchanges = {}, []
        self.corrupt_brief = False
        self.read_attempts = 0

    async def handle_async_request(self, request):
        target, path = request.url.path.lstrip("/").split("/", 1)
        caller = request.headers.get("Ocp-Apim-Subscription-Key", "")
        self.exchanges.append((caller, target, "/" + path, request.content))
        if not (path == "a2a" and json.loads(request.content).get("method") == "SendMessage"):
            self.read_attempts += 1
        request.url = request.url.copy_with(path="/" + path)
        request.headers.update(signed(request.content, target, "/" + path, caller, request.method))
        response = await httpx.ASGITransport(app=self.apps[target]).handle_async_request(request)
        if (self.corrupt_brief and target == "briefing-author" and path == "a2a"
                and json.loads(request.content).get("method") == "GetTask"):
            await response.aread()
            body = response.json()
            part = body["result"]["artifacts"][0]["parts"][0]
            product = json.loads(part["text"])
            product["narrative"] = "Corrupted test-only response"
            part["text"] = json.dumps(product)
            return httpx.Response(200, json=body)
        return response


class WorkflowTests(unittest.IsolatedAsyncioTestCase):
    async def run_case(self, fixture, *, count=4, expected_state="succeeded", data_source=None,
                       corrupt_brief=False, persisted=None, run_id="run1"):
        gateway = FixtureGateway()
        gateway.corrupt_brief = corrupt_brief
        base = data_source or reference(count)
        data = base if fixture == "base-source" else base.with_overlay(base.fixture_manifests()[fixture])
        mcp = reference_application(data, trust("reference-data"))
        gateway.apps["reference-data"] = mcp
        models, runtimes = [], {}
        now = [time.time()]

        async def rate_sleep(seconds):
            now[0] += seconds
            await asyncio.sleep(.001)

        async def poll_sleep(seconds):
            self.assertEqual(seconds, 15)
            await asyncio.sleep(.1)

        async def model_response(request):
            models.append((request.headers["Ocp-Apim-Subscription-Key"], json.loads(request.content)))
            return httpx2.Response(200, json={
                "id": "test-only-model", "object": "chat.completion", "created": 0,
                "model": "approved-deployment",
                "choices": [{"index": 0, "message": {"role": "assistant", "content":
                    "Fictional reference-data comparison; source accuracy unverified."},
                    "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120},
            })

        draft_ledger, finding_ledger = CountingLedger(clock=lambda: now[0]), CountingLedger(clock=lambda: now[0])
        ledgers = [draft_ledger, finding_ledger]
        async with AsyncExitStack() as stack:
            await stack.enter_async_context(mcp.app.router.lifespan_context(mcp.app))
            for role in ("candidate-planner", "evidence-assessor", "release-reviewer", "briefing-author"):
                http = await stack.enter_async_context(httpx.AsyncClient(transport=gateway, timeout=30))
                model_http = await stack.enter_async_context(httpx2.AsyncClient(transport=httpx2.MockTransport(model_response)))
                model = GovernedModel(role, "https://gateway.test", role, "approved-deployment",
                                      http_client=model_http, clock=lambda: now[0], sleep=rate_sleep)
                stack.push_async_callback(model.close)
                peers = GatewayPeers(role, "https://gateway.test", role, http_client=http,
                                     clock=lambda: now[0], sleep=poll_sleep)
                ledger = CountingLedger(clock=lambda: now[0])
                ledgers.append(ledger)
                runtime = Runtime(
                    role, ledger, model=model, peers=peers,
                    gateway_url="https://gateway.test", clock=lambda: now[0],
                    artifacts=draft_ledger if role == "evidence-assessor" else finding_ledger,
                    drafts=draft_ledger,
                )
                stack.push_async_callback(runtime.shutdown)
                runtimes[role] = runtime
                gateway.apps[role] = agent_application(runtime, trust(role))
            client = await stack.enter_async_context(httpx.AsyncClient(transport=gateway,
                headers={"Ocp-Apim-Subscription-Key": "operator"}, timeout=30))
            async with A2AAgent(agent_card=runtimes["candidate-planner"].card, http_client=client) as agent:
                accepted = await agent.run(json.dumps({
                    "operation_id": run_id, "run_id": run_id, "fixture": fixture,
                }), background=True)
                self.assertIsNotNone(accepted.continuation_token)
                async with asyncio.timeout(12):
                    while True:
                        state = await client.get("https://gateway.test/candidate-planner/operations/" + run_id)
                        self.assertEqual(state.status_code, 200, state.text)
                        if state.json()["state"] not in ("pending", "running"):
                            break
                        await poll_sleep(15)
                self.assertEqual(state.json()["state"], expected_state, state.text)
                if expected_state != "succeeded":
                    return state.json(), models, gateway.exchanges
                result = await agent.poll_task(accepted.continuation_token)
                self.assertIsNone(result.continuation_token)
                output = json.loads(result.text)
                repeated = await agent.run(json.dumps({
                    "operation_id": run_id, "run_id": run_id, "fixture": fixture,
                }), background=True)
                self.assertIsNone(repeated.continuation_token)
                self.assertEqual(json.loads(repeated.text), output)
                self.assertNotIn("private_notes", json.dumps(output))
                self.assertLessEqual(gateway.read_attempts + sum(item.read_attempts for item in ledgers), 512)
                self.last_read_count = gateway.read_attempts + sum(item.read_attempts for item in ledgers)
                if persisted is not None:
                    for name, ledger in zip(("drafts", "findings", *runtimes), ledgers):
                        persisted[name] = (await ledger.read())[0]
                self.assertEqual(output["provenance"], data.provenance)
                self.assertTrue(set(CAVEATS).issubset(output["caveats"]))
                if output.get("brief"):
                    ref = output["brief"]["citations"][0]
                    url = f"https://gateway.test/release-reviewer/findings/{ref['artifact_id']}/versions/{ref['version']}"
                    allowed = await client.get(url, headers={
                        "Ocp-Apim-Subscription-Key": "briefing-author",
                        "x-citadel-read-pool": output["brief"]["read_scopes"][0]["operation_id"]})
                    self.assertEqual(allowed.status_code, 200)
                    denied = await client.get("https://gateway.test/release-reviewer/operations/run1",
                        headers={"Ocp-Apim-Subscription-Key": "briefing-author"})
                    self.assertEqual(denied.status_code, 403)
                    denied = await client.post("https://gateway.test/release-reviewer/a2a",
                        headers={"Ocp-Apim-Subscription-Key": "candidate-planner"},
                        json={"jsonrpc": "2.0", "method": "SendMessage", "id": "probe"})
                    self.assertEqual(denied.status_code, 403)
                return output, models, gateway.exchanges

    async def test_five_real_protocol_apps_complete_three_exact_released_findings(self):
        output, models, exchanges = await self.run_case("base-source")
        self.assertEqual(output["status"], "complete")
        self.assertEqual(output["selected_identifiers"], ["EB01", "EB02", "EB03"])
        self.assertEqual(len(output["brief"]["citations"]), 3)
        self.assertEqual({role for role, _ in models},
                         {"candidate-planner", "evidence-assessor", "release-reviewer", "briefing-author"})
        self.assertTrue(any(target == "reference-data" for _, target, _, _ in exchanges))
        self.assertTrue(any(path.startswith("/findings/") for _, _, path, _ in exchanges))

    async def test_missing_width_replaces_candidate_without_hiding_gap_or_fixture(self):
        output, _, _ = await self.run_case("missing-width-replacement")
        self.assertEqual(output["selected_identifiers"], ["EB02", "EB03", "EB04"])
        self.assertEqual(output["assessed"][0]["classification"], "insufficient_evidence")
        self.assertIn("synthetic_missing_width", json.dumps(output["assessed"][0]))
        self.assertEqual(output["provenance"]["evidence_origin"], "synthetic-overlay")

    async def test_exhausted_fixed_pool_never_authors_a_complete_brief(self):
        output, models, _ = await self.run_case("no-alternative")
        self.assertEqual(output["status"], "bounded_pool_exhausted")
        self.assertEqual(output["selected_identifiers"], [])
        self.assertNotIn("brief", output)
        self.assertNotIn("briefing-author", {role for role, _ in models})

    async def test_entire_twenty_member_pool_is_assessed_without_a_fabricated_brief(self):
        output, models, exchanges = await self.run_case("no-alternative", count=20)
        self.assertEqual(output["status"], "bounded_pool_exhausted")
        self.assertEqual(len(output["assessed"]), 20)
        self.assertLess(len(models), 128)
        self.assertNotIn("briefing-author", {role for role, _ in models})
        self.assertLessEqual(sum(
            json.loads(body).get("method") == "SendMessage"
            for _, _, path, body in exchanges if path == "/a2a"), 42)

    async def test_wall_clock_receipt_rejection_does_not_abort_twenty_member_workflow_or_add_reads(self):
        from itertools import count
        from types import SimpleNamespace
        from unittest.mock import patch
        ticks = count(1000, -1)
        with patch("citadel.runtime.network.time", SimpleNamespace(time=lambda: next(ticks))):
            output, models, _ = await self.run_case("no-alternative", count=20)
        self.assertEqual(output["status"], "bounded_pool_exhausted")
        self.assertEqual(len(output["assessed"]), 20)
        self.assertEqual(len(models), 41)
        self.assertLessEqual(self.last_read_count, 512)
        self.assertNotIn("brief", output)

    async def test_completed_brief_must_match_the_exact_atomic_status_reference(self):
        output, _, _ = await self.run_case("base-source", expected_state="indeterminate",
                                           corrupt_brief=True)
        self.assertEqual(output["result"], {"kind": "incomplete", "code": "conflict"})


@unittest.skipUnless(os.environ.get("CITADEL_EVIDENCE_DATA"), "Approved retained dataset not selected")
class PinnedWorkflowTests(unittest.IsolatedAsyncioTestCase):
    run_case = WorkflowTests.run_case

    async def test_actual_twenty_member_no_alternative_pool_completes_within_all_run_limits(self):
        base = ReferenceData.from_directory(os.environ["CITADEL_EVIDENCE_DATA"])
        output, models, exchanges = await self.run_case("no-alternative", data_source=base)
        self.assertEqual(output["status"], "bounded_pool_exhausted")
        self.assertEqual(output["pool_count"], 20)
        self.assertEqual(len(output["assessed"]), 20)
        self.assertEqual(output["selected_identifiers"], [])
        self.assertNotIn("brief", output)
        self.assertEqual(len(models), 41)
        self.assertLessEqual(sum(json.loads(body).get("method") == "SendMessage"
                                 for _, _, path, body in exchanges if path == "/a2a"), 42)

    async def test_real_pinned_data_comparison_and_replacement_use_exact_released_versions(self):
        base = ReferenceData.from_directory(os.environ["CITADEL_EVIDENCE_DATA"])
        for fixture, identifiers in (
            ("base-source", ["BE-0052", "EBAM", "EBAR"]),
            ("missing-width-replacement", ["EBAM", "EBAR", "EBAW"]),
        ):
            with self.subTest(fixture=fixture):
                output, _, _ = await self.run_case(fixture, data_source=base)
                self.assertEqual(output["selected_identifiers"], identifiers)
                self.assertEqual(output["provenance"]["source"]["kind"], "pinned-source")
