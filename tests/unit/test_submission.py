"""Hosted submission boundary; all storage and responses are offline test data."""

import unittest
import asyncio
import json

import httpx

from citadel.operations import OperationError
from citadel.operations.testing import MemoryLedger
from citadel.runtime.agents import Runtime
from citadel.runtime.observation import DeploymentReads, RunIndex, empty_index
from citadel.runtime.submission import ScenarioSubmission, submission_run
from citadel.runtime.agents import agent_application
from tests.unit.gateway_fixtures import signed, trust
from tests.unit.agent_fixtures import AgentCase, PeerResponses, reference


class SubmissionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.ledger = MemoryLedger(clock=lambda: 1000)
        self.ledger.document = empty_index()
        reads = DeploymentReads(self.ledger.ticket_store, "fixture1", clock=lambda: 1000)
        await self.ledger.ticket_store.open_pool(reads.scope("observation"))
        self.index = RunIndex(self.ledger, reads, clock=lambda: 1000)
        self.calls = []

        async def accept(caller, payload):
            binding = await self.index.resolve(payload["run_id"])
            self.assertEqual(binding["inputs"], payload)
            self.calls.append((caller, payload))
            return {"state": "pending"}

        self.submit = ScenarioSubmission(self.index, accept)

    async def test_duplicate_after_restart_uses_saved_intent_without_dispatching_again(self):
        first = await self.submit.submit("request1", "replacement")
        repeated = await ScenarioSubmission(self.index, self.submit.accept).submit("request1", "replacement")
        self.assertEqual(first["run_id"], repeated["run_id"])
        self.assertEqual(first["execution"], "pending")
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.calls[0][0], "operator")
        self.assertEqual(self.calls[0][1]["fixture"], "missing-width-replacement")
        with self.assertRaises(OperationError):
            await self.submit.submit("request1", "comparison")

    async def test_lost_intent_write_never_dispatches_even_when_commit_really_happened(self):
        self.ledger.lose_response = True
        with self.assertRaises(OperationError):
            await self.submit.submit("request1", "comparison")
        observed = await self.submit.submit("request1", "comparison")
        self.assertEqual(observed["execution"], "unknown")
        self.assertEqual(self.calls, [])
        self.assertEqual(len((await self.index.page())["runs"]), 1)

    async def test_unresolved_hosted_intent_blocks_fresh_ui_and_cli_admission(self):
        self.ledger.lose_response = True
        with self.assertRaises(OperationError):
            await self.submit.submit("uncertain1", "comparison")
        with self.assertRaises(OperationError) as browser:
            await self.submit.submit("new1", "replacement")
        self.assertEqual(browser.exception.code, "conflict")
        workload = MemoryLedger(clock=lambda: 1000)
        runtime = Runtime("candidate-planner", workload, model=None, peers=None,
                          gateway_url="https://gateway.test", clock=lambda: 1000, run_index=self.index)
        with self.assertRaises(OperationError):
            await runtime.accept("operator", {
                "run_id": "cli1", "operation_id": "cli1", "fixture": "base-source"})
        self.assertEqual((self.calls, runtime.tasks), ([], set()))
        self.assertIsNone(workload.ticket_store.active)

    async def test_lost_execution_response_is_never_replayed_by_duplicate_request(self):
        async def lost(caller, payload):
            self.calls.append(payload)
            raise TimeoutError()

        service = ScenarioSubmission(self.index, lost)
        first = await service.submit("lost1", "exhaustion")
        repeated = await service.submit("lost1", "exhaustion")
        self.assertEqual(first, repeated)
        self.assertEqual(first["reason"], "ambiguous_dispatch")
        self.assertEqual(len(self.calls), 1)

    async def test_lost_saved_outcome_response_reopens_the_persisted_result_without_dispatch(self):
        async def accept(caller, payload):
            self.calls.append(payload)
            self.ledger.lose_response = True
            return {"state": "pending"}

        service = ScenarioSubmission(self.index, accept)
        with self.assertRaises(OperationError):
            await service.submit("outcome1", "comparison")
        repeated = await service.submit("outcome1", "comparison")
        self.assertEqual((repeated["execution"], repeated["reason"]), ("pending", "accepted"))
        self.assertEqual(len(self.calls), 1)

    async def test_hosted_http_uses_global_cli_admission_and_does_not_expand_agent_authority(self):
        workload = MemoryLedger(clock=lambda: 1000)
        await workload.ticket_store.acquire_run("operator/invoke/cli-blocker")
        runtime = Runtime("candidate-planner", workload, model=None, peers=None,
                          gateway_url="https://gateway.test", clock=lambda: 1000, run_index=self.index)
        path = "/operator/scenarios"
        body = json.dumps({"request_id": "http1", "scenario": "comparison"}).encode()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(
                app=agent_application(runtime, trust("candidate-planner")))) as client:
            response = await client.post("https://gateway.test" + path, content=body,
                headers=signed(body, "candidate-planner", path, "operator-web", "POST"))
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["reason"], "active_run_blocker")
            run = response.json()["run_id"]
            self.assertEqual((await self.index.resolve(run))["inputs"]["fixture"], "base-source")
            await workload.ticket_store.release_run("operator/invoke/cli-blocker")
            duplicate = await client.post("https://gateway.test" + path, content=body,
                headers=signed(body, "candidate-planner", path, "operator-web", "POST"))
            self.assertEqual(duplicate.json(), response.json())
            for caller in ("operator", "evidence-assessor", "candidate-planner"):
                denied = await client.post("https://gateway.test" + path, content=body,
                    headers=signed(body, "candidate-planner", path, caller, "POST"))
                self.assertEqual(denied.status_code, 403)
            a2a = await client.post("https://gateway.test/a2a", content=b"{}",
                headers=signed(b"{}", "candidate-planner", "/a2a", "operator-web", "POST"))
            self.assertEqual(a2a.status_code, 403)
        self.assertEqual(runtime.tasks, set())

    async def test_concurrent_duplicate_only_dispatches_the_confirmed_intent_writer(self):
        entered, release = asyncio.Event(), asyncio.Event()

        async def accept(caller, payload):
            self.calls.append(payload)
            entered.set()
            await release.wait()
            return {"state": "pending"}

        service = ScenarioSubmission(self.index, accept)
        first = asyncio.create_task(service.submit("race1", "comparison"))
        await entered.wait()
        duplicate = await service.submit("race1", "comparison")
        self.assertEqual(duplicate["execution"], "unknown")
        release.set()
        await first
        self.assertEqual(len(self.calls), 1)

    async def test_browser_claimed_fixture_owner_or_path_never_reaches_workflow(self):
        workload = MemoryLedger(clock=lambda: 1000)
        runtime = Runtime("candidate-planner", workload, model=None, peers=None,
                          gateway_url="https://gateway.test", clock=lambda: 1000, run_index=self.index)
        path = "/operator/scenarios"
        async with httpx.AsyncClient(transport=httpx.ASGITransport(
                app=agent_application(runtime, trust("candidate-planner")))) as client:
            for claims in ({"fixture": "base-source"}, {"caller": "operator"},
                           {"run_id": "arbitrary"}, {"path": "/private"}):
                body = json.dumps({"request_id": "bad1", "scenario": "comparison", **claims}).encode()
                response = await client.post("https://gateway.test" + path, content=body,
                    headers=signed(body, "candidate-planner", path, "operator-web", "POST"))
                self.assertEqual(response.status_code, 400)
        self.assertEqual((await self.index.page())["runs"], [])
        self.assertEqual(runtime.tasks, set())


class HostedPlannerTests(AgentCase, unittest.IsolatedAsyncioTestCase):
    async def test_spent_browsing_pool_cannot_prevent_hosted_execution_or_saved_outcome(self):
        run = submission_run("no-browsing")
        for scope in self.peers.scopes:
            scope["run_id"] = run
        runtime = await self.agent("candidate-planner")
        ledger = MemoryLedger(clock=self.clock)
        ledger.document = empty_index()
        reads = DeploymentReads(ledger.ticket_store, "fixture1", clock=self.clock)
        reads.capacities = {"observation": 1, "recovery-proof": 1}
        await reads.store.open_pool(reads.scope("observation"))
        await reads.store.create_marker(reads.scope("observation"), 0, "spent")
        runtime.run_index = RunIndex(ledger, reads, clock=self.clock)
        result = await ScenarioSubmission(runtime.run_index, runtime.accept).submit("no-browsing", "comparison")
        self.assertEqual(result["reason"], "accepted")
        await asyncio.gather(*runtime.tasks)
        self.assertEqual((await runtime.status("operator", run))["state"], "succeeded")
        self.assertEqual(ledger.document["retained_runs"][run]["execution"], "succeeded")
        duplicate = await ScenarioSubmission(runtime.run_index, runtime.accept).submit("no-browsing", "comparison")
        self.assertEqual(duplicate["execution"], "succeeded")
        self.assertEqual(len([s for s, _ in reads.store.markers if s == reads.scope("observation")]), 1)

    async def run_hosted(self, scenario, fixture):
        self.peers = PeerResponses(reference(fixture))
        for scope in self.peers.scopes:
            scope["run_id"] = submission_run("hosted1")
        runtime = await self.agent("candidate-planner", fixture=fixture)
        ledger = MemoryLedger(clock=self.clock)
        ledger.document = empty_index()
        reads = DeploymentReads(ledger.ticket_store, "fixture1", clock=self.clock)
        await ledger.ticket_store.open_pool(reads.scope("observation"))
        index = RunIndex(ledger, reads, clock=self.clock)
        runtime.run_index = index
        path = "/operator/scenarios"
        body = json.dumps({"request_id": "hosted1", "scenario": scenario}).encode()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(
                app=agent_application(runtime, trust("candidate-planner")))) as client:
            response = await client.post("https://gateway.test" + path, content=body,
                headers=signed(body, "candidate-planner", path, "operator-web", "POST"))
            self.assertEqual(response.status_code, 200)
            run = response.json()["run_id"]
            await asyncio.gather(*runtime.tasks)
            before = len(self.model_requests)
            duplicate = await client.post("https://gateway.test" + path, content=body,
                headers=signed(body, "candidate-planner", path, "operator-web", "POST"))
            self.assertEqual(duplicate.json()["run_id"], run)
            self.assertEqual(len(self.model_requests), before)
            path = "/operator/runs/" + run
            observed = await client.get("https://gateway.test" + path,
                headers=signed(b"", "candidate-planner", path, "operator-web", "GET"))
            self.assertEqual(observed.status_code, 200)
        self.assertIsNone(self.ledger.ticket_store.active)
        self.assertEqual(observed.json()["execution"], "succeeded")
        return observed.json()["summary"]

    async def test_comparison_dispatches_real_planner_once_and_observes_saved_selection(self):
        result = await self.run_hosted("comparison", "base-source")
        self.assertEqual(result["selected_identifiers"], ["EB01", "EB02", "EB03"])
        self.assertEqual(result["outcome"], "complete")
        self.assertEqual(result["brief"]["citations"], self.peers.references[:3])

    async def test_replacement_dispatches_fixed_overlay_with_real_skipped_candidate(self):
        result = await self.run_hosted("replacement", "missing-width-replacement")
        self.assertEqual(result["selected_identifiers"], ["EB02", "EB03", "EB04"])
        self.assertEqual(result["candidates"][0]["classification"], "insufficient_evidence")
        self.assertIn("synthetic_missing_width", str(result["candidates"][0]["gap_reasons"]))

    async def test_exhaustion_dispatches_fixed_pool_without_author_execution_or_brief(self):
        result = await self.run_hosted("exhaustion", "no-alternative")
        self.assertEqual(result["outcome"], "bounded_pool_exhausted")
        self.assertIsNone(result["brief"])
        self.assertIsNone(self.peers.authored)
