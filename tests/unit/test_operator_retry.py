"""Retry through the authenticated owner boundary, with no external execution."""

import asyncio
from copy import deepcopy
import json
import unittest

import httpx
import httpx2

from citadel.operations import OperationError
from tests.unit import test_operator_recovery as recovery_fixture
from tests.unit.gateway_fixtures import signed
from tests.unit.agent_fixtures import FIXTURES, PeerResponses, reference
from citadel.runtime.model import GovernedModel


class RetryTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = recovery_fixture.RecoveryTests.asyncSetUp
    check = recovery_fixture.RecoveryTests.check
    async def retry(self, request_id="retry1", *, caller="operator-web", body=None):
        path = "/operator/runs/run1/retry/" + request_id
        content = json.dumps({"confirmed": True} if body is None else body).encode()
        return await self.client.post("https://gateway.test" + path, content=content,
            headers=signed(content, "candidate-planner", path, caller))

    async def test_confirmed_retry_preserves_identity_deadline_charges_and_fences_old_owner(self):
        await self.accounting.start_agent("run1", "run1")
        await self.accounting.safe_read("run1")
        previous = await self.accounting.model("run1", "run1", input_tokens=100, output_tokens=100)
        await self.accounting.finish_model("run1", previous["attempt_id"])
        self.clock.now = 1181
        self.assertEqual((await self.check()).json()["state"], "released_no_commit")
        before = await self.accounting.status("run1")
        entered, release = asyncio.Event(), asyncio.Event()
        requests = []

        async def model_response(request):
            requests.append(request)
            entered.set()
            await release.wait()
            return httpx2.Response(200, json=json.loads((FIXTURES / "model.json").read_text()))

        remote = httpx2.AsyncClient(transport=httpx2.MockTransport(model_response))
        self.addAsyncCleanup(remote.aclose)
        self.runtime.model = GovernedModel("candidate-planner", "https://gateway.test", "fixture-key",
            "fixture-model", http_client=remote, clock=self.clock, sleep=self.clock.sleep)
        self.addAsyncCleanup(self.runtime.model.close)
        self.runtime.peers = PeerResponses(reference())
        self.addAsyncCleanup(self.runtime.shutdown)
        response = await self.retry()
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["state"], "retry_admitted", response.text)
        await entered.wait()
        budget = await self.accounting.status("run1")
        self.assertEqual(budget["remaining"]["agents"], before["remaining"]["agents"] - 1)
        self.assertEqual(budget["remaining"]["models"], before["remaining"]["models"] - 1)
        self.assertEqual(budget["remaining"]["reads"], before["remaining"]["reads"])
        self.assertLess(budget["remaining"]["tokens"], before["remaining"]["tokens"])
        self.assertEqual(budget["agents"]["run1"], 2)
        self.assertEqual(budget["deadline"], 1900)
        status = await self.ops.status("operator", "invoke", "run1")
        self.assertGreater(status["generation"], self.owner.generation)
        await self.ledger.ticket_store.release_run("operator/invoke/run1", generation=0)
        self.assertEqual(self.ledger.ticket_store.active, "operator/invoke/run1")
        self.assertEqual(self.ledger.ticket_store.active_generation, status["generation"])
        with self.assertRaises(OperationError) as fenced:
            await self.ops.complete(self.owner, product={"status": "stale"})
        self.assertEqual(fenced.exception.code, "fenced")
        duplicate = await self.retry()
        self.assertEqual(duplicate.json(), response.json())
        self.assertEqual(len(requests), 1)
        release.set()
        await asyncio.gather(*self.runtime.tasks)
        product = await self.ops.completed_result("operator", "invoke", "run1")
        self.assertEqual(product["selected_identifiers"], ["EB01", "EB02", "EB03"])
        self.assertEqual(product["provenance"]["fixture"]["id"], "base-source")
        self.assertEqual((await self.accounting.status("run1"))["deadline"], 1900)
        self.assertEqual((await self.index.resolve("run1"))["inputs"], self.payload)
        self.assertIsNone(self.ledger.ticket_store.active)
        self.assertEqual((await self.retry()).json(), response.json())
        self.assertEqual(len(requests), 1)

    async def test_confirmation_is_strict_and_agents_cannot_spend_or_retry(self):
        self.clock.now = 1181
        await self.check()
        before = deepcopy(self.ledger.document)
        for body in ({}, {"confirmed": False}, {"confirmed": 1},
                     {"confirmed": True, "fixture": "no-alternative"}):
            with self.subTest(body=body):
                self.assertNotEqual((await self.retry(body=body)).status_code, 200)
        for caller in ("operator", "candidate-planner", "evidence-assessor", "unknown"):
            self.assertEqual((await self.retry(caller=caller)).status_code, 403)
        path = "/operator/runs/run1/retry/retry1"
        self.assertEqual((await self.client.get("https://gateway.test" + path,
            headers=signed(b"", "candidate-planner", path, "operator-web", "GET"))).status_code, 403)
        self.assertEqual(self.ledger.document, before)
        self.assertEqual(self.runtime.tasks, set())

    async def test_service_refuses_partial_ambiguous_expired_exhausted_and_occupied(self):
        self.clock.now = 1181
        await self.check()
        original = deepcopy(self.ledger.document)
        mutations = {
            "partial": lambda d: d["operations"][self.owner.key].update(state="indeterminate"),
            "committed": lambda d: d["operations"][self.owner.key].update(state="succeeded"),
            "pending": lambda d: d["operations"][self.owner.key].update(state="pending"),
            "model": lambda d: d["budgets"]["run1"].update(model={"attempt_id": "unresolved"}),
            "child": lambda d: d["budgets"]["run1"].update(child={"grant_id": "unresolved"}),
            "external": lambda d: d["operations"][self.owner.key]["external"].update(
                child={"state": "indeterminate", "input_hash": "a" * 64}),
            "partial-external": lambda d: d["operations"][self.owner.key]["external"].update(
                child={"state": "succeeded", "input_hash": "a" * 64}),
            "closed": lambda d: d["budgets"]["run1"].update(closed=True),
            "missing-budget": lambda d: d["budgets"].clear(),
            "binding": lambda d: d["operations"][self.owner.key].update(input_hash="b" * 64),
            "candidates": lambda d: d["budgets"]["run1"]["candidates"].append("EB01"),
            "grants": lambda d: d["budgets"]["run1"]["grants"].append("old"),
            "attempts": lambda d: d["budgets"]["run1"]["agents"].update(run1=8),
        }
        for key in ("agents", "models", "tokens", "reads"):
            mutations[key] = lambda d, key=key: d["budgets"]["run1"]["remaining"].update({key: 0})
        mutations["expired"] = lambda d: None
        mutations["occupied"] = lambda d: None
        for name, change in mutations.items():
            with self.subTest(boundary=name):
                self.ledger.document = deepcopy(original)
                self.ledger.etag += 1
                self.clock.now = 1900 if name == "expired" else 1181
                self.ledger.ticket_store.active = "operator/invoke/other" if name == "occupied" else None
                change(self.ledger.document)
                budgets = deepcopy(self.ledger.document["budgets"])
                response = await self.retry("retry-" + name)
                self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual(response.json()["state"], "blocked", response.text)
                self.assertEqual(self.ledger.document["budgets"], budgets)
                self.assertEqual(self.runtime.tasks, set())
                if name == "occupied":
                    self.assertEqual(self.ledger.ticket_store.active, "operator/invoke/other")

    async def test_original_physical_read_exhaustion_does_not_dispatch(self):
        self.clock.now = 1181
        await self.check()
        for index in range(512):
            await self.ledger.ticket_store.create_marker("operator/invoke/run1", index, "spent")
        exhausted = await self.retry()
        self.assertEqual(exhausted.json()["state"], "blocked")
        self.assertIn("tickets exhausted", exhausted.json()["reason"])
        self.assertIsNone(self.ledger.ticket_store.active)
        self.assertEqual(self.runtime.tasks, set())

    async def test_unavailable_or_exhausted_proof_and_ambiguous_marker_never_authorize_execution(self):
        self.clock.now = 1181
        await self.check()
        original_read = self.ledger.read

        async def unavailable():
            raise OperationError("unavailable", "Fixture owner proof unavailable")

        self.ledger.read = unavailable
        response = await self.retry("unavailable")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["state"], "unknown")
        self.ledger.read = original_read
        create = self.reads.store.create_marker

        async def lost(*args):
            await create(*args)
            raise OperationError("indeterminate", "Fixture lost proof marker")

        self.reads.store.create_marker = lost
        response = await self.retry("ambiguous-marker")
        self.assertEqual(response.json()["state"], "unknown")
        self.reads.store.create_marker = create
        self.reads.capacities = {"observation": 16384, "recovery-proof": 1}
        self.assertEqual((await self.retry("exhausted")).status_code, 429)
        self.assertNotIn("unavailable", self.ledger.document["operator_controls"])
        self.assertNotIn("ambiguous-marker", self.ledger.document["operator_controls"])
        self.assertIsNone(self.ledger.ticket_store.active)
        self.assertEqual(self.runtime.tasks, set())

    async def test_unresolved_hosted_dispatch_blocks_retry_even_if_global_slot_is_empty(self):
        self.clock.now = 1181
        await self.check()
        await self.index.register("operator", {
            "run_id": "ambiguous", "operation_id": "ambiguous", "fixture": "no-alternative"})
        index_ledger = self.index.ledger.ledger
        index_ledger.document["retained_runs"]["ambiguous"]["submission"] = {
            "request_id": "ambiguous", "dispatch": "intent", "reason": "ambiguous_dispatch"}
        response = await self.retry()
        self.assertEqual(response.json()["state"], "blocked", response.text)
        self.assertIsNone(self.ledger.ticket_store.active)
        self.assertEqual(self.runtime.tasks, set())

    async def test_explicit_recovery_releases_only_exact_lost_retry_admission_without_execution(self):
        self.clock.now = 1181
        await self.check()
        acquire = self.ledger.ticket_store.acquire_run

        async def lost(*args, **kwargs):
            await acquire(*args, **kwargs)
            raise OperationError("indeterminate", "Fixture lost acquisition")

        self.ledger.ticket_store.acquire_run = lost
        result = await self.retry()
        self.assertEqual(result.json()["state"], "unknown")
        self.assertEqual(self.ledger.ticket_store.active_generation, 3)
        self.ledger.ticket_store.acquire_run = acquire
        checked = await self.check("check-retry")
        self.assertEqual(checked.json()["state"], "released_no_commit")
        self.assertIsNone(self.ledger.ticket_store.active)
        self.assertEqual(self.runtime.tasks, set())

    async def test_lost_intent_or_admission_or_outcome_never_becomes_a_restart_queue(self):
        self.clock.now = 1181
        await self.check()
        self.ledger.lose_response = True
        first = await self.retry()
        self.assertEqual(first.json()["state"], "unknown")
        second = await self.retry()
        self.assertEqual(second.json()["state"], "unknown")
        self.assertEqual(self.ledger.document["operator_controls"]["retry1"]["outcome"], second.json())
        self.assertEqual(self.runtime.tasks, set())
        self.assertEqual((await self.ops.status("operator", "invoke", "run1"))["state"], "failed_no_commit")

        acquire = self.ledger.ticket_store.acquire_run

        async def lost_admission(*args, **kwargs):
            await acquire(*args, **kwargs)
            raise OperationError("indeterminate", "Fixture lost acquisition")

        self.ledger.ticket_store.acquire_run = lost_admission
        unknown = await self.retry("admission")
        self.assertEqual(unknown.json()["state"], "unknown")
        self.ledger.ticket_store.acquire_run = acquire
        self.assertEqual((await self.retry("admission")).json(), unknown.json())
        self.assertEqual(self.runtime.tasks, set())

        commit = self.ledger.commit

        async def lost_outcome(document, etag, *, deadline):
            control = document.get("operator_controls", {}).get("outcome", {})
            if (control.get("outcome") or {}).get("state") == "retry_admitted":
                self.ledger.lose_response = True
            return await commit(document, etag, deadline=deadline)

        self.ledger.commit = lost_outcome
        lost = await self.retry("outcome")
        self.assertEqual(lost.json()["state"], "unknown")
        self.ledger.commit = commit
        self.reads.store.cursors.clear()
        from citadel.runtime.agents import Runtime, agent_application
        from tests.unit.gateway_fixtures import trust
        self.runtime = Runtime("candidate-planner", self.ledger, model=None, peers=None,
            gateway_url="https://gateway.test", clock=self.clock, run_index=self.index)
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(
            app=agent_application(self.runtime, trust("candidate-planner"))))
        self.addAsyncCleanup(self.client.aclose)
        self.assertEqual((await self.retry("outcome")).json()["state"], "unknown")
        self.assertEqual((await self.retry("new-request")).json()["state"], "blocked")
        self.assertEqual(self.runtime.tasks, set())

    async def test_recovery_request_identity_cannot_be_reused_for_retry_or_reverse(self):
        self.clock.now = 1181
        await self.check()
        self.assertNotEqual((await self.retry("check1")).status_code, 200)
        await self.retry(body={"confirmed": False})
        # A refusal is retained and cannot acquire execution with another action.
        self.clock.now = 1900
        await self.retry("refused")
        self.assertNotEqual((await self.check("refused")).status_code, 200)
