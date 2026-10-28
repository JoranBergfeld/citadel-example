"""Offline recovery through real owner handlers; fixtures are not cloud evidence."""

import json
import unittest

import httpx

from citadel.operations import Operations
from citadel.operations.limits import Accounting
from citadel.operations.testing import MemoryLedger
from citadel.runtime.agents import Runtime, agent_application
from citadel.runtime.observation import DeploymentReads, RunIndex, empty_index
from citadel.evidence.manifests import sha256
from tests.unit.agent_fixtures import Clock
from tests.unit.gateway_fixtures import signed, trust
from citadel.runtime.network import GatewayPeers
from citadel.operator.observation import ObservationClient
from citadel.operator.recovery import RecoveryClient


class RecoveryTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.clock = Clock()
        self.ledger = MemoryLedger(clock=self.clock)
        index_ledger = MemoryLedger(clock=self.clock)
        index_ledger.document = empty_index()
        self.reads = DeploymentReads(index_ledger.ticket_store, "fixture1", clock=self.clock)
        await self.reads.store.open_pool(self.reads.scope("observation"))
        await self.reads.store.open_pool(self.reads.scope("recovery-proof"))
        self.index = RunIndex(index_ledger, self.reads, clock=self.clock)
        self.payload = {"run_id": "run1", "operation_id": "run1", "fixture": "base-source"}
        await self.index.register("operator", self.payload)
        await self.ledger.ticket_store.open_pool("operator/invoke/run1", exclusive=True)
        self.accounting = Accounting(self.ledger, workload="candidate-planner", clock=self.clock)
        budget = await self.accounting.start_run("run1")
        self.ops = Operations(self.ledger, workload="candidate-planner", clock=self.clock)
        await self.ops.accept("operator", "invoke", "run1", self.payload,
                              run_id="run1", deadline=budget["deadline"])
        self.owner = await self.ops.claim("operator", "invoke", "run1", worker="old", lease_seconds=180)
        self.runtime = Runtime("candidate-planner", self.ledger, model=None, peers=None,
            gateway_url="https://gateway.test", clock=self.clock, run_index=self.index)
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(
            app=agent_application(self.runtime, trust("candidate-planner"))))
        self.addAsyncCleanup(self.client.aclose)

    async def check(self, request_id="check1", *, caller="operator-web", body=None):
        path = "/operator/runs/run1/recover/" + request_id
        content = json.dumps({} if body is None else body).encode()
        return await self.client.post("https://gateway.test" + path, content=content,
            headers=signed(content, "candidate-planner", path, caller))

    async def test_expired_owner_is_fenced_without_workflow_reads_and_duplicate_returns_durable_outcome(self):
        self.clock.now = 1181
        for index in range(512):
            await self.ledger.ticket_store.create_marker("operator/invoke/run1", index, "spent")
        markers = set(self.ledger.ticket_store.markers)
        before = await self.accounting.status("run1")
        first = await self.check()
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.json()["state"], "released_no_commit")
        self.assertEqual((await self.ops.status("operator", "invoke", "run1"))["state"], "failed_no_commit")
        self.assertIsNone(self.ledger.ticket_store.active)
        self.assertEqual(await self.accounting.status("run1"), before)
        # A restarted handler must reconcile its durable request, not execute work.
        self.reads.store.cursors.clear()
        self.runtime = Runtime("candidate-planner", self.ledger, model=None, peers=None,
            gateway_url="https://gateway.test", clock=self.clock, run_index=self.index)
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(
            app=agent_application(self.runtime, trust("candidate-planner"))))
        self.addAsyncCleanup(self.client.aclose)
        second = await self.check()
        self.assertEqual(second.json(), first.json())
        self.assertEqual(self.runtime.tasks, set())
        self.assertEqual(self.ledger.ticket_store.markers, markers)

    async def test_owner_reconciles_exact_child_and_private_artifact_without_reading_workflow_pools(self):
        allowance = {"agents": 2, "models": 2, "tokens": 36000, "reads": 22}
        grant = await self.accounting.delegate("run1", "assess1", "evidence-assessor", allowance)
        payload = {"operation_id": "assess1", "run_id": "run1", "fixture": "base-source",
                   "airport_ident": "EB01", "grant": grant}
        binding = sha256({"inputs": payload, "run_id": "run1", "deadline": 1900})
        await self.ops.begin_external(self.owner, "assess1", binding)
        child_ledger = MemoryLedger(clock=self.clock)
        artifacts = MemoryLedger(clock=self.clock)
        child = Runtime("evidence-assessor", child_ledger, artifacts=artifacts, model=None,
            peers=None, gateway_url="https://gateway.test", clock=self.clock,
            recovery_admission=self.reads)
        await Accounting(child_ledger, workload="evidence-assessor", clock=self.clock).adopt(
            grant, authenticated_issuer="candidate-planner")
        child_ops = Operations(child_ledger, workload="evidence-assessor", clock=self.clock)
        await child_ops.accept("candidate-planner", "invoke", "assess1", payload,
                              run_id="run1", deadline=1900)
        owner = await child_ops.claim("candidate-planner", "invoke", "assess1", worker="old")
        artifact_ops = Operations(artifacts, workload="evidence-assessor", clock=self.clock)
        draft_inputs = {"draft": {"fixture": "private saved prose"}, "expected_version": 0}
        draft_hash = sha256({"inputs": draft_inputs, "run_id": "run1", "deadline": 1900})
        await child_ops.begin_external(owner, "draft1", draft_hash)
        await artifact_ops.accept("evidence-assessor", "submit-draft", "draft1", draft_inputs,
                                  run_id="run1", deadline=1900)
        draft_owner = await artifact_ops.claim("evidence-assessor", "submit-draft", "draft1", worker="old")
        # Controlled durable storage boundary represents a committed private draft.
        artifacts.document["operations"][draft_owner.key].update(
            state="succeeded", result={"kind": "draft", "artifact_id": "private1", "version": 1})
        artifacts.document["drafts"] = {"private1": {"1": {"prose": "PRIVATE retained prose"}}}
        await child_ops.mark_incomplete(owner, "unavailable")
        await self.ops.mark_incomplete(self.owner, "unavailable")
        self.clock.now = 1917
        child_app = agent_application(child, trust("evidence-assessor"))
        transport = httpx.ASGITransport(app=child_app)
        fail = [True]

        async def service(request):
            if fail[0]:
                raise httpx.ReadError("Fixture child response unavailable", request=request)
            path = request.url.path.removeprefix("/evidence-assessor")
            headers = dict(request.headers)
            headers.update(signed(request.content, "evidence-assessor", path))
            return await transport.handle_async_request(httpx.Request(
                request.method, request.url.copy_with(path=path), content=request.content, headers=headers))

        async with httpx.AsyncClient(transport=httpx.MockTransport(service)) as http:
            peers = GatewayPeers("candidate-planner", "https://gateway.test", "fixture-only",
                                  http_client=http, clock=self.clock)
            self.runtime.peers = peers
            unavailable = await self.check("unavailable")
            self.assertEqual(unavailable.json()["state"], "unknown")
            self.assertEqual(self.ledger.ticket_store.active, "operator/invoke/run1")
            fail[0] = False
            result = await self.check()
            await peers.close()
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json()["state"], "released_quiescent_partial", result.text)
        self.assertEqual(artifacts.document["drafts"]["private1"]["1"]["prose"], "PRIVATE retained prose")
        self.assertNotIn("PRIVATE", result.text)
        self.assertIsNone(self.ledger.ticket_store.active)
        self.assertEqual(child.tasks, set())
        self.assertFalse(any("/invoke/" in scope for scope, _ in self.ledger.ticket_store.markers))
        self.assertTrue(any("recovery-proof" in scope for scope, _ in self.reads.store.markers))

    async def test_bound_partial_commit_is_quiescent_but_retained_incomplete_and_never_retryable(self):
        # A saved local model explanation is not an outstanding model effect.
        await self.ops.begin_external(self.owner, "saved-child", "a" * 64)
        await self.ops.reconcile_external(self.owner, "saved-child",
            {"state": "succeeded", "input_hash": "a" * 64})
        await self.ops.mark_incomplete(self.owner, "unavailable")
        self.clock.now = 1917
        before = await self.accounting.status("run1")
        result = await self.check()
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json()["state"], "released_quiescent_partial")
        self.assertEqual(result.json()["execution"], "indeterminate")
        self.assertFalse(result.json()["retryable"])
        self.assertIsNone(self.ledger.ticket_store.active)
        self.assertEqual(await self.accounting.status("run1"), before)
        record = (await self.ops.status("operator", "invoke", "run1"))
        self.assertEqual(record["state"], "indeterminate")
        self.assertEqual(self.runtime.tasks, set())
        await self.ledger.ticket_store.acquire_run("operator/invoke/newrun")
        await self.accounting.start_run("newrun")
        self.assertEqual(await self.accounting.status("run1"), before)

    async def test_partial_proof_requires_expired_write_leases_and_unchanged_owner_snapshots(self):
        await self.ops.begin_external(self.owner, "saved-child", "a" * 64)
        await self.ops.reconcile_external(self.owner, "saved-child",
            {"state": "succeeded", "input_hash": "a" * 64})
        await self.ops.mark_incomplete(self.owner, "unavailable")
        self.clock.now = 1901
        early = await self.check("early")
        self.assertEqual(early.json()["state"], "blocked")
        self.assertIn("storage-lease", early.json()["reason"])
        self.clock.now = 1917
        read, count = self.ledger.read, [0]

        async def changing():
            count[0] += 1
            if count[0] == 2:
                # Another control updates the owner document between paid reads.
                self.ledger.document["runs"]["run1"]["provenance"] = {"fixture": "changed"}
                self.ledger.etag += 1
            return await read()

        self.ledger.read = changing
        unstable = await self.check("unstable")
        self.assertEqual(unstable.json()["state"], "blocked")
        self.assertIn("snapshots changed", unstable.json()["reason"])
        self.assertEqual(self.ledger.ticket_store.active, "operator/invoke/run1")

    async def test_live_owner_and_ambiguous_model_remain_blocked_without_mutating_owner_or_allowances(self):
        before = await self.ops.status("operator", "invoke", "run1")
        live = await self.check("live")
        self.assertEqual(live.json()["state"], "blocked")
        self.assertIn("live owner", live.json()["reason"])
        self.assertEqual(await self.ops.status("operator", "invoke", "run1"), before)
        await self.accounting.start_agent("run1", "run1")
        await self.accounting.model("run1", "run1", input_tokens=100, output_tokens=100)
        self.clock.now = 1917
        model = await self.check("model")
        self.assertEqual(model.json()["state"], "blocked")
        self.assertIn("model", model.json()["reason"])
        self.assertEqual(self.ledger.ticket_store.active, "operator/invoke/run1")
        self.assertIsNotNone((await self.accounting.status("run1"))["model"])
        self.assertEqual(self.runtime.tasks, set())

    async def test_unknown_write_response_is_not_reported_as_blocked_or_success_and_duplicate_reconciles(self):
        self.clock.now = 1181
        release = self.ledger.ticket_store.release_run
        calls = []

        async def lost(*args, **kwargs):
            calls.append(args)
            await release(*args, **kwargs)
            from citadel.operations import OperationError
            raise OperationError("indeterminate", "Fixture release response lost")

        self.ledger.ticket_store.release_run = lost
        first = await self.check()
        self.assertEqual(first.json()["state"], "unknown")
        self.assertEqual(len(calls), 1)
        self.ledger.ticket_store.release_run = release
        # A newer admitted run may not be interrupted by reconciliation of the old control.
        await self.ledger.ticket_store.acquire_run("operator/invoke/newrun")
        second = await self.check()
        self.assertEqual(second.json()["state"], "released_no_commit")
        self.assertEqual(self.ledger.ticket_store.active, "operator/invoke/newrun")
        self.assertEqual(self.runtime.tasks, set())

    async def test_lost_intent_and_outcome_writes_reconcile_durable_action_after_restart(self):
        self.clock.now = 1181
        self.ledger.lose_response = True
        first = await self.check()
        self.assertEqual(first.json()["state"], "unknown")
        self.assertEqual((await self.ops.status("operator", "invoke", "run1"))["state"], "running")
        commit = self.ledger.commit

        async def lost_outcome(document, etag, *, deadline):
            if document.get("operator_controls", {}).get("check1", {}).get("outcome"):
                self.ledger.lose_response = True
            return await commit(document, etag, deadline=deadline)

        self.ledger.commit = lost_outcome
        second = await self.check()
        self.assertEqual(second.json()["state"], "unknown")
        self.ledger.commit = commit
        self.reads.store.cursors.clear()
        third = await self.check()
        self.assertEqual(third.json()["state"], "released_no_commit")
        self.assertEqual(self.runtime.tasks, set())

    async def test_exhausted_or_ambiguous_proof_admission_dispatches_no_unfunded_read(self):
        self.clock.now = 1181
        self.reads.capacities = {"observation": 16384, "recovery-proof": 1}
        before = await self.ops.status("operator", "invoke", "run1")
        first = await self.check()
        self.assertEqual(first.status_code, 429)
        self.assertEqual(first.json()["state"], "unknown")
        self.assertEqual(await self.ops.status("operator", "invoke", "run1"), before)
        self.assertEqual(self.ledger.ticket_store.active, "operator/invoke/run1")
        self.assertEqual(len([s for s, _ in self.reads.store.markers if "recovery-proof" in s]), 1)

    async def test_partial_submission_missing_operation_is_audited_not_proof_of_no_commit(self):
        del self.ledger.document["operations"]["operator/invoke/run1"]
        response = await self.check()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["state"], "blocked")
        self.assertIn("Missing", response.json()["reason"])
        async with self.reads.request():
            observed = await self.index.observe("run1", self.runtime.ledger)
        self.assertEqual(observed["recovery"], response.json())
        self.assertEqual(observed["execution"], "unknown")
        self.assertEqual(self.ledger.ticket_store.active, "operator/invoke/run1")

    async def test_hosted_client_charges_protocol_index_audit_reads_and_failed_storage_without_retries(self):
        self.clock.now = 1181
        dispatched = []

        async def service(request):
            dispatched.append(request)
            path = request.url.path.removeprefix("/candidate-planner")
            return await self.client.post("https://gateway.test" + path, content=request.content,
                headers=signed(request.content, "candidate-planner", path, "operator-web")
                | {"x-citadel-recovery-deadline": request.headers["x-citadel-recovery-deadline"]})

        async with httpx.AsyncClient(transport=httpx.MockTransport(service)) as remote:
            observer = ObservationClient("https://gateway.test", "fixture-key", self.reads,
                                         client=remote, clock=self.clock)
            result = await RecoveryClient(observer).check("run1", "check1")
            self.assertEqual(result["state"], "released_no_commit")
            self.assertEqual(len([s for s, _ in self.reads.store.markers if "recovery-proof" in s]), 3)
            from citadel.operations import OperationError

            async def unavailable():
                raise OperationError("unavailable", "Fixture storage failure")

            self.ledger.read = unavailable
            result = await RecoveryClient(observer).check("run1", "check2")
            self.assertEqual(result["state"], "unknown")
            self.assertEqual(len(dispatched), 2)
            self.assertEqual(len([s for s, _ in self.reads.store.markers if "recovery-proof" in s]), 6)

    async def test_untrusted_callers_and_browser_claims_cannot_recover_or_spend_proof(self):
        before = await self.ops.status("operator", "invoke", "run1")
        for caller in ("operator", "candidate-planner", "evidence-assessor", "unknown"):
            self.assertEqual((await self.check(caller=caller)).status_code, 403)
        claims = await self.check(body={"caller": "operator", "receipt": {"closed": True}})
        self.assertNotEqual(claims.status_code, 200)
        self.assertEqual(await self.ops.status("operator", "invoke", "run1"), before)
        self.assertFalse(any("recovery-proof" in scope for scope, _ in self.reads.store.markers))

    async def test_recovery_deadline_includes_admission_and_ambiguous_marker_never_authorizes_read(self):
        self.clock.now = 1181
        create = self.reads.store.create_marker
        before = await self.ops.status("operator", "invoke", "run1")

        async def late(*args):
            result = await create(*args)
            self.clock.now += 31
            return result

        self.reads.store.create_marker = late
        first = await self.check()
        self.assertEqual(first.json()["state"], "unknown")
        self.assertEqual(await self.ops.status("operator", "invoke", "run1"), before)
        self.assertEqual(self.ledger.ticket_store.active, "operator/invoke/run1")
        from citadel.operations import OperationError

        async def ambiguous(*args):
            await create(*args)
            raise OperationError("indeterminate", "Fixture lost marker response")

        self.reads.store.create_marker = ambiguous
        second = await self.check("check2")
        self.assertEqual(second.json()["state"], "unknown")
        self.assertEqual(await self.ops.status("operator", "invoke", "run1"), before)
        self.assertNotIn("operator_controls", self.ledger.document)
