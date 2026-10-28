"""Labelled offline Evidence Review owner/HTTP boundaries; no model or cloud calls."""

import unittest
import re
import asyncio

import httpx

from agent_fixtures import AgentCase, PeerResponses, reference
from citadel.evidence.manifests import sha256
from citadel.operations import OperationError, Operations
from citadel.operations.testing import MemoryLedger
from citadel.runtime.agents import Runtime, agent_application
from citadel.runtime.observation import DeploymentReads
from citadel.operator.observation import ObservationClient
from citadel.operator.web import AuthConfig, create_app, hash_passphrase
from tests.unit.gateway_fixtures import signed, trust


class EvidenceObservationTests(unittest.IsolatedAsyncioTestCase):
    async def test_saved_private_prose_cannot_exceed_the_bounded_response_envelope(self):
        for version in range(1, 10):
            await self.draft(version, assessment_prose="Labelled fixture prose. " * 1300)
        runtime = self.runtime("evidence-assessor")
        response = await self.get(runtime, "/operator/runs/run1/drafts")
        self.assertEqual((response.status_code, response.json()["state"]), (503, "unavailable"))
        self.assertEqual(len(self.reads.store.markers), 2)

    async def test_owner_rejects_projection_completed_after_its_total_deadline(self):
        now = [1000]
        self.clock = self.reads.clock = lambda: now[0]
        await self.draft(assessment_prose="Saved fixture prose")
        runtime = self.runtime("evidence-assessor")
        read = self.invocations.read

        async def late():
            result = await read()
            now[0] += 31
            return result

        self.invocations.read = late
        response = await self.get(runtime, "/operator/runs/run1/drafts")
        self.assertEqual((response.status_code, response.json()["state"]), (503, "unavailable"))

    async def asyncSetUp(self):
        self.clock = lambda: 1000
        self.drafts, self.findings, self.invocations = [MemoryLedger(clock=self.clock) for _ in range(3)]
        self.reads = DeploymentReads(self.invocations.ticket_store, "fixture1", clock=self.clock)
        await self.reads.store.open_pool(self.reads.scope("observation"))
        self.data = reference()
        self.draft_ops = Operations(self.drafts, workload="evidence-assessor", clock=self.clock)
        self.release_ops = Operations(self.findings, workload="release-reviewer", clock=self.clock)

    async def draft(self, version=1, **fields):
        draft = {"artifact_id": "draft1", "version": version, "schema_version": 1,
                 "run_id": "run1", "operation_id": f"draftop{version}", "airport_ident": "EB01",
                 **self.data.assess_airport("EB01"), **fields}
        op = draft["operation_id"]
        await self.draft_ops.accept("evidence-assessor", "submit-draft", op,
            {"draft": draft, "expected_version": version - 1}, run_id="run1", deadline=1800)
        owner = await self.draft_ops.claim("evidence-assessor", "submit-draft", op, worker="fixture")
        status = await self.draft_ops.submit_draft(owner, draft, expected_version=version - 1,
                                                  reference=self.data)
        return {key: status["result"][key] for key in ("artifact_id", "version", "sha256")}

    def runtime(self, role):
        return Runtime(role, self.invocations, model=None, peers=None, clock=self.clock,
            gateway_url="https://gateway.test", artifacts=(
                self.drafts if role == "evidence-assessor" else self.findings),
            drafts=self.drafts, observation_reads=self.reads)

    async def get(self, runtime, path, caller="operator-web"):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(
                app=agent_application(runtime, trust(runtime.workload)))) as client:
            return await client.get("https://gateway.test" + path,
                headers=signed(b"", runtime.workload, path, caller, "GET"))

    async def test_owner_returns_saved_prose_exact_versions_but_never_private_fields(self):
        first = await self.draft(assessment_prose="Saved assessment, not regenerated.",
            private_notes="DO NOT EXPORT", prompts=["DO NOT EXPORT"],
            reviewer_deliberation="DO NOT EXPORT", credentials="DO NOT EXPORT",
            storage_path="/DO-NOT-EXPORT")
        await self.draft(2, assessment_prose="Corrected saved prose.")
        runtime = self.runtime("evidence-assessor")
        before = len(self.reads.store.markers)
        response = await self.get(runtime, "/operator/runs/run1/drafts")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual([item["draft"]["version"] for item in data["drafts"]], [1, 2])
        self.assertEqual(data["drafts"][0]["draft"], first)
        self.assertEqual(data["drafts"][0]["assessment_prose"], "Saved assessment, not regenerated.")
        self.assertEqual(data["visibility"], "private_operator_inspection")
        self.assertNotIn("DO NOT EXPORT", response.text)
        self.assertNotIn("DO-NOT-EXPORT", response.text)
        self.assertNotIn("private_notes", response.text)
        self.assertEqual(len(self.reads.store.markers) - before, 2)
        self.assertEqual(runtime.tasks, set())
        denied = await self.get(runtime, "/operator/runs/run1/drafts", "candidate-planner")
        self.assertEqual(denied.status_code, 403)
        self.assertFalse(any("/invoke/" in scope for scope, _ in self.reads.store.markers))

    async def release(self, ref, op="release1"):
        await self.release_ops.accept("evidence-assessor", "release", op, {"draft": ref},
                                      run_id="run1", deadline=1800)
        owner = await self.release_ops.claim("evidence-assessor", "release", op, worker="fixture")
        status = await self.release_ops.release(owner, ref, drafts=self.draft_ops, reference=self.data)
        return {key: status["result"][key] for key in ("artifact_id", "version", "sha256")}

    async def test_exact_finding_link_never_substitutes_a_later_draft_or_regenerates_history(self):
        first = await self.draft(private_notes="DO NOT EXPORT")
        finding_ref = await self.release(first)
        await self.draft(2, assessment_prose="Correction not released.")
        runtime = self.runtime("release-reviewer")
        response = await self.get(runtime, "/operator/runs/run1/releases")
        self.assertEqual(response.status_code, 200)
        release = response.json()["releases"][0]
        self.assertEqual(release["draft"], first)
        self.assertEqual(release["finding"], finding_ref)
        self.assertEqual(release["outcome"], "approved")
        before = len(self.reads.store.markers)
        opened = await self.get(runtime, release["finding_path"])
        self.assertEqual(opened.status_code, 200)
        finding = opened.json()
        self.assertEqual(finding["finding"]["draft"], first)
        self.assertEqual(finding["bindings"]["finding"], finding_ref)
        self.assertIn("not operational suitability", finding["finding"]["caveats"])
        self.assertNotIn("DO NOT EXPORT", opened.text)
        self.assertEqual(len(self.reads.store.markers) - before, 2)
        other_run = await self.get(runtime, release["finding_path"].replace("run1", "other"))
        self.assertEqual(other_run.json()["state"], "partial")
        self.assertNotIn("finding", other_run.json())
        missing_version = await self.get(runtime, release["finding_path"].replace("/versions/1", "/versions/2"))
        self.assertEqual(missing_version.status_code, 404)
        self.assertEqual(runtime.tasks, set())

    async def test_authenticated_view_reads_actual_owners_and_keeps_stale_exact_citations(self):
        ref = await self.draft(assessment_prose="<Saved assessment>", private_notes="DO NOT EXPORT")
        finding = await self.release(ref)
        owner_clients = {}
        fail, calls = False, []
        for role in ("evidence-assessor", "release-reviewer"):
            client = httpx.AsyncClient(transport=httpx.ASGITransport(
                app=agent_application(self.runtime(role), trust(role))))
            self.addAsyncCleanup(client.aclose)
            owner_clients[role] = client

        async def service(request):
            calls.append(request)
            role, path = request.url.path.lstrip("/").split("/", 1)
            path = "/" + path
            if fail or role not in owner_clients:
                return httpx.Response(503, json={"state": "unavailable"})
            return await owner_clients[role].get("https://gateway.test" + path,
                headers={**signed(b"", role, path, "operator-web", "GET"),
                         "x-citadel-observation-deadline": request.headers["x-citadel-observation-deadline"]})

        downstream = httpx.AsyncClient(transport=httpx.MockTransport(service))
        observer = ObservationClient("https://gateway.test", "fixture-key", self.reads,
                                     client=downstream, clock=self.clock)
        self.addAsyncCleanup(observer.close)
        config = AuthConfig("operator", hash_passphrase("fixture only passphrase"), "https://operator.test")
        app = create_app(config, observation=observer)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=config.origin) as browser:
            path = "/teams/evidence/runs/run1"
            self.assertEqual((await browser.get(path)).status_code, 401)
            self.assertEqual(calls, [])
            await browser.post("/login", headers={"origin": config.origin},
                data={"username": "operator", "password": "fixture only passphrase"})
            pages = await asyncio.gather(browser.get(path), browser.get(path))
            self.assertEqual(len(calls), 4)
            self.assertIn("&lt;Saved assessment&gt;", pages[0].text)
            self.assertIn("Private Operator inspection", pages[0].text)
            self.assertNotIn("DO NOT EXPORT", pages[0].text)
            citation = f'/teams/evidence/runs/run1/findings/{finding["artifact_id"]}/versions/1'
            self.assertIn(citation, pages[0].text)
            opened = await browser.get(citation)
            self.assertIn(finding["sha256"], opened.text)
            self.assertIn("Approval permits sharing", opened.text)
            private_draft = await browser.get("/teams/evidence/runs/run1/drafts/draft1/versions/1")
            self.assertIn("&lt;Saved assessment&gt;", private_draft.text)
            self.assertNotIn("DO NOT EXPORT", private_draft.text)
            csrf = re.search(r'name="csrf" value="([^"]+)"', pages[0].text)[1]
            fail = True
            stale = await browser.post(path + "/refresh", data={"csrf": csrf},
                                       headers={"origin": config.origin})
            self.assertIn("stale", stale.text)
            self.assertIn("unavailable", stale.text)
            self.assertIn("&lt;Saved assessment&gt;", stale.text)
            self.assertIn("1970-01-01T00:16:40", stale.text)
            self.assertNotIn("fixture-key", stale.text)

    async def test_legacy_prose_missing_history_and_failed_reads_are_not_reconstructed(self):
        await self.draft(private_notes="Legacy notes must stay private")
        runtime = self.runtime("evidence-assessor")
        legacy = await self.get(runtime, "/operator/runs/run1/drafts")
        self.assertEqual(legacy.json()["state"], "partial")
        self.assertIsNone(legacy.json()["drafts"][0]["assessment_prose"])
        self.assertNotIn("Legacy notes", legacy.text)
        unknown = await self.get(runtime, "/operator/runs/unknown/drafts")
        self.assertEqual(unknown.json()["state"], "partial")
        self.assertEqual(unknown.json()["reason"], "unavailable_history")
        self.assertEqual(unknown.json()["drafts"], [])

        class MissingLedger:
            async def read(self):
                raise OperationError("missing", "Offline fixture lost owner artifact source")

        from citadel.runtime.state import ScopedLedger
        runtime.artifact_ops.ledger = ScopedLedger(MissingLedger())
        before = len(self.reads.store.markers)
        unavailable = await self.get(runtime, "/operator/runs/run1/drafts")
        self.assertEqual((unavailable.status_code, unavailable.json()["state"]), (503, "unavailable"))
        self.assertEqual(len(self.reads.store.markers) - before, 1)

    async def test_insufficient_evidence_is_approved_for_sharing_and_pages_keep_exact_versions(self):
        self.data = reference("missing-width-replacement")
        ref = await self.draft(assessment_prose="Saved width gap explanation")
        approved = await self.release(ref)
        runtime = self.runtime("release-reviewer")
        path = f'/operator/runs/run1/findings/{approved["artifact_id"]}/versions/1'
        response = await self.get(runtime, path)
        self.assertEqual(response.json()["finding"]["classification"], "insufficient_evidence")
        self.assertIn("runway[1].width_ft: synthetic_missing_width", response.json()["finding"]["gap_reasons"])
        for version in range(2, 24):
            await self.draft(version, assessment_prose=f"Saved correction {version}")
        assessor = self.runtime("evidence-assessor")
        first = (await self.get(assessor, "/operator/runs/run1/drafts")).json()
        self.assertEqual(len(first["drafts"]), 20)
        second = (await self.get(assessor, "/operator/runs/run1/drafts/page/" + first["next_cursor"])).json()
        self.assertEqual([item["draft"]["version"] for item in second["drafts"]], [21, 22, 23])
        self.assertIsNone(second["next_cursor"])
        exact_draft = await self.get(assessor, "/operator/runs/run1/drafts/draft1/versions/23")
        self.assertEqual(exact_draft.status_code, 200)
        self.assertEqual(exact_draft.json()["draft"]["assessment_prose"], "Saved correction 23")

    async def test_exhaustion_and_expired_deadline_stop_physical_reads_without_workflow_pools(self):
        await self.draft(assessment_prose="Saved prose")
        runtime = self.runtime("evidence-assessor")
        self.reads.capacities = {"observation": 1, "recovery-proof": 1}
        response = await self.get(runtime, "/operator/runs/run1/drafts")
        self.assertEqual((response.status_code, response.json()["state"]), (429, "exhausted"))
        self.assertEqual(len(self.reads.store.markers), 1)

        path = "/operator/runs/run1/drafts"
        async with httpx.AsyncClient(transport=httpx.ASGITransport(
                app=agent_application(runtime, trust(runtime.workload)))) as client:
            response = await client.get("https://gateway.test" + path,
                headers={**signed(b"", runtime.workload, path, "operator-web", "GET"),
                         "x-citadel-observation-deadline": "999"})
        self.assertEqual(response.status_code, 503)
        self.assertEqual(len(self.reads.store.markers), 1)

    async def test_missing_draft_binding_is_partial_not_confirmed_artifact_absence(self):
        await self.draft(assessment_prose="Saved product with lost linkage")
        # Storage-boundary fault: retained bytes survive, original commit record does not.
        self.drafts.document["operations"].clear()
        response = await self.get(self.runtime("evidence-assessor"),
                                  "/operator/runs/run1/drafts/draft1/versions/1")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["state"], "partial")
        self.assertNotIn("draft", response.json())
        self.assertEqual(response.json()["reason"], "unavailable_historical_draft_binding")

    async def test_partial_release_history_does_not_hide_an_independently_bound_finding(self):
        first = await self.release(await self.draft())
        await self.release(await self.draft(2), op="release2")
        # Storage-boundary fault affects only the second exact release linkage.
        del self.findings.document["operations"]["evidence-assessor/release/release2"]
        runtime = self.runtime("release-reviewer")
        response = await self.get(runtime, f'/operator/runs/run1/findings/{first["artifact_id"]}/versions/1')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["bindings"]["finding"], first)
        page = (await self.get(runtime, "/operator/runs/run1/releases")).json()
        self.assertEqual(page["state"], "partial")
        self.assertEqual(page["releases"][0]["finding"], first)
        self.assertEqual(page["releases"][1]["outcome"], "unknown")
        self.assertNotIn("finding", page["releases"][1])


class ReviewOutcomeTests(AgentCase, unittest.IsolatedAsyncioTestCase):
    async def test_real_rejected_review_retains_exact_draft_link_not_a_finding_or_successful_release(self):
        ref = await self.save_draft()
        self.peers = PeerResponses(reference("missing-width-replacement"))
        runtime = await self.agent("release-reviewer", draft=ref, fixture="missing-width-replacement")
        status, _ = await self.execute(runtime)
        self.assertEqual(status["state"], "succeeded")
        reads = DeploymentReads(self.ledger.ticket_store, "fixture1", clock=self.clock)
        await reads.store.open_pool(reads.scope("observation"))
        runtime.observation_reads = reads
        path = "/operator/runs/run1/releases"
        async with httpx.AsyncClient(transport=httpx.ASGITransport(
                app=agent_application(runtime, trust(runtime.workload)))) as client:
            response = await client.get("https://gateway.test" + path,
                headers=signed(b"", runtime.workload, path, "operator-web", "GET"))
        self.assertEqual(response.status_code, 200)
        release = response.json()["releases"][0]
        self.assertEqual(release["outcome"], "rejected")
        self.assertEqual(release["draft"], ref)
        self.assertEqual(release["reason"], "draft_evidence_mismatch")
        self.assertNotIn("finding", release)
        self.assertNotIn("Private unit-fixture", response.text)
