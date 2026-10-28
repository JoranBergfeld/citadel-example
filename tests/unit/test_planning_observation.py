"""Offline owner, authenticated HTTP and saved planning presentation boundaries."""

import unittest
import asyncio
import re

import httpx

from agent_fixtures import AgentCase, PeerResponses, reference
from citadel.evidence.manifests import sha256
from citadel.operations.testing import MemoryLedger
from citadel.operations import OperationError
from citadel.runtime.agents import Runtime, agent_application
from citadel.runtime.observation import DeploymentReads, RunIndex, empty_index
from citadel.runtime.state import ScopedLedger
from citadel.operator.observation import ObservationClient
from citadel.operator.web import AuthConfig, create_app, hash_passphrase
from tests.unit.gateway_fixtures import signed, trust


class PlanningObservationTests(AgentCase, unittest.IsolatedAsyncioTestCase):
    async def planner(self, fixture="base-source"):
        self.peers = PeerResponses(reference(fixture))
        runtime = await self.agent("candidate-planner", fixture=fixture)
        context = MemoryLedger(clock=self.clock)
        context.document = empty_index()
        self.reads = DeploymentReads(context.ticket_store, "fixture1", clock=self.clock)
        await self.reads.store.open_pool(self.reads.scope("observation"))
        runtime.run_index = RunIndex(context, self.reads, clock=self.clock)
        runtime.observation_reads = self.reads
        return runtime

    async def get(self, runtime, projection, caller="operator-web", run="run1", deadline=None):
        path = f"/operator/runs/{run}/{projection}"
        headers = signed(b"", runtime.workload, path, caller, "GET")
        if deadline is not None:
            headers["x-citadel-observation-deadline"] = str(deadline)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(
                app=agent_application(runtime, trust(runtime.workload)))) as client:
            return await client.get("https://gateway.test" + path, headers=headers)

    async def test_saved_replacement_decisions_keep_every_candidate_without_draft_previews(self):
        runtime = await self.planner("missing-width-replacement")
        for finding in self.peers.findings.values():
            finding.update(private_notes="DO NOT EXPORT", assessment_prose="PRIVATE DRAFT",
                           prompts=["DO NOT EXPORT"], storage_path="/DO-NOT-EXPORT")
        status, _ = await self.execute(runtime)
        self.assertEqual(status["state"], "succeeded")
        before = len(self.reads.store.markers)
        response = await self.get(runtime, "decisions")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["outcome"], "complete")
        self.assertEqual([item["airport_ident"] for item in data["candidates"]],
                         ["EB01", "EB02", "EB03", "EB04"])
        gap, *selected = data["candidates"]
        self.assertEqual((gap["classification"], gap["release"], gap["selection"]),
                         ("insufficient_evidence", "approved", "skipped"))
        self.assertIn("runway[1].width_ft: synthetic_missing_width", gap["gap_reasons"])
        self.assertEqual(selected[0]["reason"], "complete_approved_finding")
        self.assertEqual(selected[1]["reason"], "complete_approved_finding")
        self.assertEqual(selected[-1]["reason"], "replacement_after_skipped_candidate")
        self.assertEqual(selected[-1]["finding"], self.peers.references[3])
        self.assertEqual(data["provenance"]["fixture"]["id"], "missing-width-replacement")
        self.assertEqual(len(self.reads.store.markers) - before, 2)
        self.assertNotIn("PRIVATE DRAFT", response.text)
        self.assertNotIn("DO NOT EXPORT", response.text)
        self.assertNotIn("DO-NOT-EXPORT", response.text)
        self.assertNotIn("planner_commentary", response.text)
        self.assertFalse(any(not task.done() for task in runtime.tasks))
        denied = await self.get(runtime, "decisions", caller="briefing-author")
        self.assertEqual(denied.status_code, 403)

    async def test_author_exposes_only_the_actual_saved_brief_and_its_exact_citations(self):
        self.peers.findings["finding1"].update(private_notes="DO NOT EXPORT",
            assessment_prose="PRIVATE DRAFT", credentials="DO NOT EXPORT")
        self.peers.references[0]["sha256"] = sha256(self.peers.findings["finding1"])
        runtime = await self.agent("briefing-author", findings=self.peers.references[:3],
                                   read_scopes=self.peers.scopes[:3])
        self.reads = DeploymentReads(self.ledger.ticket_store, "fixture1", clock=self.clock)
        await self.reads.store.open_pool(self.reads.scope("observation"))
        runtime.observation_reads = self.reads
        _, product = await self.execute(runtime)
        before = len(self.reads.store.markers)
        response = await self.get(runtime, "brief")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["brief"]["narrative"], product["narrative"])
        self.assertEqual(data["brief"]["citations"], self.peers.references[:3])
        self.assertEqual(data["bindings"]["brief"]["sha256"], sha256(product))
        self.assertEqual(len(self.reads.store.markers) - before, 1)
        self.assertNotIn("PRIVATE DRAFT", response.text)
        self.assertNotIn("DO NOT EXPORT", response.text)
        self.assertNotIn("read_scopes", response.text)
        self.assertNotIn('"findings"', response.text)
        other = await self.get(runtime, "brief", run="other")
        self.assertEqual(other.json()["state"], "partial")
        self.assertIsNone(other.json()["brief"])
        self.assertEqual(len(self.model_requests), 1)
        denied = await self.get(runtime, "brief", caller="candidate-planner")
        self.assertEqual(denied.status_code, 403)

    async def test_authenticated_planning_page_uses_real_owners_exact_links_and_independent_stale_times(self):
        planner = await self.planner("missing-width-replacement")
        child = self.peers.child

        async def copied_brief(*args):
            product = await child(*args)
            if args[3] == "briefing-author":
                product["narrative"] = "DO NOT DISPLAY PLANNER COPY"
            return product

        self.peers.child = copied_brief
        await self.execute(planner)
        self.ledger = MemoryLedger(clock=self.clock)
        author = await self.agent("briefing-author", fixture="missing-width-replacement",
            findings=self.peers.references[1:4], read_scopes=self.peers.scopes[1:4])
        author.observation_reads = self.reads
        _, saved_brief = await self.execute(author)
        owners = {}
        for owner in (planner, author):
            owners[owner.workload] = await self.stack.enter_async_context(httpx.AsyncClient(
                transport=httpx.ASGITransport(app=agent_application(owner, trust(owner.workload)))))
        calls, failed = [], set()

        async def service(request):
            calls.append(request)
            role, tail = request.url.path.lstrip("/").split("/", 1)
            if role in failed or role not in owners:
                return httpx.Response(503)
            path = "/" + tail
            return await owners[role].get("https://gateway.test" + path, headers={
                **signed(b"", role, path, "operator-web", "GET"),
                "x-citadel-observation-deadline": request.headers["x-citadel-observation-deadline"]})

        observer = ObservationClient("https://gateway.test", "DO-NOT-EXPORT-KEY", self.reads,
            client=httpx.AsyncClient(transport=httpx.MockTransport(service)), clock=self.clock)
        self.stack.push_async_callback(observer.close)
        config = AuthConfig("operator", hash_passphrase("fixture passphrase"), "https://operator.test")
        app = create_app(config, observation=observer)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=config.origin) as browser:
            path = "/teams/planning/runs/run1"
            self.assertEqual((await browser.get(path)).status_code, 401)
            self.assertEqual(calls, [])
            await browser.post("/login", headers={"origin": config.origin},
                data={"username": "operator", "password": "fixture passphrase"})
            before = len(self.reads.store.markers)
            pages = await asyncio.gather(browser.get(path), browser.get(path))
            page = pages[0]
            self.assertEqual(len(calls), 5)
            self.assertEqual(len(self.reads.store.markers) - before, 10)
            self.assertIn("replacement_after_skipped_candidate", page.text)
            self.assertIn("synthetic_missing_width", page.text)
            self.assertIn("Fictional unit-fixture prose", page.text)
            self.assertIn("Saved brief", page.text)
            self.assertIn(sha256(saved_brief), page.text)
            self.assertIn("Profile: fictional-airport-comparison · version 1", page.text)
            self.assertIn("Labelled synthetic overlay: missing-width-replacement · version 1", page.text)
            self.assertIn("Operator-only Evidence Review", page.text)
            self.assertIn("Check and recover", page.text)
            self.assertIn('data-run-observation="run1"', page.text)
            self.assertIn('data-execution="succeeded"', page.text)
            self.assertNotIn("DO NOT DISPLAY PLANNER COPY", page.text)
            citation = "/teams/evidence/runs/run1/findings/finding4/versions/1"
            self.assertIn(citation, page.text)
            self.assertIn(self.peers.references[3]["sha256"], page.text)
            self.assertNotIn("DO-NOT-EXPORT", page.text)
            csrf = re.search(r'name="csrf" value="([^"]+)"', page.text)[1]
            self.clock.now += 60
            failed.add("briefing-author")
            refreshed = await browser.post(path + "/refresh", data={"csrf": csrf},
                headers={"origin": config.origin})
            self.assertIn("stale", refreshed.text)
            self.assertIn("1970-01-01T00:16:40", refreshed.text)
            self.assertIn("1970-01-01T00:17:40", refreshed.text)
            self.assertIn(citation, refreshed.text)
            self.assertIn("Fictional unit-fixture prose", refreshed.text)
            self.assertEqual(len(calls), 10)
            await browser.post(path + "/refresh", data={"csrf": csrf},
                headers={"origin": config.origin, "x-citadel-refresh": "automatic"})
            self.assertEqual(len(calls), 10)

    async def test_legacy_completed_plan_uses_saved_product_not_current_reference_or_index_backfill(self):
        runtime = await self.planner("missing-width-replacement")
        for ref in self.peers.references:
            finding = self.peers.findings[ref["artifact_id"]]
            finding.update(artifact_id=ref["artifact_id"], version=ref["version"], run_id="run1")
            ref["sha256"] = sha256(finding)
        _, product = await self.execute(runtime)
        context = runtime.run_index.ledger.ledger.document["retained_runs"]["run1"]
        for name in ("decisions", "assessed", "assessed_complete", "provenance"):
            context.pop(name)
        before = len(self.peers.calls)
        response = await self.get(runtime, "decisions")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["state"], "ok")
        self.assertEqual(len(response.json()["candidates"]), 4)
        self.assertEqual(response.json()["candidates"][0]["finding"], self.peers.references[0])
        self.assertEqual(response.json()["candidates"][-1]["selection"], "selected")
        self.assertEqual(response.json()["bindings"]["product"]["sha256"], sha256(product))
        self.assertEqual(response.json()["bindings"]["product"]["artifact_id"], sha256("operator/invoke/run1"))
        self.assertEqual(len(self.peers.calls), before)
        self.assertNotIn("decisions", context)

    async def test_complete_saved_plan_does_not_hide_candidates_when_observation_context_is_partial(self):
        runtime = await self.planner("missing-width-replacement")
        await self.execute(runtime)
        entry = runtime.run_index.ledger.ledger.document["retained_runs"]["run1"]
        entry["assessed"] = entry["assessed"][:1]
        entry["decisions"] = entry["decisions"][:1]
        entry["assessed_complete"] = False
        response = await self.get(runtime, "decisions")
        self.assertEqual(len(response.json()["candidates"]), 4)
        self.assertEqual([item["airport_ident"] for item in response.json()["candidates"]
                          if item["selection"] == "selected"], ["EB02", "EB03", "EB04"])

    async def test_expected_pool_exhaustion_preserves_rejection_gaps_and_never_manufactures_a_brief(self):
        runtime = await self.planner("no-alternative")
        self.peers.rejected.add("EB02")
        await self.execute(runtime)
        response = await self.get(runtime, "decisions")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual((data["execution"], data["outcome"], data["pool_count"]),
                         ("succeeded", "bounded_pool_exhausted", 4))
        self.assertEqual(len(data["candidates"]), 4)
        rejected = data["candidates"][1]
        self.assertEqual((rejected["release"], rejected["selection"], rejected["classification"]),
                         ("rejected", "skipped", "unknown"))
        self.assertIsNone(self.peers.authored)
        self.assertNotIn("brief", data)

    async def test_author_interruption_keeps_saved_decisions_but_never_claims_expected_exhaustion(self):
        runtime = await self.planner()
        child = self.peers.child

        async def fail_author(*args):
            if args[3] == "briefing-author":
                raise OperationError("unavailable", "Controlled Author outage")
            return await child(*args)

        self.peers.child = fail_author
        await self.execute(runtime)
        calls = len(self.peers.calls)
        response = await self.get(runtime, "decisions")
        data = response.json()
        self.assertEqual((data["state"], data["execution"], data["outcome"]),
                         ("partial", "indeterminate", "incomplete"))
        self.assertEqual(data["reason"], "no_saved_plan")
        self.assertEqual([item["airport_ident"] for item in data["candidates"]],
                         ["EB01", "EB02", "EB03"])
        self.assertTrue(all(item["selection"] == "selected" for item in data["candidates"]))
        self.assertIsNone(data["bindings"]["product"])
        self.assertEqual(len(self.peers.calls), calls)

    async def test_lost_owner_source_is_unavailable_not_confirmed_missing_history(self):
        runtime = await self.planner()
        await self.execute(runtime)

        class LostSource:
            async def read(self):
                raise OperationError("missing", "/PRIVATE-STORAGE-PATH")

        runtime.ledger = ScopedLedger(LostSource())
        before = len(self.reads.store.markers)
        response = await self.get(runtime, "decisions")
        self.assertEqual((response.status_code, response.json()["state"]), (503, "unavailable"))
        self.assertEqual(len(self.reads.store.markers) - before, 2)
        self.assertNotIn("PRIVATE-STORAGE-PATH", response.text)

    async def test_planning_response_body_is_bounded_before_caching_with_no_automatic_retry(self):
        runtime = await self.planner()
        calls = []

        def service(request):
            calls.append(request)
            return httpx.Response(200, json={"state": "ok", "run_id": "run1",
                "bindings": {}, "brief": {"narrative": "x" * 262145}})

        observer = ObservationClient("https://gateway.test", "fixture-key", self.reads,
            client=httpx.AsyncClient(transport=httpx.MockTransport(service)), clock=self.clock)
        self.stack.push_async_callback(observer.close)
        before = len(self.reads.store.markers)
        first = await observer.planning("run1", "brief")
        self.assertEqual(first.state, "unavailable")
        self.assertIsNone(first.data)
        await observer.planning("run1", "brief")
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(self.reads.store.markers) - before, 1)
        self.assertEqual(runtime.tasks, set())

    async def test_owner_deadline_includes_storage_and_expired_requests_spend_nothing(self):
        runtime = await self.planner()
        await self.execute(runtime)
        before = len(self.reads.store.markers)
        expired = await self.get(runtime, "decisions", deadline=999)
        self.assertEqual(expired.status_code, 503)
        self.assertEqual(len(self.reads.store.markers), before)
        read = self.ledger.read

        async def late_storage():
            saved = await read()
            self.clock.now += 31
            return saved

        self.ledger.read = late_storage
        late = await self.get(runtime, "decisions", deadline=2000)
        self.assertEqual((late.status_code, late.json()["state"]), (503, "unavailable"))
        self.assertEqual(len(self.reads.store.markers) - before, 2)

    async def test_saved_author_citations_open_original_releases_never_newer_or_regenerated_findings(self):
        data, refs = reference(), []

        async def release(number, version):
            ident, op = f"EB{number:02}", f"draft{number}v{version}"
            draft = {"artifact_id": f"draft{number}", "version": version, "schema_version": 1,
                "run_id": "run1", "operation_id": op, "airport_ident": ident,
                **data.assess_airport(ident), "assessment_prose": "PRIVATE DRAFT",
                "private_notes": "DO NOT EXPORT"}
            await self.draft_store.accept("evidence-assessor", "submit-draft", op,
                {"draft": draft, "expected_version": version - 1}, run_id="run1", deadline=1800)
            owner = await self.draft_store.claim("evidence-assessor", "submit-draft", op, worker="fixture")
            status = await self.draft_store.submit_draft(owner, draft, expected_version=version - 1,
                                                        reference=data)
            ref = {key: status["result"][key] for key in ("artifact_id", "version", "sha256")}
            release_id = f"release{number}v{version}"
            await self.finding_store.accept("evidence-assessor", "release", release_id, {"draft": ref},
                                             run_id="run1", deadline=1800)
            owner = await self.finding_store.claim("evidence-assessor", "release", release_id, worker="fixture")
            status = await self.finding_store.release(owner, ref, drafts=self.draft_store, reference=data)
            return {key: status["result"][key] for key in ("artifact_id", "version", "sha256")}

        for number in range(1, 4):
            ref = await release(number, 1)
            refs.append(ref)
            self.peers.findings[ref["artifact_id"]] = await self.finding_store.get_finding(ref["artifact_id"], 1)
        author = await self.agent("briefing-author", findings=refs, read_scopes=self.peers.scopes[:3])
        self.reads = DeploymentReads(self.ledger.ticket_store, "fixture1", clock=self.clock)
        await self.reads.store.open_pool(self.reads.scope("observation"))
        author.observation_reads = self.reads
        await self.execute(author)
        newer = await release(1, 2)
        self.assertEqual(newer["artifact_id"], refs[0]["artifact_id"])
        saved = (await self.get(author, "brief")).json()
        self.assertEqual(saved["brief"]["citations"], refs)
        reviewer = Runtime("release-reviewer", MemoryLedger(clock=self.clock), model=None, peers=None,
            gateway_url="https://gateway.test", artifacts=self.artifacts, drafts=self.drafts,
            observation_reads=self.reads, clock=self.clock)
        exact = f'findings/{refs[0]["artifact_id"]}/versions/1'
        opened = await self.get(reviewer, exact)
        self.assertEqual(opened.json()["bindings"]["finding"], refs[0])
        self.assertNotIn("PRIVATE DRAFT", opened.text)
        del self.artifacts.document["findings"][refs[0]["artifact_id"]]["1"]
        missing = await self.get(reviewer, exact)
        self.assertEqual((missing.status_code, missing.json()["state"]), (404, "missing"))
        self.assertEqual((await self.get(author, "brief")).json()["brief"]["citations"], refs)
        self.assertEqual(len(self.model_requests), 1)

    async def test_legacy_partial_history_and_spent_allowance_do_not_infer_missing_decisions(self):
        runtime = await self.planner()
        await self.execute(runtime)
        entry = runtime.run_index.ledger.ledger.document["retained_runs"]["run1"]
        entry.pop("decisions")
        self.ledger.document["operations"].clear()
        partial = (await self.get(runtime, "decisions")).json()
        self.assertEqual((partial["state"], partial["execution"], partial["outcome"]),
                         ("partial", "unknown", "unknown"))
        self.assertTrue(all(item["selection"] == "unknown" for item in partial["candidates"]))
        self.assertTrue(all(item["finding"] is None for item in partial["candidates"]))
        missing = await self.get(runtime, "decisions", run="not-retained")
        self.assertEqual((missing.status_code, missing.json()["state"]), (404, "missing"))
        spent = len(self.reads.store.markers)
        self.reads.capacities = {"observation": spent + 1, "recovery-proof": 1}
        exhausted = await self.get(runtime, "decisions")
        self.assertEqual((exhausted.status_code, exhausted.json()["state"]), (429, "exhausted"))
        self.assertEqual(len(self.reads.store.markers), spent + 1)
        self.assertTrue(all(scope == self.reads.scope("observation")
                            for scope, _ in self.reads.store.markers))
