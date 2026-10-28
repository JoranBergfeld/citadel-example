"""Labelled offline Reference Data inspection fixtures, not live-demo evidence."""

import unittest
import httpx
import asyncio
import re

from citadel.operations import OperationError
from citadel.operations.testing import MemoryLedger
from citadel.runtime.observation import DeploymentReads, RunIndex, empty_index
from tests.unit.agent_fixtures import reference
from tests.unit.gateway_fixtures import signed, trust


class ReferenceObservationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.ledger = MemoryLedger(clock=lambda: 1000)
        self.ledger.document = empty_index()
        self.reads = DeploymentReads(self.ledger.ticket_store, "fixture1", clock=lambda: 1000)
        await self.ledger.ticket_store.open_pool(self.reads.scope("observation"))
        self.index = RunIndex(self.ledger, self.reads, clock=lambda: 1000)
        await self.index.register("operator", {
            "run_id": "run1", "operation_id": "run1", "fixture": "missing-width-replacement"})

    async def test_only_saved_assessed_candidates_expose_exact_raw_source_and_labelled_overlay(self):
        from citadel.runtime.reference_observation import ReferenceObservation
        base, overlay = reference(), reference("missing-width-replacement")
        await self.index.assessed("run1", "EB01", overlay.provenance, complete=True)
        owner = ReferenceObservation(self.ledger, self.reads, {
            "base-source": base, "missing-width-replacement": overlay})
        before = len(self.ledger.ticket_store.markers)
        observed = await owner.observe("run1")
        self.assertEqual(len(self.ledger.ticket_store.markers) - before, 1)
        self.assertEqual(observed["state"], "ok")
        self.assertEqual([item["airport_ident"] for item in observed["candidates"]], ["EB01"])
        candidate = observed["candidates"][0]
        self.assertEqual(candidate["original_source"]["runways"][0]["width_ft"]["raw"], "80")
        self.assertIsNone(candidate["assessment"]["evidence"]["runways"][0]["width_ft"]["raw"])
        self.assertEqual(candidate["assessment"]["classification"], "insufficient_evidence")
        self.assertEqual(candidate["overlay_differences"][0]["field"], "width_ft")
        self.assertEqual(candidate["overlay_differences"][0]["original"]["parsed"], 80)
        self.assertEqual(candidate["overlay_differences"][0]["overlay"]["quality_reasons"], ["synthetic_missing_width"])
        self.assertEqual(observed["bindings"]["source"], overlay.provenance)
        self.assertEqual(base.list_runways("EB01")["runways"][0]["width_ft"]["raw"], "80")
        self.assertNotIn("operator", str(observed))
        with self.assertRaises(OperationError) as caught:
            await self.index.assessed("run1", "EB01", base.provenance)
        self.assertEqual(caught.exception.code, "conflict")

    async def test_historical_source_profile_and_overlay_are_never_replaced_by_current_data(self):
        from citadel.runtime.reference_observation import ReferenceObservation
        from copy import deepcopy
        overlay = reference("missing-width-replacement")
        for field in ("source", "profile", "fixture"):
            with self.subTest(field=field):
                provenance = deepcopy(overlay.provenance)
                provenance[field]["sha256"] = "0" * 64
                self.ledger.document["retained_runs"]["run1"].update(
                    provenance=provenance, assessed=["EB01"])
                observed = await ReferenceObservation(self.ledger, self.reads, {
                    "base-source": reference(), "missing-width-replacement": overlay}).observe("run1")
                self.assertEqual((observed["state"], observed["reason"]), ("partial", "unavailable_source"))
                self.assertEqual(observed["candidates"], [])
        self.ledger.document["retained_runs"]["run1"].pop("assessed")
        old = await ReferenceObservation(self.ledger, self.reads, {}).observe("run1")
        self.assertEqual(old["reason"], "unavailable_assessed_bindings")

    async def test_saved_subset_remains_partial_and_overlay_never_discloses_unassessed_candidates(self):
        from citadel.runtime.reference_observation import ReferenceObservation
        data = reference("no-alternative")
        self.ledger.document["retained_runs"].clear()
        await self.index.register("operator", {
            "run_id": "run1", "operation_id": "run1", "fixture": "no-alternative"})
        owner = ReferenceObservation(self.ledger, self.reads, {"base-source": reference(), "no-alternative": data})
        empty = await owner.observe("run1")
        self.assertEqual(empty["state"], "empty")
        await self.index.assessed("run1", "EB01", data.provenance)
        partial = await owner.observe("run1")
        self.assertEqual((partial["state"], partial["reason"]), ("partial", "incomplete_assessed_context"))
        self.assertEqual([x["airport_ident"] for x in partial["candidates"]], ["EB01"])
        self.assertNotIn("EB02", str(partial))
        with self.assertRaises(OperationError) as missing:
            await owner.observe("notretained")
        self.assertEqual(missing.exception.code, "missing")

    async def test_http_owner_authorization_rejects_browser_bindings_and_meters_failed_reads(self):
        from citadel.runtime.reference_observation import ReferenceObservation
        from citadel.runtime.reference import reference_application
        data = reference("missing-width-replacement")
        await self.index.assessed("run1", "EB01", data.provenance, complete=True)
        observation = ReferenceObservation(self.ledger, self.reads, {
            "base-source": reference(), "missing-width-replacement": data})
        app = reference_application({}, trust("reference-data"), observation=observation)
        path = "/operator/reference/runs/run1"
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                    base_url="https://gateway.test") as http:
            before = len(self.ledger.ticket_store.markers)
            for url, caller in ((path, "candidate-planner"), (path + "/EB02", "operator-web"),
                                ("/mcp", "operator-web"), (path + "?source=current", "operator-web")):
                response = await http.get(url, headers=signed(b"", "reference-data", url.split("?")[0],
                                                             caller, "GET"))
                self.assertEqual(response.status_code, 403)
            self.assertEqual(len(self.ledger.ticket_store.markers), before)
            good = await http.get(path, headers=signed(b"", "reference-data", path, "operator-web", "GET"))
            self.assertEqual(good.status_code, 200)
            self.assertEqual([x["airport_ident"] for x in good.json()["candidates"]], ["EB01"])
            self.assertNotIn("EB02", good.text)
            self.assertEqual(len(self.ledger.ticket_store.markers) - before, 1)

            async def missing():
                raise OperationError("missing", "fixture removed historical source")

            self.ledger.read = missing
            failed = await http.get(path, headers=signed(b"", "reference-data", path, "operator-web", "GET"))
            self.assertEqual((failed.status_code, failed.json()["state"]), (503, "unavailable"))
            self.assertEqual(len(self.ledger.ticket_store.markers) - before, 2)

    async def test_authenticated_team_view_coalesces_actual_owner_reads_and_keeps_stale_exact_evidence(self):
        from citadel.runtime.reference_observation import ReferenceObservation
        from citadel.runtime.reference import reference_application
        from citadel.operator.reference_observation import ReferenceObservationClient
        from citadel.operator.web import AuthConfig, create_app, hash_passphrase
        data = reference("missing-width-replacement")
        await self.index.assessed("run1", "EB01", data.provenance, complete=True)
        owner = ReferenceObservation(self.ledger, self.reads, {
            "base-source": reference(), "missing-width-replacement": data})
        app = reference_application({}, trust("reference-data"), observation=owner)
        calls = []

        async def sign(request):
            calls.append(request)
            path = request.url.path.removeprefix("/reference-data")
            request.url = request.url.copy_with(path=path)
            request.headers.update(signed(b"", "reference-data", path, "operator-web", "GET"))

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                    event_hooks={"request": [sign]}) as downstream:
            observer = ReferenceObservationClient("https://gateway.test", "fixture-key", self.reads,
                                                 client=downstream, clock=lambda: 1000)
            config = AuthConfig("operator", hash_passphrase("labelled fixture passphrase"), "https://operator.test")
            web = create_app(config, reference_observation=observer)
            path = "/teams/reference/runs/run1"
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=web),
                                        base_url=config.origin) as browser:
                self.assertEqual((await browser.get(path)).status_code, 401)
                self.assertEqual(calls, [])
                await browser.post("/login", headers={"origin": config.origin},
                    data={"username": "operator", "password": "labelled fixture passphrase"})
                before = len(self.ledger.ticket_store.markers)
                pages = await asyncio.gather(browser.get(path), browser.get(path))
                self.assertEqual(len(calls), 1)
                self.assertEqual(len(self.ledger.ticket_store.markers) - before, 2)
                text = pages[0].text
                for expected in ("Raw", "Parsed", "Quality", "Original source", "synthetic-overlay",
                                 "synthetic_missing_width", "Comparison profile", "/teams/evidence/runs/run1",
                                 "Last successful", "EB01"):
                    self.assertIn(expected, text)
                self.assertNotIn("EB02", text)
                csrf = re.search(r'name="csrf" value="([^"]+)"', text)[1]
                denied = await browser.post(path + "/refresh", headers={"origin": config.origin},
                                            data={"csrf": "forged"})
                self.assertEqual(denied.status_code, 403)
                self.assertEqual(len(calls), 1)
                spent = sum(scope == self.reads.scope("observation")
                            for scope, _ in self.ledger.ticket_store.markers)
                self.reads.capacities = {"observation": spent, "recovery-proof": 1}
                stale = await browser.post(path + "/refresh", headers={"origin": config.origin},
                                           data={"csrf": csrf})
                self.assertIn("stale", stale.text)
                self.assertIn("exhausted", stale.text)
                self.assertIn("EB01", stale.text)
                self.assertEqual(len(calls), 1)

    async def test_real_blob_sdk_supporting_get_is_prepaid_and_truncated_body_never_retries(self):
        from azure.storage.blob.aio import BlobClient
        from citadel.evidence.manifests import canonical_bytes
        from citadel.operations.blob import AzureBlobLedger
        from citadel.runtime.reference_observation import ReferenceObservation
        from tests.operations.test_blob import WireCredential, WireResponse, WireTransport
        data = reference("missing-width-replacement")
        await self.index.assessed("run1", "EB01", data.provenance, complete=True)
        document = canonical_bytes(self.ledger.document)

        class IndexTransport(WireTransport):
            async def send(self, request, **kwargs):
                self.requests.append(request)
                response = WireResponse(request, status=206, content=document)
                response.fail_body = self.fail_body
                return response

        for truncated in (False, True):
            with self.subTest(truncated=truncated):
                transport = IndexTransport()
                transport.fail_body = truncated
                async with BlobClient("https://planning.blob.core.windows.net", "planner-operations",
                        "retained-runs-v1.json", credential=WireCredential(), transport=transport,
                        api_version="2026-10-06", retry_total=0, retry_connect=0, retry_read=0,
                        retry_status=0) as blob:
                    before = len(self.ledger.ticket_store.markers)
                    spent = sum(scope == self.reads.scope("observation")
                                for scope, _ in self.ledger.ticket_store.markers)
                    self.reads.capacities = {"observation": spent + 1, "recovery-proof": 1}
                    owner = ReferenceObservation(AzureBlobLedger(blob, clock=lambda: 1000),
                        self.reads, {"base-source": reference(), "missing-width-replacement": data})
                    if truncated:
                        with self.assertRaises(OperationError) as caught:
                            await owner.observe("run1")
                        self.assertEqual(caught.exception.code, "unavailable")
                    else:
                        self.assertEqual((await owner.observe("run1"))["state"], "ok")
                    self.assertEqual(len(transport.requests), 1)
                    self.assertEqual(len(self.ledger.ticket_store.markers), before + 1)
                    with self.assertRaises(OperationError) as caught:
                        await owner.observe("run1")
                    self.assertEqual(caught.exception.code, "exhausted")
                    self.assertEqual(len(transport.requests), 1)

    async def test_owner_expired_deadline_and_ambiguous_marker_never_dispatch_supporting_get(self):
        from citadel.runtime.reference_observation import ReferenceObservation
        dispatched = []
        read = self.ledger.read

        async def counted():
            dispatched.append("GET")
            return await read()

        self.ledger.read = counted
        owner = ReferenceObservation(self.ledger, self.reads, {})
        with self.assertRaises(OperationError) as expired:
            await owner.observe("run1", deadline=999)
        self.assertEqual(expired.exception.code, "deadline")
        self.assertEqual(dispatched, [])
        create = self.ledger.ticket_store.create_marker

        async def lost(*args):
            await create(*args)
            raise OperationError("indeterminate", "Fixture lost committed marker response")

        before = len(self.ledger.ticket_store.markers)
        self.ledger.ticket_store.create_marker = lost
        with self.assertRaises(OperationError) as ambiguous:
            await owner.observe("run1")
        self.assertEqual(ambiguous.exception.code, "indeterminate")
        self.assertEqual(len(self.ledger.ticket_store.markers), before + 1)
        self.assertEqual(dispatched, [])
