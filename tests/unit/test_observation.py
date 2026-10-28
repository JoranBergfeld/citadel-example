"""Labelled offline retained-run and deployment accounting fixtures."""

import asyncio
import unittest
import re

import httpx

from citadel.operations import OperationError
from citadel.operations.testing import MemoryLedger
from citadel.runtime.observation import DeploymentReads, RunIndex, empty_index
from citadel.operator.web import AuthConfig, create_app, hash_passphrase
from citadel.operator.observation import ObservationClient
from citadel.runtime.agents import Runtime, agent_application
from citadel.operations import Operations
from tests.unit.gateway_fixtures import signed, trust


class ObservationTests(unittest.IsolatedAsyncioTestCase):
    async def test_owner_reports_actual_inflight_model_request_not_persisted_running_label(self):
        entered, release = asyncio.Event(), asyncio.Event()

        class Model:
            async def explain(self, *args):
                entered.set()
                await release.wait()
                raise OperationError("unavailable", "Labelled controlled model failure")

        workload = MemoryLedger(clock=lambda: 1000)
        runtime = Runtime("candidate-planner", workload,
            model=Model(), peers=None, gateway_url="https://gateway.test",
            clock=lambda: 1000, run_index=self.index)
        await runtime.accept("operator", {
            "run_id": "active1", "operation_id": "active1", "fixture": "base-source"})
        await entered.wait()
        path = "/operator/runs/active1"
        try:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(
                    app=agent_application(runtime, trust("candidate-planner")))) as client:
                before = len(self.store.markers)
                response = await client.get("https://gateway.test" + path,
                    headers=signed(b"", "candidate-planner", path, "operator-web", "GET"))
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()["activity"], {
                    "owner": "candidate-planner", "run_id": "active1", "target": "model",
                    "kind": "inflight", "observed_at": 1000, "expires_at": 1015})
                self.assertEqual(len(self.store.markers) - before, 2)
                self.assertNotIn("worker", response.text)
                restarted = Runtime("candidate-planner", workload, model=None, peers=None,
                    gateway_url="https://gateway.test", clock=lambda: 1000, run_index=self.index)
                async with httpx.AsyncClient(transport=httpx.ASGITransport(
                        app=agent_application(restarted, trust("candidate-planner")))) as other:
                    saved_running = await other.get("https://gateway.test" + path,
                        headers=signed(b"", "candidate-planner", path, "operator-web", "GET"))
                    self.assertEqual(saved_running.json()["execution"], "running")
                    self.assertIsNone(saved_running.json()["activity"])
                release.set()
                await asyncio.gather(*runtime.tasks)
                finished = await client.get("https://gateway.test" + path,
                    headers=signed(b"", "candidate-planner", path, "operator-web", "GET"))
                self.assertIsNone(finished.json()["activity"])
        finally:
            release.set()
            await runtime.shutdown()

    async def test_auto_refresh_across_tabs_shares_recent_manual_work_and_stops_at_exhaustion(self):
        now, calls = [1000], []

        async def service(request):
            calls.append(request)
            if len(calls) == 3:
                return httpx.Response(429)
            return httpx.Response(200, json={"state": "ok", "execution": "running", "bindings": {}})

        async with httpx.AsyncClient(transport=httpx.MockTransport(service)) as client:
            observer = ObservationClient("https://gateway.test", "fixture-key", self.reads,
                                         client=client, clock=lambda: now[0])
            await observer.observe("run1")
            await observer.observe("run1", refresh=True, automatic=True)
            self.assertEqual(len(calls), 1)
            now[0] += 15
            await observer.observe("run1", refresh=True)
            await observer.observe("run1", refresh=True, automatic=True)
            self.assertEqual(len(calls), 2)
            now[0] += 15
            result = await observer.observe("run1", refresh=True, automatic=True)
            self.assertEqual((result.state, result.stale), ("exhausted", True))
            now[0] += 15
            await observer.observe("run1", refresh=True)
            self.assertEqual(len(calls), 3)

    async def test_failed_automatic_refresh_is_coalesced_across_tabs_without_losing_last_success(self):
        now, calls = [1000], []

        async def service(request):
            calls.append(request)
            return (httpx.Response(200, json={"state": "ok", "execution": "running", "bindings": {}})
                    if len(calls) == 1 else httpx.Response(503))

        async with httpx.AsyncClient(transport=httpx.MockTransport(service)) as client:
            observer = ObservationClient("https://gateway.test", "fixture-key", self.reads,
                                         client=client, clock=lambda: now[0])
            await observer.observe("run1")
            now[0] += 15
            first = await observer.observe("run1", refresh=True, automatic=True)
            second = await observer.observe("run1", refresh=True, automatic=True)
            self.assertEqual((first.state, second.state, second.last_success), ("unavailable", "unavailable", 1000))
            self.assertEqual((second.stale, second.data["execution"]), (True, "running"))
            self.assertEqual(len(calls), 2)

    async def test_control_invalidation_cannot_repopulate_cache_from_an_older_inflight_read(self):
        entered, release = asyncio.Event(), asyncio.Event()
        calls = []

        async def service(request):
            calls.append(request)
            entered.set()
            await release.wait()
            return httpx.Response(200, json={"state": "ok", "execution": "running", "bindings": {}})

        async with httpx.AsyncClient(transport=httpx.MockTransport(service)) as client:
            observer = ObservationClient("https://gateway.test", "fixture-key", self.reads,
                                         client=client, clock=lambda: 1000)
            pending = asyncio.create_task(observer.observe("run1"))
            await entered.wait()
            observer.invalidate("run1")
            release.set()
            old = await pending
            self.assertTrue(old.stale)
            await observer.observe("run1")
            self.assertEqual(len(calls), 2)

    async def asyncSetUp(self):
        self.ledger = MemoryLedger(clock=lambda: 1000)
        self.ledger.document = empty_index()
        self.store = self.ledger.ticket_store
        self.reads = DeploymentReads(self.store, "fixture1", clock=lambda: 1000)
        await self.store.open_pool(self.reads.scope("observation"))
        await self.store.open_pool(self.reads.scope("recovery-proof"))
        self.index = RunIndex(self.ledger, self.reads, clock=lambda: 1000)

    async def test_retained_submission_is_immutable_paginated_and_survives_restart(self):
        self.assertEqual((await self.index.page())["state"], "empty")
        for i in range(23):
            await self.index.register("operator", {
                "run_id": f"run{i:02}", "operation_id": f"run{i:02}", "fixture": "base-source"})
        first = await self.index.page()
        self.assertEqual(len(first["runs"]), 20)
        restarted = RunIndex(self.ledger, self.reads, clock=lambda: 1000)
        second = await restarted.page(first["next_cursor"])
        self.assertEqual([r["run_id"] for r in second["runs"]], ["run20", "run21", "run22"])
        self.assertIsNone(second["next_cursor"])
        self.assertEqual((await restarted.resolve("run00"))["caller"], "operator")
        with self.assertRaises(OperationError) as caught:
            await restarted.register("operator", {
                "run_id": "run00", "operation_id": "run00", "fixture": "no-alternative"})
        self.assertEqual(caught.exception.code, "conflict")
        self.assertEqual((await restarted.page())["runs"][0]["execution"], "unknown")
        restarted.capacity = 23
        with self.assertRaises(OperationError) as full:
            await restarted.register("operator", {
                "run_id": "extra", "operation_id": "extra", "fixture": "base-source"})
        self.assertEqual(full.exception.code, "exhausted")
        self.assertEqual(len((await restarted.page(first["next_cursor"]))["runs"]), 3)

    async def test_shared_deployment_markers_never_refund_ambiguous_admission(self):
        self.reads.capacities = {"observation": 2, "recovery-proof": 1}
        create = self.store.create_marker

        async def lost(*args):
            await create(*args)
            raise OperationError("indeterminate", "Fixture response lost")

        self.store.create_marker = lost
        with self.assertRaises(OperationError):
            async with self.reads.request():
                await self.reads.charge()
        self.store.create_marker = create
        self.store.cursors.clear()

        async def spend():
            try:
                async with self.reads.request():
                    await self.reads.charge()
                    return True
            except OperationError:
                return False

        self.assertEqual(sum(await asyncio.gather(spend(), spend())), 1)
        async with self.reads.request("recovery-proof"):
            await self.reads.charge()
        self.assertFalse(any("/invoke/" in scope for scope, _ in self.store.markers))

    async def test_real_service_charges_bindings_and_operation_reads_and_filters_private_fields(self):
        await self.index.register("operator", {
            "run_id": "partial1", "operation_id": "partial1", "fixture": "base-source"})
        runtime = Runtime("candidate-planner", MemoryLedger(clock=lambda: 1000),
                          model=None, peers=None, gateway_url="https://gateway.test", run_index=self.index)
        path = "/operator/runs/partial1"
        async with httpx.AsyncClient(transport=httpx.ASGITransport(
                app=agent_application(runtime, trust("candidate-planner")))) as client:
            before = len(self.store.markers)
            response = await client.get("https://gateway.test" + path,
                headers=signed(b"", "candidate-planner", path, "operator-web", "GET"))
            self.assertEqual(response.status_code, 200)
            self.assertEqual((response.json()["state"], response.json()["execution"]), ("partial", "unknown"))
            self.assertEqual(len(self.store.markers) - before, 2)
            self.assertNotIn("caller", response.text)
            self.assertNotIn("receipt", response.text)
            denied = await client.get("https://gateway.test/operations/partial1",
                headers=signed(b"", "candidate-planner", "/operations/partial1", "operator-web", "GET"))
            self.assertEqual(denied.status_code, 403)
            path = "/operator/runs/notindexed"
            missing = await client.get("https://gateway.test" + path,
                headers=signed(b"", "candidate-planner", path, "operator-web", "GET"))
            self.assertEqual((missing.status_code, missing.json()["state"]), (404, "missing"))

    async def test_cli_admission_failure_is_indexed_before_dispatch_and_never_replayed_by_observation(self):
        workload = MemoryLedger(clock=lambda: 1000)
        await workload.ticket_store.acquire_run("operator/invoke/blocker")
        runtime = Runtime("candidate-planner", workload, model=None, peers=None,
                          gateway_url="https://gateway.test", clock=lambda: 1000, run_index=self.index)
        payload = {"run_id": "blocked1", "operation_id": "blocked1", "fixture": "no-alternative"}
        with self.assertRaises(OperationError):
            await runtime.accept("operator", payload)
        self.assertEqual((await self.index.page())["runs"][0]["run_id"], "blocked1")
        async with self.reads.request():
            observed = await self.index.observe("blocked1", runtime.ledger)
        self.assertEqual(observed["execution"], "unknown")
        self.assertEqual(workload.ticket_store.active, "operator/invoke/blocker")
        self.assertEqual(runtime.tasks, set())

    async def test_missing_index_source_is_unavailable_not_a_confirmed_empty_history(self):
        class MissingLedger:
            async def read(self):
                raise OperationError("missing", "Fixture deleted historical index")

        missing = RunIndex(MissingLedger(), self.reads, clock=lambda: 1000)
        with self.assertRaises(OperationError) as caught:
            await missing.page()
        self.assertEqual(caught.exception.code, "unavailable")
        self.assertEqual(len(self.store.markers), 1)

    async def test_absent_retained_binding_collection_is_not_a_confirmed_empty_index(self):
        incomplete = RunIndex(MemoryLedger(clock=lambda: 1000), self.reads, clock=lambda: 1000)
        with self.assertRaises(OperationError) as caught:
            await incomplete.page()
        self.assertEqual(caught.exception.code, "unavailable")

    async def test_total_deadline_includes_admission_and_expiry_prevents_protocol_dispatch(self):
        now = [1000]
        admission = DeploymentReads(self.store, "fixture1", clock=lambda: now[0])
        create = self.store.create_marker
        dispatched = []

        async def late_marker(*args):
            result = await create(*args)
            now[0] += 31
            return result

        async def service(request):
            dispatched.append(request)
            return httpx.Response(200, json={"state": "empty", "runs": [], "next_cursor": None})

        self.store.create_marker = late_marker
        async with httpx.AsyncClient(transport=httpx.MockTransport(service)) as client:
            observer = ObservationClient("https://gateway.test", "fixture-key", admission,
                                         client=client, clock=lambda: now[0])
            result = await observer.observe()
        self.assertEqual(result.state, "unavailable")
        self.assertEqual(dispatched, [])
        self.assertEqual(len(self.store.markers), 1)

    async def test_missing_pool_descriptor_never_means_missing_run_and_never_opens_a_pool(self):
        self.store.pools.clear()
        dispatched = []

        async def service(request):
            dispatched.append(request)
            return httpx.Response(200, json={"state": "empty"})

        async with httpx.AsyncClient(transport=httpx.MockTransport(service)) as client:
            observer = ObservationClient("https://gateway.test", "fixture-key", self.reads,
                                         client=client, clock=lambda: 1000)
            result = await observer.observe("run1")
        self.assertEqual(result.state, "unavailable")
        self.assertEqual((self.store.pools, dispatched), (set(), []))

    async def test_selected_binding_uses_original_operation_not_new_inputs_or_private_products(self):
        payload = {"run_id": "saved1", "operation_id": "saved1", "fixture": "base-source"}
        await self.index.register("operator", payload)
        workload = MemoryLedger(clock=lambda: 1000)
        ops = Operations(workload, workload="candidate-planner", clock=lambda: 1000)
        await ops.accept("operator", "invoke", "saved1", payload, run_id="saved1", deadline=1800)
        owner = await ops.claim("operator", "invoke", "saved1", worker="fixture", lease_seconds=180)
        provenance = {
            "schema_version": 1, "source": {"kind": "test-data", "snapshot": "retained", "sha256": "a" * 64},
            "profile": {"id": "test-profile", "version": 1, "sha256": "b" * 64},
            "fixture": {"id": "base-source", "version": 1, "sha256": "c" * 64},
            "evidence_origin": "base-source", "private_path": "/private/fixture"}
        await ops.complete(owner, product={"provenance": provenance, "private_notes": "DO NOT SHARE"})
        from citadel.runtime.state import ScopedLedger
        async with self.reads.request():
            observed = await self.index.observe("saved1", ScopedLedger(workload))
        self.assertEqual(observed["execution"], "succeeded")
        self.assertEqual(observed["bindings"]["source"]["source"]["snapshot"], "retained")
        self.assertNotIn("DO NOT SHARE", str(observed))
        self.assertNotIn("private_path", str(observed))
        self.assertNotIn("operator", str(observed))
        await self.index.update("saved1", "succeeded")
        self.assertEqual((await self.index.page())["runs"][0]["execution"], "succeeded")

    async def test_authenticated_history_coalesces_refresh_and_retains_stale_data(self):
        calls, fail = [], False
        entered, release = asyncio.Event(), asyncio.Event()

        async def service(request):
            calls.append(request)
            entered.set()
            await release.wait()
            if fail:
                return httpx.Response(503, json={"state": "unavailable"})
            return httpx.Response(200, json={"state": "ok", "run_id": "run1",
                "fixture": "base-source", "input_hash": "a" * 64, "execution": "indeterminate",
                "bindings": {"inputs": "a" * 64, "source": None}})

        async with httpx.AsyncClient(transport=httpx.MockTransport(service)) as downstream:
            observation = ObservationClient("https://gateway.test", "fixture-credential", self.reads,
                                            client=downstream, clock=lambda: 1000)
            config = AuthConfig("operator", hash_passphrase("fixture only passphrase"), "https://operator.test")
            app = create_app(config, observation=observation)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                         base_url=config.origin) as browser:
                self.assertEqual((await browser.get("/history/run1")).status_code, 401)
                self.assertEqual(calls, [])
                await browser.post("/login", headers={"origin": config.origin},
                    data={"username": "operator", "password": "fixture only passphrase"})
                a = asyncio.create_task(browser.get("/history/run1"))
                await entered.wait()
                b = asyncio.create_task(browser.get("/history/run1"))
                await asyncio.sleep(0)
                release.set()
                pages = await asyncio.gather(a, b)
                self.assertEqual(len(calls), 1)
                self.assertIn("indeterminate", pages[0].text)
                csrf = re.search(r'name="csrf" value="([^"]+)"', pages[0].text)[1]
                fail = True
                denied = await browser.post("/history/run1/refresh", data={"csrf": "bad"},
                                             headers={"origin": config.origin})
                self.assertEqual(denied.status_code, 403)
                self.assertEqual(len(calls), 1)
                await browser.post("/history/run1/refresh", data={"csrf": csrf},
                                   headers={"origin": config.origin})
                stale = await browser.get("/history/run1")
                self.assertIn("indeterminate", stale.text)
                self.assertIn("stale", stale.text)
                self.assertIn("unavailable", stale.text)
                self.assertEqual(len(calls), 2)
                await browser.post("/logout", data={"csrf": csrf}, headers={"origin": config.origin})
                self.assertEqual((await browser.get("/history/run1")).status_code, 401)
                self.assertEqual(len(calls), 2)
