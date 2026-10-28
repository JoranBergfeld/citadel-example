"""Authenticated production handlers with controlled, local owner transport."""

import asyncio
import re
import unittest

import httpx

from citadel.operator.observation import ObservationClient
from citadel.operator.reference_observation import ReferenceObservationClient
from citadel.operator.recovery import RecoveryClient
from citadel.operator.web import AuthConfig, create_app, hash_passphrase
from citadel.operations.testing import MemoryLedger
from citadel.runtime.observation import DeploymentReads


class RecoveryWebTests(unittest.IsolatedAsyncioTestCase):
    async def test_control_invalidates_composed_evidence_and_reference_observations(self):
        store = MemoryLedger().ticket_store
        reads = DeploymentReads(store, "fixture1", clock=lambda: 1000)
        await store.open_pool(reads.scope("observation"))
        await store.open_pool(reads.scope("recovery-proof"))
        calls = []

        async def service(request):
            calls.append(request)
            if request.method == "POST":
                return httpx.Response(200, json={"state": "blocked", "run_id": "run1",
                    "request_id": "check1", "reason": "Live owner", "execution": "unknown"})
            return httpx.Response(200, json={"state": "empty", "bindings": {}})

        async with httpx.AsyncClient(transport=httpx.MockTransport(service)) as remote:
            observer = ObservationClient("https://gateway.test", "fixture-key", reads, client=remote,
                                         clock=lambda: 1000)
            reference = ReferenceObservationClient("https://gateway.test", "fixture-key", reads,
                                                   client=remote, clock=lambda: 1000)
            await observer.evidence("run1", "drafts")
            await reference.observe("run1")
            await RecoveryClient(observer, observations=(reference,)).check("run1", "check1")
            await observer.evidence("run1", "drafts")
            await reference.observe("run1")
            self.assertEqual(len(calls), 5)

    async def test_control_does_not_allow_inflight_pre_control_observation_to_repopulate_cache(self):
        store = MemoryLedger().ticket_store
        reads = DeploymentReads(store, "fixture1", clock=lambda: 1000)
        await store.open_pool(reads.scope("observation"))
        await store.open_pool(reads.scope("recovery-proof"))
        entered, release = asyncio.Event(), asyncio.Event()
        calls = []

        async def service(request):
            calls.append(request)
            if request.method == "POST":
                return httpx.Response(200, json={"state": "unknown", "run_id": "run1",
                    "request_id": "check1", "reason": "Unknown", "execution": "unknown"})
            if len(calls) == 1:
                entered.set()
                await release.wait()
                return httpx.Response(200, json={"state": "partial", "execution": "running"})
            return httpx.Response(200, json={"state": "partial", "execution": "failed_no_commit"})

        async with httpx.AsyncClient(transport=httpx.MockTransport(service)) as remote:
            observer = ObservationClient("https://gateway.test", "fixture-key", reads, client=remote,
                                         clock=lambda: 1000)
            old = asyncio.create_task(observer.observe("run1"))
            await entered.wait()
            await RecoveryClient(observer).check("run1", "check1")
            release.set()
            await old
            current = await observer.observe("run1")
            self.assertEqual(current.data["execution"], "failed_no_commit")
            self.assertEqual(len(calls), 3)

    async def test_auth_csrf_expiry_and_explicit_recovery_invalidate_history_without_retry(self):
        store = MemoryLedger().ticket_store
        reads = DeploymentReads(store, "fixture1", clock=lambda: 1000)
        await store.open_pool(reads.scope("observation"))
        await store.open_pool(reads.scope("recovery-proof"))
        now, calls = [0], []

        async def service(request):
            calls.append(request)
            if request.method == "POST":
                return httpx.Response(200, json={"state": "blocked", "run_id": "run1",
                    "request_id": request.url.path.split("/")[-1], "execution": "unknown",
                    "reason": "A live owner cannot be recovered", "retryable": False, "recorded_at": 1000})
            return httpx.Response(200, json={"state": "partial", "run_id": "run1",
                "fixture": "base-source", "execution": "indeterminate", "bindings": {}})

        async with httpx.AsyncClient(transport=httpx.MockTransport(service)) as remote:
            observer = ObservationClient("https://gateway.test", "fixture-key", reads, client=remote,
                                         clock=lambda: 1000)
            controller = RecoveryClient(observer)
            config = AuthConfig("operator", hash_passphrase("fixture only passphrase"), "https://operator.test")
            app = create_app(config, observation=observer, recovery=controller, clock=lambda: now[0])
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                         base_url=config.origin) as browser:
                self.assertEqual((await browser.post("/history/run1/recover")).status_code, 401)
                self.assertEqual(calls, [])
                await browser.post("/login", headers={"origin": config.origin},
                    data={"username": "operator", "password": "fixture only passphrase"})
                page = await browser.get("/history/run1")
                csrf = re.search(r'name="csrf" value="([^"]+)"', page.text)[1]
                request_id = re.search(r'name="request_id" value="([^"]+)"', page.text)[1]
                self.assertIn("Check and recover", page.text)
                self.assertNotIn("Retry this run", page.text)
                denied = await browser.post("/history/run1/recover",
                    data={"csrf": "bad", "request_id": request_id}, headers={"origin": config.origin})
                self.assertEqual(denied.status_code, 403)
                self.assertEqual(len(calls), 1)
                outcome = await browser.post("/history/run1/recover",
                    data={"csrf": csrf, "request_id": request_id}, headers={"origin": config.origin})
                self.assertIn("live owner", outcome.text)
                self.assertEqual(calls[-1].method, "POST")
                self.assertEqual(calls[-1].content, b"{}")
                self.assertIn("x-citadel-recovery-deadline", calls[-1].headers)
                self.assertEqual(len([s for s, _ in store.markers if "recovery-proof" in s]), 1)
                await browser.get("/history/run1")
                self.assertEqual(len(calls), 3, "Control invalidates mutable observation")
                now[0] = 8 * 3600
                expired = await browser.post("/history/run1/recover",
                    data={"csrf": csrf, "request_id": request_id}, headers={"origin": config.origin})
                self.assertEqual(expired.status_code, 401)
                await browser.post("/login", headers={"origin": config.origin},
                    data={"username": "operator", "password": "fixture only passphrase"})
                await browser.get("/history/run1")
                self.assertEqual(sum(r.method == "POST" for r in calls), 1)
