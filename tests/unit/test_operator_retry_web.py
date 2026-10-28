"""Real login, form, client, gateway trust and owner handler with local storage."""

import json
import asyncio
import re
import unittest

import httpx
import httpx2

from citadel.operator.observation import ObservationClient
from citadel.operator.recovery import RecoveryClient
from citadel.operator.web import AuthConfig, create_app, hash_passphrase
from tests.unit import test_operator_recovery as recovery_fixture
from tests.unit.gateway_fixtures import signed
from tests.unit.agent_fixtures import FIXTURES, PeerResponses, reference
from citadel.runtime.model import GovernedModel


class RetryWebTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = recovery_fixture.RecoveryTests.asyncSetUp
    check = recovery_fixture.RecoveryTests.check

    async def test_confirmed_backend_retry_runs_once_and_observes_saved_result(self):
        self.clock.now = 1181
        await self.check()
        model_calls, controls = [], []

        async def model_response(request):
            model_calls.append(request)
            return httpx2.Response(200, json=json.loads((FIXTURES / "model.json").read_text()))

        async def service(request):
            if request.method == "POST":
                controls.append(request)
            path = request.url.path.removeprefix("/candidate-planner")
            return await self.client.request(request.method, "https://gateway.test" + path,
                content=request.content, headers=signed(
                    request.content, "candidate-planner", path, "operator-web", request.method))

        async with httpx2.AsyncClient(transport=httpx2.MockTransport(model_response)) as model_http:
            self.runtime.model = GovernedModel("candidate-planner", "https://gateway.test", "fixture-key",
                "fixture-model", http_client=model_http, clock=self.clock, sleep=self.clock.sleep)
            self.addAsyncCleanup(self.runtime.model.close)
            self.runtime.peers = PeerResponses(reference())
            self.addAsyncCleanup(self.runtime.shutdown)
            async with httpx.AsyncClient(transport=httpx.MockTransport(service)) as remote:
                observer = ObservationClient("https://gateway.test", "fixture-key", self.reads,
                                             client=remote, clock=self.clock)
                config = AuthConfig("operator", hash_passphrase("fixture only passphrase"), "https://operator.test")
                app = create_app(config, observation=observer, recovery=RecoveryClient(observer))
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                             base_url=config.origin) as browser:
                    await browser.post("/login", headers={"origin": config.origin},
                        data={"username": "operator", "password": "fixture only passphrase"})
                    page = await browser.get("/runs/run1")
                    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text)[1]
                    values = {"csrf": csrf, "request_id": "confirmed", "confirmed": "yes"}
                    result = await browser.post("/history/run1/retry",
                        data=values, headers={"origin": config.origin})
                    self.assertIn("retry_admitted", result.text)
                    await asyncio.gather(*self.runtime.tasks)
                    duplicate = await browser.post("/history/run1/retry",
                        data=values, headers={"origin": config.origin})
                    self.assertIn("retry_admitted", duplicate.text)
                    page = await browser.get("/runs/run1")
                    self.assertIn("Execution: succeeded", page.text)
                    self.assertIn("EB01", page.text)
                    self.assertNotIn('name="confirmed"', page.text)
                    self.assertEqual(len(model_calls), 1)
                    self.assertEqual(len(controls), 2)
                    self.assertEqual(json.loads(controls[0].content), {"confirmed": True})

    async def test_confirmation_auth_denial_cache_invalidation_and_no_replay_after_relogin(self):
        self.clock.now = 1181
        await self.check()
        calls = []

        async def service(request):
            calls.append(request)
            path = request.url.path.removeprefix("/candidate-planner")
            return await self.client.request(request.method, "https://gateway.test" + path,
                content=request.content, headers=signed(
                    request.content, "candidate-planner", path, "operator-web", request.method))

        async with httpx.AsyncClient(transport=httpx.MockTransport(service)) as remote:
            observer = ObservationClient("https://gateway.test", "fixture-key", self.reads,
                                         client=remote, clock=self.clock)
            now = [0]
            config = AuthConfig("operator", hash_passphrase("fixture only passphrase"), "https://operator.test")
            app = create_app(config, observation=observer, recovery=RecoveryClient(observer), clock=lambda: now[0])
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                         base_url=config.origin) as browser:
                self.assertEqual((await browser.post("/history/run1/retry")).status_code, 401)
                self.assertEqual(calls, [])
                await browser.post("/login", headers={"origin": config.origin},
                    data={"username": "operator", "password": "fixture only passphrase"})
                page = await browser.get("/history/run1")
                self.assertIn("Retry this run", page.text)
                self.assertIn('name="confirmed"', page.text)
                csrf = re.search(r'name="csrf" value="([^"]+)"', page.text)[1]
                values = {"csrf": csrf, "request_id": "retry-browser", "confirmed": "yes"}
                denied = await browser.post("/history/run1/retry",
                    data=values | {"csrf": "bad"}, headers={"origin": config.origin})
                self.assertEqual(denied.status_code, 403)
                unconfirmed = await browser.post("/history/run1/retry",
                    data={"csrf": csrf, "request_id": "retry-browser"}, headers={"origin": config.origin})
                self.assertEqual(unconfirmed.status_code, 400)
                self.assertEqual(len(calls), 1)
                # Expire the original run after rendering an eligible hint. The
                # actual owning service must still refuse this confirmed form.
                self.clock.now = 1900
                result = await browser.post("/history/run1/retry",
                    data=values, headers={"origin": config.origin})
                self.assertIn("blocked", result.text)
                self.assertIn("Original deadline", result.text)
                self.assertEqual(calls[-1].url.path,
                    "/candidate-planner/operator/runs/run1/retry/retry-browser")
                self.assertEqual(json.loads(calls[-1].content), {"confirmed": True})
                await browser.get("/history/run1")
                self.assertEqual(len(calls), 3, "Retry invalidates the mutable observation")
                now[0] = 8 * 3600
                self.assertEqual((await browser.post("/history/run1/retry",
                    data=values, headers={"origin": config.origin})).status_code, 401)
                await browser.post("/login", headers={"origin": config.origin},
                    data={"username": "operator", "password": "fixture only passphrase"})
                await browser.get("/history/run1")
                self.assertEqual(sum(r.method == "POST" for r in calls), 1)
                self.assertEqual(self.runtime.tasks, set())
