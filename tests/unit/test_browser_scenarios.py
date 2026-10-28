"""Authenticated real backend boundary with a controlled hosted transport."""

import re
import unittest

import httpx

from citadel.operator.observation import ObservationClient
from citadel.operator.submission import SubmissionClient
from citadel.operator.web import AuthConfig, create_app, hash_passphrase
from citadel.operations.testing import MemoryLedger
from citadel.runtime.observation import DeploymentReads
from citadel.runtime.submission import submission_run


class BrowserScenarioTests(unittest.IsolatedAsyncioTestCase):
    async def test_current_run_refresh_composes_evidence_review_but_reopened_terminal_detail_is_manual(self):
        requests, now, terminal = [], [1000], [False]

        async def service(request):
            requests.append(request)
            if "/candidate-planner/" in request.url.path:
                return httpx.Response(200, json={"state": "ok",
                    "execution": "succeeded" if terminal[0] else "running",
                    "fixture": "base-source", "bindings": {}})
            return httpx.Response(200, json={"state": "empty", "bindings": {}})

        ledger = MemoryLedger(clock=lambda: now[0])
        reads = DeploymentReads(ledger.ticket_store, "fixture1", clock=lambda: now[0])
        await ledger.ticket_store.open_pool(reads.scope("observation"))
        async with httpx.AsyncClient(transport=httpx.MockTransport(service)) as downstream:
            observer = ObservationClient("https://gateway.test", "fixture-key", reads,
                                         client=downstream, clock=lambda: now[0])
            config = AuthConfig("operator", hash_passphrase("fixture only passphrase"), "https://operator.test")
            async with httpx.AsyncClient(transport=httpx.ASGITransport(
                    app=create_app(config, observation=observer)), base_url=config.origin) as browser:
                await browser.post("/login", headers={"origin": config.origin},
                    data={"username": "operator", "password": "fixture only passphrase"})
                await browser.get("/runs/run1")
                path = "/teams/evidence/runs/run1"
                current = await browser.get(path)
                self.assertIn('data-run-observation="run1"', current.text)
                self.assertIn("Private Operator inspection", current.text)
                self.assertEqual(len(requests), 3)
                csrf = re.search(r'name="csrf" value="([^"]+)"', current.text)[1]
                now[0] += 15
                terminal[0] = True
                completed = await browser.post(path + "/refresh", data={"csrf": csrf},
                    headers={"origin": config.origin, "x-citadel-refresh": "automatic"})
                self.assertIn('data-execution="succeeded"', completed.text)
                self.assertIn("Private Operator inspection", completed.text)
                self.assertEqual(len(requests), 6)
                reopened = await browser.get(path)
                self.assertNotIn('src="/scenario-client.mjs"', reopened.text)
                self.assertEqual(len(requests), 6)

    async def test_authenticated_run_uses_only_narrow_hosted_caller_and_lost_response_reopens_identity(self):
        requests = []

        async def service(request):
            requests.append(request)
            if request.method == "POST":
                raise httpx.ReadTimeout("Labelled lost response")
            return httpx.Response(200, json={"state": "partial", "execution": "unknown",
                "fixture": "base-source", "bindings": {"inputs": "a" * 64, "source": None}})

        ledger = MemoryLedger(clock=lambda: 1000)
        reads = DeploymentReads(ledger.ticket_store, "fixture1", clock=lambda: 1000)
        await ledger.ticket_store.open_pool(reads.scope("observation"))
        async with httpx.AsyncClient(transport=httpx.MockTransport(service)) as downstream:
            observer = ObservationClient("https://gateway.test", "server-only-fixture-key", reads,
                                         client=downstream, clock=lambda: 1000)
            submit = SubmissionClient(observer)
            config = AuthConfig("operator", hash_passphrase("fixture only passphrase"), "https://operator.test")
            app = create_app(config, observation=observer, submission=submit)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                         base_url=config.origin) as browser:
                self.assertEqual((await browser.post("/run")).status_code, 401)
                await browser.post("/login", headers={"origin": config.origin},
                    data={"username": "operator", "password": "fixture only passphrase"})
                page = await browser.get("/")
                csrf = re.search(r'name="csrf" value="([^"]+)"', page.text)[1]
                request_id = re.search(r'name="request_id" value="([^"]+)"', page.text)[1]
                self.assertNotIn("disabled", page.text)
                for values in ({"csrf": csrf, "scenario": "replacement"},
                               {"csrf": "bad", "scenario": "comparison", "request_id": request_id}):
                    denied = await browser.post("/run", data=values, headers={"origin": config.origin})
                    self.assertIn(denied.status_code, (400, 403))
                self.assertEqual(requests, [])
                body = {"csrf": csrf, "scenario": "comparison", "request_id": request_id}
                response = await browser.post("/run", data=body, headers={"origin": config.origin})
                self.assertEqual(response.status_code, 303)
                self.assertEqual(response.headers["location"], "/runs/" + submission_run(request_id))
                reopened = await browser.get(response.headers["location"])
                self.assertIn("unknown", reopened.text)
                self.assertNotIn("server-only-fixture-key", reopened.text)
                self.assertIn('src="/scenario-client.mjs"', reopened.text)
                self.assertEqual(str(requests[0].url), "https://gateway.test/candidate-planner/operator/scenarios")
                self.assertEqual(requests[0].headers["Ocp-Apim-Subscription-Key"], "server-only-fixture-key")
                self.assertNotIn("csrf", requests[0].content.decode())
                self.assertEqual(len([r for r in requests if r.method == "POST"]), 1)
                self.assertIn("script-src 'self'", reopened.headers["content-security-policy"])
