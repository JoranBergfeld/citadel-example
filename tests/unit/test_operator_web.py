"""Offline Operator HTTP boundary; credentials below are labelled test data."""

import asyncio
import re
import threading
import unittest
from unittest.mock import patch

import httpx

from citadel.operator.web import AuthConfig, create_app, hash_passphrase


PASSWORD = "test only café passphrase"
ORIGIN = "https://operator.test"


class OperatorWebTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.now = 1000.0
        self.config = AuthConfig("test-operator", hash_passphrase(PASSWORD), ORIGIN)
        self.app = create_app(self.config, clock=lambda: self.now)
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app), base_url=ORIGIN,
        )

    async def asyncTearDown(self):
        await self.client.aclose()

    async def login(self, username="test-operator", password=PASSWORD):
        return await self.client.post("/login", headers={"origin": ORIGIN},
                                      data={"username": username, "password": password})

    async def test_protected_shell_requires_login_and_never_offers_simulated_execution(self):
        denied = await self.client.get("/")
        self.assertEqual(denied.status_code, 401)
        self.assertEqual(denied.headers["cache-control"], "no-store")
        logged_in = await self.login()
        self.assertEqual(logged_in.status_code, 303)
        cookie = logged_in.headers["set-cookie"]
        for flag in ("Secure", "HttpOnly", "SameSite=strict", "Path=/"):
            self.assertIn(flag, cookie)
        for forbidden in ("Domain=", "Max-Age=", "Expires="):
            self.assertNotIn(forbidden, cookie)
        shell = await self.client.get("/")
        self.assertEqual(shell.status_code, 200)
        for text in ("Comparison", "Replacement", "Exhaustion", "Reference Data",
                     "Evidence Review", "Exercise Planning", "unavailable"):
            self.assertIn(text, shell.text)
        for scenario in ("comparison", "replacement", "exhaustion"):
            self.assertIn(f'name="scenario" value="{scenario}"', shell.text)
        self.assertIn("disabled", shell.text)
        self.assertNotIn("<script", shell.text)
        self.assertEqual((await self.client.post("/run")).status_code, 403)

    async def test_mutations_require_origin_and_session_bound_csrf_and_logout_revokes(self):
        cross_origin = await self.client.post("/login", headers={"origin": "https://attacker.test"},
                                              data={"username": "test-operator", "password": PASSWORD})
        self.assertEqual(cross_origin.status_code, 403)
        self.assertEqual((await self.client.get("/")).status_code, 401)
        await self.login()
        csrf = re.search(r'name="csrf" value="([^"]+)"', (await self.client.get("/")).text)[1]
        for data, headers in (({}, {"origin": ORIGIN}), ({"csrf": csrf}, {}),
                              ({"csrf": "☃"}, {"origin": ORIGIN})):
            self.assertEqual((await self.client.post("/logout", data=data, headers=headers)).status_code, 403)
        self.assertEqual((await self.client.get("/logout")).status_code, 405)
        self.assertEqual((await self.client.get("/teams/evidence")).status_code, 200)
        response = await self.client.post("/logout", data={"csrf": csrf}, headers={"origin": ORIGIN})
        self.assertEqual(response.status_code, 303)
        self.assertEqual((await self.client.get("/")).status_code, 401)

    async def test_browser_form_policy_preserves_login_and_csrf_protected_logout(self):
        response = await self.client.get("/login")
        # Fetch suppresses navigation POST Origin under the no-referrer policy.
        origin = "null" if response.headers.get("referrer-policy") == "no-referrer" else ORIGIN
        response = await self.client.post("/login", headers={"origin": origin},
            data={"username": "test-operator", "password": PASSWORD})
        self.assertEqual(response.status_code, 303)
        response = await self.client.get("/")
        self.assertEqual(response.status_code, 200)
        csrf = re.search(r'name="csrf" value="([^"]+)"', response.text)[1]
        origin = "null" if response.headers.get("referrer-policy") == "no-referrer" else ORIGIN
        response = await self.client.post("/logout", headers={"origin": origin}, data={"csrf": csrf})
        self.assertEqual(response.status_code, 303)
        self.assertEqual((await self.client.get("/")).status_code, 401)
        response = await self.client.post("/login", headers={"origin": "null"},
            data={"username": "test-operator", "password": PASSWORD})
        self.assertEqual(response.status_code, 403)

    async def test_login_replaces_session_and_absolute_expiry_never_slides(self):
        await self.login()
        first_cookie = self.client.cookies.get("__Host-citadel-session")
        first_csrf = re.search(r'name="csrf" value="([^"]+)"', (await self.client.get("/")).text)[1]
        await self.login()
        second_cookie = self.client.cookies.get("__Host-citadel-session")
        self.assertNotEqual(first_cookie, second_cookie)
        self.assertNotIn(first_csrf, (await self.client.get("/")).text)
        response = await self.client.get("/", headers={"cookie": f"__Host-citadel-session={first_cookie}"})
        self.assertEqual(response.status_code, 401)
        restarted = create_app(self.config, clock=lambda: self.now)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=restarted), base_url=ORIGIN) as other:
            response = await other.get("/", headers={"cookie": f"__Host-citadel-session={second_cookie}"})
            self.assertEqual(response.status_code, 401)
        self.now += 8 * 3600 - 1
        self.assertEqual((await self.client.get("/")).status_code, 200)
        self.now += 1
        self.assertEqual((await self.client.get("/")).status_code, 401)

    async def test_failures_across_usernames_trigger_nonextending_cooldown(self):
        for i in range(5):
            response = await self.login(username=f"unknown-{i}")
            self.assertEqual((response.status_code, response.text), (401, "Authentication failed"))
        self.now += 299
        self.assertEqual((await self.login()).status_code, 401)
        restarted = create_app(self.config, clock=lambda: self.now)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=restarted), base_url=ORIGIN) as other:
            response = await other.post("/login", headers={"origin": ORIGIN},
                data={"username": "test-operator", "password": PASSWORD})
            self.assertEqual(response.status_code, 303)
        self.now += 1
        self.assertEqual((await self.login()).status_code, 303)

    async def test_rolling_verification_limit_and_untrusted_forwarded_address(self):
        for _ in range(10):
            self.assertEqual((await self.login()).status_code, 303)
        response = await self.client.post("/login", headers={"origin": ORIGIN, "x-forwarded-for": "1.2.3.4"},
                                          data={"username": "test-operator", "password": PASSWORD})
        self.assertEqual(response.status_code, 401)
        self.now += 60
        self.assertEqual((await self.login()).status_code, 303)

    async def test_oversized_duplicate_and_unbounded_input_is_denied(self):
        for body in ("username=x&password=" + "a" * 5000,
                     "username=test-operator&username=other&password=" + PASSWORD,
                     "username=test-operator&password=" + "a" * 129):
            response = await self.client.post("/login", content=body,
                headers={"origin": ORIGIN, "content-type": "application/x-www-form-urlencoded"})
            self.assertEqual(response.status_code, 401)
        self.assertEqual((await self.client.get("/", headers={"host": "attacker.test"})).status_code, 400)
        self.assertEqual((await self.client.get("/?token=forbidden")).status_code, 400)

    async def test_only_one_verification_can_run_and_excess_does_not_queue(self):
        entered, release = threading.Event(), threading.Event()

        def verify(*args):
            entered.set()
            if not release.wait(5):
                raise AssertionError("test verifier was not released")

        with patch("citadel.operator.web.Argon2id") as primitive:
            primitive.verify_phc_encoded.side_effect = verify
            pending = asyncio.create_task(self.login())
            try:
                self.assertTrue(await asyncio.to_thread(entered.wait, 2))
                denied = await self.login(username="another-user")
                self.assertEqual((denied.status_code, denied.text), (401, "Authentication failed"))
            finally:
                release.set()
                accepted = await pending
            self.assertEqual(accepted.status_code, 303)
            self.assertEqual(primitive.verify_phc_encoded.call_count, 1)

    async def test_invalid_length_failures_also_share_cooldown_without_expensive_work(self):
        for _ in range(5):
            self.assertEqual((await self.login(password="short")).status_code, 401)
        self.assertEqual((await self.login()).status_code, 401)
        self.now += 300
        self.assertEqual((await self.login()).status_code, 303)

    async def test_unicode_passphrase_at_character_limit_is_accepted_without_browser_truncation(self):
        phrase = "🛫" * 128
        configured = AuthConfig("test-operator", hash_passphrase(phrase), ORIGIN)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(configured)), base_url=ORIGIN,
        ) as client:
            login_page = (await client.get("/login")).text
            password_input = re.search(r'<input type="password"[^>]+>', login_page)[0]
            self.assertIn('maxlength="256"', password_input)
            response = await client.post("/login", headers={"origin": ORIGIN},
                data={"username": "test-operator", "password": phrase})
            self.assertEqual(response.status_code, 303)
            self.assertEqual((await client.get("/")).status_code, 200)

    async def test_authentication_audit_contains_outcomes_not_credentials_or_session_values(self):
        with self.assertLogs("citadel.operator.auth", level="INFO") as audit:
            await self.login(username="unknown-test-user")
            await self.login()
            cookie = self.client.cookies.get("__Host-citadel-session")
            csrf = re.search(r'name="csrf" value="([^"]+)"', (await self.client.get("/")).text)[1]
            await self.client.post("/logout", headers={"origin": ORIGIN}, data={"csrf": csrf})
        text = "\n".join(audit.output)
        for expected in ("login denied", "login accepted", "logout accepted"):
            self.assertIn(expected, text)
        for secret in (PASSWORD, "test-operator", "unknown-test-user", cookie, csrf, self.config.password_hash):
            self.assertNotIn(secret, text)
