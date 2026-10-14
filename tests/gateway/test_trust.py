import base64
import hashlib
import hmac
import json
import unittest
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import FastAPI, Request

from citadel.gateway import GatewayTrust, TrustConfiguration


NOW = datetime.now(timezone.utc)
PIN = "a" * 64
KEY = "a-test-only-signing-key-with-at-least-32-bytes"


def headers(body=b"", caller="candidate-planner", target="evidence-assessor",
            path="/a2a", method="POST", request_id="request-1"):
    timestamp = str(int(datetime.now(timezone.utc).timestamp()))
    canonical = "\n".join((
        "v1", "current", timestamp, request_id, caller, target, method, path,
        hashlib.sha256(body).hexdigest(),
    ))
    signature = base64.b64encode(hmac.digest(KEY.encode(), canonical.encode(), "sha256")).decode()
    return {
        "x-forwarded-client-cert": f"Hash={PIN};Subject=\"CN=gateway\";",
        "x-citadel-key-id": "current",
        "x-citadel-timestamp": timestamp,
        "x-citadel-request-id": request_id,
        "x-citadel-caller": caller,
        "x-citadel-target": target,
        "x-citadel-signature": signature,
    }


class TrustTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        app = FastAPI()

        @app.api_route("/{path:path}", methods=["GET", "POST", "DELETE"])
        async def echo(request: Request):
            return {
                "caller": request.scope["citadel.caller"],
                "action": request.scope["citadel.action"],
                "body": (await request.body()).decode(),
            }

        config = TrustConfiguration(
            target="evidence-assessor",
            certificates={PIN: (NOW - timedelta(days=1), NOW + timedelta(days=89))},
            signing_keys={"current": KEY},
        )
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=GatewayTrust(app, config)),
            base_url="https://backend",
        )

    async def asyncTearDown(self):
        await self.client.aclose()

    async def test_allowed_gateway_request_preserves_body_and_sets_validated_context(self):
        body = json.dumps({"jsonrpc": "2.0", "id": "1", "method": "SendMessage", "params": {}}).encode()
        response = await self.client.post("/a2a", content=body, headers=headers(body))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            "caller": "candidate-planner", "action": "invoke", "body": body.decode(),
        })

    async def test_forged_caller_with_approved_certificate_header_is_rejected(self):
        body = b'{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{}}'
        forged = headers(body)
        forged["x-citadel-caller"] = "operator"
        response = await self.client.post("/a2a", content=body, headers=forged)
        self.assertEqual(response.status_code, 403)

    async def test_adjacent_duplicate_certificate_fingerprints_are_rejected(self):
        body = b'{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{}}'
        forged = headers(body)
        forged["x-forwarded-client-cert"] = f"Hash={PIN};Hash={'b' * 64};"
        response = await self.client.post("/a2a", content=body, headers=forged)
        self.assertEqual(response.status_code, 403)

    async def test_route_matrix_separates_invocation_status_and_findings(self):
        expected = {
            "candidate-planner": {"operator"},
            "evidence-assessor": {"candidate-planner"},
            "release-reviewer": {"evidence-assessor"},
            "briefing-author": {"candidate-planner"},
            "reference-data": {"candidate-planner", "evidence-assessor", "release-reviewer"},
        }
        callers = ["operator", "candidate-planner", "evidence-assessor", "release-reviewer", "briefing-author", "reference-data", "unknown"]
        for target, allowed in expected.items():
            app = FastAPI()

            @app.api_route("/{path:path}", methods=["GET", "POST"])
            async def accepted(request: Request):
                return {"action": request.scope["citadel.action"]}

            config = TrustConfiguration(target, {PIN: (NOW - timedelta(days=1), NOW + timedelta(days=89))}, {"current": KEY})
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=GatewayTrust(app, config)), base_url="https://backend") as client:
                for caller in callers:
                    for method, path, body, route_allowed in [
                        ("POST", "/a2a", b'{"jsonrpc":"2.0","method":"SendMessage"}', target != "reference-data" and caller in allowed),
                        ("POST", "/a2a", b'{"jsonrpc":"2.0","method":"GetTask"}', target != "reference-data" and caller in allowed),
                        ("GET", "/operations/op1", b"", target != "reference-data" and caller in allowed),
                        ("GET", "/.well-known/agent-card.json", b"", target != "reference-data" and caller in allowed),
                        ("GET", "/findings/f1/versions/v1", b"", target == "release-reviewer" and caller in {"candidate-planner", "briefing-author"}),
                        ("POST", "/mcp", b'{"jsonrpc":"2.0","method":"tools/list"}', target == "reference-data" and caller in allowed),
                    ]:
                        with self.subTest(target=target, caller=caller, path=path, body=body):
                            response = await client.request(method, path, content=body, headers=headers(body, caller, target, path, method))
                            self.assertEqual(response.status_code, 200 if route_allowed else 403)

    async def test_modified_body_wrong_cert_missing_context_and_unknown_methods_fail_closed(self):
        valid = b'{"jsonrpc":"2.0","method":"SendMessage"}'
        for bad in [b"[]", b"invalid-json", b'{"jsonrpc":"2.0","method":"CancelTask"}', b'{"jsonrpc":"2.0","method":"SendMessage","x":1}']:
            response = await self.client.post("/a2a", content=bad, headers=headers(valid))
            self.assertEqual(response.status_code, 403)
        for change in [
            {"x-forwarded-client-cert": f"Hash={'b' * 64}"},
            {"x-forwarded-client-cert": f"Hash={PIN},Hash={PIN}"},
            {"x-citadel-target": "release-reviewer"},
            {"x-citadel-signature": "wrong"},
            {"x-citadel-timestamp": "0"},
        ]:
            forged = headers(valid) | change
            self.assertEqual((await self.client.post("/a2a", content=valid, headers=forged)).status_code, 403)
        self.assertEqual((await self.client.post("/a2a", content=valid)).status_code, 403)
        duplicate = list(headers(valid).items()) + [("x-citadel-caller", "operator")]
        self.assertEqual((await self.client.post("/a2a", content=valid, headers=duplicate)).status_code, 403)
        self.assertEqual((await self.client.post("/a2a?override=1", content=valid, headers=headers(valid))).status_code, 403)

    async def test_certificate_validity_is_exactly_ninety_days_not_calendar_months(self):
        with self.assertRaisesRegex(ValueError, "exactly 90 days"):
            TrustConfiguration("evidence-assessor", {PIN: (NOW, NOW + timedelta(days=91))}, {"current": KEY})

    async def test_valid_signatures_do_not_authorize_unlisted_methods_paths_or_oversized_bodies(self):
        for body in (
            b"[]",
            b'{"jsonrpc":"2.0","method":"CancelTask"}',
            b'{"jsonrpc":"0.3","method":"SendMessage"}',
            b"x" * (1024 * 1024 + 1),
        ):
            self.assertEqual((await self.client.post("/a2a", content=body, headers=headers(body))).status_code, 403)
        for path in ["/admin", "/a2a/", "/operations/a/b", "/findings/f1", "/docs"]:
            self.assertEqual((await self.client.get(path, headers=headers(path=path, method="GET"))).status_code, 403)

    async def test_context_key_rotation_revokes_old_key_without_accepting_unsigned_requests(self):
        body = b'{"jsonrpc":"2.0","method":"SendMessage"}'
        self.assertEqual((await self.client.post("/a2a", content=body, headers=headers(body))).status_code, 200)
        app = FastAPI()

        @app.post("/a2a")
        async def accepted():
            return {"accepted": True}

        config = TrustConfiguration(
            "evidence-assessor",
            {PIN: (NOW - timedelta(days=1), NOW + timedelta(days=89))},
            {"replacement": "b" * 43},
        )
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=GatewayTrust(app, config)), base_url="https://backend") as client:
            self.assertEqual((await client.post("/a2a", content=body, headers=headers(body))).status_code, 403)

    async def test_expired_allowlisted_certificate_is_denied(self):
        config = TrustConfiguration(
            "evidence-assessor",
            {PIN: (NOW - timedelta(days=91), NOW - timedelta(days=1))},
            {"current": KEY},
        )
        called = False

        async def forbidden(scope, receive, send):
            nonlocal called
            called = True

        body = b'{"jsonrpc":"2.0","method":"SendMessage"}'
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=GatewayTrust(forbidden, config)), base_url="https://backend") as client:
            self.assertEqual((await client.post("/a2a", content=body, headers=headers(body))).status_code, 403)
        self.assertFalse(called)


if __name__ == "__main__":
    unittest.main()
