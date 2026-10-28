import base64
import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping
from uuid import uuid4
from citadel.acceptance.telemetry import correlate, emit, opaque, uncorrelated


INVOCATION_CALLERS = {
    "candidate-planner": frozenset({"operator"}),
    "evidence-assessor": frozenset({"candidate-planner"}),
    "release-reviewer": frozenset({"evidence-assessor"}),
    "briefing-author": frozenset({"candidate-planner"}),
    "reference-data": frozenset({"candidate-planner", "evidence-assessor", "release-reviewer"}),
}
FINDING_CALLERS = frozenset({"candidate-planner", "briefing-author"})
TOKEN = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
PIN = re.compile(r"[a-f0-9]{64}\Z")
XFCC_FIELD = re.compile(r'([A-Za-z]+)=(?:"((?:[^"\\\r\n]|\\.)*)"|([^;,"\r\n]*))(?:;|$)')


@dataclass(frozen=True)
class TrustConfiguration:
    target: str
    certificates: Mapping[str, tuple[datetime, datetime]]
    signing_keys: Mapping[str, str]

    def __post_init__(self):
        if self.target not in INVOCATION_CALLERS or not self.certificates or not self.signing_keys:
            raise ValueError("A known target, certificate allowlist and signing keys are required")
        for fingerprint, (start, end) in self.certificates.items():
            if not PIN.fullmatch(fingerprint) or start.tzinfo is None or end.tzinfo is None:
                raise ValueError("Certificate SHA256 and timezone-aware validity required")
            if (end - start).total_seconds() != 90 * 86400:
                raise ValueError("Gateway certificates must be valid for exactly 90 days")
        for key_id, key in self.signing_keys.items():
            if not TOKEN.fullmatch(key_id) or len(key.encode()) < 32:
                raise ValueError("Signing keys require an identifier and at least 32 bytes")

    @classmethod
    def from_json(cls, target: str, certificates: str, signing_keys: str):
        """Load public certificate metadata and allocated secret JSON, never environment fallbacks."""
        material = json.loads(certificates)
        return cls(
            target,
            {item["sha256"]: (
                datetime.fromisoformat(item["not_before"]),
                datetime.fromisoformat(item["not_after"]),
            ) for item in material},
            json.loads(signing_keys),
        )


class GatewayTrust:
    """Wrap the whole ASGI app, outside routers/mounts.

    ACA accepts and forwards client certificates; this wrapper requires the
    allowlisted certificate and signed, body-bound APIM context. Neither
    missing certificates nor caller/XFCC header forgery grant authorization. Each
    backend knows only its own context-validation key, never the gateway key.
    """

    def __init__(self, app, configuration: TrustConfiguration):
        self.app = app
        self.configuration = configuration

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            return await self.app(scope, receive, send)
        if scope["type"] != "http":
            await send({"type": "websocket.close", "code": 1008})
            return
        denial_reason = "invalid_gateway_context"
        try:
            headers = {}
            for key, value in scope["headers"]:
                name = key.decode("ascii").lower()
                if name in headers and (name.startswith("x-citadel-") or name == "x-forwarded-client-cert"):
                    raise ValueError("Duplicate trust header")
                headers[name] = value.decode("ascii")
            denial_reason = "certificate_required"
            certificate = headers["x-forwarded-client-cert"]
            denial_reason = "certificate_rejected"
            # One ingress-generated Envoy entry; no appended client-supplied chain.
            fingerprints = []
            position = 0
            while position < len(certificate):
                field = XFCC_FIELD.match(certificate, position)
                if field is None:
                    raise ValueError("Ambiguous forwarded certificate")
                if field[1] == "Hash":
                    fingerprints.append((field[2] if field[2] is not None else field[3]).lower())
                position = field.end()
            if len(fingerprints) != 1 or not PIN.fullmatch(fingerprints[0]):
                raise ValueError("Missing or ambiguous certificate fingerprint")
            start, end = self.configuration.certificates[fingerprints[0]]
            if not start <= datetime.now(timezone.utc) < end:
                raise ValueError("Certificate outside validity")
            denial_reason = "invalid_gateway_context"
            caller = headers["x-citadel-caller"]
            target = headers["x-citadel-target"]
            key_id = headers["x-citadel-key-id"]
            timestamp = headers["x-citadel-timestamp"]
            request_id = headers["x-citadel-request-id"]
            if target != self.configuration.target or not TOKEN.fullmatch(request_id):
                raise ValueError("Invalid target or correlation identifier")
            if not timestamp.isdecimal() or abs(time.time() - int(timestamp)) > 30:
                raise ValueError("Expired gateway context")
            key = self.configuration.signing_keys[key_id]
            if scope.get("query_string"):
                raise ValueError("Query strings are not authorized")
            body = bytearray()
            messages = []
            while True:
                message = await receive()
                if message["type"] != "http.request":
                    raise ValueError("Disconnected request")
                body.extend(message.get("body", b""))
                messages.append(message)
                if len(body) > 1024 * 1024:
                    raise ValueError("Request exceeds trust boundary limit")
                if not message.get("more_body", False):
                    break
            path = scope["path"]
            canonical = "\n".join((
                "v1", key_id, timestamp, request_id, caller, target,
                scope["method"], path, hashlib.sha256(body).hexdigest(),
            ))
            expected = hmac.digest(key.encode(), canonical.encode(), "sha256")
            supplied = base64.b64decode(headers["x-citadel-signature"], validate=True)
            if not hmac.compare_digest(expected, supplied):
                raise ValueError("Untrusted gateway context")
            denial_reason = "route_denied"
            action = self._authorize(caller, scope["method"], path, body)
        except (ValueError, KeyError, UnicodeError, TypeError, OverflowError):
            denial_id = uuid4().hex
            with uncorrelated():
                emit("authorization.denied", request_id=denial_id, status_code=403,
                     facts={"reason": denial_reason, "business_state": "not_dispatched"})
            await send({"type": "http.response.start", "status": 403, "headers": [
                (b"content-type", b"application/json"), (b"x-citadel-origin-request-id", denial_id.encode())]})
            await send({"type": "http.response.body", "body": b'{"error":"gateway_authorization_denied"}'})
            return
        scope = dict(scope)
        scope["citadel.caller"] = caller
        scope["citadel.action"] = action
        scope["citadel.request_id"] = request_id

        async def replay():
            return messages.pop(0) if messages else await receive()

        method = action
        if action in ("invoke", "status") and scope["method"] == "POST":
            method = json.loads(body)["method"]
        elif action == "mcp":
            payload = json.loads(body) if body else {}
            method = (payload["params"]["name"] if payload.get("method") == "tools/call"
                      else payload.get("method", "mcp." + scope["method"]))
        try:
            run_id = opaque(headers.get("x-citadel-run-id", request_id))
            operation_id = opaque(headers.get("x-citadel-operation-id", request_id))
        except ValueError:
            run_id = operation_id = request_id
        scope["citadel.run_id"] = run_id
        scope["citadel.operation_id"] = operation_id

        async def observed_send(message):
            if message["type"] == "http.response.start":
                emit("SendMessage.cached" if method == "SendMessage" and scope.get("citadel.cached") else method,
                     request_id=request_id, status_code=int(message["status"]))
            await send(message)

        with correlate(run_id, operation_id, caller):
            await self.app(scope, replay, observed_send)

    def _authorize(self, caller, method, path, body):
        target = self.configuration.target
        allowed = caller in INVOCATION_CALLERS[target]
        if (target == "candidate-planner" and caller == "operator-web"
                and method == "POST" and path == "/operator/scenarios"):
            return "operator-submit"
        if target == "evidence-assessor" and caller == "operator-web" and method == "GET":
            if re.fullmatch(r"/operator/runs/[A-Za-z0-9_-]{1,64}/drafts(?:/page/[A-Za-z0-9_-]{1,64})?", path):
                return "operator-drafts"
            if re.fullmatch(r"/operator/runs/[A-Za-z0-9_-]{1,64}/drafts/[A-Za-z0-9_-]{1,64}/versions/[0-9]{1,9}", path):
                return "operator-draft"
        if target == "release-reviewer" and caller == "operator-web" and method == "GET":
            if re.fullmatch(r"/operator/runs/[A-Za-z0-9_-]{1,64}/releases(?:/page/[A-Za-z0-9_-]{1,64})?", path):
                return "operator-releases"
            if re.fullmatch(r"/operator/runs/[A-Za-z0-9_-]{1,64}/findings/[A-Za-z0-9_-]{1,64}/versions/[0-9]{1,9}", path):
                return "operator-finding"
        if target == "candidate-planner" and caller == "operator-web" and method == "GET":
            if re.fullmatch(r"/operator/runs(?:/(?:page/)?[A-Za-z0-9_-]{1,64})?", path):
                return "operator-observe"
        if method == "GET" and path == "/.well-known/agent-card.json" and target != "reference-data" and allowed:
            return "discovery"
        if method == "GET" and re.fullmatch(r"/operations/[A-Za-z0-9_-]{1,128}", path) and allowed and target != "reference-data":
            return "status"
        if target == "release-reviewer" and caller in FINDING_CALLERS and method == "GET":
            if re.fullmatch(r"/findings/[A-Za-z0-9_-]{1,128}/versions/[A-Za-z0-9_-]{1,128}", path):
                return "findings-read"
        if target == "reference-data" and path == "/mcp" and allowed:
            if method in {"GET", "DELETE"}:
                return "mcp"
            if method == "POST":
                payload = json.loads(body)
                if not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0":
                    raise ValueError("Invalid MCP envelope")
                if payload.get("method") in {"initialize", "notifications/initialized", "ping", "tools/list"}:
                    return "mcp"
                if payload.get("method") == "tools/call" and isinstance(payload.get("params"), dict):
                    if payload["params"].get("name") in {"search_airports", "lookup_airport", "list_runways"}:
                        return "mcp"
        if target != "reference-data" and path == "/a2a" and method == "POST" and allowed:
            payload = json.loads(body)
            if isinstance(payload, dict) and payload.get("jsonrpc") == "2.0":
                action = {"SendMessage": "invoke", "GetTask": "status"}.get(payload.get("method"))
                if action:
                    return action
        raise ValueError("Route or protocol method is not authorized")
