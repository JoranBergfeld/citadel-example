"""Single-process Operator application; no direct team-data access."""

import asyncio
from collections import deque
from contextlib import asynccontextmanager
from dataclasses import dataclass
import hashlib
import hmac
from html import escape
import logging
import os
import re
import secrets
import threading
import time
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4
from pathlib import Path

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route


LOG = logging.getLogger("citadel.operator.auth")
COOKIE = "__Host-citadel-session"
MAX_BODY = 4096


def hash_passphrase(passphrase):
    if not isinstance(passphrase, str) or not 15 <= len(passphrase) <= 128:
        raise ValueError("Passphrase must contain 15-128 characters")
    return Argon2id(salt=secrets.token_bytes(16), length=32, iterations=3,
                    lanes=1, memory_cost=65536).derive_phc_encoded(passphrase.encode("utf-8"))


@dataclass(frozen=True, repr=False)
class AuthConfig:
    username: str
    password_hash: str
    origin: str

    def __post_init__(self):
        if (not isinstance(self.username, str) or not 1 <= len(self.username) <= 128
                or any(ord(c) < 32 for c in self.username)):
            raise ValueError("Invalid Operator authentication configuration")
        if not isinstance(self.password_hash, str) or not re.fullmatch(
            r"\$argon2id\$v=19\$m=65536,t=3,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}",
            self.password_hash,
        ):
            raise ValueError("Invalid Operator authentication configuration")
        # Validate the encoding using the maintained verifier, not just its prefix.
        try:
            Argon2id.verify_phc_encoded(b"configuration-validation", self.password_hash)
        except InvalidKey:
            pass
        parsed = urlsplit(self.origin)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.path or parsed.query or parsed.fragment or self.origin != f"https://{parsed.netloc}"):
            raise ValueError("HTTPS Operator origin required")

    @classmethod
    def from_environment(cls):
        try:
            return cls(os.environ["CITADEL_OPERATOR_USERNAME"], os.environ["CITADEL_OPERATOR_PASSWORD_HASH"],
                       os.environ["CITADEL_OPERATOR_ORIGIN"])
        except (KeyError, ValueError, TypeError):
            raise ValueError("Invalid Operator authentication configuration") from None


class Authentication:
    def __init__(self, config, clock):
        self.config, self.clock = config, clock
        self.lock = threading.Lock()
        self.session_lock = threading.Lock()
        self.failures, self.verifications = deque(), deque()
        self.cooldown_until = 0
        self.session = None

    def failed(self, now):
        self.failures.append(now)
        if len(self.failures) >= 5:
            self.cooldown_until = now + 300
            self.failures.clear()
        LOG.info("login denied")

    def login(self, username, password):
        if not self.lock.acquire(blocking=False):
            LOG.info("login denied")
            return None
        try:
            now = self.clock()
            while self.failures and self.failures[0] <= now - 300:
                self.failures.popleft()
            while self.verifications and self.verifications[0] <= now - 60:
                self.verifications.popleft()
            if now < self.cooldown_until or len(self.verifications) >= 10:
                LOG.info("login denied")
                return None
            if not (isinstance(username, str) and 1 <= len(username) <= 128
                    and isinstance(password, str) and 15 <= len(password) <= 128):
                self.failed(now)
                return None
            self.verifications.append(now)
            valid = True
            try:
                Argon2id.verify_phc_encoded(password.encode("utf-8"), self.config.password_hash)
            except InvalidKey:
                valid = False
            valid = hmac.compare_digest(username.encode(), self.config.username.encode()) and valid
            if not valid:
                self.failed(now)
                return None
            token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            with self.session_lock:
                self.session = (hashlib.sha256(token.encode()).digest(), csrf, self.clock() + 8 * 3600)
            LOG.info("login accepted")
            return token
        finally:
            self.lock.release()

    def context(self, token):
        with self.session_lock:
            return self._context(token)

    def _context(self, token):
        if (not self.session or not token or len(token) != 43 or self.clock() >= self.session[2]
                or not hmac.compare_digest(hashlib.sha256(token.encode()).digest(), self.session[0])):
            return None
        return self.session[1]

    def logout(self, token, csrf):
        with self.session_lock:
            expected = self._context(token)
            if not expected or not hmac.compare_digest(csrf.encode(), expected.encode()):
                return False
            self.session = None
            return True


STYLE = """
:root{color-scheme:light dark;font-family:system-ui,sans-serif}
body{max-width:70rem;margin:auto;padding:2rem;line-height:1.6;background:#101b28;color:#e5edf5}
a{color:#8ed8eb}header,nav{display:flex;gap:1.5rem;flex-wrap:wrap;align-items:center}
header{justify-content:space-between;border-bottom:1px solid #536478}
main{padding:1.5rem 0}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(16rem,1fr));gap:1rem}
article,aside{border:1px solid #536478;border-radius:.8rem;padding:1.2rem;margin:1rem 0}
button,input{font:inherit;padding:.6rem}button:disabled{opacity:.7}label{display:block;margin:1rem 0}
input{max-width:90%;display:block}footer{border-top:1px solid #536478;margin-top:2rem}
input[type=radio]{display:inline}fieldset{border:0;padding:0}
:focus-visible{outline:3px solid #ffd47c;outline-offset:3px}
"""


def page(title, content):
    return HTMLResponse(f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{title} · Citadel</title>
<link rel="stylesheet" href="/style.css"></head><body>{content}
<footer><p>Fictional exercise only. Not aviation advice or operational clearance.
Complete evidence does not establish accuracy or airport safety. Approval permits sharing, not completeness.</p>
</footer></body></html>""")


def login_page(status=200):
    # HTML limits count UTF-16 units; the server enforces the 128-character limit.
    response = page("Operator login", """<main><h1>Citadel Operator</h1>
<p>One shared Operator login. No individual attribution.</p>
<form method="post" action="/login"><label>Username
<input name="username" maxlength="256" autocomplete="username" required></label>
<label>Passphrase (15–128 characters)<input type="password" name="password" minlength="15" maxlength="256"
autocomplete="current-password" required></label><button>Log in</button></form></main>""")
    response.status_code = status
    return response


async def form(request):
    content = bytearray()
    try:
        async with asyncio.timeout(5):
            async for chunk in request.stream():
                if len(content) + len(chunk) > MAX_BODY:
                    return {}
                content.extend(chunk)
    except TimeoutError:
        return {}
    if request.headers.get("content-type", "").split(";")[0] != "application/x-www-form-urlencoded":
        return {}
    try:
        values = parse_qs(content.decode("utf-8", errors="strict"), max_num_fields=4,
                          keep_blank_values=True, errors="strict")
        if any(len(v) != 1 for v in values.values()):
            return {}
        return {key: value[0] for key, value in values.items()}
    except (ValueError, UnicodeError):
        return {}


def create_app(config, *, clock=time.monotonic, observation=None, submission=None,
               reference_observation=None, recovery=None, lifespan=None):
    auth = Authentication(config, clock)

    def same_origin(request):
        return request.headers.get("origin") == config.origin

    async def login(request):
        if request.method == "GET":
            return login_page()
        if not same_origin(request):
            LOG.info("login denied")
            return Response("Authentication failed", status_code=403)
        values = await form(request)
        token = await asyncio.to_thread(auth.login, values.get("username"), values.get("password"))
        if not token:
            return Response("Authentication failed", status_code=401)
        response = RedirectResponse("/", status_code=303)
        response.set_cookie(COOKIE, token, secure=True, httponly=True, samesite="strict", path="/")
        return response

    async def shell(request):
        csrf = auth.context(request.cookies.get(COOKIE))
        if not csrf:
            LOG.info("session denied")
            return login_page(401)
        selected = request.path_params.get("team")
        perspectives = {"reference": "Reference Data", "evidence": "Evidence Review", "planning": "Exercise Planning"}
        if selected and selected not in perspectives:
            return Response("Not found", status_code=404)
        run = request.path_params.get("run_id")
        suffix = f'/runs/{escape(run)}' if run else ''
        nav = '<nav aria-label="Team perspectives"><a href="/">Choose a scenario</a><a href="/history">Earlier runs</a>' + "".join(
            f'<a href="/teams/{key}{suffix}"' + (' aria-current="page"' if key == selected else '') +
            f'>{value}</a>' for key, value in perspectives.items()) + "</nav>"
        header = f"""<header><h1>Citadel · Operator</h1><form method="post" action="/logout">
<input type="hidden" name="csrf" value="{escape(csrf)}"><button>Log out</button></form></header>{nav}"""
        if request.url.path.startswith("/history") or run:
            from citadel.operations import OperationError, identity
            cursor = request.path_params.get("cursor")
            try:
                if run:
                    identity(run)
                if cursor:
                    identity(cursor)
            except OperationError:
                return Response("Invalid run selection", status_code=400)
            if request.method == "POST":
                values = await form(request)
                if (not same_origin(request) or not hmac.compare_digest(
                        values.get("csrf", "").encode(), csrf.encode())):
                    return Response("Request denied", status_code=403)
            observer = observation or getattr(request.app.state, "observation", None)
            automatic = request.headers.get("x-citadel-refresh") == "automatic"
            detail = None
            active = observer and getattr(observer, "selected_active", lambda _: False)(run)
            compose = observer and (active or request.headers.get("x-citadel-refresh") in ("automatic", "manual"))
            if selected == "reference":
                from .reference_observation import reference_content
                reference = reference_observation or getattr(request.app.state, "reference_observation", None)
                if not compose:
                    observed = await reference.observe(run, refresh=request.method == "POST") if reference else None
                    return page("Reference Data", header + reference_content(observed, csrf, run))
                try:
                    async with asyncio.timeout(30):
                        if reference:
                            observed, reference_result = await asyncio.gather(
                                observer.observe(run, refresh=request.method == "POST", automatic=automatic),
                                reference.observe(run, refresh=request.method == "POST", automatic=automatic))
                        else:
                            observed = await observer.observe(run, refresh=request.method == "POST", automatic=automatic)
                            reference_result = None
                    detail = reference_content(reference_result, csrf, run)
                except TimeoutError:
                    return Response("Observation unavailable; execution outcome remains unknown", status_code=503)
            elif selected == "evidence":
                from .evidence_view import render
                try:
                    if not compose:
                        return page("Evidence Review", header + await render(request, observer, run, csrf))
                    async with asyncio.timeout(30):
                        observed, detail = await asyncio.gather(
                            observer.observe(run, refresh=request.method == "POST", automatic=automatic),
                            render(request, observer, run, csrf))
                except OperationError:
                    return Response("Invalid Evidence Review selection", status_code=400)
                except TimeoutError:
                    return Response("Observation unavailable; execution outcome remains unknown", status_code=503)
            else:
                observed = (await observer.observe(run, cursor=cursor, refresh=request.method == "POST",
                                                  **({"automatic": True} if automatic else {}))
                            if observer else None)
            current = bool(run and not request.url.path.startswith("/history"))
            content = history_content(observed, csrf, run, cursor, current=current,
                                      refresh_target=request.url.path.removesuffix("/refresh") if current else None)
            if detail:
                content += detail
            elif selected:
                content += f"<aside>{perspectives[selected]} detail is not yet available. Run selection is preserved.</aside>"
            if current:
                content = (f'<section data-run-observation="{escape(run)}">{content}</section>'
                           '<script type="module" src="/scenario-client.mjs"></script>')
            return page("Current run" if run else "Earlier runs", header + content)
        if selected:
            notes = {
                "reference": "Only candidates assessed in a selected run will be inspectable, with original source and labelled overlays.",
                "evidence": "Private assessment drafts and exact approved findings will remain distinct. The Release Reviewer approves sharing; there is no human release gate.",
                "planning": "Planning uses approved findings only, never private draft previews. Exact finding citations will accompany saved briefs.",
            }
            return page(perspectives[selected], header + f"<main><h2>{perspectives[selected]}</h2><p>{notes[selected]}</p>"
                        "<aside>No run selected. Connected run inspection is not available in this release.</aside></main>")
        enabled = submission or getattr(request.app.state, "submission", None)
        controls = (f'<input type="hidden" name="csrf" value="{escape(csrf)}">'
                    f'<input type="hidden" name="request_id" value="{uuid4().hex}">'
                    '<button>Run scenario</button>' if enabled else
                    '<button type="button" disabled>Run scenario</button><p>Connected submission is unavailable; no work has been submitted.</p>')
        return page("Choose a scenario", header + """<main><h2>Choose a scenario</h2>
<p>Observe Reference Data, Evidence Review and Exercise Planning collaborate on a fictional airport comparison.</p>
<form method="post" action="/run">
<fieldset><legend>Scenario</legend><div class="cards"><article><h3><label>
<input type="radio" name="scenario" value="comparison" checked> Comparison</label></h3><p>Agents assess three complete-evidence candidates,
review release and write a comparison brief.</p><p>Expected: three complete candidates and a saved brief citing exact approved findings.</p></article>
<article><h3><label><input type="radio" name="scenario" value="replacement"> Replacement</label></h3><p>A labelled missing-width overlay creates an evidence gap. Agents skip
that candidate and assess a replacement.</p><p>Expected: the gap, skipped candidate, replacement and saved brief remain visible. Original source values are unchanged.</p></article>
<article><h3><label><input type="radio" name="scenario" value="exhaustion"> Exhaustion</label></h3><p>Agents assess a bounded candidate pool with insufficient evidence and no alternative.</p>
<p>Expected: an explained exhausted pool and no brief, not a technical failure.</p></article></div></fieldset>
""" + controls + """</form><p><a href="/history">Reopen retained runs</a>;
this page never plays back fixtures.</p></main>""")

    async def run_scenario(request):
        csrf = auth.context(request.cookies.get(COOKIE))
        if not csrf:
            return Response("Authentication required", status_code=401)
        values = await form(request)
        if not same_origin(request) or not hmac.compare_digest(values.get("csrf", "").encode(), csrf.encode()):
            return Response("Request denied", status_code=403)
        from citadel.operations import OperationError, identity
        from citadel.runtime.submission import SCENARIOS
        try:
            if values.keys() != {"csrf", "scenario", "request_id"} or values["scenario"] not in SCENARIOS:
                raise OperationError("invalid_input", "Invalid scenario selection")
            identity(values["request_id"])
        except OperationError:
            return Response("Invalid scenario selection", status_code=400)
        submitter = submission or getattr(request.app.state, "submission", None)
        if not submitter:
            return Response("Connected submission unavailable; no dispatch", status_code=503)
        result = await submitter.submit(values["request_id"], values["scenario"])
        if result.get("state") == "conflict":
            response = page("Run blocked", "<main><h1>Run blocked</h1><p>An unresolved prior dispatch "
                            "or conflicting immutable submission blocks this start. No automatic replay, "
                            "reset or admission bypass is available.</p><a href=\"/history\">Inspect retained runs</a></main>")
            response.status_code = 409
            return response
        return RedirectResponse("/runs/" + result["run_id"], status_code=303)

    async def logout(request):
        csrf = auth.context(request.cookies.get(COOKIE))
        if not csrf:
            LOG.info("logout denied")
            return Response("Authentication required", status_code=401)
        values = await form(request)
        if not same_origin(request) or not auth.logout(request.cookies.get(COOKIE), values.get("csrf", "")):
            LOG.info("logout denied")
            return Response("Request denied", status_code=403)
        LOG.info("logout accepted")
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="strict")
        return response

    async def recover(request):
        csrf = auth.context(request.cookies.get(COOKIE))
        if not csrf:
            return login_page(401)
        values = await form(request)
        if (not same_origin(request) or not hmac.compare_digest(
                values.get("csrf", "").encode(), csrf.encode())):
            return Response("Request denied", status_code=403)
        from citadel.operations import OperationError, identity
        from .recovery import recovery_content
        try:
            run_id = identity(request.path_params["run_id"])
            request_id = identity(values.get("request_id"))
        except OperationError:
            return Response("Invalid control identity", status_code=400)
        controller = recovery or getattr(request.app.state, "recovery", None)
        if controller is None:
            return Response("Recovery unavailable; no work dispatched", status_code=503)
        outcome = await controller.check(run_id, request_id)
        return page("Recovery outcome", recovery_content(run_id, csrf, outcome)
                    + f'<a href="/history/{escape(run_id)}">Reopen retained run</a>')

    async def style(request):
        return Response(STYLE, media_type="text/css")

    async def scenario_client(request):
        return Response(Path(__file__).with_name("scenario-client.mjs").read_text(),
                        media_type="text/javascript")

    from .retry import retry_routes
    app = Starlette(lifespan=lifespan, routes=[*retry_routes(auth, same_origin, form, page, recovery, COOKIE),
                           Route("/", shell), Route("/teams/{team}", shell),
                           Route("/run", run_scenario, methods=["POST"]),
                           Route("/runs/{run_id}", shell),
                           Route("/runs/{run_id}/refresh", shell, methods=["POST"]),
                           Route("/scenario-client.mjs", scenario_client),
                           Route("/teams/{team}/runs/{run_id}", shell),
                           Route("/teams/{team}/runs/{run_id}/refresh", shell, methods=["POST"]),
                           Route("/teams/{team}/runs/{run_id}/{projection}/page/{detail_cursor}", shell),
                           Route("/teams/{team}/runs/{run_id}/{projection}/page/{detail_cursor}/refresh",
                                 shell, methods=["POST"]),
                           Route("/teams/{team}/runs/{run_id}/findings/{artifact_id}/versions/{version}", shell),
                           Route("/teams/{team}/runs/{run_id}/findings/{artifact_id}/versions/{version}/refresh",
                                 shell, methods=["POST"]),
                           Route("/teams/{team}/runs/{run_id}/{collection}/" +
                                 "{artifact_id}/versions/{version}", shell),
                           Route("/teams/{team}/runs/{run_id}/{collection}/" +
                                 "{artifact_id}/versions/{version}/refresh", shell, methods=["POST"]),
                           Route("/history", shell), Route("/history/refresh", shell, methods=["POST"]),
                           Route("/history/page/{cursor}", shell),
                           Route("/history/page/{cursor}/refresh", shell, methods=["POST"]),
                           Route("/history/{run_id}", shell),
                           Route("/history/{run_id}/refresh", shell, methods=["POST"]),
                           Route("/history/{run_id}/recover", recover, methods=["POST"]),
                           Route("/login", login, methods=["GET", "POST"]),
                           Route("/logout", logout, methods=["POST"]), Route("/style.css", style)])

    async def protection(request: Request, call_next):
        if request.headers.get("host") != urlsplit(config.origin).netloc:
            response = Response("Request denied", status_code=400)
        elif request.url.query:
            response = Response("Query parameters are not accepted", status_code=400)
        else:
            response = await call_next(request)
        response.headers.update({
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
            "Content-Security-Policy": "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Strict-Transport-Security": "max-age=31536000",
        })
        return response

    app.add_middleware(BaseHTTPMiddleware, dispatch=protection)
    return app


def history_content(observed, csrf, run_id, cursor, *, current=False, refresh_target=None):
    state = observed.state if observed else "unavailable"
    descriptions = {
        "denied": "Observation denied; no execution outcome is established.",
        "missing": "Confirmed missing from this retained index. No backfill or proof of non-execution.",
        "empty": "Confirmed empty retained page. Earlier unindexed work is not reconstructed.",
        "partial": "Partial history: missing records or immutable source bindings. Execution may be unknown.",
        "unavailable": "Observation unavailable. This is not an execution failure.",
        "exhausted": "Deployment observation allowance exhausted. No fallback or refill.",
        "unknown": "Execution unknown; missing observations are not proof of no work.",
        "ok": "Saved service observation; no live activity is implied.",
    }
    data = observed.data if observed and observed.data else {}
    timestamp = (datetime.fromtimestamp(observed.last_success, timezone.utc).isoformat()
                 if observed and observed.last_success is not None else "none")
    target = "/history/" + escape(run_id) if run_id else (
        "/history/page/" + escape(cursor) if cursor else "/history")
    target = escape(refresh_target) if refresh_target else target
    attributes = (f' data-current-run="{escape(run_id)}" data-execution="{escape(data.get("execution", "unknown"))}"'
                  f' data-state="{escape(state)}"' if current else "")
    content = f"""<main{attributes}><h2>{'Current run' if current else 'Retained run' if run_id else 'Earlier runs'}</h2>
<p>Planner projection: {escape(state)}. {descriptions.get(state, descriptions['unknown'])}</p>
<p>Last successful observation (UTC): {timestamp}. Not an atomic cross-team snapshot.</p>"""
    if observed and observed.stale:
        content += "<aside>stale — refresh failed or observation invalidated; showing last successfully observed data, not current activity.</aside>"
    if run_id:
        content += f"<h3>{escape(run_id)}</h3><p>Execution: {escape(data.get('execution', 'unknown'))}</p>"
        from .scenario_views import scenario_content
        content += scenario_content(data)
        if data.get("outcome") == "incomplete_execution":
            content += f'<aside>Incomplete execution; technical failure: {escape(data.get("technical_failure", "unknown"))}. Partial effects may remain.</aside>'
        content += "<p>A saved running state does not establish a live owner. Indeterminate means incomplete execution with unknown effects; missing history never proves no work.</p>"
        content += f"<p>Scenario binding: {escape(data.get('fixture', 'unavailable'))}</p>"
        content += "<p>Original immutable source binding: " + (
            "retained" if data.get("bindings", {}).get("source") else "unavailable; not replaced with current data") + "</p>"
        bindings = data.get("bindings", {})
        content += f'<details><summary>Exact saved bindings</summary><p>Inputs: {escape(bindings.get("inputs", "unavailable"))}</p>'
        source = bindings.get("source")
        if source:
            for name in ("source", "profile", "fixture"):
                item = source[name]
                content += f'<p>{name}: {escape(str(item.get("id", item.get("snapshot", ""))))} · {escape(item["sha256"])}</p>'
        if bindings.get("product"):
            product = bindings["product"]
            content += f'<p>Product {escape(product["artifact_id"])} · version {escape(str(product["version"]))} · {escape(product["sha256"])}</p>'
        content += "</details>"
        from .recovery import recovery_content
        content += recovery_content(run_id, csrf, data.get("recovery"))
        from .retry import retry_content
        content += retry_content(run_id, csrf, data.get("retryable") is True
                                 and not observed.stale and state in ("ok", "partial"))
    else:
        content += "<ul>" + "".join(
            f'<li><a href="/history/{escape(item["run_id"])}">{escape(item["run_id"])}</a>'
            f' · {escape(item["fixture"])} · last indexed execution: {escape(item["execution"])}</li>'
            for item in data.get("runs", [])) + "</ul>"
        if data.get("next_cursor"):
            content += f'<a href="/history/page/{escape(data["next_cursor"])}">Next 20 runs</a>'
    return content + f"""<form data-observation-refresh method="post" action="{target}/refresh">
<input type="hidden" name="csrf" value="{escape(csrf)}"><button>Refresh observation</button></form>
<p>{'Visible active run: automatic observation every 15 seconds; terminal/unknown/exhausted views stop.' if current else 'History refresh is manual.'}
Opening or refreshing never submits, retries or recovers work.</p></main>"""


def main():
    import uvicorn
    logging.basicConfig(level=logging.INFO, format="%(name)s %(message)s")
    config = AuthConfig.from_environment()
    uvicorn.run(create_app(config, lifespan=production_observation), host="0.0.0.0", port=8000, workers=1,
                proxy_headers=False, access_log=False, limit_concurrency=32)


@asynccontextmanager
async def production_observation(app):
    from azure.identity.aio import ManagedIdentityCredential
    from azure.storage.blob.aio import ContainerClient
    from citadel.runtime.configuration import endpoint
    from citadel.runtime.observation import DeploymentReads
    from citadel.runtime.tickets import AzureTicketStore
    from .observation import ObservationClient
    from .recovery import RecoveryClient
    from uuid import UUID

    client_id = str(UUID(os.environ["AZURE_CLIENT_ID"]))
    blob = endpoint(os.environ["CITADEL_OBSERVATION_BLOB_URL"], ".blob.core.windows.net")
    gateway = endpoint(os.environ["CITADEL_GATEWAY_URL"])
    credential_value = os.environ["CITADEL_OPERATOR_SUBSCRIPTION"]
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", credential_value):
        raise ValueError("Invalid allocated Operator caller credential")
    async with ManagedIdentityCredential(client_id=client_id) as credential:
        async with ContainerClient(blob, "read-accounting", credential=credential,
                api_version="2026-10-06", retry_total=0, retry_connect=0, retry_read=0,
                retry_status=0, connection_timeout=5, read_timeout=30) as container:
            reads = DeploymentReads(AzureTicketStore(container), os.environ["CITADEL_DEPLOYMENT_ID"])
            observer = ObservationClient(gateway, credential_value, reads)
            from .reference_observation import ReferenceObservationClient
            reference = ReferenceObservationClient(gateway, credential_value, reads)
            app.state.observation = observer
            app.state.recovery = RecoveryClient(observer, observations=(reference,))
            from .submission import SubmissionClient
            app.state.submission = SubmissionClient(observer, related=(reference,))
            app.state.reference_observation = reference
            try:
                yield
            finally:
                await observer.close()
                await reference.close()


if __name__ == "__main__":
    main()
