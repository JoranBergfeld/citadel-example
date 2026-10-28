"""Single-process Operator shell. No workflow, gateway or team-data client."""

import asyncio
from collections import deque
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
from urllib.parse import parse_qs, urlsplit

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


def create_app(config, *, clock=time.monotonic):
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
        nav = '<nav aria-label="Team perspectives"><a href="/">Choose a scenario</a>' + "".join(
            f'<a href="/teams/{key}"' + (' aria-current="page"' if key == selected else '') +
            f'>{value}</a>' for key, value in perspectives.items()) + "</nav>"
        header = f"""<header><h1>Citadel · Operator</h1><form method="post" action="/logout">
<input type="hidden" name="csrf" value="{escape(csrf)}"><button>Log out</button></form></header>{nav}"""
        if selected:
            notes = {
                "reference": "Only candidates assessed in a selected run will be inspectable, with original source and labelled overlays.",
                "evidence": "Private assessment drafts and exact approved findings will remain distinct. The Release Reviewer approves sharing; there is no human release gate.",
                "planning": "Planning uses approved findings only, never private draft previews. Exact finding citations will accompany saved briefs.",
            }
            return page(perspectives[selected], header + f"<main><h2>{perspectives[selected]}</h2><p>{notes[selected]}</p>"
                        "<aside>No run selected. Connected run inspection is not available in this release.</aside></main>")
        return page("Choose a scenario", header + """<main><h2>Choose a scenario</h2>
<p>Observe Reference Data, Evidence Review and Exercise Planning collaborate on a fictional airport comparison.</p>
<fieldset><legend>Scenario</legend><div class="cards"><article><h3><label>
<input type="radio" name="scenario" value="comparison" checked> Comparison</label></h3><p>Agents assess three complete-evidence candidates,
review release and write a comparison brief.</p><p>Expected: three complete candidates and a saved brief citing exact approved findings.</p></article>
<article><h3><label><input type="radio" name="scenario" value="replacement"> Replacement</label></h3><p>A labelled missing-width overlay creates an evidence gap. Agents skip
that candidate and assess a replacement.</p><p>Expected: the gap, skipped candidate, replacement and saved brief remain visible. Original source values are unchanged.</p></article>
<article><h3><label><input type="radio" name="scenario" value="exhaustion"> Exhaustion</label></h3><p>Agents assess a bounded candidate pool with insufficient evidence and no alternative.</p>
<p>Expected: an explained exhausted pool and no brief, not a technical failure.</p></article></div></fieldset>
<button type="button" disabled aria-describedby="unavailable">Run scenario</button>
<p id="unavailable">Scenario execution is not available in this release. No run has been submitted.
Connected execution and retained-run inspection arrive in later slices; this page never plays back fixtures.</p></main>""")

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

    async def style(request):
        return Response(STYLE, media_type="text/css")

    app = Starlette(routes=[Route("/", shell), Route("/teams/{team}", shell),
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
            "Content-Security-Policy": "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Strict-Transport-Security": "max-age=31536000",
        })
        return response

    app.add_middleware(BaseHTTPMiddleware, dispatch=protection)
    return app


def main():
    import uvicorn
    logging.basicConfig(level=logging.INFO, format="%(name)s %(message)s")
    config = AuthConfig.from_environment()
    uvicorn.run(create_app(config), host="0.0.0.0", port=8000, workers=1,
                proxy_headers=False, access_log=False, limit_concurrency=32)


if __name__ == "__main__":
    main()
