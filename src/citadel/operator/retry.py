"""Separately confirmed hosted retry, composed without a general replay API."""

import hmac
from html import escape
from pathlib import Path
from secrets import token_urlsafe

from starlette.responses import Response
from starlette.routing import Route

from citadel.operations import OperationError, identity
from .recovery import recovery_content


def retry_content(run_id, csrf, eligible):
    if not eligible:
        return ""
    return f"""<section><h3>Retry this run</h3>
<p>Last observed authoritative no-commit state only. The service rechecks the original
deadline, remaining allowances, unresolved effects and global admission. No deadline extension,
budget refill or partial-work replay. Admission does not guarantee completion.</p>
<form data-retry-run method="post" action="/history/{escape(run_id)}/retry">
<input type="hidden" name="csrf" value="{escape(csrf)}">
<input type="hidden" name="request_id" value="{token_urlsafe(24)}">
<label><input type="checkbox" name="confirmed" value="yes" required>
I confirm retrying this same run with its original inputs, deadline and remaining allowances.</label>
<button>Confirm retry this run</button></form>
<p>Unknown or lost responses must be inspected, never automatically resubmitted.</p></section>
<script type="module" src="/retry-client.mjs"></script>"""


def retry_routes(auth, same_origin, form, page, recovery, cookie):
    async def retry(request):
        csrf = auth.context(request.cookies.get(cookie))
        if not csrf:
            return Response("Authentication required", status_code=401)
        values = await form(request)
        if not same_origin(request) or not hmac.compare_digest(values.get("csrf", "").encode(), csrf.encode()):
            return Response("Request denied", status_code=403)
        try:
            if values.keys() != {"csrf", "request_id", "confirmed"} or values["confirmed"] != "yes":
                raise OperationError("invalid_input", "Separate explicit retry confirmation required")
            run_id = identity(request.path_params["run_id"])
            request_id = identity(values["request_id"])
        except OperationError:
            return Response("Explicit retry confirmation and valid identities required", status_code=400)
        controller = recovery or getattr(request.app.state, "recovery", None)
        if controller is None:
            return Response("Retry unavailable; no work dispatched", status_code=503)
        outcome = await controller.retry(run_id, request_id, confirmed=True)
        return page("Retry outcome", recovery_content(run_id, csrf, outcome)
                    + f'<a href="/runs/{escape(run_id)}">Observe this run</a>')

    async def client(request):
        return Response(Path(__file__).with_name("retry-client.mjs").read_text(),
                        media_type="text/javascript")

    return [Route("/history/{run_id}/retry", retry, methods=["POST"]),
            Route("/retry-client.mjs", client)]
