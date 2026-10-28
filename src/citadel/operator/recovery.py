"""Narrow hosted explicit control client and recovery presentation."""

from html import escape
from secrets import token_urlsafe

import httpx

from citadel.operations import OperationError, identity
from citadel.runtime.state import read_deadline


class RecoveryClient:
    def __init__(self, observation, *, observations=()):
        self.observation = observation
        self.observations = (observation, *observations)

    async def check(self, run_id, request_id):
        return await self._control(run_id, request_id, "recover", {})

    async def retry(self, run_id, request_id, *, confirmed=False):
        if confirmed is not True:
            raise OperationError("invalid_input", "Separate explicit retry confirmation required")
        return await self._control(run_id, request_id, "retry", {"confirmed": True})

    async def _control(self, run_id, request_id, action, body):
        identity(run_id)
        identity(request_id)
        observer = self.observation
        allowed = {"blocked", "unknown"} | (
            {"retry_admitted"} if action == "retry" else
            {"released_no_commit", "released_quiescent_partial", "already_complete"})
        try:
            async with observer.admission.request("recovery-proof"):
                await observer.admission.charge()
                response = await observer.client.post(
                    observer.gateway + f"/candidate-planner/operator/runs/{run_id}/{action}/{request_id}",
                    json=body, headers={"Ocp-Apim-Subscription-Key": observer.credential,
                                      "X-Citadel-Recovery-Deadline": str(read_deadline.get())},
                    timeout=max(0.001, read_deadline.get() - observer.clock()))
                data = response.json()
                if (response.status_code == 200 and isinstance(data, dict)
                        and data.get("run_id") == run_id and data.get("request_id") == request_id
                        and data.get("state") in allowed):
                    return data
                reason = ("Recovery-proof allowance exhausted; no fallback or refill."
                          if response.status_code == 429 else
                          "Recovery outcome unknown; inspect saved state or check explicitly later.")
        except (OperationError, httpx.HTTPError, TimeoutError, ValueError, TypeError):
            reason = "Recovery proof unavailable or exhausted. No replay; check explicitly later."
        finally:
            for projection in self.observations:
                projection.invalidate(run_id)
        return {"run_id": run_id, "request_id": request_id, "state": "unknown",
                "execution": "unknown", "reason": reason, "retryable": False}


def recovery_content(run_id, csrf, outcome=None):
    content = "<section><h3>Check and recover</h3>"
    if outcome:
        label = "Persisted control outcome" if outcome.get("recorded_at") is not None else "Unconfirmed control outcome"
        content += (f'<p>{label}: {escape(outcome["state"])} · '
                    f'{escape(outcome["reason"])}</p>')
        if outcome.get("recorded_at") is not None:
            content += (f'<p>Control {escape(outcome["request_id"])} · recorded at '
                        f'{escape(str(outcome["recorded_at"]))}. Historical action, not current admission status.</p>')
    content += f"""<form method="post" action="/history/{escape(run_id)}/recover">
<input type="hidden" name="csrf" value="{escape(csrf)}">
<input type="hidden" name="request_id" value="{token_urlsafe(24)}">
<button>Check and recover</button></form>
<p>Explicit reconciliation only. A live owner is never interrupted. Unknown effects remain blocked.
Partial products stay incomplete and retained. Starting a new run is separate.
Authentication loss never resubmits this action.</p></section>"""
    return content
