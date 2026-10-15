"""Framework inference with no automatic retry and admission at the HTTP boundary."""

import asyncio
import json
import time
from contextvars import ContextVar

import httpx2
from agent_framework import Agent
from agent_framework_openai import OpenAIChatCompletionClient
from openai import AsyncOpenAI

from citadel.operations import OperationError
from citadel.acceptance.telemetry import correlation_headers, emit


INSTRUCTIONS = {
    "candidate-planner": (
        "You are Candidate Planner for Exercise Planning. Describe only the fictional "
        "reference-data comparison. Code selects the stable bounded pool, replaces "
        "insufficient candidates, and obtains released findings. Never infer safety."
    ),
    "evidence-assessor": (
        "You are Evidence Assessor for Evidence Review. Explain the supplied deterministic "
        "completeness result privately. Missing reference evidence is not a negative airport "
        "judgment. You cannot publish findings; an exact draft requires Release Reviewer."
    ),
    "release-reviewer": (
        "You are Release Reviewer for Evidence Review. Explain the independent reference "
        "recheck of an exact immutable draft. Code alone validates and releases the finding. "
        "Approval permits sharing, not safety certification. Preserve every evidence gap."
    ),
    "briefing-author": (
        "You are Briefing Author for Exercise Planning. Write a short fictional comparison "
        "using only supplied exact released findings. Do not claim safety, operational "
        "suitability or usable landing distance. State source accuracy is unverified. "
        "Do not add facts absent from the supplied evidence. The operator reviews prose."
    ),
}
ALLOWED_TOOLS = {
    "candidate-planner": ("search_airports", "assess", "get_finding", "author", "owner_status"),
    "evidence-assessor": ("lookup_airport", "list_runways", "submit_draft", "review", "owner_status"),
    "release-reviewer": ("lookup_airport", "list_runways", "read_exact_draft", "release"),
    "briefing-author": ("get_finding",),
}
_permit = ContextVar("citadel_model_permit", default=None)


class GovernedModel:
    def __init__(self, workload, gateway_url, subscription_key, deployment, *, http_client=None,
                 clock=time.time, sleep=asyncio.sleep):
        self.workload, self.clock, self.sleep = workload, clock, sleep
        self.url = gateway_url.rstrip("/") + "/openai/v1/chat/completions"
        self.owns_http = http_client is None
        self.http = http_client or httpx2.AsyncClient(follow_redirects=False, timeout=60)
        self.http.event_hooks.setdefault("request", []).append(self._before_request)
        self.http.event_hooks.setdefault("response", []).append(self._response)
        self.client = AsyncOpenAI(
            api_key="gateway-subscription-only", base_url=gateway_url.rstrip("/") + "/openai/v1/",
            default_headers={"Ocp-Apim-Subscription-Key": subscription_key},
            http_client=self.http, max_retries=0, timeout=60,
        )
        adapter = OpenAIChatCompletionClient(model=deployment, async_client=self.client)
        self.agent = Agent(adapter, name=workload, instructions=INSTRUCTIONS[workload], tools=[],
                           default_options={"max_tokens": 2000})

    async def _before_request(self, request):
        admission = _permit.get()
        if (admission is None or admission["sent"] or self.clock() >= admission["deadline"]
                or str(request.url) != self.url or request.method != "POST"):
            raise OperationError("forbidden", "Unadmitted model dispatch or hidden retry")
        payload = json.loads(request.content)
        if payload.get("max_completion_tokens") != 2000 or payload.get("tools"):
            raise OperationError("forbidden", "Model cannot select network tools or raise output bound")
        admission["sent"] = True
        request.headers.update(correlation_headers())

    async def _response(self, response):
        emit("chat.completions",
             request_id=response.headers.get("apim-request-id") or response.headers.get("x-request-id"),
             status_code=response.status_code)

    async def explain(self, accounting, budget_id, execution_id, evidence):
        prompt = json.dumps(evidence, sort_keys=True, ensure_ascii=False, allow_nan=False)
        # UTF-8 byte count bounds BPE text tokens; fixed allowance covers framing.
        bound = len((INSTRUCTIONS[self.workload] + prompt).encode("utf-8")) + 1024
        if bound > 16000:
            raise OperationError("exhausted", "Model input exceeds the conservative token envelope")
        while True:
            try:
                permit = await accounting.model(budget_id, execution_id, input_tokens=bound, output_tokens=2000)
                break
            except OperationError as exc:
                if exc.code != "rate_limited":
                    raise
                await self.sleep(5)
        token = _permit.set({**permit, "sent": False})
        try:
            async with asyncio.timeout(max(0, permit["deadline"] - self.clock())):
                result = await self.agent.run(prompt)
            if self.clock() >= permit["deadline"]:
                raise OperationError("deadline", "Late model response cannot release admission")
            await accounting.finish_model(budget_id, permit["attempt_id"])
            return result.text
        finally:
            _permit.reset(token)

    async def close(self):
        self.http.event_hooks["request"].remove(self._before_request)
        self.http.event_hooks["response"].remove(self._response)
        if self.owns_http:
            await self.client.close()
