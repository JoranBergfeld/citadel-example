"""One-shot actual-MI direct inference denial, not an unmetered gateway control."""

import asyncio
import hashlib
import json
import math
import time
from uuid import UUID, uuid4

import httpx2
from azure.core.exceptions import AzureError

from citadel.gateway.trust import INVOCATION_CALLERS
from citadel.operations import OperationError, identity
from citadel.runtime.configuration import endpoint
from .telemetry import correlate, emit, gateway_request_id, opaque


PROMPT = "Reply with exactly OK for a fictional connectivity check."
INPUT_BOUND = len(PROMPT.encode()) + 1024
OUTPUT_BOUND = 2000
AUTH_ERRORS = {"PermissionDenied", "Forbidden", "Unauthorized", "AccessDenied", "AuthorizationFailed"}


def model_origin(value):
    value = endpoint(value)
    if not value.endswith((".openai.azure.com", ".cognitiveservices.azure.com")):
        raise ValueError("Only the actual inventoried Azure model origin is permitted")
    return value


def validate_model_manifest(value):
    if not isinstance(value, dict) or set(value) != {"origin", "deployment", "run_id"}:
        raise ValueError("Exact inventoried direct-model manifest required")
    model_origin(value["origin"])
    identity(value["deployment"])
    identity(value["run_id"])
    return value


class DirectModelProbe:
    def __init__(self, *, workload, origin, deployment, credential, principal_id,
                 enabled, run_id, deadline, admit, client_factory=None, operation_id=None):
        if (enabled is not True or workload not in INVOCATION_CALLERS or not callable(admit)
                or type(deadline) not in (float, int) or not math.isfinite(deadline)
                or not time.time() < deadline <= time.time() + 900):
            raise ValueError("An allocated, one-shot and bounded model probe is required")
        self.url = model_origin(origin) + "/openai/v1/chat/completions"
        self.workload, self.deployment, self.run_id = workload, identity(deployment), identity(run_id)
        self.identity = hashlib.sha256(str(UUID(principal_id)).encode()).hexdigest()
        self.credential, self.deadline, self.admit = credential, deadline, admit
        self.client, self.sent = client_factory or httpx2.AsyncClient, False
        self.operation = identity(operation_id) if operation_id is not None else uuid4().hex

    async def observe(self):
        if self.sent or time.time() >= self.deadline:
            raise OperationError("deadline" if not self.sent else "conflict",
                                 "Expired or repeated direct model dispatch refused")
        self.sent = True
        await self.admit()
        operation = self.operation
        result = {"check_id": f"model.{self.workload}.direct-denied",
            "run_id": self.run_id, "operation_id": operation, "caller": self.workload,
            "runtime_identity": self.identity, "target": hashlib.sha256(self.url.encode()).hexdigest(),
            "started": time.time(), "state": "indeterminate", "status": "blocked",
            "reason": "direct_model_outcome_unverified", "model_attempts": 1,
            "input_tokens": INPUT_BOUND, "output_tokens": OUTPUT_BOUND}
        try:
            async with asyncio.timeout(max(0, min(60, self.deadline - time.time()))):
                token = await self.credential.get_token("https://cognitiveservices.azure.com/.default")
                if time.time() >= self.deadline:
                    raise OperationError("deadline", "Model credential arrived after deadline")
                async with self.client(timeout=60, follow_redirects=False, trust_env=False) as client:
                    async with client.stream("POST", self.url, headers={
                            "Authorization": "Bearer " + token.token, "x-ms-client-request-id": operation},
                            json={"model": self.deployment, "stream": False,
                                  "messages": [{"role": "user", "content": PROMPT}],
                                  "max_completion_tokens": OUTPUT_BOUND}) as response:
                        content = bytearray()
                        async for chunk in response.aiter_bytes():
                            content.extend(chunk)
                            if len(content) > 1024 * 1024:
                                raise OperationError("result_limit", "Direct model evidence exceeds bound")
                        result["status_code"] = int(response.status_code)
                        request_id = (response.headers.get("x-ms-request-id")
                            or response.headers.get("apim-request-id") or response.headers.get("x-request-id"))
                        if request_id:
                            result["request_id"] = opaque(request_id)
                        document = json.loads(content)
                        if not isinstance(document, dict):
                            raise ValueError("Malformed model response")
                        error = document.get("error", {})
                        if (response.status_code in (401, 403) and isinstance(error, dict)
                                and isinstance(error.get("code"), str)
                                and error.get("code") in AUTH_ERRORS and "usage" not in document):
                            result.update(state="observed", reason=error["code"])
                        elif response.status_code == 200 and isinstance(document.get("usage"), dict):
                            usage = document["usage"]
                            if all(type(usage.get(key)) is int and 0 <= usage[key] <= limit
                                   for key, limit in (("prompt_tokens", INPUT_BOUND),
                                                      ("completion_tokens", OUTPUT_BOUND))):
                                result.update(state="observed", reason="unauthorized_model_succeeded",
                                    actual={"input_tokens": usage["prompt_tokens"],
                                            "output_tokens": usage["completion_tokens"]})
                        with correlate(self.run_id, operation, self.workload):
                            emit("model.direct", request_id=result.get("request_id"),
                                 status_code=int(response.status_code), target=result["target"],
                                 facts={"model_attempts": 1, "input_tokens": INPUT_BOUND,
                                        "output_tokens": OUTPUT_BOUND, "reason": result["reason"]})
        except (AzureError, httpx2.HTTPError, TimeoutError, ValueError, OperationError):
            # No retry or admission release on an ambiguous provider outcome.
            pass
        result["finished"] = time.time()
        return result


class OperatorModelProbe:
    def __init__(self, lifecycle, *, enabled, run_id, operation_id, deadline, admit, client_factory=None):
        if (enabled is not True or not callable(admit)
                or type(deadline) not in (int, float) or not math.isfinite(deadline)
                or not time.time() < deadline <= time.time() + 900):
            raise ValueError("An explicit bounded operator model control is required")
        self.run_id, self.operation = identity(run_id), identity(operation_id)
        credentials = lifecycle.credentials()
        if credentials["callerStates"]["operator"] != "active":
            raise ValueError("Operator model control requires its own active subscription")
        self.key = credentials["callerKeys"]["operator"]["primary"]
        self.url = endpoint(lifecycle.value["outputs"]["gatewayUrl"]) + "/openai/v1/chat/completions"
        self.deadline, self.admit, self.sent = deadline, admit, False
        self.client = client_factory or httpx2.AsyncClient

    async def observe(self):
        if self.sent or time.time() >= self.deadline:
            raise OperationError("conflict", "Late or repeated operator model dispatch refused")
        self.sent = True
        await self.admit()
        result = {"check_id": "route.operator.model.inference", "caller": "operator",
            "run_id": self.run_id, "operation_id": self.operation, "started": time.time(),
            "target": hashlib.sha256(self.url.encode()).hexdigest(), "state": "indeterminate",
            "reason": "operator_model_outcome_unverified", "model_attempts": 1,
            "input_tokens": INPUT_BOUND, "output_tokens": OUTPUT_BOUND}
        try:
            async with asyncio.timeout(max(0, min(60, self.deadline - time.time()))):
                async with self.client(timeout=60, follow_redirects=False, trust_env=False) as client:
                    async with client.stream("POST", self.url, headers={
                            "Ocp-Apim-Subscription-Key": self.key, "x-citadel-run-id": self.run_id,
                            "x-citadel-operation-id": self.operation}, json={
                                "model": "citadel-gpt-41-mini", "stream": False,
                                "messages": [{"role": "user", "content": PROMPT}],
                                "max_completion_tokens": OUTPUT_BOUND}) as response:
                        content = bytearray()
                        async for chunk in response.aiter_bytes():
                            content.extend(chunk)
                            if len(content) > 1024 * 1024:
                                raise OperationError("result_limit", "Operator model response exceeds bound")
                        result.update(status_code=int(response.status_code),
                                      request_id=gateway_request_id(response.headers))
                        if response.status_code == 403 and response.headers.get("x-citadel-denial") == "model_caller_denied":
                            result.update(state="observed", reason="model_caller_denied")
                        elif response.status_code == 200:
                            document = json.loads(content)
                            usage = document.get("usage") if isinstance(document, dict) else None
                            if isinstance(usage, dict) and all(type(usage.get(key)) is int and 0 <= usage[key] <= bound
                                    for key, bound in (("prompt_tokens", INPUT_BOUND), ("completion_tokens", OUTPUT_BOUND))):
                                result.update(state="observed", reason="unauthorized_model_succeeded")
        except (httpx2.HTTPError, TimeoutError, ValueError, OperationError):
            pass
        result["finished"] = time.time()
        return result
