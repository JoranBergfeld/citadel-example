"""Gateway-only protocol clients. Every physical read consumes prepaid tickets."""

import asyncio
import json
import time
from contextvars import ContextVar

import httpx
from a2a.types import AgentCard
from agent_framework_a2a import A2AAgent
from google.protobuf.json_format import ParseDict
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.types import CallToolResult, CallToolRequest, CallToolRequestParams, ClientRequest, RequestParams

from citadel.evidence import EvidenceError
from citadel.evidence.manifests import sha256
from citadel.operations import OperationError
from citadel.operations.limits import EDGES
from citadel.acceptance.telemetry import correlation_headers
from .reference import RetrievedReference
from .state import reads


_exchange = ContextVar("citadel_network_exchange", default=None)


class GatewayPeers:
    def __init__(self, workload, gateway_url, subscription_key, *, http_client=None,
                 clock=time.time, sleep=asyncio.sleep):
        self.workload, self.gateway, self.key = workload, gateway_url.rstrip("/"), subscription_key
        self.clock, self.sleep = clock, sleep
        self.owns_http = http_client is None
        self.http = http_client or httpx.AsyncClient(follow_redirects=False, timeout=30)
        self.http.event_hooks.setdefault("request", []).insert(0, self._admit)
        self.cards = {}

    async def _admit(self, request):
        admission = _exchange.get()
        if admission is None or self.clock() >= admission["deadline"]:
            raise OperationError("deadline", "No live network admission")
        if not str(request.url).startswith(self.gateway + "/"):
            raise OperationError("forbidden", "Network destination is not the configured gateway")
        target, path = request.url.path.lstrip("/").split("/", 1)
        if target != admission["target"]:
            raise OperationError("forbidden", "Protocol redirected to an unapproved target")
        if admission["invoke"]:
            if admission["sent"] or path != "a2a":
                raise OperationError("forbidden", "Hidden A2A invocation retry blocked")
            admission["sent"] = True
        else:
            allowance = reads.get()
            if allowance is None:
                raise OperationError("exhausted", "Safe read requires prepaid admission")
            await allowance.admit()
        request.headers["Ocp-Apim-Subscription-Key"] = self.key
        request.headers.update(correlation_headers())

    async def exchange(self, target, deadline, callback, *, invoke=False):
        timeout = 180 if invoke else 30
        limit = min(deadline, self.clock() + timeout)
        token = _exchange.set({"target": target, "deadline": limit, "invoke": invoke, "sent": False})
        try:
            async with asyncio.timeout(max(0, limit - self.clock())):
                return await callback()
        finally:
            _exchange.reset(token)

    async def reference(self, fixture, deadline, ident=None):
        if self.workload not in ("candidate-planner", "evidence-assessor", "release-reviewer"):
            raise OperationError("forbidden", "Workload has no Reference Data capability")

        async def read():
            async with streamable_http_client(self.gateway + "/reference-data/mcp", http_client=self.http) as (read, write, _):
                async with ClientSession(read, write) as session:
                    initialized = await session.initialize()
                    if initialized.protocolVersion != "2025-11-25":
                        raise OperationError("unsupported_version", "Unexpected MCP protocol version")

                    async def call(name, arguments):
                        # Fixed evidence contracts have no remote output schemas.
                        # The public typed request avoids call_tool's redundant tools/list.
                        response = await session.send_request(ClientRequest(CallToolRequest(
                            params=CallToolRequestParams(name=name, arguments=arguments,
                                _meta=RequestParams.Meta(**{"citadel-fixture": fixture})))),
                            CallToolResult)
                        payload = json.loads(response.content[0].text)
                        if response.isError:
                            raise EvidenceError(payload.get("error", "temporary_unavailability"), "Reference read rejected")
                        if payload["provenance"]["fixture"]["id"] != fixture:
                            raise EvidenceError("data_integrity", "Reference fixture differs from run")
                        return payload

                    if ident is None:
                        return await call("search_airports", {})
                    return RetrievedReference(await call("lookup_airport", {"ident": ident}),
                                              await call("list_runways", {"ident": ident}))
        return await self.exchange("reference-data", deadline, read)

    async def finding(self, reference, deadline, *, read_scope):
        if self.workload not in ("candidate-planner", "briefing-author"):
            raise OperationError("forbidden", "Workload has no deterministic finding-read capability")

        async def read():
            response = await self.http.get(
                f"{self.gateway}/release-reviewer/findings/{reference['artifact_id']}/versions/{reference['version']}",
                headers={"x-citadel-read-pool": read_scope["operation_id"]})
            response.raise_for_status()
            finding = response.json()
            if sha256(finding) != reference["sha256"]:
                raise OperationError("conflict", "Released finding differs from exact reference")
            return finding
        return await self.exchange("release-reviewer", deadline, read)

    async def child(self, runtime, ownership, payload, child, arguments, allowance):
        if child not in EDGES[self.workload]:
            raise OperationError("forbidden", "Invocation edge is not permitted")
        parent_id = payload["operation_id"]
        from uuid import uuid4
        operation_id = uuid4().hex
        await reads.get().delegate(allowance["reads"])
        grant = await runtime.accounting.delegate(parent_id, operation_id, child, allowance)
        child_input = {
            "operation_id": operation_id, "run_id": payload["run_id"], "fixture": payload["fixture"],
            "grant": grant, **arguments,
        }
        binding = sha256({"inputs": child_input, "run_id": payload["run_id"], "deadline": grant["deadline"]})
        await runtime.ops.begin_external(ownership, operation_id, binding)

        async def discover():
            response = await self.http.get(f"{self.gateway}/{child}/.well-known/agent-card.json")
            response.raise_for_status()
            card = ParseDict(response.json(), AgentCard())
            if (len(card.supported_interfaces) != 1 or
                    card.supported_interfaces[0].url != f"{self.gateway}/{child}/a2a" or
                    card.supported_interfaces[0].protocol_binding != "JSONRPC" or
                    card.supported_interfaces[0].protocol_version != "1.0"):
                raise OperationError("forbidden", "Agent card advertises an unapproved follow-up")
            return card

        if child not in self.cards:
            self.cards[child] = await self.exchange(child, grant["deadline"], discover)
        card = self.cards[child]
        async with A2AAgent(agent_card=card, http_client=self.http) as agent:
            continuation = None
            try:
                accepted = await self.exchange(child, grant["deadline"],
                    lambda: agent.run(json.dumps(child_input), background=True), invoke=True)
                continuation = accepted.continuation_token
            except (httpx.RequestError, TimeoutError):
                pass
            while self.clock() < grant["deadline"]:
                await runtime.renew_if_needed(ownership)
                await self.sleep(15)

                async def status_read():
                    started = time.time()
                    response = await self.http.get(f"{self.gateway}/{child}/operations/{operation_id}")
                    response.raise_for_status()
                    from citadel.acceptance.workflow_routes import observe_status
                    observe_status(response, caller=self.workload, target=child, run_id=payload["run_id"],
                                   operation_id=parent_id, started=started, finished=time.time())
                    return response.json()

                status = await self.exchange(child, grant["deadline"], status_read)
                if status["state"] == "succeeded":
                    if status["input_hash"] != binding or status["run_id"] != payload["run_id"]:
                        raise OperationError("conflict", "Child status is not the admitted invocation")
                    await runtime.accounting.settle(parent_id, status["result"]["receipt"],
                                                     authenticated_child=child)
                    await runtime.ops.reconcile_external(ownership, operation_id, status)
                    if child == "briefing-author":
                        if continuation is None:
                            # Exact task mapping is the durable operation ID. The
                            # official GetTask serializer needs no in-memory token.
                            from a2a.types import GetTaskRequest
                            response = await self.exchange(child, grant["deadline"],
                                lambda: agent.client.get_task(GetTaskRequest(id=operation_id)))
                            product = json.loads(response.artifacts[0].parts[0].text)
                        else:
                            result = await self.exchange(child, grant["deadline"], lambda: agent.poll_task(continuation))
                            if result.continuation_token is not None:
                                raise OperationError("indeterminate", "Completed status has no completed task result")
                            product = json.loads(result.text)
                        if (sha256(product) != status["result"]["sha256"]
                                or product.get("citations") != arguments["findings"]):
                            raise OperationError("conflict", "Brief differs from its committed exact reference")
                        return product
                    return status["result"]
                if status["state"] in ("failed_no_commit", "indeterminate"):
                    raise OperationError("indeterminate", "Child work remains partial; do not replay")
            raise OperationError("deadline", "Inherited child deadline expired")

    async def close(self):
        self.http.event_hooks["request"].remove(self._admit)
        if self.owns_http:
            await self.http.aclose()
