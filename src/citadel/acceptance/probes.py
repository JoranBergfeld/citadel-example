"""Fixed-purpose wire probes. No public proxy, caller override or successful fake response."""

import asyncio
import hashlib
import time
from uuid import uuid4

import httpx

from citadel.gateway.trust import INVOCATION_CALLERS
from citadel.evidence.manifests import sha256
from citadel.operations import identity, OperationError
from citadel.runtime.configuration import endpoint
from .telemetry import correlate, emit, gateway_request_id


AGENTS = ("candidate-planner", "evidence-assessor", "release-reviewer", "briefing-author")


class ProbeDisabled(ValueError):
    pass


class GatewayProbe:
    """Allocated subscription only. Production construction happens inside its workload."""

    def __init__(self, workload, gateway, subscription_key, *, client, enabled, run_id,
                 deadline=None, admit=None):
        if enabled is not True:
            raise ProbeDisabled("Acceptance probes are disabled in normal mode")
        if workload not in AGENTS:
            raise ValueError("Only the actual allocated agent may run a workload probe")
        self.workload, self.gateway, self.key = workload, endpoint(gateway), subscription_key
        self.http, self.run_id = client, identity(run_id)
        self.deadline = min(deadline or time.time() + 900, time.time() + 900)
        self.remaining, self.admit = 512, admit

    async def _exchange(self, target, path, *, capability, method="GET", payload=None, headers=None):
        if target not in (*AGENTS, "reference-data"):
            raise ValueError("Probe target is not an allocated workload")
        if self.remaining <= 0 or time.time() >= self.deadline:
            raise OperationError("exhausted", "Probe control envelope exhausted")
        self.remaining -= 1
        if self.admit:
            await self.admit()
        started = time.time()
        operation = uuid4().hex
        check_id = f"route.{self.workload}.{target}.{capability}"
        url = f"{self.gateway}/{target}{path}"
        target_hash = hashlib.sha256(url.encode()).hexdigest()
        request_headers = {"Ocp-Apim-Subscription-Key": self.key, "x-citadel-run-id": self.run_id,
                           "x-citadel-operation-id": operation,
                           "x-ms-client-request-id": uuid4().hex}
        if headers:
            request_headers.update(headers)
        try:
            async with asyncio.timeout(min(30, self.deadline - time.time())):
                response = await self.http.request(method, url,
                                                   headers=request_headers, json=payload,
                                                   follow_redirects=False)
            request_id = gateway_request_id(response.headers)
            denial = response.headers.get("x-citadel-denial")
            reason = denial if denial in ("route_denied", "method_denied", "unknown_caller") else "observed"
            result = {
                "check_id": check_id, "target": target_hash,
                "run_id": self.run_id, "operation_id": operation, "caller": self.workload,
                "started": started, "finished": time.time(), "request_id": request_id,
                "status_code": response.status_code, "sources": ["gateway"],
                "reason": reason,
            }
            if response.status_code == 200 and path == "/.well-known/agent-card.json":
                card = response.json()
                expected = f"{self.gateway}/{target}/a2a"
                interfaces = card.get("supportedInterfaces", [])
                result["actual"] = ("gateway_card" if len(interfaces) == 1 and
                                    interfaces[0].get("url") == expected and
                                    interfaces[0].get("protocolBinding") == "JSONRPC" and
                                    interfaces[0].get("protocolVersion") == "1.0" else "invalid_card")
            if response.status_code == 200 and path in ("/mcp", "/a2a"):
                envelope = response.json()
                if (not isinstance(envelope, dict) or envelope.get("jsonrpc") != "2.0"
                        or "error" in envelope or not isinstance(envelope.get("result"), dict)
                        or envelope["result"].get("isError", False) is not False
                        or payload.get("method") == "initialize"
                        and envelope["result"].get("protocolVersion") != "2025-11-25"):
                    result.update(status="blocked", reason="protocol_control_failed")
                elif capability == "initialize":
                    result["actual"] = "mcp_initialized"
                elif path == "/mcp":
                    content = envelope["result"].get("structuredContent")
                    valid = isinstance(content, dict) and (
                        content.get("provenance", {}).get("fixture", {}).get("id") == "base-source")
                    if valid and capability == "search_airports":
                        airports = content.get("airports")
                        valid = isinstance(airports, list) and 0 < len(airports) <= 20
                    elif valid and capability == "lookup_airport":
                        valid = content.get("airport", {}).get("ident", {}).get("parsed") == (
                            payload["params"]["arguments"]["ident"])
                    elif valid and capability == "list_runways":
                        runways = content.get("runways")
                        valid = isinstance(runways, list) and 0 < len(runways) <= 50 and all(
                            row.get("airport_ident", {}).get("parsed") == payload["params"]["arguments"]["ident"]
                            for row in runways)
                    if valid:
                        result.update(actual="reference_data", sha256=sha256(content))
                    else:
                        result.update(status="blocked", reason="protocol_control_failed")
            with correlate(self.run_id, operation, self.workload):
                emit("probe", request_id=request_id, status_code=response.status_code, target=target_hash,
                     facts={"probe_id": check_id, "reason": reason, "sha256": sha256(result)})
            return result
        except (httpx.HTTPError, TimeoutError, ValueError, TypeError, AttributeError):
            return {"run_id": self.run_id, "operation_id": operation, "caller": self.workload, "status": "blocked",
                    "reason": "transport_or_protocol_unavailable",
                    "started": started, "finished": time.time()}

    async def discovery(self, target):
        if target not in AGENTS:
            raise ValueError("Discovery requires an allocated agent")
        return await self._exchange(target, "/.well-known/agent-card.json", capability="discovery")

    async def status(self, target, operation_id):
        if target not in AGENTS:
            raise ValueError("Status requires an allocated agent")
        return await self._exchange(target, "/operations/" + identity(operation_id), capability="status")

    async def task(self, target, operation_id):
        if target not in AGENTS:
            raise ValueError("Task reads require an allocated agent")
        return await self._exchange(target, "/a2a", method="POST", capability="task",
            payload={"jsonrpc": "2.0", "method": "GetTask", "id": uuid4().hex,
                     "params": {"id": identity(operation_id)}})

    async def denied_invocation(self, target):
        if target not in AGENTS or self.workload in INVOCATION_CALLERS[target]:
            raise ValueError("This probe is only an unauthorized invocation, not fabricated allowed work")
        payload = {"jsonrpc": "2.0", "method": "SendMessage", "id": uuid4().hex,
                   "params": {"message": {"messageId": uuid4().hex, "role": "ROLE_USER",
                                         "parts": [{"text": "{}"}]},
                              "configuration": {"returnImmediately": True}}}
        return await self._exchange(target, "/a2a", method="POST", payload=payload, capability="invoke")

    async def finding(self, reference, read_scope):
        artifact = identity(reference["artifact_id"])
        version = reference["version"]
        if type(version) is not int or version < 1:
            raise ValueError("An exact observed finding version is required")
        return await self._exchange("release-reviewer", f"/findings/{artifact}/versions/{version}", capability="findings",
                                    headers={"x-citadel-read-pool": identity(read_scope["operation_id"])})

    async def mcp_initialize(self):
        return await self._exchange("reference-data", "/mcp", method="POST", capability="initialize",
            headers={"Accept": "application/json, text/event-stream"},
            payload={"jsonrpc": "2.0", "id": uuid4().hex, "method": "initialize",
                     "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                                "clientInfo": {"name": "citadel-acceptance", "version": "1"}}})

    async def reference_tool(self, tool, *, ident=None):
        if tool not in ("search_airports", "lookup_airport", "list_runways"):
            raise ValueError("Only the three approved Reference Data tools may be probed")
        if tool == "search_airports":
            if ident is not None:
                raise ValueError("Search has no identifier argument")
            arguments = {}
        else:
            arguments = {"ident": identity(ident)}
            if len(ident) > 64:
                raise ValueError("Reference identifiers are at most 64 characters")
        return await self._exchange("reference-data", "/mcp", method="POST", capability=tool,
            headers={"Accept": "application/json, text/event-stream",
                     "MCP-Protocol-Version": "2025-11-25"},
            payload={"jsonrpc": "2.0", "id": uuid4().hex, "method": "tools/call",
                     "params": {"name": tool, "arguments": arguments}})
