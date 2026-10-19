"""The three evidence capabilities over the pinned genuine MCP transport."""

import json
from contextlib import asynccontextmanager

from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.types import CallToolResult, TextContent, Tool, ToolAnnotations
from starlette.applications import Starlette
from starlette.routing import Route

from citadel.evidence import EvidenceError, EvidenceAssessment
from citadel.evidence.manifests import sha256
from citadel.gateway import GatewayTrust
from citadel.acceptance.telemetry import correlate, emit


def reference_application(reference, trust):
    server = Server("ReferenceData", version="1.0.0")
    schemas = {
        "search_airports": {
            "type": "object", "additionalProperties": False,
            "properties": {
                "countries": {"type": "array", "items": {"enum": ["BE", "DE", "NL"]},
                              "minItems": 1, "uniqueItems": True},
                "types": {"type": "array", "items": {"enum": [
                    "small_airport", "medium_airport", "large_airport"]},
                          "minItems": 1, "uniqueItems": True},
                "limit": {"type": "integer", "minimum": 1, "maximum": 20},
            },
        },
        "lookup_airport": {"type": "object", "additionalProperties": False,
                           "properties": {"ident": {"type": "string", "pattern": "^[A-Za-z0-9_-]{1,64}$"}},
                           "required": ["ident"]},
    }
    schemas["list_runways"] = schemas["lookup_airport"]

    @server.list_tools()
    async def tools():
        return [Tool(name=name, description={
            "search_airports": "Read the stable bounded airport pool; no arbitrary query.",
            "lookup_airport": "Read one exact airport with resolved country and region.",
            "list_runways": "Read all recorded runways of one airport; at most fifty, never truncate.",
        }[name], inputSchema=schema, annotations=ToolAnnotations(
            readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False,
        )) for name, schema in schemas.items()]

    @server.call_tool(validate_input=False)
    async def call(name, arguments):
        if name not in schemas:
            raise ValueError("Unknown read capability")
        try:
            meta = server.request_context.meta
            fixture = (meta.model_extra or {}).get("citadel-fixture", "base-source") if meta else "base-source"
            selected = reference.get(fixture) if isinstance(reference, dict) else reference
            if selected is None or selected.provenance["fixture"]["id"] != fixture:
                raise EvidenceError("unsupported_version", "Unknown fixture")
            payload = getattr(selected, name)(**arguments)
            scope = server.request_context.request.scope
            with correlate(scope["citadel.run_id"], scope["citadel.operation_id"], scope["citadel.caller"]):
                emit("reference.observed", request_id=scope["citadel.request_id"], status_code=200,
                     facts={"probe_id": name, "sha256": sha256(payload),
                            "source_sha256": sha256(payload["provenance"])})
            return CallToolResult(content=[TextContent(type="text", text=json.dumps(payload))],
                                  structuredContent=payload)
        except EvidenceError as exc:
            payload = {"error": exc.code, "provenance": exc.provenance}
            return CallToolResult(isError=True, content=[
                TextContent(type="text", text=json.dumps(payload))], structuredContent=payload)

    manager = StreamableHTTPSessionManager(server, stateless=True, json_response=True)

    @asynccontextmanager
    async def lifespan(app):
        async with manager.run():
            yield

    return GatewayTrust(Starlette(routes=[
        Route("/mcp", endpoint=manager.asgi_app, methods=["POST", "GET", "DELETE"]),
    ], lifespan=lifespan), trust)


class RetrievedReference(EvidenceAssessment):
    """Reuse deterministic rules on evidence read through the authorized MCP seam.

    The source is authenticated Reference Data, not model/body-claimed evidence.
    This object is scoped to one exact airport and one matching provenance.
    """

    def __init__(self, lookup, runways):
        if lookup["provenance"] != runways["provenance"]:
            raise EvidenceError("data_integrity", "MCP evidence provenance changed between reads")
        self.lookup, self.runways = lookup, runways

    @property
    def provenance(self):
        return self.lookup["provenance"]

    def lookup_airport(self, ident=None, **arguments):
        if arguments or ident != self.lookup["airport"]["ident"]["parsed"]:
            raise EvidenceError("invalid_input", "Retrieved evidence is for one exact airport")
        return self.lookup

    def list_runways(self, ident=None, **arguments):
        self.lookup_airport(ident, **arguments)
        if len(self.runways["runways"]) > 50:
            raise EvidenceError("result_limit", "MCP runway evidence exceeds bound")
        return self.runways
