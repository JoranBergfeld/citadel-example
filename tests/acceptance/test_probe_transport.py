import json
import hashlib
import unittest

import httpx

from citadel.acceptance.probes import GatewayProbe, ProbeDisabled
from citadel.operations import OperationError


class ProbeTransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_normal_mode_refuses_probe_before_any_network_request(self):
        async with httpx.AsyncClient(transport=httpx.MockTransport(
                lambda request: self.fail("Disabled probe dispatched"))) as client:
            with self.assertRaises(ProbeDisabled):
                GatewayProbe("candidate-planner", "https://gateway.example", "allocated-key",
                             client=client, enabled=False, run_id="r1")

    async def test_discovery_uses_allocated_credential_and_actual_gateway_request_id(self):
        requests = []

        def provider(request):
            requests.append(request)
            return httpx.Response(403, headers={"apim-request-id": "service-denial"},
                                  json={"statusCode": 403, "message": "Access denied"})

        async with httpx.AsyncClient(transport=httpx.MockTransport(provider)) as client:
            probe = GatewayProbe("candidate-planner", "https://gateway.example", "allocated-key",
                                 client=client, enabled=True, run_id="r1")
            result = await probe.discovery("release-reviewer")
        self.assertEqual(result["status_code"], 403)
        self.assertEqual(result["request_id"], "service-denial")
        self.assertEqual(result["caller"], "candidate-planner")
        self.assertEqual(requests[0].url.path, "/release-reviewer/.well-known/agent-card.json")
        self.assertEqual(requests[0].headers["Ocp-Apim-Subscription-Key"], "allocated-key")
        self.assertEqual(requests[0].headers["x-citadel-operation-id"], result["operation_id"])
        self.assertNotIn("allocated-key", str(result))
        self.assertEqual(result["reason"], "observed")
        self.assertEqual(result["check_id"], "route.candidate-planner.release-reviewer.discovery")
        self.assertEqual(result["target"], hashlib.sha256(
            b"https://gateway.example/release-reviewer/.well-known/agent-card.json").hexdigest())

    async def test_only_explicit_gateway_denial_metadata_establishes_a_denial_reason(self):
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(
                403, headers={"apim-request-id": "actual-denial", "x-citadel-denial": "route_denied"}))) as client:
            probe = GatewayProbe("candidate-planner", "https://gateway.example", "allocated",
                                 client=client, enabled=True, run_id="r1")
            result = await probe.denied_invocation("release-reviewer")
        self.assertEqual(result["reason"], "route_denied")
        self.assertEqual(result["check_id"], "route.candidate-planner.release-reviewer.invoke")

    async def test_missing_service_id_is_not_replaced_with_a_client_id(self):
        async with httpx.AsyncClient(transport=httpx.MockTransport(
                lambda request: httpx.Response(403))) as client:
            probe = GatewayProbe("candidate-planner", "https://gateway.example", "allocated-key",
                                 client=client, enabled=True, run_id="r1")
            result = await probe.discovery("release-reviewer")
        self.assertIsNone(result["request_id"])

    async def test_gateway_guid_response_matches_the_signed_backend_context_representation(self):
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(
                403, headers={"apim-request-id": "75A98280-52C1-4D14-A7DA-D01B5445A305"}))) as client:
            probe = GatewayProbe("candidate-planner", "https://gateway.example", "allocated",
                                 client=client, enabled=True, run_id="r1")
            result = await probe.discovery("release-reviewer")
        self.assertEqual(result["request_id"], "75a9828052c14d14a7dad01b5445a305")

    async def test_fixed_purpose_transport_refuses_operator_impersonation_and_arbitrary_targets(self):
        async with httpx.AsyncClient() as client:
            with self.assertRaises(ValueError):
                GatewayProbe("operator", "https://gateway.example", "key", client=client,
                             enabled=True, run_id="r1")
            probe = GatewayProbe("candidate-planner", "https://gateway.example", "key",
                                 client=client, enabled=True, run_id="r1")
            with self.assertRaises(ValueError):
                await probe.discovery("https://other.example")

    async def test_task_and_all_reference_tools_use_actual_fixed_wire_contracts(self):
        requests = []

        def provider(request):
            requests.append(request)
            return httpx.Response(200, headers={"apim-request-id": str(len(requests))},
                                  json={"jsonrpc": "2.0", "result": {}})

        async with httpx.AsyncClient(transport=httpx.MockTransport(provider)) as client:
            probe = GatewayProbe("candidate-planner", "https://gateway.example", "allocated",
                                 client=client, enabled=True, run_id="r1")
            await probe.task("evidence-assessor", "known-task")
            for tool in ("search_airports", "lookup_airport", "list_runways"):
                await probe.reference_tool(tool, ident=None if tool == "search_airports" else "EBAM")
            with self.assertRaises(ValueError):
                await probe.reference_tool("arbitrary")
            with self.assertRaises(OperationError):
                await probe.reference_tool("lookup_airport", ident="../private")
        self.assertEqual(len(requests), 4)
        self.assertEqual(json.loads(requests[0].content)["method"], "GetTask")
        self.assertEqual(json.loads(requests[0].content)["params"], {"id": "known-task"})
        for request, tool in zip(requests[1:], ("search_airports", "lookup_airport", "list_runways")):
            body = json.loads(request.content)
            self.assertEqual(request.url.path, "/reference-data/mcp")
            self.assertEqual(request.headers["MCP-Protocol-Version"], "2025-11-25")
            self.assertEqual(body["method"], "tools/call")
            self.assertEqual(body["params"]["name"], tool)
            self.assertEqual(body["params"]["arguments"], {} if tool == "search_airports" else {"ident": "EBAM"})
            self.assertEqual(request.headers["Ocp-Apim-Subscription-Key"], "allocated")

    async def test_mcp_error_envelope_cannot_be_an_allowed_control(self):
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(
                200, headers={"apim-request-id": "service1"},
                json={"jsonrpc": "2.0", "result": {"isError": True, "content": []}}))) as client:
            probe = GatewayProbe("candidate-planner", "https://gateway.example", "allocated",
                                 client=client, enabled=True, run_id="r1")
            result = await probe.reference_tool("lookup_airport", ident="EBAM")
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["reason"], "protocol_control_failed")

    async def test_reference_control_requires_real_shaped_payload_not_an_empty_success_envelope(self):
        results = [{}, {"structuredContent": {"provenance": {"fixture": {"id": "base-source"}},
                                            "airports": [{"ident": {"parsed": "EBAM"}}]}}]
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(
                200, headers={"apim-request-id": "service1"},
                json={"jsonrpc": "2.0", "result": results.pop(0)}))) as client:
            probe = GatewayProbe("candidate-planner", "https://gateway.example", "allocated",
                                 client=client, enabled=True, run_id="r1")
            absent = await probe.reference_tool("search_airports")
            observed = await probe.reference_tool("search_airports")
        self.assertEqual(absent.get("status"), "blocked")
        self.assertEqual(observed.get("actual"), "reference_data")
        self.assertNotIn("airports", observed)
        self.assertNotIn("provenance", observed)
