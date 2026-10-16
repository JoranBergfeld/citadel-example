import io
import json
import os
import sys
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import httpx
import httpx2
from azure.storage.blob.aio import ContainerClient

from citadel.acceptance.worker import run_gateway_matrix
from tests.runtime.test_storage import FixtureCredential


class WorkerExecutionTests(unittest.IsolatedAsyncioTestCase):
    async def test_direct_model_worker_never_borrows_subscription_or_reacquires_operator_run_slot(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))
        try:
            from test_ticket_storage import TicketWire
        finally:
            sys.path.pop(0)
        wire, requests, allocations = TicketWire(clock=time.time), [], []
        existing = set(wire.blobs)

        class Credential(FixtureCredential):
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

        def credential(**options):
            allocations.append(options)
            return Credential()

        async def provider(request):
            requests.append(request)
            return httpx2.Response(403, headers={"x-ms-request-id": "actual-model-id"},
                                   json={"error": {"code": "PermissionDenied"}})

        config = SimpleNamespace(target="candidate-planner",
            client_id="11111111-1111-1111-1111-111111111111",
            blob="https://allocated.blob.core.windows.net", operations_container="planner-operations",
            model_deployment="citadel-gpt-41-mini")
        request = {"schema_version": 1, "mode": "direct-model", "workload": config.target,
            "client_id": config.client_id, "run_id": "modelworker1", "deadline": time.time() + 120,
            "model": {"run_id": "modelphase1", "origin": "https://allocated.openai.azure.com",
                      "deployment": "citadel-gpt-41-mini"}}
        client_type = httpx2.AsyncClient
        with (patch.dict(os.environ, {"CITADEL_ACCEPTANCE_ENABLED": "true",
                                      "AZURE_PRINCIPAL_ID": config.client_id}),
              patch("citadel.acceptance.worker.ManagedIdentityCredential", credential),
              patch("citadel.acceptance.worker.ContainerClient",
                    lambda *args, **kw: ContainerClient(*args, transport=wire, **kw)),
              patch("httpx2.AsyncClient", lambda **kw: client_type(
                  transport=httpx2.MockTransport(provider), **kw))):
            observations = await run_gateway_matrix(config, request)
            with self.assertRaises(Exception):
                await run_gateway_matrix(config, request)
        self.assertEqual(len(requests), 1)
        self.assertEqual(allocations[0], {"client_id": config.client_id, "retry_total": 0})
        self.assertNotIn("Ocp-Apim-Subscription-Key", requests[0].headers)
        self.assertEqual(observations[0]["operation_id"], "modelworker1")
        self.assertEqual(observations[0]["run_id"], "modelphase1")
        self.assertEqual(set(wire.blobs) - existing, {
            "/planner-operations/acceptance/modelworker1/dispatch.json",
            "/planner-operations/acceptance/modelworker1/observations.json"})
        self.assertEqual(wire.leases, {})

    async def test_gateway_worker_uses_allocated_secret_and_publishes_digest_bound_wire_observations(self):
        from citadel.acceptance.telemetry import configure
        from citadel.acceptance.route_context import build_route_context
        from citadel.evidence.manifests import sha256
        from tests.acceptance.test_route_context import ledgers
        from a2a.types import Task, TaskStatus, TaskState, Artifact, Part
        from google.protobuf.json_format import MessageToDict
        documents = ledgers()
        context = build_route_context(documents, run_ids=["real-run"])
        runtime_tests = str(Path(__file__).resolve().parents[1] / "runtime")
        sys.path.insert(0, runtime_tests)
        try:
            from test_ticket_storage import TicketWire
        finally:
            sys.path.remove(runtime_tests)
        wire, requests, records, secret_names, identities, options_seen = TicketWire(clock=time.time), [], [], [], [], []
        wire.blobs["/planner-operations/active-run-slot.json"] = b"{}"
        wire.etags["/planner-operations/active-run-slot.json"] = 1

        class Credential(FixtureCredential):
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

        class Vault:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            async def get_secret(self, name):
                secret_names.append(name)
                return SimpleNamespace(value="fixture-allocated-candidate-key")

        async def http(request):
            requests.append(request)
            self.assertEqual(request.headers["Ocp-Apim-Subscription-Key"], "fixture-allocated-candidate-key")
            headers = {"apim-request-id": f"{len(requests):032x}"}
            target = request.url.path.split("/")[1]
            if target in ("evidence-assessor", "briefing-author") and (
                    "/operations/" in request.url.path or request.url.path.endswith("/a2a")):
                reference = context["operations"][target]
                row = documents[target]["operations"]["candidate-planner/invoke/" + reference["operation_id"]]
                if request.method == "GET":
                    return httpx.Response(200, headers=headers, json=row)
                self.assertEqual(request.headers["a2a-version"], "1.0")
                payload = json.loads(request.content)
                self.assertEqual(payload["method"], "GetTask")
                self.assertEqual(payload["params"], {"id": reference["operation_id"]})
                task = Task(id=reference["operation_id"], context_id="real-run",
                    status=TaskStatus(state=TaskState.TASK_STATE_COMPLETED),
                    artifacts=[Artifact(artifact_id=reference["operation_id"],
                        parts=[Part(text=json.dumps(row.get("product", row["result"])))])])
                return httpx.Response(200, headers=headers,
                                      json={"jsonrpc": "2.0", "id": payload["id"], "result": MessageToDict(task)})
            if "/findings/" in request.url.path:
                self.assertEqual(request.headers["x-citadel-read-pool"], "review1")
                return httpx.Response(200, headers=headers, json=documents["findings"]["findings"]["finding1"]["1"])
            if request.url.path.endswith("agent-card.json") and request.url.path.split("/")[1] in (
                    "evidence-assessor", "briefing-author"):
                return httpx.Response(200, headers=headers, json={"supportedInterfaces": [{
                    "url": "https://gateway.example/" + request.url.path.split("/")[1] + "/a2a",
                    "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}]})
            if request.url.path == "/reference-data/mcp":
                payload = json.loads(request.content)
                if payload["method"] == "initialize":
                    result = {"protocolVersion": "2025-11-25"}
                else:
                    tool = payload["params"]["name"]
                    content = {"provenance": {"fixture": {"id": "base-source"}}}
                    if tool == "search_airports":
                        content["airports"] = [{"ident": {"parsed": "EBAM"}}]
                    elif tool == "lookup_airport":
                        content["airport"] = {"ident": {"parsed": "EBAM"}}
                    else:
                        content["runways"] = [{"airport_ident": {"parsed": "EBAM"}}]
                    result = {"structuredContent": content}
                return httpx.Response(200, headers=headers,
                                      json={"jsonrpc": "2.0", "id": payload["id"], "result": result})
            return httpx.Response(403, headers=headers | {"x-citadel-denial": "route_denied"})

        client_type = httpx.AsyncClient

        def client(**options):
            options_seen.append(options)
            return client_type(transport=httpx.MockTransport(http), **options)

        def credential(**options):
            identities.append(options)
            return Credential()

        config = SimpleNamespace(target="candidate-planner",
            client_id="11111111-1111-1111-1111-111111111111",
            blob="https://allocated.blob.core.windows.net", operations_container="planner-operations",
            vault="https://allocated.vault.azure.net", subscription_secret="caller-candidate-planner",
            gateway="https://gateway.example")
        request = {"schema_version": 1, "mode": "gateway-matrix", "workload": config.target,
            "client_id": config.client_id, "run_id": "gateway-worker", "deadline": time.time() + 120,
            "routes": context}
        with (patch.dict(os.environ, {"CITADEL_ACCEPTANCE_ENABLED": "true"}),
              patch("citadel.acceptance.worker.ManagedIdentityCredential", credential),
              patch("citadel.acceptance.worker.ContainerClient",
                    lambda *args, **kw: ContainerClient(*args, transport=wire, **kw)),
              patch("citadel.acceptance.worker.SecretClient", lambda *args, **kw: Vault()),
              patch("citadel.acceptance.monitor.MonitorExporter",
                    lambda *args, **kw: SimpleNamespace(emit=records.append)),
              patch("citadel.acceptance.telemetry._exporter", None),
              patch("httpx.AsyncClient", client), redirect_stdout(io.StringIO())):
            configure(config.target, config.client_id, client_id=config.client_id, connection_string="fixture")
            observations = await run_gateway_matrix(config, request)
        self.assertEqual(identities, [{"client_id": config.client_id}])
        self.assertEqual(secret_names, ["caller-candidate-planner"])
        self.assertEqual(len(requests), 18)
        self.assertTrue(all(options.get("trust_env") is False for options in options_seen))
        self.assertEqual(len(observations), 18)
        self.assertEqual(sum(row.get("actual") in ("owned_status", "owned_task", "exact_finding")
                             for row in observations), 4)
        self.assertNotIn("/planner-operations/active-run-slot.json", wire.leases)
        self.assertLessEqual(len([key for key in wire.blobs if "/read-tickets/" in key]), 512)
        for row in observations:
            corresponding = [record for record in records if record["method"] == "probe"
                and record["operation_id"] == row["operation_id"]]
            self.assertEqual(len(corresponding), 1)
            self.assertEqual(corresponding[0]["facts"]["sha256"], sha256(row))
            self.assertEqual(corresponding[0]["facts"]["probe_id"], row["check_id"])
            self.assertEqual(corresponding[0]["target"], row["target"])
            self.assertEqual(corresponding[0]["request_id"], row["request_id"])
        self.assertNotIn("fixture-allocated-candidate-key", json.dumps(records))

    async def test_all_fault_drivers_execute_real_blob_sdk_and_restore_admission_only_after_results(self):
        from citadel.acceptance.operation_harness import bind_operation_result
        runtime_tests = str(Path(__file__).resolve().parents[1] / "runtime")
        sys.path.insert(0, runtime_tests)
        try:
            from test_ticket_storage import TicketWire
        finally:
            sys.path.remove(runtime_tests)

        class Wire(TicketWire):
            async def send(self, request, **options):
                response = await super().send(request, **options)
                response.headers["x-ms-request-id"] = "fixture-service-" + str(len(self.requests))
                return response

        class Credential(FixtureCredential):
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

        wire = Wire(clock=time.time)
        wire.blobs["/planner-operations/active-run-slot.json"] = b"{}"
        wire.etags["/planner-operations/active-run-slot.json"] = 1
        config = SimpleNamespace(target="candidate-planner",
            client_id="11111111-1111-1111-1111-111111111111",
            blob="https://allocated.blob.core.windows.net", operations_container="planner-operations")
        request = {"schema_version": 1, "mode": "operation-faults", "workload": config.target,
            "client_id": config.client_id, "run_id": "fault-worker", "deadline": time.time() + 180}
        with (patch.dict(os.environ, {"CITADEL_ACCEPTANCE_ENABLED": "true",
                                     "AZURE_PRINCIPAL_ID": config.client_id}),
              patch("citadel.acceptance.worker.ManagedIdentityCredential", lambda **kw: Credential()),
              patch("citadel.acceptance.worker.ContainerClient",
                    lambda *args, **kw: ContainerClient(*args, transport=wire, **kw)),
              patch("citadel.acceptance.worker.SecretClient",
                    side_effect=AssertionError("Fault probes must not fetch subscription secrets"))):
            observations = await run_gateway_matrix(config, request)
        result = json.loads(wire.blobs["/planner-operations/acceptance/fault-worker/observations.json"])
        self.assertEqual(result["state"], "complete", result)
        self.assertEqual(len(observations), 6)
        self.assertEqual(len(bind_operation_result(result, run_id=request["run_id"],
            principal=observations[0]["runtime_identity"], account=config.blob)), 6)
        self.assertEqual(len({row["request_id"] for row in observations}), 6)
        self.assertTrue(all(row["status_code"] == 201 for row in observations))
        self.assertLessEqual(len([path for path in wire.blobs if "/read-tickets/" in path]), 512)
        self.assertNotIn("/planner-operations/active-run-slot.json", wire.leases)
        self.assertTrue(all("/planner-operations/" in request.url for request in wire.requests))

    async def test_origin_worker_uses_allocated_mi_tickets_and_no_subscription_secret(self):
        runtime_tests = str(Path(__file__).resolve().parents[1] / "runtime")
        sys.path.insert(0, runtime_tests)
        try:
            from test_ticket_storage import TicketWire
        finally:
            sys.path.remove(runtime_tests)
        wire, requests, identities = TicketWire(clock=time.time), [], []
        wire.blobs["/planner-operations/active-run-slot.json"] = b"{}"
        wire.etags["/planner-operations/active-run-slot.json"] = 1

        class Credential(FixtureCredential):
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

        def credential(**options):
            identities.append(options)
            return Credential()

        def container(*args, **options):
            return ContainerClient(*args, transport=wire, **options)

        async def http(request):
            requests.append(request)
            return httpx.Response(403, headers={"x-citadel-origin-request-id": "backend-" + str(len(requests))},
                                  json={"error": "gateway_authorization_denied"})

        client_type = httpx.AsyncClient

        def client(**options):
            return client_type(transport=httpx.MockTransport(http), **options)

        config = SimpleNamespace(target="candidate-planner",
            client_id="11111111-1111-1111-1111-111111111111",
            blob="https://allocated.blob.core.windows.net", operations_container="planner-operations",
            vault="https://must-not-call.vault.azure.net",
            trust=SimpleNamespace(certificates={"a" * 64: None}, signing_keys={"current": "not-needed"}))
        request = {"schema_version": 1, "mode": "origin-boundary", "workload": config.target,
            "client_id": config.client_id, "run_id": "origin-worker", "deadline": time.time() + 120,
            "origin": "https://allocated.example.azurecontainerapps.io"}
        with (patch.dict(os.environ, {"CITADEL_ACCEPTANCE_ENABLED": "true",
                                     "AZURE_PRINCIPAL_ID": config.client_id}),
              patch("citadel.acceptance.worker.ManagedIdentityCredential", credential),
              patch("citadel.acceptance.worker.ContainerClient", container),
              patch("citadel.acceptance.worker.SecretClient",
                    side_effect=AssertionError("Origin probes must not fetch subscription secrets")),
              patch("httpx.AsyncClient", client), redirect_stdout(io.StringIO())):
            observations = await run_gateway_matrix(config, request)
        self.assertEqual(identities, [{"client_id": config.client_id}])
        self.assertEqual(len(requests), 3)
        self.assertEqual(len(observations), 3)
        result = json.loads(wire.blobs["/planner-operations/acceptance/origin-worker/observations.json"])
        self.assertEqual(result["state"], "complete")
        self.assertEqual(result["observations"], observations)
        self.assertEqual(len([key for key in wire.blobs if "/read-tickets/" in key]), 3)
        self.assertTrue(all("/planner-operations/" in str(item.url) for item in wire.requests))
        self.assertEqual(len([key for key in wire.blobs if "/observations/" in key]), 3)
        released = next(index for index, item in enumerate(wire.requests)
                        if item.headers.get("x-ms-lease-action") == "release")
        completed = next(index for index, item in enumerate(wire.requests)
                         if "/observations.json" in str(item.url))
        self.assertLess(released, completed, "Completion must not race restoration before slot release")
