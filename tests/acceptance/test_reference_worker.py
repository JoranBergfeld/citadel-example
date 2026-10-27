import hashlib
import json
import time
import unittest
from types import SimpleNamespace

from azure.core.credentials import AccessToken
import httpx
import httpx2

from citadel.acceptance.coverage import CONTAINERS
from citadel.acceptance.reference_worker import execute
from tests.acceptance.test_storage_probes import Response, StorageTransport, DATA, HASH
from tests.acceptance.storage_fixture import storage_accounts


class ReferenceTransport(StorageTransport):
    async def send(self, request, **options):
        self.requests.append(request)
        allowed = request.method == "GET" and "/reference/" in request.url
        response = Response(request, DATA if allowed else
            b"<Error><Code>AuthorizationPermissionMismatch</Code><Message>Denied</Message></Error>")
        response.headers["x-ms-request-id"] = f"reference-service-{len(self.requests)}"
        if not allowed:
            response.status_code, response.reason = 403, "Forbidden"
            response.headers["x-ms-error-code"] = "AuthorizationPermissionMismatch"
            response.content_type = "application/xml"
        return response


class ReferenceWorkerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.config = SimpleNamespace(target="reference-data",
            client_id="11111111-1111-1111-1111-111111111111",
            blob="https://referencefixture.blob.core.windows.net",
            operations_container=None, subscription_secret=None)
        self.principal = "22222222-2222-2222-2222-222222222222"
        self.request = {"schema_version": 1, "run_id": "reference1", "workload": "reference-data",
            "client_id": self.config.client_id, "deadline": time.time() + 120,
            "mode": "storage-boundaries", "storage": {"suite_id": "suite1", "accounts": storage_accounts(), "targets": {
                container: {"sha256": HASH, "etag": '"verified-fixture"'} for container in CONTAINERS}}}

    async def test_one_shot_readonly_identity_executes_real_sdk_boundaries_without_a_secret_or_writable_ledger(self):
        calls, transport = [], ReferenceTransport()

        class Credential:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            async def get_token(self, *scopes, **options):
                calls.append(("scope", scopes))
                return AccessToken("fixture-reference-token", time.time() + 3600)

        def credential(**options):
            calls.append(("identity", options))
            return Credential()

        result = await execute(self.config, self.request, enabled=True,
            principal_id=self.principal, credential_factory=credential, storage_transport=transport)
        self.assertEqual(result["state"], "complete")
        self.assertEqual(result["read_attempts"], 19)
        self.assertEqual(len(result["observations"]), 19)
        self.assertEqual(result["runtime_identity"], hashlib.sha256(self.principal.encode()).hexdigest())
        self.assertEqual(calls[0], ("identity", {"client_id": self.config.client_id, "retry_total": 0}))
        self.assertEqual({item[1] for item in calls if item[0] == "scope"}, {("https://storage.azure.com/.default",)})
        self.assertTrue(all("/acceptance/suite1/storage-boundary-v1.json" in item.url for item in transport.requests))
        self.assertEqual({request.url.split("/")[2] for request in transport.requests}, {
            "referencefixture.blob.core.windows.net", "evidencefixture.blob.core.windows.net",
            "planningfixture.blob.core.windows.net"})
        for request in transport.requests:
            container = request.url.split("/")[3]
            self.assertTrue(request.url.startswith(storage_accounts()[container] + "/" + container + "/"))
        self.assertFalse(any("dispatch.json" in item.url or "read-tickets" in item.url for item in transport.requests))
        self.assertNotIn("fixture-reference-token", str(result))

    async def test_normal_mode_changed_identity_or_writable_authority_refuses_before_any_provider(self):
        def forbidden(**options):
            raise AssertionError("No SDK may be constructed for an unadmitted reference probe")

        for changes, enabled in (({}, False), ({"client_id": "33333333-3333-3333-3333-333333333333"}, True),
                                 ({"mode": "gateway-matrix"}, True)):
            with self.subTest(changes=changes, enabled=enabled), self.assertRaises(ValueError):
                await execute(self.config, self.request | changes, enabled=enabled,
                    principal_id=self.principal, credential_factory=forbidden)
        self.config.operations_container = "planner-operations"
        with self.assertRaises(ValueError):
            await execute(self.config, self.request, enabled=True,
                principal_id=self.principal, credential_factory=forbidden)

    async def test_cross_account_probe_manifest_cannot_select_another_deployment_or_arbitrary_endpoint(self):
        def forbidden(**options):
            raise AssertionError("Unallocated storage selection must fail before identity/provider access")

        for endpoint in ("https://evidenceother.blob.core.windows.net", "https://other.example"):
            accounts = storage_accounts() | {"drafts": endpoint}
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                await execute(self.config, self.request | {"storage": self.request["storage"] | {"accounts": accounts}},
                    enabled=True, principal_id=self.principal, credential_factory=forbidden)

    async def test_reference_origin_probes_use_real_mcp_initialize_without_subscription_or_gateway_private_key(self):
        requests = []

        class Credential:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            async def get_token(self, *args, **options):
                raise AssertionError("Origin TLS probes must not acquire a caller credential")

        async def respond(request):
            requests.append(request)
            return httpx.Response(403, headers={"x-citadel-origin-request-id": f"origin-{len(requests)}"})

        self.config.trust = SimpleNamespace(certificates={"a" * 64: None}, signing_keys={"current": "not-exported"})
        request = {key: value for key, value in self.request.items() if key != "storage"} | {
            "mode": "origin-boundary", "origin": "https://reference.example.azurecontainerapps.io"}
        result = await execute(self.config, request, enabled=True, principal_id=self.principal,
            credential_factory=lambda **options: Credential(),
            client_factory=lambda **options: httpx.AsyncClient(transport=httpx.MockTransport(respond), **options))
        self.assertEqual(result["state"], "complete")
        self.assertEqual(result["read_attempts"], 3)
        self.assertEqual(len(requests), 3)
        for item in requests:
            self.assertEqual(item.method, "POST")
            self.assertTrue(str(item.url).endswith("/mcp"))
            self.assertEqual(json.loads(item.content)["method"], "initialize")
            self.assertEqual(json.loads(item.content)["params"]["protocolVersion"], "2025-11-25")
            self.assertNotIn("Ocp-Apim-Subscription-Key", item.headers)
        self.assertNotIn("not-exported", str(result))

    async def test_reference_model_control_uses_own_identity_without_storage_or_subscription_authority(self):
        requests, scopes, allocations = [], [], []

        class Credential:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

            async def get_token(self, *args, **kwargs):
                scopes.append(args)
                return AccessToken("reference-only-token", time.time() + 3600)

        def credential(**kwargs):
            allocations.append(kwargs)
            return Credential()

        async def respond(request):
            requests.append(request)
            return httpx2.Response(403, headers={"x-ms-request-id": "actual-reference-model-id"},
                                   json={"error": {"code": "PermissionDenied"}})

        request = {key: value for key, value in self.request.items() if key != "storage"} | {
            "mode": "direct-model", "model": {"run_id": "modelphase1",
                "origin": "https://allocated.openai.azure.com", "deployment": "citadel-gpt-41-mini"}}
        result = await execute(self.config, request, enabled=True, principal_id=self.principal,
            credential_factory=credential,
            client_factory=lambda **options: httpx2.AsyncClient(transport=httpx2.MockTransport(respond), **options))
        self.assertEqual(result["state"], "complete")
        self.assertEqual(len(requests), 1)
        self.assertEqual(scopes, [("https://cognitiveservices.azure.com/.default",)])
        self.assertEqual(allocations, [{"client_id": self.config.client_id, "retry_total": 0}])
        self.assertEqual(result["observations"][0]["operation_id"], "reference1")
        self.assertEqual(result["observations"][0]["run_id"], "modelphase1")
        self.assertNotIn("Ocp-Apim-Subscription-Key", requests[0].headers)
        self.assertEqual(result["read_attempts"], 0)
        self.assertNotIn("reference-only-token", str(result))
