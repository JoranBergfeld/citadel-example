import hashlib
import json
import time
import unittest

import httpx2

from citadel.acceptance.model_probes import DirectModelProbe
from citadel.operations import OperationError
from tests.acceptance.test_storage_probes import Credential


class ModelProbeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.requests, self.admissions, self.credential = [], 0, Credential()

    async def admit(self):
        self.admissions += 1

    def client(self, **options):
        async def provider(request):
            self.requests.append(request)
            return httpx2.Response(403, headers={"apim-request-id": "actual-model-service-id"},
                                   json={"error": {"code": "PermissionDenied", "message": "not exported"}})
        return httpx2.AsyncClient(transport=httpx2.MockTransport(provider), **options)

    def probe(self, **changes):
        options = dict(workload="evidence-assessor", origin="https://allocated.openai.azure.com",
            deployment="approved-deployment", credential=self.credential,
            principal_id="11111111-1111-1111-1111-111111111111", enabled=True,
            run_id="direct1", deadline=time.time() + 60, admit=self.admit,
            client_factory=self.client)
        return DirectModelProbe(**(options | changes))

    async def test_fixed_model_request_uses_actual_assigned_token_not_subscription_or_operator(self):
        probe = self.probe()
        record = await probe.observe()
        self.assertEqual(len(self.requests), 1)
        request = self.requests[0]
        self.assertEqual(request.method, "POST")
        self.assertEqual(str(request.url), "https://allocated.openai.azure.com/openai/v1/chat/completions")
        self.assertEqual(request.headers["Authorization"], "Bearer test-only-no-cloud-token")
        self.assertNotIn("Ocp-Apim-Subscription-Key", request.headers)
        self.assertEqual(self.credential.scopes, [("https://cognitiveservices.azure.com/.default",)])
        payload = json.loads(request.content)
        self.assertEqual(payload["model"], "approved-deployment")
        self.assertEqual(payload["max_completion_tokens"], 2000)
        self.assertNotIn("tools", payload)
        self.assertEqual(record["request_id"], "actual-model-service-id")
        self.assertEqual(record["status_code"], 403)
        self.assertEqual(record["reason"], "PermissionDenied")
        self.assertEqual(record["runtime_identity"], hashlib.sha256(
            b"11111111-1111-1111-1111-111111111111").hexdigest())
        self.assertNotIn("not exported", str(record))
        self.assertNotIn("test-only-no-cloud-token", str(record))
        self.assertEqual(self.admissions, 1)
        with self.assertRaises(OperationError):
            await probe.observe()
        self.assertEqual(len(self.requests), 1)

    async def test_fixed_purpose_authority_and_absolute_deadline_fail_before_token_access(self):
        for change in ({"enabled": False}, {"workload": "operator"},
                       {"origin": "https://other.example"}, {"deadline": time.time() + 901}):
            with self.assertRaises(ValueError):
                self.probe(**change)
        probe = self.probe()
        probe.deadline = time.time() - 1
        with self.assertRaises(OperationError):
            await probe.observe()
        self.assertEqual(self.credential.scopes, [])
        self.assertEqual(self.requests, [])

    async def test_malformed_authorization_response_remains_indeterminate_without_payload_leak(self):
        async def provider(request):
            return httpx2.Response(403, json={"error": {"code": [], "message": "private-provider-details"}})

        def client(**options):
            return httpx2.AsyncClient(transport=httpx2.MockTransport(provider), **options)

        result = await self.probe(client_factory=client).observe()
        self.assertEqual(result["state"], "indeterminate")
        self.assertEqual(result["status"], "blocked")
        self.assertNotIn("private-provider-details", str(result))
