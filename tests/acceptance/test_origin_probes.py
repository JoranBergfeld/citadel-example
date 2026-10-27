import hashlib
import json
import os
import shutil
import ssl
import time
import unittest
from pathlib import Path
from uuid import uuid4

import httpx

from citadel.acceptance.origin_probes import OriginProbe
from citadel.operations import OperationError


class OriginProbeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.requests, self.contexts, self.admissions = [], [], 0

    async def admit(self):
        self.admissions += 1

    def client(self, **options):
        self.contexts.append(options["verify"])

        async def handler(request):
            self.requests.append(request)
            return httpx.Response(403, headers={"x-citadel-origin-request-id": "real-origin-response"},
                                  json={"error": "gateway_authorization_denied"})

        return httpx.AsyncClient(transport=httpx.MockTransport(handler), **options)

    def probe(self, **changes):
        options = dict(workload="evidence-assessor",
            origin="https://allocated.example.azurecontainerapps.io",
            principal_id="11111111-1111-1111-1111-111111111111",
            approved_certificate="a" * 64, key_id="current", enabled=True,
            run_id="origin1", deadline=time.time() + 120, admit=self.admit,
            client_factory=self.client)
        return OriginProbe(**(options | changes))

    async def test_fixed_origin_probes_use_real_tls_and_never_gateway_credentials(self):
        probe = self.probe()
        results = [await probe.observe(mode) for mode in (
            "missing-certificate", "unrelated-certificate", "forged-context")]
        self.assertEqual(self.admissions, 3)
        self.assertEqual(len(self.requests), 3)
        for request, result, context in zip(self.requests, results, self.contexts):
            self.assertEqual(request.method, "GET")
            self.assertEqual(str(request.url),
                             "https://allocated.example.azurecontainerapps.io/.well-known/agent-card.json")
            self.assertNotIn("authorization", request.headers)
            self.assertNotIn("ocp-apim-subscription-key", request.headers)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertTrue(context.check_hostname)
            self.assertEqual(result["request_id"], "real-origin-response")
            self.assertEqual(result["target"], hashlib.sha256(str(request.url).encode()).hexdigest())
            self.assertEqual(result["runtime_identity"], hashlib.sha256(
                b"11111111-1111-1111-1111-111111111111").hexdigest())
            self.assertEqual(result["status_code"], 403)
        self.assertNotIn("x-forwarded-client-cert", self.requests[0].headers)
        self.assertNotIn("x-forwarded-client-cert", self.requests[1].headers)
        self.assertEqual(self.requests[2].headers["x-forwarded-client-cert"], "Hash=" + "a" * 64)
        self.assertNotEqual(self.requests[2].headers["x-citadel-request-id"], results[2]["request_id"])
        self.assertNotEqual(results[1]["certificate_sha256"], "a" * 64)
        self.assertNotIn("PRIVATE KEY", json.dumps(results))

    async def test_normal_mode_arbitrary_destinations_and_exhausted_deadline_refuse_dispatch(self):
        for options in ({"enabled": False}, {"origin": "https://other.example"},
                        {"origin": "https://allocated.example.azurecontainerapps.io/admin"},
                        {"workload": "operator"}):
            with self.assertRaises(ValueError):
                self.probe(**options)
        probe = self.probe()
        with self.assertRaises(ValueError):
            await probe.observe("arbitrary-request")
        probe.deadline = time.time() - 1
        with self.assertRaises(OperationError):
            await probe.observe("missing-certificate")
        self.assertEqual(self.requests, [])

    async def test_ingress_response_id_is_observed_not_supplied_by_the_probe(self):
        def client(**options):
            async def handler(request):
                self.requests.append(request)
                return httpx.Response(403, headers={"x-request-id": "actual-ingress-generated-id"})
            return httpx.AsyncClient(transport=httpx.MockTransport(handler), **options)

        result = await self.probe(client_factory=client).observe("missing-certificate")
        self.assertEqual(result.get("request_id"), "actual-ingress-generated-id")
        self.assertNotIn("x-request-id", self.requests[0].headers)

    async def test_unrelated_certificate_files_are_private_and_removed_from_a_fresh_working_directory(self):
        previous = Path.cwd()
        root = previous / ".build" / ("cold-origin-" + uuid4().hex)
        root.mkdir(parents=True)
        try:
            os.chdir(root)

            def client(**options):
                certificates = list(Path(".").rglob("*.pem"))
                self.assertEqual(len(certificates), 2)
                self.assertTrue(all(path.stat().st_mode & 0o777 == 0o600 for path in certificates))
                return self.client(**options)

            await self.probe(client_factory=client).observe("unrelated-certificate")
            self.assertEqual(list(Path(".").rglob("*.pem")), [])
        finally:
            os.chdir(previous)
            shutil.rmtree(root)
