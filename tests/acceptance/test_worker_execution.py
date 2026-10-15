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
from azure.storage.blob.aio import ContainerClient

from citadel.acceptance.worker import run_gateway_matrix
from tests.runtime.test_storage import FixtureCredential


class WorkerExecutionTests(unittest.IsolatedAsyncioTestCase):
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
