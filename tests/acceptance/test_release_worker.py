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

from citadel.acceptance.worker import run_gateway_matrix, validate_request
from citadel.evidence.manifests import canonical_bytes, sha256
from citadel.operations import Operations
from citadel.operations.testing import MemoryLedger
from citadel.runtime.reference import reference_application
from tests.runtime.test_storage import FixtureCredential


class ReleaseWorkerTests(unittest.IsolatedAsyncioTestCase):
    async def test_actual_reviewer_wire_runs_release_faults_with_read_only_source_and_allocated_key(self):
        runtime_tests = str(Path(__file__).resolve().parents[1] / "runtime")
        sys.path.insert(0, runtime_tests)
        try:
            from test_ticket_storage import TicketWire
            from test_reference import reference, trust
            from test_workflow import FixtureGateway
        finally:
            sys.path.remove(runtime_tests)
        data, source = reference(), MemoryLedger(clock=time.time)
        assessor = Operations(source, workload="evidence-assessor")
        draft = {"artifact_id": "draft", "version": 1, "schema_version": 1, "run_id": "comparison",
                 "operation_id": "assess", "airport_ident": "EB01", "private_notes": "NEVER EXPORT",
                 **data.assess_airport("EB01")}
        await assessor.accept("candidate-planner", "draft", "assess", {"draft": draft, "expected_version": 0},
                              run_id="comparison", deadline=time.time() + 120)
        owner = await assessor.claim("candidate-planner", "draft", "assess", worker="assessor")
        await assessor.submit_draft(owner, draft, expected_version=0, reference=data)

        class Wire(TicketWire):
            async def send(self, request, **options):
                if "/drafts/" in request.url:
                    self_outer.assertEqual(request.method, "GET", "Reviewer never writes source drafts")
                response = await super().send(request, **options)
                response.headers["x-ms-request-id"] = "service-" + str(len(self.requests))
                return response

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
                secrets.append(name)
                return SimpleNamespace(value="release-reviewer")

        self_outer = self
        class Gateway(FixtureGateway):
            async def handle_async_request(self, request):
                response = await super().handle_async_request(request)
                response.headers["apim-request-id"] = "external-request"
                return response

        wire, gateway, secrets, identities = Wire(clock=time.time), Gateway(), [], []
        wire.blobs["/drafts/ledger-v1.json"] = canonical_bytes((await source.read())[0])
        wire.etags["/drafts/ledger-v1.json"] = 1
        before = wire.blobs["/drafts/ledger-v1.json"]
        app = reference_application(data, trust("reference-data"))
        gateway.apps["reference-data"] = app
        client_type = httpx.AsyncClient
        config = SimpleNamespace(target="release-reviewer",
            client_id="11111111-1111-1111-1111-111111111111",
            blob="https://allocated.blob.core.windows.net", operations_container="reviewer-operations",
            vault="https://allocated.vault.azure.net", subscription_secret="caller-release-reviewer",
            gateway="https://gateway.test")
        request = {"schema_version": 1, "mode": "release-faults", "workload": config.target,
            "client_id": config.client_id, "run_id": "release-worker", "deadline": time.time() + 120,
            "release": {"run_id": "comparison", "draft": {
                "artifact_id": "draft", "version": 1, "sha256": sha256(draft)}}}
        def credential(**options):
            identities.append(options)
            return Credential()
        with self.assertRaises(ValueError):
            validate_request(request, enabled=False, workload=config.target, client_id=config.client_id)
        with self.assertRaises(ValueError):
            validate_request(request | {"workload": "candidate-planner"}, enabled=True,
                             workload="candidate-planner", client_id=config.client_id)
        with (patch.dict(os.environ, {"CITADEL_ACCEPTANCE_ENABLED": "true", "AZURE_PRINCIPAL_ID": config.client_id}),
              patch("citadel.acceptance.worker.ManagedIdentityCredential", credential),
              patch("citadel.acceptance.worker.ContainerClient",
                    lambda *args, **kw: ContainerClient(*args, transport=wire, **kw)),
              patch("citadel.acceptance.worker.SecretClient", lambda *args, **kw: Vault()),
              patch("httpx.AsyncClient", lambda **kw: client_type(transport=gateway, **kw)),
              redirect_stdout(io.StringIO())):
            async with app.app.router.lifespan_context(app.app):
                observations = await run_gateway_matrix(config, request)
        self.assertEqual(identities, [{"client_id": config.client_id}])
        self.assertEqual(secrets, ["caller-release-reviewer"])
        self.assertEqual({row["check_id"] for row in observations}, {
            "fault.dropped-committed-release", "fault.concurrent-exact-draft-release",
            "fault.concurrent-different-operation-release", "fault.draft-hash-binding"})
        rejected = next(row["actual"] for row in observations if row["check_id"] == "fault.draft-hash-binding")
        self.assertEqual((rejected["response"], rejected["rejected_count"]), ("conflict", 0))
        self.assertTrue(all(row["actual"]["artifact_count"] == 1 for row in observations))
        self.assertTrue(all(len(row["actual"]["reference_reads"]) == 3 for row in observations))
        self.assertTrue(all(receipt["request_id"] == "external-request"
                            for row in observations for receipt in row["actual"]["reference_reads"]))
        self.assertTrue(all(row["caller"] == "release-reviewer" and row["status_code"] == 201
                            and row["request_id"].startswith("service-") for row in observations))
        self.assertEqual(wire.blobs["/drafts/ledger-v1.json"], before)
        self.assertNotIn("/findings/ledger-v1.json", wire.blobs)
        self.assertLessEqual(len([key for key in wire.blobs if "/read-tickets/" in key]), 512)
        self.assertNotIn("NEVER EXPORT", json.dumps(observations))
        summary = json.loads(wire.blobs["/reviewer-operations/acceptance/release-worker/observations.json"])
        self.assertEqual(summary["state"], "complete")
