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
from citadel.operations import empty_ledger
from citadel.operations.blob import API_VERSION
from citadel.runtime.reference import reference_application
from tests.runtime.test_storage import FixtureCredential


class VersionWorkerTests(unittest.IsolatedAsyncioTestCase):
    async def test_assessor_sdk_version_race_uses_only_own_authority_and_preserves_actual_source(self):
        runtime_tests = str(Path(__file__).resolve().parents[1] / "runtime")
        sys.path.insert(0, runtime_tests)
        try:
            from test_ticket_storage import TicketWire
            from test_reference import reference, trust
            from test_workflow import FixtureGateway
        finally:
            sys.path.remove(runtime_tests)
        data, document = reference(), empty_ledger()
        draft = {"artifact_id": "source", "version": 1, "schema_version": 1, "run_id": "comparison",
            "operation_id": "assessment", "airport_ident": "EB01", "private_notes": "PRIVATE ASSESSMENT",
            **data.assess_airport("EB01")}
        document["drafts"] = {"source": {"1": draft}}
        identities, secret_names = [], []
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
                return SimpleNamespace(value="evidence-assessor")
        class Wire(TicketWire):
            async def send(self, request, **options):
                response = await super().send(request, **options)
                response.headers["x-ms-request-id"] = "actual-wire-" + str(len(self.requests))
                return response
        wire, gateway = Wire(clock=time.time), FixtureGateway()
        before = canonical_bytes(document)
        wire.blobs["/drafts/ledger-v1.json"] = before
        wire.etags["/drafts/ledger-v1.json"] = 1
        app = reference_application(data, trust("reference-data"))
        gateway.apps["reference-data"] = app
        config = SimpleNamespace(target="evidence-assessor", client_id="11111111-1111-1111-1111-111111111111",
            blob="https://allocated.blob.core.windows.net", operations_container="assessor-operations",
            vault="https://allocated.vault.azure.net", subscription_secret="caller-evidence-assessor",
            gateway="https://gateway.test")
        request = {"schema_version": 1, "mode": "draft-versions", "workload": config.target,
            "client_id": config.client_id, "run_id": "version-worker", "deadline": time.time() + 120,
            "release": {"run_id": "comparison", "draft": {
                "artifact_id": "source", "version": 1, "sha256": sha256(draft)}}}
        for actor, enabled in (("release-reviewer", True), ("evidence-assessor", False)):
            with self.assertRaises(ValueError):
                validate_request(request | {"workload": actor}, enabled=enabled,
                                 workload=actor, client_id=config.client_id)
        client_type = httpx.AsyncClient
        def credential(**options):
            identities.append(options)
            return Credential()
        with (patch.dict(os.environ, {"CITADEL_ACCEPTANCE_ENABLED": "true", "AZURE_PRINCIPAL_ID": config.client_id}),
              patch("citadel.acceptance.worker.ManagedIdentityCredential", credential),
              patch("citadel.acceptance.worker.SecretClient", lambda *args, **kw: Vault()),
              patch("citadel.acceptance.worker.ContainerClient",
                    lambda *args, **kw: ContainerClient(*args, transport=wire, **kw)),
              patch("httpx.AsyncClient", lambda **kw: client_type(transport=gateway, **kw)),
              redirect_stdout(io.StringIO())):
            async with app.app.router.lifespan_context(app.app):
                rows = await run_gateway_matrix(config, request)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["check_id"], "fault.concurrent-version-conflict")
        self.assertEqual(rows[0]["actual"]["states"], ["running", "succeeded"])
        self.assertEqual(rows[0]["actual"]["artifact_count"], 2)
        self.assertGreaterEqual(rows[0]["actual"]["conditional_conflicts"], 1)
        self.assertEqual(len(rows[0]["actual"]["reference_reads"]), 3)
        self.assertEqual(identities, [{"client_id": config.client_id}])
        self.assertEqual(secret_names, ["caller-evidence-assessor"])
        self.assertEqual(wire.blobs["/drafts/ledger-v1.json"], before)
        self.assertTrue(all("/findings/" not in row.url and "/reviewer-operations/" not in row.url
                            for row in wire.requests))
        self.assertTrue(all(row.headers["x-ms-version"] == API_VERSION for row in wire.requests))
        self.assertNotIn("PRIVATE ASSESSMENT", json.dumps(rows))
        self.assertLessEqual(len([key for key in wire.blobs if "/read-tickets/" in key]), 512)
