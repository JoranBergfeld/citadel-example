import hashlib
import json
import unittest

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from citadel.evidence import ReferenceData
from citadel.runtime.reference import reference_application, RetrievedReference
from tests.unit.gateway_fixtures import signed, trust


def reference(count=4):
    return ReferenceData.from_rows(
        airports=[{"id": str(n), "ident": f"EB{n:02}", "name": f"Fictional {n}",
                   "type": "small_airport", "latitude_deg": "51", "longitude_deg": "4",
                   "iso_country": "BE", "iso_region": "BE-VAN"} for n in range(1, count + 1)],
        runways=[{"id": str(n), "airport_ref": str(n), "airport_ident": f"EB{n:02}",
                  "length_ft": "1200", "width_ft": "80", "surface": "grass",
                  "closed": "0", "lighted": "0"} for n in range(1, count + 1)],
        countries=[{"code": "BE", "name": "Belgium"}],
        regions=[{"code": "BE-VAN", "name": "Antwerp", "iso_country": "BE"}],
    )


class RetrievedEvidenceTests(unittest.TestCase):
    def test_one_airport_evidence_supports_only_assessment_projection_and_exact_reads(self):
        from citadel.evidence import EvidenceError
        data = reference()
        retrieved = RetrievedReference(data.lookup_airport("EB01"), data.list_runways("EB01"))
        for capability in ("search_airports", "fixture_gate", "export_rows", "with_overlay"):
            self.assertFalse(hasattr(retrieved, capability), "Retrieved evidence is not an entire dataset")
        assessed = retrieved.assess_airport("EB01")
        self.assertEqual(assessed["classification"], "complete")
        self.assertEqual(assessed["gap_reasons"], [])
        draft = {"schema_version": 1, "artifact_id": "draft", "version": 1, "run_id": "run",
                 "operation_id": "assessment", "airport_ident": "EB01", "private_notes": "private", **assessed}
        projected = retrieved.shareable_projection(draft)
        self.assertEqual(projected["classification"], "complete")
        self.assertNotIn("private_notes", projected)
        with self.assertRaises(EvidenceError):
            retrieved.assess_airport("EB02")
        with self.assertRaises(EvidenceError):
            retrieved.shareable_projection(draft | {"classification": "invented"})


class ReferenceProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def test_actual_mcp_results_emit_only_source_hashes_with_authenticated_request_context(self):
        import io
        from contextlib import redirect_stdout
        from types import SimpleNamespace
        from unittest.mock import patch
        from citadel.acceptance.telemetry import configure
        from citadel.evidence.manifests import sha256
        data, records, requests = reference(), [], []
        app = reference_application(data, trust("reference-data"))

        async def gateway(request):
            requests.append(request)
            request.headers.update(signed(request.content, "reference-data", request.url.path,
                method=request.method, request_id=f"service-{len(requests)}"))
            request.headers.update({"x-citadel-run-id": "run1", "x-citadel-operation-id": "assess1"})

        with (patch("citadel.acceptance.monitor.MonitorExporter",
                    lambda *args, **kwargs: SimpleNamespace(emit=records.append)),
              patch("citadel.acceptance.telemetry._exporter", None), redirect_stdout(io.StringIO())):
            principal = "11111111-1111-1111-1111-111111111111"
            configure("reference-data", principal, client_id=principal, connection_string="fixture")
            async with app.app.router.lifespan_context(app.app):
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                        event_hooks={"request": [gateway]}) as client:
                    async with streamable_http_client("https://reference.test/mcp", http_client=client) as (read, write, _):
                        async with ClientSession(read, write) as session:
                            await session.initialize()
                            for name in ("search_airports", "lookup_airport", "list_runways"):
                                await session.call_tool(name, {} if name == "search_airports" else {"ident": "EB01"})
                            await session.call_tool("lookup_airport", {"ident": "EB01", "extra": 1})
        observations = [row for row in records if row["method"] == "reference.observed"]
        self.assertEqual(len(observations), 3)
        self.assertEqual(len({row["request_id"] for row in observations}), 3)
        for row in observations:
            name = row["facts"]["probe_id"]
            expected = getattr(data, name)(**({} if name == "search_airports" else {"ident": "EB01"}))
            self.assertEqual(row["facts"]["sha256"], sha256(expected))
            self.assertEqual(row["facts"]["source_sha256"], sha256(data.provenance))
            self.assertEqual((row["caller"], row["run_id"], row["operation_id"]),
                             ("candidate-planner", "run1", "assess1"))
            self.assertEqual(row["runtime_identity"], hashlib.sha256(principal.encode()).hexdigest())
        self.assertNotIn("Fictional", json.dumps(observations))
        self.assertNotIn("width_ft", json.dumps(observations))

    async def test_real_mcp_exposes_only_bounded_read_tools_and_preserves_provenance(self):
        data = reference()
        app = reference_application(data, trust("reference-data"))

        async def gateway(request):
            request.headers.update(signed(request.content, "reference-data", request.url.path,
                                          method=request.method))

        async with app.app.router.lifespan_context(app.app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                        event_hooks={"request": [gateway]}) as client:
                async with streamable_http_client("https://reference.test/mcp", http_client=client) as (read, write, _):
                    async with ClientSession(read, write) as session:
                        self.assertEqual((await session.initialize()).protocolVersion, "2025-11-25")
                        tools = await session.list_tools()
                        self.assertEqual({t.name for t in tools.tools},
                                         {"search_airports", "lookup_airport", "list_runways"})
                        result = await session.call_tool("search_airports", {})
                        self.assertFalse(result.isError)
                        payload = json.loads(result.content[0].text)
                        self.assertEqual(payload["provenance"], data.provenance)
                        self.assertEqual(len(payload["airports"]), 4)
                        invalid = await session.call_tool("search_airports", {"limit": True})
                        self.assertTrue(invalid.isError)
                        unknown = await session.call_tool("lookup_airport", {"ident": "EB01", "extra": 1})
                        self.assertTrue(unknown.isError)

    async def test_unsigned_origin_and_wrong_caller_never_receive_reference_data(self):
        app = reference_application(reference(), trust("reference-data"))
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                    base_url="https://reference.test") as client:
            body = b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
            self.assertEqual((await client.post("/mcp", content=body)).status_code, 403)
            denied = await client.post("/mcp", content=body,
                                       headers=signed(body, "reference-data", "/mcp", "operator"))
            self.assertEqual(denied.status_code, 403)
            self.assertNotIn("EB01", denied.text)
