import base64
import hashlib
import hmac
import json
import time
import unittest
from datetime import datetime, timedelta, timezone

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from citadel.evidence import ReferenceData
from citadel.gateway import TrustConfiguration
from citadel.runtime.reference import reference_application


KEY = "runtime-test-only-context-secret-32bytes"
PIN = "a" * 64


def trust(target):
    now = datetime.now(timezone.utc)
    return TrustConfiguration(target, {PIN: (now - timedelta(days=1), now + timedelta(days=89))},
                              {"test": KEY})


def signed(body, target, path, caller="candidate-planner", method="POST", request_id="test-request"):
    timestamp = str(int(time.time()))
    canonical = "\n".join(("v1", "test", timestamp, request_id, caller, target,
                           method, path, hashlib.sha256(body).hexdigest()))
    return {
        "x-forwarded-client-cert": f"Hash={PIN}",
        "x-citadel-key-id": "test", "x-citadel-timestamp": timestamp,
        "x-citadel-request-id": request_id, "x-citadel-caller": caller,
        "x-citadel-target": target,
        "x-citadel-signature": base64.b64encode(hmac.digest(KEY.encode(), canonical.encode(), "sha256")).decode(),
    }


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
