import io
import json
import time
import threading
import unittest

from azure.core.credentials import AccessToken
from azure.core.pipeline.transport import HttpResponse, HttpTransport

from citadel.acceptance.monitor import MonitorExporter
from citadel.acceptance.telemetry import Telemetry, correlate


class Credential:
    def __init__(self, **options):
        self.options, self.scopes = options, []

    def get_token(self, *scopes, **options):
        self.scopes.append(scopes)
        return AccessToken("fixture-only-token", time.time() + 3600)

    def close(self):
        pass


class Response(HttpResponse):
    def __init__(self, request, status, body):
        super().__init__(request, None)
        self.status_code, self.reason = status, "Fixture response"
        self.headers = {"content-type": "application/json", "x-ms-request-id": "real-ingestion-id"}
        self.content_type, self.content = "application/json", json.dumps(body).encode()

    def body(self):
        return self.content

    def json(self):
        return json.loads(self.content)


class Transport(HttpTransport):
    def __init__(self):
        self.requests, self.status, self.partial = [], 200, False

    def open(self):
        pass

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def send(self, request, **options):
        self.requests.append(request)
        count = len(json.loads(request.body))
        return Response(request, self.status, {
            "itemsReceived": count, "itemsAccepted": 0 if self.partial else count,
            "errors": [{"index": 0, "statusCode": 403, "message": "private-provider-error"}]
                      if self.status != 200 else []})


class MonitorTests(unittest.TestCase):
    def exporter(self, transport):
        self.credential = Credential()

        def credential(**options):
            self.credential.options = options
            return self.credential

        return MonitorExporter("candidate-planner",
            client_id="11111111-1111-1111-1111-111111111111",
            principal_id="22222222-2222-2222-2222-222222222222",
            connection_string="InstrumentationKey=33333333-3333-3333-3333-333333333333;"
                "IngestionEndpoint=https://westeurope-0.in.applicationinsights.azure.com/",
            credential_factory=credential, transport=transport)

    def test_real_sdk_sends_only_sanitized_records_with_explicit_identity_scope_and_v21(self):
        transport, output = Transport(), io.StringIO()
        exporter = self.exporter(transport)
        try:
            telemetry = Telemetry("candidate-planner", "22222222-2222-2222-2222-222222222222",
                                  output=output, exporter=exporter)
            with correlate("run1", "op1", "operator"):
                telemetry.emit("storage.read", request_id="blob-service-id", status_code=206,
                    facts={"read_attempts": 1, "private_notes": "private-draft", "prompt": "private-prompt"})
            health = exporter.flush()
            self.assertEqual(health["acknowledged_records"], 1)
            self.assertEqual(health["failed_records"], 0)
            self.assertEqual(health["request_id"], "real-ingestion-id")
            self.assertEqual(health["status_code"], 200)
            self.assertEqual(self.credential.options["client_id"], "11111111-1111-1111-1111-111111111111")
            self.assertEqual(set(self.credential.scopes), {("https://monitor.azure.com//.default",)})
            self.assertEqual(len(transport.requests), 1)
            request = transport.requests[0]
            self.assertEqual(request.url, "https://westeurope-0.in.applicationinsights.azure.com/v2.1/track")
            self.assertEqual(request.method, "POST")
            self.assertEqual(request.headers["Authorization"], "Bearer fixture-only-token")
            wire = request.body.decode() if isinstance(request.body, bytes) else request.body
            self.assertIn("blob-service-id", wire)
            self.assertNotIn("private-draft", wire)
            self.assertNotIn("private-prompt", wire)
            self.assertNotIn("fixture-only-token", output.getvalue())
        finally:
            exporter.close()

    def test_provider_failure_or_partial_acknowledgement_never_retries_or_claims_delivery(self):
        for status, partial in ((503, False), (200, True)):
            with self.subTest(status=status, partial=partial):
                transport = Transport()
                transport.status, transport.partial = status, partial
                exporter = self.exporter(transport)
                try:
                    telemetry = Telemetry("candidate-planner", "22222222-2222-2222-2222-222222222222",
                                          output=io.StringIO(), exporter=exporter)
                    telemetry.emit("execution", request_id=None, status_code=0, facts={"generation": 1})
                    health = exporter.flush()
                    self.assertEqual(health["acknowledged_records"], 0)
                    self.assertEqual(health["failed_records"], 1)
                    self.assertEqual(len(transport.requests), 1)
                    self.assertNotIn("private-provider-error", str(health))
                finally:
                    exporter.close()

    def test_bounded_queue_reports_loss_without_sampling_or_hiding_pending_delivery(self):
        class HeldTransport(Transport):
            def __init__(self):
                super().__init__()
                self.entered, self.release = threading.Event(), threading.Event()

            def send(self, request, **options):
                self.entered.set()
                if not self.release.wait(10):
                    raise TimeoutError("Fixture transport was not released")
                return super().send(request, **options)

        transport = HeldTransport()
        exporter = self.exporter(transport)
        try:
            telemetry = Telemetry("candidate-planner", "22222222-2222-2222-2222-222222222222",
                                  output=io.StringIO(), exporter=exporter)
            telemetry.emit("execution", request_id=None, status_code=0)
            self.assertTrue(transport.entered.wait(2))
            for _ in range(4097):
                telemetry.emit("execution", request_id=None, status_code=0)
            pending = exporter.flush(0)
            self.assertEqual(pending["dropped_records"], 1)
            self.assertEqual(pending["queued_records"], 4096)
            self.assertTrue(pending["inflight"])
            self.assertFalse(pending["ingestion_verified"])
            transport.release.set()
            health = exporter.flush()
            self.assertEqual(health["acknowledged_records"], 4097)
            self.assertEqual(health["failed_records"], 0)
        finally:
            transport.release.set()
            exporter.close()

    def test_exporter_rejects_incomplete_or_malformed_metadata_before_dispatch(self):
        transport = Transport()
        exporter = self.exporter(transport)
        try:
            output = io.StringIO()
            telemetry = Telemetry("candidate-planner", "22222222-2222-2222-2222-222222222222",
                                  output=output)
            telemetry.emit("execution", request_id=None, status_code=0)
            record = json.loads(output.getvalue())
            incomplete = dict(record)
            del incomplete["event_id"]
            for changed in (incomplete, record | {"method": []}, record | {"caller": []},
                            record | {"prompt": "private"}, record | {"runtime_identity": "a" * 64}):
                with self.subTest(keys=sorted(changed)), self.assertRaises(ValueError):
                    exporter.emit(changed)
            self.assertEqual(exporter.flush()["submitted_records"], 0)
            self.assertEqual(transport.requests, [])
        finally:
            exporter.close()
