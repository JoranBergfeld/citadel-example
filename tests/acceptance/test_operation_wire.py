import hashlib
import sys
import time
import unittest
from pathlib import Path

from azure.storage.blob.aio import ContainerClient

from citadel.acceptance.faults import OperationProbes
from citadel.acceptance.worker import publish_operation
from citadel.operations.blob import AzureBlobLedger
from tests.runtime.test_storage import FixtureCredential


class OperationWireTests(unittest.IsolatedAsyncioTestCase):
    async def test_committed_fault_and_receipt_use_actual_blob_sdk_without_payload_export(self):
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

        wire = Wire(clock=time.time)
        async with ContainerClient("https://allocated.blob.core.windows.net", "planner-operations",
                credential=FixtureCredential(), transport=wire, api_version="2026-10-06",
                retry_total=0, retry_connect=0, retry_read=0, retry_status=0) as container:
            ledger = AzureBlobLedger(container.get_blob_client("acceptance/worker1/ledger-v1.json"),
                                     control_plane=True)
            await ledger.initialize()
            deadline, started = time.time() + 120, time.time()
            actual = await OperationProbes(ledger, workload="candidate-planner",
                enabled=True, run_id="worker1", deadline=deadline).committed_response_loss("operation1")
            observed = await publish_operation(container, run_id="worker1",
                workload="candidate-planner", principal_id="11111111-1111-1111-1111-111111111111",
                check_id="fault.dropped-committed-write", actual=actual, started=started, deadline=deadline)
        self.assertEqual(observed["status_code"], 201)
        self.assertEqual(observed["request_id"], "fixture-service-" + str(len(wire.requests)))
        self.assertEqual(observed["runtime_identity"], hashlib.sha256(
            b"11111111-1111-1111-1111-111111111111").hexdigest())
        self.assertEqual(wire.requests[-1].headers["x-ms-client-request-id"], "operation1")
        self.assertEqual(observed["actual"]["response"], "indeterminate")
        self.assertEqual(observed["actual"]["artifact_count"], 1)
        self.assertNotIn("disposable-acceptance-product", str(observed))
        self.assertTrue(all("/planner-operations/" in request.url for request in wire.requests))
