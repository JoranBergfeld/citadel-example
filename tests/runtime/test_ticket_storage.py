import asyncio
import json
import time
import unittest
from email.utils import formatdate
from urllib.parse import unquote, urlsplit
import httpx

from azure.core.exceptions import ServiceResponseError
from azure.core.pipeline.transport import AsyncHttpTransport
from azure.storage.blob.aio import ContainerClient

from citadel.evidence.manifests import canonical_bytes
from citadel.operations import OperationError, empty_ledger
from citadel.operations.blob import AzureBlobLedger
from citadel.runtime.state import ScopedLedger, read_scope
from citadel.runtime.tickets import AzureTicketStore, TicketPool
from citadel.runtime.observation import DeploymentReads, RunIndex, empty_index
from citadel.operator.observation import ObservationClient
from citadel.runtime.agents import Runtime, agent_application
from tests.unit.gateway_fixtures import signed, trust
from test_storage import BlobResponse, FixtureCredential
from tests.unit import test_read_tickets as owner_tests
from tests.unit import test_recovery as recovery_tests


class TicketWire(AsyncHttpTransport):
    """Offline storage service boundary; the actual pinned Azure SDK sends every request."""
    def __init__(self, *, clock=lambda: 1000):
        self.clock = clock
        self.blobs = {"/workload/ledger-v1.json": canonical_bytes(empty_ledger()),
                      "/workload/active-run-slot.json": b"{}"}
        self.etags = {key: 1 for key in self.blobs}
        self.leases, self.requests = {}, []
        self.drop_write = None

    async def open(self):
        pass

    async def close(self):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def send(self, request, **kwargs):
        await asyncio.sleep(0)
        self.requests.append(request)
        path = unquote(urlsplit(request.url).path)
        exists = path in self.blobs
        etag = f'"{self.etags.get(path, 0)}"'

        def respond(status, content=b"", code=None):
            if code:
                content = f"<Error><Code>{code}</Code><Message>Offline test</Message></Error>".encode()
            response = BlobResponse(request, content)
            response.status_code = status
            response.headers["etag"] = f'"{self.etags.get(path, 0)}"'
            response.headers["date"] = formatdate(self.clock(), usegmt=True)
            if code:
                response.headers["x-ms-error-code"] = code
                response.content_type = "application/xml"
            return response

        if request.method == "GET":
            return respond(206, self.blobs[path]) if exists else respond(404, code="BlobNotFound")
        if request.method != "PUT":
            raise AssertionError("Unexpected SDK request")
        match = request.headers.get("If-Match")
        if match and match != etag:
            return respond(412, code="ConditionNotMet")
        action = request.headers.get("x-ms-lease-action")
        lease_id = request.headers.get("x-ms-lease-id")
        if action:
            if not exists:
                return respond(404, code="BlobNotFound")
            if action == "acquire":
                if path in self.leases:
                    return respond(409, code="LeaseAlreadyPresent")
                self.leases[path] = request.headers.get("x-ms-proposed-lease-id",
                    "00000000-0000-0000-0000-000000000001")
            elif self.leases.get(path) != lease_id:
                return respond(412, code="LeaseIdMismatchWithLeaseOperation")
            elif action == "release":
                del self.leases[path]
            response = respond(201 if action == "acquire" else 200)
            response.headers["x-ms-lease-id"] = self.leases.get(path, lease_id)
            return response
        if request.headers.get("If-None-Match") == "*" and exists:
            return respond(409, code="BlobAlreadyExists")
        if path in self.leases and self.leases[path] != lease_id:
            return respond(412, code="LeaseIdMismatchWithBlobOperation")
        self.blobs[path] = request.body
        self.etags[path] = self.etags.get(path, 0) + 1
        if self.drop_write and self.drop_write in path:
            self.drop_write = None
            raise ServiceResponseError("Test-only lost committed PUT response")
        return respond(201)


class TicketSDKTests(unittest.IsolatedAsyncioTestCase):
    def container(self, wire):
        return ContainerClient("https://unit.blob.core.windows.net", "workload",
            credential=FixtureCredential(), transport=wire, api_version="2026-10-06",
            retry_total=0, retry_connect=0, retry_read=0, retry_status=0)

    async def test_deployment_index_physical_gets_are_prepaid_and_restart_cannot_refill(self):
        wire = TicketWire()
        wire.blobs["/workload/ledger-v1.json"] = canonical_bytes(empty_index())
        async with self.container(wire) as container:
            store = AzureTicketStore(container)
            admission = DeploymentReads(store, "fixture1", clock=lambda: 1000)
            admission.capacities = {"observation": 2, "recovery-proof": 1}
            await store.open_pool(admission.scope("observation"))
            await store.open_pool(admission.scope("recovery-proof"))
            index = RunIndex(AzureBlobLedger(container.get_blob_client("ledger-v1.json"),
                                             clock=lambda: 1000), admission, clock=lambda: 1000,
                             execution_store=store)
            await index.register("operator", {
                "run_id": "run1", "operation_id": "run1", "fixture": "base-source"})
            self.assertEqual((await index.page())["runs"][0]["run_id"], "run1")
            restarted = DeploymentReads(AzureTicketStore(container), "fixture1", clock=lambda: 1000)
            restarted.capacities = admission.capacities
            other = RunIndex(AzureBlobLedger(container.get_blob_client("ledger-v1.json"),
                                             clock=lambda: 1000), restarted, clock=lambda: 1000,
                             execution_store=restarted.store)
            self.assertEqual((await other.resolve("run1"))["fixture"], "base-source")
            before = len(wire.requests)
            with self.assertRaises(OperationError) as caught:
                await other.page()
            self.assertEqual(caught.exception.code, "exhausted")
            self.assertFalse(any(request.method == "GET" for request in wire.requests[before:]))
            async with restarted.request("recovery-proof"):
                await restarted.charge()
        self.assertEqual(sum(r.method == "GET" for r in wire.requests), 3)
        self.assertFalse(any("operator/invoke" in urlsplit(r.url).path for r in wire.requests))

    async def test_hosted_protocol_and_both_supporting_storage_gets_are_separately_charged(self):
        wire = TicketWire()
        wire.blobs["/workload/index.json"] = canonical_bytes(empty_index())
        async with self.container(wire) as container:
            store = AzureTicketStore(container)
            admission = DeploymentReads(store, "fixture1", clock=lambda: 1000)
            await store.open_pool(admission.scope("observation"))
            index = RunIndex(AzureBlobLedger(container.get_blob_client("index.json"),
                                             clock=lambda: 1000), admission, clock=lambda: 1000,
                             execution_store=store)
            await index.register("operator", {
                "run_id": "run1", "operation_id": "run1", "fixture": "base-source"})
            runtime = Runtime("candidate-planner",
                AzureBlobLedger(container.get_blob_client("ledger-v1.json"), clock=lambda: 1000),
                model=None, peers=None, gateway_url="https://gateway.test", ticket_store=store,
                run_index=index, clock=lambda: 1000)

            async def gateway(request):
                request.url = request.url.copy_with(
                    path=request.url.path.removeprefix("/candidate-planner"))
                request.headers.update(signed(
                    b"", "candidate-planner", request.url.path, "operator-web", "GET"))

            async with httpx.AsyncClient(transport=httpx.ASGITransport(
                    app=agent_application(runtime, trust("candidate-planner"))),
                    event_hooks={"request": [gateway]}) as client:
                observer = ObservationClient("https://gateway.test", "fixture-key", admission,
                                             client=client, clock=lambda: 1000)
                before = len(wire.requests)
                markers = sum("/read-tickets/" in p for p in wire.blobs)
                result = await observer.observe("run1")
                self.assertEqual((result.state, result.data["execution"]), ("partial", "unknown"))
                self.assertEqual(sum(r.method == "GET" for r in wire.requests[before:]), 2)
                self.assertEqual(sum("/read-tickets/" in p for p in wire.blobs) - markers, 3)
                del wire.blobs["/workload/index.json"]
                failed = await observer.observe("run1", refresh=True)
                self.assertEqual((failed.state, failed.stale), ("unavailable", True))
                self.assertEqual(failed.last_success, result.last_success)
                self.assertEqual(runtime.tasks, set())

    async def test_reset_cursors_and_concurrent_processes_cannot_reuse_conditional_tickets(self):
        wire = TicketWire()
        async with self.container(wire) as container:
            first, second = AzureTicketStore(container), AzureTicketStore(container)
            self.assertTrue(await first.open_pool("owner/invoke/run", exclusive=True))
            self.assertFalse(await second.open_pool("owner/invoke/run", exclusive=True))
            pools = [TicketPool(store, "owner/invoke/run", 8, clock=lambda: 1000)
                     for store in (first, second)]
            async def spend(pool):
                pool.store.cursors.clear()
                with read_scope(pool, deadline=1900):
                    try:
                        await pool.admit()
                        return True
                    except OperationError as exc:
                        self.assertEqual(exc.code, "exhausted")
                        return False
            results = await asyncio.gather(*(spend(pools[index % 2]) for index in range(16)))
            self.assertEqual(sum(results), 8)
            self.assertEqual(len([key for key in wire.blobs if "/read-tickets/" in key]), 8)
        self.assertEqual({request.method for request in wire.requests}, {"PUT"})
        markers = [request for request in wire.requests if "/read-tickets/" in request.url]
        self.assertTrue(all(request.headers["If-None-Match"] == "*" for request in markers))
        self.assertTrue(all(request.headers["x-ms-version"] == "2026-10-06" for request in wire.requests))

    async def test_ambiguous_ticket_put_never_authorizes_a_get_or_refunds_a_ticket(self):
        wire = TicketWire()
        async with self.container(wire) as container:
            store = AzureTicketStore(container)
            await store.open_pool("owner/invoke/run", exclusive=True)
            pool = TicketPool(store, "owner/invoke/run", 1, clock=lambda: 1000)
            ledger = ScopedLedger(AzureBlobLedger(container.get_blob_client("ledger-v1.json"),
                                                 clock=lambda: 1000))
            wire.drop_write = "/read-tickets/"
            with read_scope(pool, deadline=1900):
                with self.assertRaises(OperationError):
                    await ledger.read()
            store.cursors.clear()
            with read_scope(pool, deadline=1900):
                with self.assertRaises(OperationError) as caught:
                    await ledger.read()
                self.assertEqual(caught.exception.code, "exhausted")
        self.assertFalse(any(request.method == "GET" for request in wire.requests))
        self.assertEqual(len([key for key in wire.blobs if "/read-tickets/" in key]), 1)

    async def test_snapshots_advance_only_with_real_committed_etag_and_reconcile_lost_response(self):
        wire = TicketWire()
        async with self.container(wire) as container:
            store = AzureTicketStore(container)
            await store.open_pool("owner/invoke/run", exclusive=True)
            pool = TicketPool(store, "owner/invoke/run", 5, clock=lambda: 1000)
            ledger = ScopedLedger(AzureBlobLedger(container.get_blob_client("ledger-v1.json"),
                                                 clock=lambda: 1000))
            with read_scope(pool, deadline=1900):
                document, etag = await ledger.read()
                document["fixture"] = "committed"
                committed_etag = await ledger.commit(document, etag, deadline=1030)
                cached, observed_etag = await ledger.read()
                self.assertEqual(committed_etag, observed_etag)
                self.assertNotEqual(etag, observed_etag)
                cached["fixture"] = "uncommitted mutation"
                self.assertEqual((await ledger.read())[0]["fixture"], "committed")
                wire.drop_write = "/ledger-v1.json"
                document["fixture"] = "lost response"
                with self.assertRaises(OperationError) as caught:
                    await ledger.commit(document, observed_etag, deadline=1030)
                self.assertEqual(caught.exception.code, "indeterminate")
                reconciled, _ = await ledger.read()
                self.assertEqual(reconciled["fixture"], "lost response")
        self.assertEqual(sum(request.method == "GET" for request in wire.requests), 2)
        self.assertEqual(len([key for key in wire.blobs if "/read-tickets/" in key]), 2)

    async def test_run_admission_and_finding_bindings_fail_closed_without_gets(self):
        wire = TicketWire()
        async with self.container(wire) as container:
            store = AzureTicketStore(container)
            await store.open_pool("owner/invoke/one", exclusive=True)
            with self.assertRaises(OperationError):
                await store.open_pool("owner/invoke/two", exclusive=True)
            await store.bind_finding("owner/invoke/one", "finding1", 1)
            await store.require_finding("owner/invoke/one", "finding1", 1)
            with self.assertRaises(OperationError):
                await store.require_finding("owner/invoke/one", "finding2", 1)
            await store.release_run("owner/invoke/one")
            self.assertTrue(await store.open_pool("owner/invoke/two", exclusive=True))
            await store.release_run("owner/invoke/one")
            with self.assertRaises(OperationError):
                await store.open_pool("owner/invoke/three", exclusive=True)
        self.assertFalse(any(request.method == "GET" for request in wire.requests))


class AzureOwnerReadBudgetTests(owner_tests.ExternalReadBudgetTests):
    async def asyncSetUp(self):
        self.wire = TicketWire(clock=time.time)
        self.client = TicketSDKTests().container(self.wire)
        await self.client.__aenter__()

    async def asyncTearDown(self):
        await self.client.close()

    def make_ledger(self):
        wire = self.wire

        class ObservedLedger(AzureBlobLedger):
            @property
            def read_attempts(self):
                return sum(request.method == "GET" for request in wire.requests)

        ledger = ObservedLedger(self.client.get_blob_client("ledger-v1.json"))
        ledger.ticket_store = AzureTicketStore(self.client)
        return ledger


class AzureRecoveryTests(recovery_tests.RuntimeRecoveryTests):
    async def asyncSetUp(self):
        self.now = [1000.0]
        self.wire = TicketWire(clock=lambda: self.now[0])
        self.client = TicketSDKTests().container(self.wire)
        await self.client.__aenter__()
        self.ledger = AzureBlobLedger(self.client.get_blob_client("ledger-v1.json"),
                                      clock=lambda: self.now[0], control_plane=True)
        wire = self.wire

        class ObservedStore(AzureTicketStore):
            @property
            def markers(self):
                return {path for path in wire.blobs if "/read-tickets/" in path}

        self.ledger.ticket_store = ObservedStore(self.client)

    async def asyncTearDown(self):
        await self.client.close()
