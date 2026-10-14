import unittest
from azure.core.credentials import AccessToken
from azure.core.pipeline.transport import AsyncHttpResponse, AsyncHttpTransport
from azure.core.utils import CaseInsensitiveDict
from azure.storage.blob.aio import BlobClient
from azure.core.exceptions import ServiceResponseError

from citadel.evidence.manifests import canonical_bytes
from citadel.operations import OperationError, empty_ledger
from citadel.operations.blob import AzureBlobLedger
from citadel.operations.limits import ReadAllowance


class BlobClientBoundary:
    """Storage boundary double: no mock of operation/release internals."""

    def __init__(self):
        self.leases = []
        self.writes = []

    async def acquire_lease(self, **kwargs):
        self.leases.append(kwargs)
        kwargs["raw_response_hook"](type("Response", (), {
            "http_response": type("HTTP", (), {"headers": {"Date": "Thu, 01 Jan 1970 00:16:40 GMT"}})()
        })())
        return self

    async def upload_blob(self, data, **kwargs):
        self.writes.append((data, kwargs))

    async def release(self, **kwargs):
        pass


class BlobAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_every_update_uses_etag_and_expiring_storage_lease(self):
        blob = BlobClientBoundary()
        ledger = AzureBlobLedger(blob, clock=lambda: 1000)
        await ledger.commit(empty_ledger(), '"etag1"', deadline=1030)
        self.assertEqual(blob.leases[0]["lease_duration"], 15)
        self.assertEqual(blob.writes[0][1]["etag"], '"etag1"')
        self.assertIs(blob.writes[0][1]["lease"], blob)
        with self.assertRaises(OperationError) as caught:
            await ledger.commit(empty_ledger(), '"etag2"', deadline=1015)
        self.assertEqual(caught.exception.code, "deadline")
        self.assertEqual(len(blob.writes), 1)

    async def test_pinned_sdk_emits_conditional_lease_and_single_nonretried_put(self):
        transport = WireTransport()
        async with BlobClient(
            "https://unit.blob.core.windows.net", "workload", "ledger.json",
            credential=WireCredential(), transport=transport, api_version="2026-10-06",
            retry_total=0, retry_connect=0, retry_read=0, retry_status=0,
        ) as client:
            ledger = AzureBlobLedger(client, clock=lambda: 1000)
            await ledger.commit(empty_ledger(), '"etag1"', deadline=1030)
        self.assertEqual(len(transport.requests), 3)
        acquire, upload, release = transport.requests
        self.assertEqual(acquire.headers["x-ms-lease-duration"], "15")
        self.assertEqual(acquire.headers["If-Match"], '"etag1"')
        self.assertEqual(upload.headers["If-Match"], '"etag1"')
        self.assertEqual(upload.headers["x-ms-lease-id"], "00000000-0000-0000-0000-000000000001")
        self.assertEqual(upload.headers["x-ms-version"], "2026-10-06")
        self.assertEqual(release.headers["x-ms-lease-action"], "release")

    async def test_runtime_storage_reads_fail_closed_without_prepaid_allowance(self):
        ledger = AzureBlobLedger(BlobClientBoundary(), clock=lambda: 1000)
        with self.assertRaises(OperationError) as caught:
            await ledger.read()
        self.assertEqual(caught.exception.code, "exhausted")

    async def test_actual_sdk_download_is_metered_and_lost_put_response_never_retries(self):
        transport = WireTransport()
        async with BlobClient(
            "https://unit.blob.core.windows.net", "workload", "ledger.json",
            credential=WireCredential(), transport=transport, api_version="2026-10-06",
            retry_total=0, retry_connect=0, retry_read=0, retry_status=0,
        ) as client:
            ledger = AzureBlobLedger(client, clock=lambda: 1000,
                                     read_allowance=ReadAllowance(1, 1900, lambda: 1000))
            document, etag = await ledger.read()
            self.assertEqual(document, empty_ledger())
            self.assertEqual(etag, '"etag2"')
            with self.assertRaises(OperationError):
                await ledger.read()
            transport.drop_put = True
            with self.assertRaises(OperationError) as caught:
                await ledger.commit(document, etag, deadline=1030)
            self.assertEqual(caught.exception.code, "indeterminate")
        self.assertEqual(len([request for request in transport.requests if request.method == "GET"]), 1)
        self.assertEqual(len([request for request in transport.requests
                              if request.method == "PUT" and "comp=lease" not in request.url]), 1)

    async def test_sdk_stream_body_retry_cannot_hide_an_extra_get_attempt(self):
        transport = WireTransport()
        transport.fail_body = True
        async with BlobClient(
            "https://unit.blob.core.windows.net", "workload", "ledger.json",
            credential=WireCredential(), transport=transport, api_version="2026-10-06",
            retry_total=0, retry_connect=0, retry_read=0, retry_status=0,
        ) as client:
            ledger = AzureBlobLedger(client, clock=lambda: 1000,
                                     read_allowance=ReadAllowance(1, 1900, lambda: 1000))
            with self.assertRaises(OperationError) as caught:
                await ledger.read()
            self.assertEqual(caught.exception.code, "unavailable")
        self.assertEqual(len(transport.requests), 1)


class WireCredential:
    async def get_token(self, *args, **kwargs):
        return AccessToken("offline-test-not-a-real-token", 9999999999)


class WireResponse(AsyncHttpResponse):
    def __init__(self, request, *, status=201, content=b""):
        super().__init__(request, None)
        self.status_code = status
        self.reason = "Created"
        self.headers = CaseInsensitiveDict({
            "date": "Thu, 01 Jan 1970 00:16:40 GMT", "etag": '"etag2"',
            "x-ms-lease-id": "00000000-0000-0000-0000-000000000001",
        })
        self.content_type = "application/xml"
        self.content = content
        if content:
            self.headers.update({"content-length": str(len(content)),
                                 "content-range": f"bytes 0-{len(content) - 1}/{len(content)}",
                                 "x-ms-blob-type": "BlockBlob"})

    def body(self):
        return self.content

    def stream_download(self, pipeline, **kwargs):
        return WireStream(self)

    async def load_body(self):
        pass


class WireStream:
    def __init__(self, response):
        self.response = response
        self.content_length = len(response.content)

    async def __aiter__(self):
        if getattr(self.response, "fail_body", False):
            raise ServiceResponseError("Fixed-purpose truncated response")
        yield self.response.content


class WireTransport(AsyncHttpTransport):
    def __init__(self):
        self.requests = []
        self.drop_put = False
        self.fail_body = False

    async def send(self, request, **kwargs):
        self.requests.append(request)
        if request.method == "GET":
            response = WireResponse(request, status=206, content=canonical_bytes(empty_ledger()))
            response.fail_body = self.fail_body
            return response
        if self.drop_put and "comp=lease" not in request.url:
            raise ServiceResponseError("Fixed-purpose lost committed response")
        status = 200 if request.headers.get("x-ms-lease-action") == "release" else 201
        return WireResponse(request, status=status)

    async def open(self):
        pass

    async def close(self):
        pass

    async def __aexit__(self, *args):
        await self.close()
