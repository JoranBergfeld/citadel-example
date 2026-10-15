"""Pinned Azure Blob adapter; one atomic, bounded document per workload authority.

No DefaultAzureCredential, account keys, SAS, implicit retries, or background replay.
Provision the empty ledger before accepting runs. All business updates carry both
an ETag and a finite server-side lease expiring before their execution deadline.
"""

import asyncio
import json
import time
from contextlib import asynccontextmanager
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse
from uuid import UUID

from azure.core import MatchConditions
from azure.core.exceptions import AzureError, HttpResponseError, ResourceNotFoundError
from azure.identity.aio import ManagedIdentityCredential
from azure.storage.blob.aio import BlobClient

from citadel.evidence.manifests import canonical_bytes
from . import OperationError, empty_ledger
from citadel.acceptance.telemetry import storage_response

MAX_LEDGER_BYTES = 4 * 1024 * 1024
API_VERSION = "2026-10-06"


@asynccontextmanager
async def managed_ledger(*, account_url, container, client_id, blob_name="ledger-v1.json",
                         read_allowance=None, control_plane=False):
    """Explicit allocated user-assigned MI only; caller supplies inventoried container."""
    parsed = urlparse(account_url)
    if (parsed.scheme != "https" or not parsed.hostname
            or not parsed.hostname.endswith(".blob.core.windows.net")
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment or parsed.username
            or parsed.port is not None):
        raise OperationError("invalid_input", "Expected a public Azure account HTTPS endpoint without credentials")
    try:
        UUID(client_id)
    except (ValueError, TypeError, AttributeError) as exc:
        raise OperationError("invalid_input", "An explicit assigned identity client ID is required") from exc
    async with ManagedIdentityCredential(client_id=client_id) as credential:
        async with BlobClient(
            account_url, container, blob_name, credential=credential, api_version=API_VERSION,
            retry_total=0, retry_connect=0, retry_read=0, retry_status=0,
            connection_timeout=5, read_timeout=30,
            max_single_put_size=MAX_LEDGER_BYTES, max_single_get_size=MAX_LEDGER_BYTES + 1,
        ) as client:
            yield AzureBlobLedger(client, read_allowance=read_allowance, control_plane=control_plane)


def _error(exc, *, writing):
    if isinstance(exc, ResourceNotFoundError):
        return OperationError("missing", "Ledger is absent; non-execution is not established")
    if isinstance(exc, HttpResponseError):
        if exc.status_code in (409, 412):
            return OperationError("conflict", "Storage rejected the conditional update or lease")
        if exc.status_code in (401, 403):
            return OperationError("forbidden", "Workload storage authority was denied")
    return OperationError("indeterminate" if writing else "unavailable",
                          "Storage outcome requires explicit reconciliation" if writing else "Storage read unavailable")


class AzureBlobLedger:
    """Injected client is the Azure SDK boundary; production uses managed_ledger."""

    def __init__(self, client, *, clock=time.time, read_allowance=None, control_plane=False):
        self.client, self.clock = client, clock
        self.read_allowance = read_allowance
        self.control_plane = control_plane

    async def initialize(self):
        """Deployment/probe bootstrap only. Never call to repair missing operation status."""
        try:
            async with asyncio.timeout(30):
                await self.client.upload_blob(canonical_bytes(empty_ledger()), overwrite=False)
        except (AzureError, TimeoutError) as exc:
            raise _error(exc, writing=True) from None

    async def read(self):
        if self.read_allowance is None and not self.control_plane:
            raise OperationError("exhausted", "Runtime reads require a durably prepaid read allowance")
        deadline = self.read_allowance.take() if self.read_allowance else self.clock() + 30
        sent = False

        def once(request):
            nonlocal sent
            # The pinned downloader retries truncated bodies outside its retry policy.
            # Abort before an additional HTTP request; the bounded caller owns retries.
            if sent:
                raise OperationError("unavailable", "Hidden SDK read retry blocked before dispatch")
            sent = True

        def block_blob(response):
            storage_response(response)
            if response.http_response.status_code < 400:
                headers = response.http_response.headers
                if headers.get("x-ms-blob-type") != "BlockBlob":
                    raise OperationError("data_integrity", "Ledger must be a block blob")

        try:
            async with asyncio.timeout(max(0, deadline - self.clock())):
                response = await self.client.download_blob(
                    offset=0, length=MAX_LEDGER_BYTES + 1, max_concurrency=1, timeout=30,
                    raw_request_hook=once, raw_response_hook=block_blob,
                )
                content = await response.readall()
                if len(content) > MAX_LEDGER_BYTES:
                    raise OperationError("result_limit", "Ledger exceeds bounded sample storage")
                document = json.loads(content)
                if document.get("schema_version") != 1:
                    raise OperationError("unsupported_version", "Unsupported ledger schema")
                return document, response.properties.etag
        except (AzureError, TimeoutError) as exc:
            raise _error(exc, writing=False) from None
        except (ValueError, AttributeError) as exc:
            raise OperationError("data_integrity", "Ledger is not valid structured state") from exc

    async def commit(self, document, etag, *, deadline):
        content = canonical_bytes(document)
        if len(content) > MAX_LEDGER_BYTES:
            raise OperationError("result_limit", "Ledger exceeds bounded sample storage")
        if deadline <= self.clock() + 16:
            raise OperationError("deadline", "Insufficient remaining time for a fenced storage lease")
        lease, server_date = None, None

        def received(response):
            nonlocal server_date
            storage_response(response)
            headers = response.http_response.headers
            value = headers.get("Date") or headers.get("date")
            if value:
                server_date = parsedate_to_datetime(value).timestamp()

        try:
            async with asyncio.timeout(min(30, deadline - self.clock())):
                lease = await self.client.acquire_lease(
                    lease_duration=15, etag=etag, match_condition=MatchConditions.IfNotModified,
                    raw_response_hook=received, timeout=15,
                )
                # Date has second precision. The lease began before the response.
                # Never renew: an arbitrarily delayed write loses its server-side lease.
                if server_date is None or server_date + 16 >= deadline or self.clock() >= deadline:
                    raise OperationError("deadline", "Storage lease cannot fit the inherited deadline")
                committed = await self.client.upload_blob(
                    content, overwrite=True, etag=etag, match_condition=MatchConditions.IfNotModified,
                    lease=lease, max_concurrency=1, timeout=15,
                    raw_response_hook=storage_response,
                )
                return committed.get("etag") if committed else None
        except (AzureError, TimeoutError) as exc:
            raise _error(exc, writing=True) from None
        finally:
            if lease is not None:
                try:
                    async with asyncio.timeout(5):
                        await lease.release(timeout=5)
                except (AzureError, TimeoutError):
                    # Lease expires on the service; cleanup cannot retry the business write.
                    pass
