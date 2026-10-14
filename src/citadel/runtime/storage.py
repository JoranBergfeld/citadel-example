"""Startup-only read of the eight immutable bundle objects; no storage writes."""

import asyncio
from pathlib import Path

from azure.storage.blob.aio import BlobClient

from citadel.evidence import EvidenceError, ReferenceData
from citadel.evidence.preparation import ARTIFACT_NAMES
from .configuration import endpoint


async def download_reference_bundle(account_url, credential, directory, *, transport=None):
    endpoint(account_url, ".blob.core.windows.net")
    directory = Path(directory)
    if directory.is_absolute():
        raise ValueError("Reference cache must be relative to the application working directory")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name in sorted(ARTIFACT_NAMES | {"bundle-manifest.json"}):
        limit = 16 * 1024 * 1024 if name == "reference-data.json" else 2 * 1024 * 1024
        sent = False

        def once(request):
            nonlocal sent
            if sent:
                raise EvidenceError("temporary_unavailability", "Hidden Blob download retry blocked")
            sent = True

        options = {"transport": transport} if transport is not None else {}
        async with BlobClient(account_url, "reference", name, credential=credential,
                              api_version="2026-10-06", retry_total=0, retry_connect=0,
                              retry_read=0, retry_status=0, connection_timeout=5, read_timeout=30,
                              max_single_get_size=limit + 1, **options) as client:
            async with asyncio.timeout(30):
                download = await client.download_blob(offset=0, length=limit + 1, max_concurrency=1,
                                                       raw_request_hook=once, timeout=30)
                content = await download.readall()
        if len(content) > limit:
            raise EvidenceError("result_limit", "Reference bundle object exceeds startup bound")
        path = directory / name
        if path.exists():
            if path.read_bytes() != content:
                raise EvidenceError("data_integrity", "Cached immutable bundle differs from storage")
        else:
            with path.open("xb") as stream:
                stream.write(content)
    # The existing loader checks the independently pinned rows and all manifests,
    # not merely a caller-supplied hash, before any MCP capability becomes ready.
    return {fixture: ReferenceData.from_bundle(directory, fixture=fixture)
            for fixture in ("base-source", "missing-width-replacement", "no-alternative")}
