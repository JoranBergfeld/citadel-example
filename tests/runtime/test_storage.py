import os
import shutil
import unittest
from pathlib import Path
from urllib.parse import unquote, urlsplit
from uuid import uuid4

from azure.core.credentials import AccessToken
from azure.core.pipeline.transport import AsyncHttpResponse, AsyncHttpTransport
from azure.core.utils import CaseInsensitiveDict

from citadel.evidence import EvidenceError
from citadel.evidence.preparation import prepare_bundle
from citadel.runtime.storage import download_reference_bundle


class FixtureCredential:
    async def get_token(self, *args, **kwargs):
        return AccessToken("test-only-no-cloud-token", 9999999999)


class BlobResponse(AsyncHttpResponse):
    def __init__(self, request, content):
        super().__init__(request, None)
        self.status_code, self.reason = 206, "Partial Content"
        self.content_type, self.content = "application/json", content
        self.headers = CaseInsensitiveDict({
            "content-length": str(len(content)), "content-range": f"bytes 0-{len(content)-1}/{len(content)}",
            "x-ms-blob-type": "BlockBlob", "etag": '"verified-fixture"',
        })

    def body(self):
        return self.content

    async def load_body(self):
        pass

    def stream_download(self, pipeline, **kwargs):
        response = self

        class Stream:
            def __init__(self):
                self.response = response
                self.content_length = len(response.content)

            def __aiter__(self):
                return self

            async def __anext__(self):
                if not response.content:
                    raise StopAsyncIteration
                value, response.content = response.content, b""
                return value

        return Stream()


class BlobTransport(AsyncHttpTransport):
    def __init__(self, directory):
        self.directory, self.requests, self.corrupt = directory, [], False

    async def open(self):
        pass

    async def close(self):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def send(self, request, **kwargs):
        self.requests.append(request)
        name = unquote(urlsplit(request.url).path).split("/")[-1]
        content = (self.directory / name).read_bytes()
        if self.corrupt and name == "reference-data.json":
            content = b"{}"
        return BlobResponse(request, content)


@unittest.skipUnless(os.environ.get("CITADEL_EVIDENCE_DATA"), "Approved retained dataset not selected")
class ReferenceStorageTests(unittest.IsolatedAsyncioTestCase):
    async def test_actual_blob_gets_feed_existing_hash_checked_loader_without_write_authority(self):
        root = Path(".build") / ("reference-" + uuid4().hex)
        root.mkdir(parents=True)
        try:
            source = root / "source"
            prepare_bundle(os.environ["CITADEL_EVIDENCE_DATA"], source)
            transport = BlobTransport(source)
            data = await download_reference_bundle("https://reference.blob.core.windows.net",
                FixtureCredential(), root / "cache", transport=transport)
            self.assertEqual(data["base-source"].fixture_gate()["complete_count"], 16)
            self.assertEqual(set(data), {"base-source", "missing-width-replacement", "no-alternative"})
            self.assertEqual(len(transport.requests), 8)
            self.assertEqual({request.method for request in transport.requests}, {"GET"})
            self.assertTrue(all("/reference/" in request.url for request in transport.requests))
            self.assertTrue(all(request.headers["x-ms-version"] == "2026-10-06" for request in transport.requests))
            transport.corrupt = True
            with self.assertRaises(EvidenceError):
                await download_reference_bundle("https://reference.blob.core.windows.net",
                    FixtureCredential(), root / "corrupt", transport=transport)
        finally:
            shutil.rmtree(root)
