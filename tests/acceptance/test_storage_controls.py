import hashlib
import json
import unittest
from types import SimpleNamespace

from citadel.acceptance.coverage import CONTAINERS
from citadel.acceptance.storage_probes import StorageControls, storage_target
from citadel.operations import OperationError


class BlobProvider:
    def __init__(self):
        self.objects = {}
        self.requests = []
        for container in CONTAINERS:
            name = "bundle-manifest.json" if container == "reference" else "ledger-v1.json"
            self.objects[container, name] = json.dumps({
                "schema_version": 1, "drafts": {"known": {"private_notes": "not-for-reports"}},
                "findings": {"known": {"version": 1}}, "container": container}).encode()

    def blob(self, account, container, name):
        provider = self

        class Blob:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def exchange(self, method, options):
                request = SimpleNamespace(http_request=SimpleNamespace(
                    headers={}, method=method, url=account + "/" + container + "/" + name))
                options["raw_request_hook"](request)
                provider.requests.append((method, container, name))
                options["raw_response_hook"](SimpleNamespace(
                    http_request=request.http_request,
                    http_response=SimpleNamespace(status_code=206 if method == "GET" else 201,
                        headers={"x-ms-request-id": f"actual-provider-{len(provider.requests)}"})))

            def download_blob(self, **options):
                self.exchange("GET", options)
                return SimpleNamespace(properties=SimpleNamespace(etag='"known"'),
                                       readall=lambda: provider.objects[container, name])

            def upload_blob(self, content, **options):
                assert options["overwrite"] is False
                if (container, name) in provider.objects:
                    raise AssertionError("Observer must never replay or overwrite")
                self.exchange("PUT", options)
                provider.objects[container, name] = content

        return Blob()


class StorageControlTests(unittest.TestCase):
    def test_disposable_controls_copy_known_real_products_without_exporting_private_content(self):
        provider = BlobProvider()
        admissions = []
        controls = StorageControls(provider, account="https://allocated.blob.core.windows.net",
                                   suite_id="suite1", admit=lambda: admissions.append(1))
        original = dict(provider.objects)
        seeds = controls.prepare()
        snapshots = controls.snapshot()
        self.assertEqual(len(admissions), 27)
        for container in CONTAINERS:
            source = "bundle-manifest.json" if container == "reference" else "ledger-v1.json"
            self.assertEqual(provider.objects[container, storage_target("suite1")], original[container, source])
            self.assertEqual(snapshots[container]["sha256"],
                             hashlib.sha256(original[container, source]).hexdigest())
            self.assertEqual(seeds[container]["caller"], "operator")
            self.assertTrue(seeds[container]["request_id"].startswith("actual-provider-"))
        self.assertNotIn("not-for-reports", str(seeds) + str(snapshots))
        self.assertTrue(all(name == storage_target("suite1") for method, _, name in provider.requests if method == "PUT"))
        for key, content in original.items():
            self.assertEqual(provider.objects[key], content)

    def test_missing_actual_draft_cannot_be_replaced_with_a_fabricated_control(self):
        provider = BlobProvider()
        provider.objects["drafts", "ledger-v1.json"] = b'{"drafts":{}}'
        controls = StorageControls(provider, account="https://allocated.blob.core.windows.net",
                                   suite_id="suite1", admit=lambda: None)
        with self.assertRaises(OperationError):
            controls.prepare()
        self.assertNotIn(("drafts", storage_target("suite1")), provider.objects)

    def test_malformed_source_products_block_without_exposing_contents(self):
        for content in (b'["private-details"]', b'{"drafts":"private-details"}', b'private-details'):
            with self.subTest(content=content):
                provider = BlobProvider()
                provider.objects["drafts", "ledger-v1.json"] = content
                controls = StorageControls(provider, account="https://allocated.blob.core.windows.net",
                                           suite_id="suite1", admit=lambda: None)
                with self.assertRaises(OperationError) as error:
                    controls.prepare()
                self.assertNotIn("private-details", str(error.exception))
                self.assertNotIn(("drafts", storage_target("suite1")), provider.objects)
