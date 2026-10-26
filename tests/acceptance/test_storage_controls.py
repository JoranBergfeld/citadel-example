import hashlib
import json
import unittest
from types import SimpleNamespace

from azure.core.exceptions import ResourceNotFoundError

from citadel.acceptance.coverage import CONTAINERS
from citadel.acceptance.storage_probes import StorageControls, storage_target
from citadel.operations import OperationError


class BlobProvider:
    def __init__(self):
        self.objects = {}
        self.requests = []
        for container in CONTAINERS:
            if container in ("candidate-lists", "briefs"):
                continue
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
                    http_response=SimpleNamespace(status_code=(
                        206 if (container, name) in provider.objects else 404) if method == "GET" else 201,
                        headers={"x-ms-request-id": f"actual-provider-{len(provider.requests)}"})))

            def download_blob(self, **options):
                self.exchange("GET", options)
                if (container, name) not in provider.objects:
                    from azure.core.exceptions import ResourceNotFoundError
                    raise ResourceNotFoundError("External fixture: blob does not exist")
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
    def test_disposable_planning_targets_use_the_real_authority_ledgers(self):
        provider = BlobProvider()
        for container in ("candidate-lists", "briefs"):
            self.assertNotIn((container, "ledger-v1.json"), provider.objects)
        original = dict(provider.objects)
        controls = StorageControls(provider, account="https://allocated.blob.core.windows.net",
                                   suite_id="suite1", admit=lambda: None)
        try:
            controls.prepare()
        except ResourceNotFoundError as error:
            self.fail(f"Real planning authorities must seed controls without fictional source blobs: {type(error).__name__}")
        for destination, source in (("candidate-lists", "planner-operations"), ("briefs", "author-operations")):
            self.assertEqual(provider.objects[destination, storage_target("suite1")],
                             original[source, "ledger-v1.json"])
            self.assertNotIn((destination, "ledger-v1.json"), provider.objects)
            self.assertNotIn(("GET", destination, "ledger-v1.json"), provider.requests)
        for key, content in original.items():
            self.assertEqual(provider.objects[key], content)

    def test_observer_routes_each_container_to_its_inventoried_team_account(self):
        from citadel.acceptance.storage_accounts import storage_accounts
        groups = {
            "reference": ("reference",),
            "evidence": ("drafts", "findings", "assessor-operations", "reviewer-operations"),
            "planning": ("candidate-lists", "briefs", "planner-operations", "author-operations"),
        }
        inventory, expected = [], {}
        for team, containers in groups.items():
            account = "/owned/providers/Microsoft.Storage/storageAccounts/" + team + "fixture"
            inventory.append(account)
            for container in containers:
                inventory.append(account + "/blobServices/default/containers/" + container)
                expected[container] = "https://" + team + "fixture.blob.core.windows.net"
        lifecycle = SimpleNamespace(value={"inventory": inventory})
        accounts = storage_accounts(lifecycle)
        self.assertEqual(accounts, expected)
        provider, destinations = BlobProvider(), []
        original = provider.blob

        def blob(account, container, name):
            self.assertEqual(account, expected[container], "Cross-team reads must use the owning account")
            destinations.append((account, container))
            return original(account, container, name)

        provider.blob = blob
        controls = StorageControls(provider, account=accounts, suite_id="suite1", admit=lambda: None)
        controls.prepare()
        controls.snapshot()
        self.assertEqual({container for _, container in destinations}, set(CONTAINERS))
        for row in controls.products().values():
            self.assertEqual(row["target"], hashlib.sha256(
                (expected[row["container"]] + "/" + row["container"] + "/ledger-v1.json").encode()).hexdigest())
        lifecycle.value["inventory"] += [
            "/owned/providers/Microsoft.Storage/storageAccounts/planningfixture/blobServices/default/containers/drafts"]
        from citadel.operator.state import Blocked
        with self.assertRaises(Blocked):
            storage_accounts(lifecycle)

    def test_release_source_selects_an_observed_comparison_finding_without_exporting_the_payload(self):
        from citadel.evidence.manifests import sha256
        provider, admissions = BlobProvider(), []
        finding = {"artifact_id": "finding", "version": 1, "run_id": "comparison",
            "operation_id": "original-review", "draft": {"artifact_id": "draft", "version": 1, "sha256": "a" * 64},
            "reviewer": "release-reviewer", "private_notes": "NOT EXPORTED"}
        provider.objects["findings", "ledger-v1.json"] = json.dumps(
            {"schema_version": 1, "findings": {"finding": {"1": finding}}}).encode()
        control = StorageControls(provider, account="https://allocated.blob.core.windows.net",
                                  suite_id="suite1", admit=lambda: admissions.append(1))
        observed = control.release_source(["comparison"])
        self.assertEqual(observed["release_source"], {"run_id": "comparison", "draft": finding["draft"]})
        self.assertEqual(observed["projection_sha256"], sha256(
            {key: value for key, value in finding.items() if key != "operation_id"}))
        self.assertEqual(len(admissions), 1)
        self.assertNotIn("NOT EXPORTED", str(observed))
        self.assertEqual(provider.requests, [("GET", "findings", "ledger-v1.json")])
        with self.assertRaises(OperationError):
            control.release_source(["unrelated"])

    def test_route_context_observes_existing_ledgers_without_exporting_products_or_funding_new_pools(self):
        from tests.acceptance.test_route_context import ledgers
        provider = BlobProvider()
        documents = ledgers()
        containers = {"candidate-planner": "planner-operations", "evidence-assessor": "assessor-operations",
                      "release-reviewer": "reviewer-operations", "briefing-author": "author-operations",
                      "findings": "findings"}
        for actor, container in containers.items():
            provider.objects[container, "ledger-v1.json"] = json.dumps(
                documents[actor] | {"schema_version": 1}).encode()
        original, admissions = dict(provider.objects), []
        from citadel.evidence.manifests import sha256
        from citadel.runtime.tickets import CAPACITY
        provider.objects["assessor-operations", "read-tickets/" + sha256(
            "candidate-planner/invoke/assess2") + f"/{CAPACITY['evidence-assessor'] - 1:03}.json"] = b"spent"
        original = dict(provider.objects)
        controls = StorageControls(provider, account="https://allocated.blob.core.windows.net",
                                   suite_id="suite1", admit=lambda: admissions.append(1))
        result = controls.route_context(["real-run"])
        self.assertEqual(result["context"]["read_scope"]["operation_id"], "review1")
        self.assertNotEqual(result["context"]["operations"]["evidence-assessor"]["operation_id"], "assess2")
        self.assertEqual(len(result["observations"]), 5)
        self.assertEqual(len(admissions), 11)
        self.assertEqual(len(result["ticket_reads"]), 6)
        self.assertEqual(provider.objects, original)
        self.assertEqual({(method, container, name) for method, container, name in provider.requests
                          if name == "ledger-v1.json"},
                         {("GET", container, "ledger-v1.json") for container in containers.values()})
        self.assertNotIn("private test prose", str(result))
        self.assertNotIn("product", result["context"]["operations"]["briefing-author"])

    def test_product_observer_reads_real_business_ledgers_without_seeding_or_writes(self):
        provider = BlobProvider()
        original = dict(provider.objects)
        controls = StorageControls(provider, account="https://allocated.blob.core.windows.net",
                                   suite_id="suite1", admit=lambda: None)
        observations = controls.products()
        self.assertEqual(set(observations), {"drafts", "findings"})
        self.assertEqual(provider.objects, original)
        self.assertEqual(provider.requests, [
            ("GET", "drafts", "ledger-v1.json"), ("GET", "findings", "ledger-v1.json")])
        self.assertTrue(all(record["count"] == 1 for record in observations.values()))
        self.assertNotIn("not-for-reports", str(observations))

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
            source_container = {"candidate-lists": "planner-operations", "briefs": "author-operations"}.get(
                container, container)
            self.assertEqual(provider.objects[container, storage_target("suite1")], original[source_container, source])
            self.assertEqual(snapshots[container]["sha256"],
                             hashlib.sha256(original[source_container, source]).hexdigest())
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
