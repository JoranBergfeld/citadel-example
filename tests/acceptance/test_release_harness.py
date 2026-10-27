import asyncio
import base64
import copy
import hashlib
import json
import time
import unittest
from tests.acceptance.storage_fixture import storage_inventory
from types import SimpleNamespace

from citadel.acceptance.release_probes import ReleaseProbes
from citadel.evidence.manifests import canonical_bytes, sha256
from citadel.operations import DraftReader, Operations, empty_ledger
from citadel.operations.testing import MemoryLedger
from citadel.operator.state import Blocked
from tests.acceptance.test_revision import NativeFixture
from tests.acceptance.test_storage_controls import BlobProvider
from tests.operations.test_operations import reference


class ReleaseHarnessTests(unittest.TestCase):
    def test_operator_dispatches_actual_reviewer_manifest_and_independently_reads_each_isolated_result(self):
        from citadel.acceptance.release_harness import ReleaseAcceptance
        data, drafts, normal = reference(), MemoryLedger(clock=time.time), MemoryLedger(clock=time.time)
        async def seed():
            assessor = Operations(drafts, workload="evidence-assessor")
            draft = {"artifact_id": "draft", "version": 1, "schema_version": 1, "run_id": "comparison",
                "operation_id": "assess", "airport_ident": "EB01", "private_notes": "PRIVATE",
                **data.assess_airport("EB01")}
            await assessor.accept("candidate-planner", "draft", "assess", {"draft": draft, "expected_version": 0},
                                  run_id="comparison", deadline=time.time() + 120)
            owner = await assessor.claim("candidate-planner", "draft", "assess", worker="assessor")
            await assessor.submit_draft(owner, draft, expected_version=0, reference=data)
            ref = {"artifact_id": "draft", "version": 1, "sha256": sha256(draft)}
            await ReleaseProbes(normal, drafts=DraftReader(drafts), reference=data,
                workload="release-reviewer", enabled=True, source_run="comparison", deadline=time.time() + 120
                ).committed_response_loss(ref, operation_id="original")
        asyncio.run(seed())
        account = "https://allocated.blob.core.windows.net"
        principal = "11111111-1111-1111-1111-111111111111"

        class Native(NativeFixture, BlobProvider):
            def __init__(self):
                NativeFixture.__init__(self)
                BlobProvider.__init__(self)
                self.objects["drafts", "ledger-v1.json"] = canonical_bytes(asyncio.run(drafts.read())[0])
                self.objects["findings", "ledger-v1.json"] = canonical_bytes(asyncio.run(normal.read())[0])
                self.app["properties"]["template"]["containers"][0]["env"] = [
                    {"name": "CITADEL_BLOB_URL", "value": account},
                    {"name": "CITADEL_OPERATIONS_CONTAINER", "value": "reviewer-operations"}]
                self.dispatches = []

            def rest(self, method, resource, version, body=None):
                result = super().rest(method, resource, version, body)
                if method == "patch":
                    env = {row["name"]: row.get("value") for row in
                           result["properties"]["template"]["containers"][0]["env"]}
                    if "CITADEL_ACCEPTANCE_REQUEST" in env:
                        request = json.loads(base64.b64decode(env["CITADEL_ACCEPTANCE_REQUEST"]))
                        self.dispatches.append(request)
                        asyncio.run(self.execute(request))
                return result

            async def execute(self, request):
                rows = []
                if request["mode"] == "immutable-versions":
                    descriptor = request["versions"]
                    version_drafts, ledger = MemoryLedger(clock=time.time), MemoryLedger(clock=time.time)
                    version_drafts.document = json.loads(self.objects["drafts",
                        f"acceptance/{descriptor['run_id']}/drafts/{descriptor['operation_id']}.json"])
                    operation, started = "immutableprobe", time.time()
                    actual = await ReleaseProbes(ledger, drafts=DraftReader(version_drafts), reference=data,
                        workload=request["workload"], enabled=True, source_run=descriptor["run_id"],
                        deadline=request["deadline"]).immutable_versions(descriptor["drafts"], operation_id=operation)
                    check = "fault.immutable-versions"
                    rows.append({"check_id": check, "probe_id": check, "run_id": request["run_id"],
                        "operation_id": operation, "caller": request["workload"],
                        "runtime_identity": hashlib.sha256(request["client_id"].encode()).hexdigest(), "actual": actual,
                        "target": hashlib.sha256((account + "/reviewer-operations/acceptance/" + request["run_id"]
                                                  + "/observations/" + operation + ".json").encode()).hexdigest(),
                        "request_id": "external-immutable", "status_code": 201,
                        "started": started, "finished": time.time()})
                    self.objects["findings", f"acceptance/{request['run_id']}/releases/{operation}.json"] = (
                        canonical_bytes((await ledger.read())[0]))
                    self.summary = canonical_bytes({"schema_version": 1, "run_id": request["run_id"],
                                                    "state": "complete", "observations": rows})
                    return
                if request["mode"] == "draft-versions":
                    from citadel.acceptance.version_probes import VersionProbes
                    ledger, operation, started = MemoryLedger(clock=time.time), "versionprobe", time.time()
                    ref = request["release"]["draft"]
                    source_draft = await DraftReader(drafts).get_draft(
                        ref["artifact_id"], ref["version"], ref["sha256"])
                    actual = await VersionProbes(ledger, reference=data, workload=request["workload"],
                        enabled=True, run_id=request["run_id"], deadline=request["deadline"]).concurrent_version(
                            source_draft, operation_id=operation)
                    check = "fault.concurrent-version-conflict"
                    rows.append({"check_id": check, "probe_id": check, "run_id": request["run_id"],
                        "operation_id": operation, "caller": request["workload"],
                        "runtime_identity": hashlib.sha256(request["client_id"].encode()).hexdigest(), "actual": actual,
                        "target": hashlib.sha256((account + "/assessor-operations/acceptance/" + request["run_id"]
                                                  + "/observations/" + operation + ".json").encode()).hexdigest(),
                        "request_id": "external-version", "status_code": 201,
                        "started": started, "finished": time.time()})
                    self.objects["drafts", f"acceptance/{request['run_id']}/drafts/{operation}.json"] = (
                        canonical_bytes((await ledger.read())[0]))
                    self.summary = canonical_bytes({"schema_version": 1, "run_id": request["run_id"],
                                                    "state": "complete", "observations": rows})
                    return
                for n, check in enumerate(("fault.dropped-committed-release", "fault.concurrent-exact-draft-release",
                                           "fault.concurrent-different-operation-release", "fault.draft-hash-binding")):
                    ledger, operation, started = MemoryLedger(clock=time.time), "probe" + str(n), time.time()
                    probe = ReleaseProbes(ledger, drafts=DraftReader(drafts), reference=data,
                        workload=request["workload"], enabled=True, source_run=request["release"]["run_id"],
                        deadline=request["deadline"])
                    actual = (await probe.hash_binding(request["release"]["draft"], operation_id=operation) if n == 3
                        else await probe.committed_response_loss(request["release"]["draft"], operation_id=operation)
                        if n == 0 else await probe.concurrent_release(request["release"]["draft"],
                            operation_id=operation, distinct_operations=n == 2))
                    rows.append({"check_id": check, "probe_id": check, "run_id": request["run_id"],
                        "operation_id": operation, "caller": request["workload"],
                        "runtime_identity": hashlib.sha256(principal.encode()).hexdigest(), "actual": actual,
                        "target": hashlib.sha256((account + "/reviewer-operations/acceptance/" + request["run_id"]
                                                  + "/observations/" + operation + ".json").encode()).hexdigest(),
                        "request_id": "external-" + operation, "status_code": 201,
                        "started": started, "finished": time.time()})
                    self.objects["findings", f"acceptance/{request['run_id']}/releases/{operation}.json"] = (
                        canonical_bytes((await ledger.read())[0]))
                self.summary = canonical_bytes({"schema_version": 1, "run_id": request["run_id"],
                                                "state": "complete", "observations": rows})

            def blob_read(self, account, container, name):
                if container not in ("reviewer-operations", "assessor-operations") or not name.endswith("/observations.json"):
                    raise AssertionError("Wrong reviewer result authority")
                return self.summary

        native, saves = Native(), []
        original = copy.deepcopy(native.app["properties"]["template"])
        app = {"app": "/subscriptions/s/resourceGroups/g/providers/Microsoft.App/containerApps/d-release-reviewer",
               "identityClientId": principal, "identityPrincipalId": principal,
               "image": "registry.example/image@sha256:" + "a" * 64}
        lifecycle = SimpleNamespace(id="d", native=native,
            state=SimpleNamespace(save=lambda: saves.append(1)), value={
                "inventory": storage_inventory(evidence="allocated", planning="planningfixture"),
                "outputs": {"appInventory": [app]}})
        report = {"run_id": "suite", "operation_ids": ["comparison"],
                  "scenarios": {"comparison": {"operation_id": "comparison"}}}
        ReleaseAcceptance(lifecycle).execute(report)
        self.assertEqual(report["release_phase"]["state"], "observed")
        self.assertEqual(len(report["release_phase"]["snapshots"]), 4)
        self.assertEqual(native.app["properties"]["template"], original)
        self.assertEqual(native.dispatches[0]["workload"], "release-reviewer")
        self.assertEqual(native.dispatches[0]["mode"], "release-faults")
        self.assertEqual(native.dispatches[0]["release"]["run_id"], "comparison")
        self.assertEqual(report["operation_ids"].count("probe2-a"), 1)
        self.assertEqual(report["operation_ids"].count("probe2-b"), 1)
        self.assertEqual(report["operation_ids"].count("probe3-bad"), 1)
        self.assertTrue(saves)
        self.assertNotIn("PRIVATE", str(report))
        with self.assertRaises(Blocked):
            ReleaseAcceptance(lifecycle).execute(report)
        self.assertEqual(len(native.dispatches), 1)
        assessor_app = app | {"app": app["app"].replace("release-reviewer", "evidence-assessor"),
            "identityClientId": "22222222-2222-2222-2222-222222222222",
            "identityPrincipalId": "22222222-2222-2222-2222-222222222222"}
        lifecycle.value["outputs"]["appInventory"] = [assessor_app]
        native.app["properties"]["template"]["containers"][0]["env"][1]["value"] = "assessor-operations"
        restored = copy.deepcopy(native.app["properties"]["template"])
        ReleaseAcceptance(lifecycle).execute(report, mode="draft-versions")
        self.assertEqual(report["version_phase"]["state"], "observed")
        self.assertEqual(len(report["version_phase"]["snapshots"]), 1)
        self.assertEqual(report["operation_ids"].count("versionprobe-v1"), 1)
        self.assertEqual(report["operation_ids"].count("versionprobe-a"), 1)
        self.assertEqual(report["operation_ids"].count("versionprobe-b"), 1)
        self.assertEqual(native.app["properties"]["template"], restored)
        self.assertNotIn("PRIVATE", str(report))
        with self.assertRaises(Blocked):
            ReleaseAcceptance(lifecycle).execute(report, mode="draft-versions")
        self.assertEqual(len(native.dispatches), 2)
        lifecycle.value["outputs"]["appInventory"] = [app]
        native.app["properties"]["template"]["containers"][0]["env"][1]["value"] = "reviewer-operations"
        restored = copy.deepcopy(native.app["properties"]["template"])
        ReleaseAcceptance(lifecycle).execute(report, mode="immutable-versions")
        self.assertEqual(report["immutable_phase"]["state"], "observed")
        self.assertEqual(report["immutable_phase"]["deadline"], report["version_phase"]["deadline"])
        self.assertEqual(report["immutable_phase"]["source"]["draft_before"]["sha256"],
                         report["immutable_phase"]["source"]["draft_after"]["sha256"])
        self.assertEqual(report["operation_ids"].count("immutableprobe-v1"), 1)
        self.assertEqual(report["operation_ids"].count("immutableprobe-v2"), 1)
        self.assertEqual(native.app["properties"]["template"], restored)
        self.assertNotIn("PRIVATE", str(report))
        with self.assertRaises(Blocked):
            ReleaseAcceptance(lifecycle).execute(report, mode="immutable-versions")
        self.assertEqual(len(native.dispatches), 3)
