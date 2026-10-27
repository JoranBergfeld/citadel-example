import time
import asyncio
import unittest
import sys
from pathlib import Path

from citadel.evidence.manifests import sha256
from citadel.operations import DraftReader, Operations, OperationError
from citadel.operations.testing import MemoryLedger
from tests.operations.test_operations import reference


class ReleaseProbeTests(unittest.IsolatedAsyncioTestCase):
    async def test_simultaneous_same_and_different_operations_release_one_exact_finding(self):
        from citadel.acceptance.release_probes import ReleaseProbes
        data, source = reference(), MemoryLedger(clock=time.time)
        assessor = Operations(source, workload="evidence-assessor")
        draft = {"artifact_id": "draft", "version": 1, "schema_version": 1,
            "run_id": "actual-run", "operation_id": "assessment", "airport_ident": "EB01",
            "private_notes": "private assessment", **data.assess_airport("EB01")}
        await assessor.accept("candidate-planner", "submit-draft", "assessment",
            {"draft": draft, "expected_version": 0}, run_id="actual-run", deadline=time.time() + 120)
        owner = await assessor.claim("candidate-planner", "submit-draft", "assessment", worker="assessor")
        await assessor.submit_draft(owner, draft, expected_version=0, reference=data)
        for distinct in (False, True):
            with self.subTest(distinct=distinct):
                probe = ReleaseProbes(MemoryLedger(clock=time.time), drafts=DraftReader(source), reference=data,
                    workload="release-reviewer", enabled=True, source_run="actual-run", deadline=time.time() + 120)
                result = await probe.concurrent_release(
                    {"artifact_id": "draft", "version": 1, "sha256": sha256(draft)},
                    operation_id="race", distinct_operations=distinct)
                self.assertEqual(result["states"], ["succeeded", "succeeded"])
                self.assertEqual(result["artifact_count"], 1)
                self.assertEqual(result["simultaneous_commits"], 2)
                self.assertGreaterEqual(result["conditional_conflicts"], 1)
                self.assertEqual(len(set(result["operation_ids"])), 2 if distinct else 1)
                self.assertEqual(result["result_hashes"][0], result["result_hashes"][1])
                self.assertNotIn("private assessment", str(result))
        class FailingStorage(MemoryLedger):
            writes = 0
            settled = False

            async def commit(self, document, etag, *, deadline):
                self.writes += 1
                if self.writes == 3:
                    raise OperationError("indeterminate", "External storage outcome unavailable")
                delayed = self.writes == 4
                if delayed:
                    await asyncio.sleep(.05)
                result = await super().commit(document, etag, deadline=deadline)
                if delayed:
                    self.settled = True
                return result
        failing = FailingStorage(clock=time.time)
        probe = ReleaseProbes(failing, drafts=DraftReader(source), reference=data,
            workload="release-reviewer", enabled=True, source_run="actual-run", deadline=time.time() + 120)
        with self.assertRaises(OperationError):
            await probe.concurrent_release({"artifact_id": "draft", "version": 1, "sha256": sha256(draft)},
                                           operation_id="interrupted-race")
        self.assertTrue(failing.settled, "Both dispatched participants must settle before reporting a blocked race")

    async def test_release_fault_uses_actual_blob_sdk_conditional_requests_not_a_success_adapter(self):
        from citadel.acceptance.release_probes import ReleaseProbes
        from citadel.operations.blob import AzureBlobLedger, API_VERSION
        from azure.storage.blob.aio import BlobClient
        from tests.runtime.test_storage import FixtureCredential
        runtime_tests = str(Path(__file__).resolve().parents[1] / "runtime")
        sys.path.insert(0, runtime_tests)
        try:
            from test_ticket_storage import TicketWire
        finally:
            sys.path.remove(runtime_tests)
        wire, data = TicketWire(clock=time.time), reference()
        async with BlobClient("https://allocated.blob.core.windows.net", "findings",
                "acceptance/probe/release.json", credential=FixtureCredential(), transport=wire,
                api_version=API_VERSION, retry_total=0) as client:
            ledger = AzureBlobLedger(client, control_plane=True)
            await ledger.initialize()
            source = MemoryLedger(clock=time.time)
            assessor = Operations(source, workload="evidence-assessor")
            draft = {"artifact_id": "actual-draft", "version": 1, "schema_version": 1,
                "run_id": "actual-run", "operation_id": "assessment", "airport_ident": "EB01",
                "private_notes": "private assessment", **data.assess_airport("EB01")}
            await assessor.accept("candidate-planner", "submit-draft", "assessment",
                {"draft": draft, "expected_version": 0}, run_id="actual-run", deadline=time.time() + 120)
            owner = await assessor.claim("candidate-planner", "submit-draft", "assessment", worker="assessor")
            await assessor.submit_draft(owner, draft, expected_version=0, reference=data)
            result = await ReleaseProbes(ledger, drafts=DraftReader(source), reference=data,
                workload="release-reviewer", enabled=True, source_run="actual-run",
                deadline=time.time() + 120).committed_response_loss(
                    {"artifact_id": "actual-draft", "version": 1, "sha256": sha256(draft)}, operation_id="release")
        self.assertEqual(result["state"], "succeeded")
        self.assertEqual(result["response"], "indeterminate")
        self.assertEqual(result["artifact_count"], 1)
        writes = [request for request in wire.requests if request.method == "PUT"
                  and request.headers.get("x-ms-blob-type") == "BlockBlob"]
        self.assertEqual(len(writes), 4, "Initialize, accept, claim and exactly one release; no effect replay")
        self.assertTrue(all(request.headers.get("If-Match") and request.headers.get("x-ms-lease-id")
                            for request in writes[1:]))
        self.assertTrue(all("/findings/acceptance/probe/release.json" in request.url for request in wire.requests))

    async def test_dropped_actual_release_response_is_reconciled_without_replaying_effect(self):
        from citadel.acceptance.release_probes import ReleaseProbes
        data, source = reference(), MemoryLedger(clock=time.time)
        assessor = Operations(source, workload="evidence-assessor")
        draft = {"artifact_id": "actual-draft", "version": 1, "schema_version": 1,
            "run_id": "actual-run", "operation_id": "actual-assessment", "airport_ident": "EB01",
            "private_notes": "private assessment", **data.assess_airport("EB01")}
        await assessor.accept("candidate-planner", "submit-draft", "actual-assessment",
            {"draft": draft, "expected_version": 0}, run_id="actual-run", deadline=time.time() + 900)
        owner = await assessor.claim("candidate-planner", "submit-draft", "actual-assessment", worker="assessor")
        await assessor.submit_draft(owner, draft, expected_version=0, reference=data)
        released = MemoryLedger(clock=time.time)
        probe = ReleaseProbes(released, drafts=DraftReader(source), reference=data,
            workload="release-reviewer", enabled=True, source_run="actual-run", deadline=time.time() + 120)
        result = await probe.committed_response_loss(
            {"artifact_id": "actual-draft", "version": 1, "sha256": sha256(draft)}, operation_id="release-probe")
        self.assertEqual(result["state"], "succeeded")
        self.assertEqual(result["response"], "indeterminate")
        self.assertEqual(result["replay"], "conflict")
        self.assertEqual(result["artifact_count"], 1)
        self.assertEqual(result["draft_sha256"], sha256(draft))
        self.assertNotIn("private assessment", str(result))
        self.assertEqual((await source.read())[0]["drafts"]["actual-draft"]["1"], draft)
        binding = ReleaseProbes(MemoryLedger(clock=time.time), drafts=DraftReader(source), reference=data,
            workload="release-reviewer", enabled=True, source_run="actual-run", deadline=time.time() + 120)
        checked = await binding.hash_binding(
            {"artifact_id": "actual-draft", "version": 1, "sha256": sha256(draft)}, operation_id="binding")
        self.assertEqual(checked["response"], "conflict")
        self.assertEqual(checked["rejected_count"], 0)
        self.assertEqual(checked["rejected_sha256"], checked["before_sha256"])
        self.assertEqual(checked["state"], "succeeded")
        self.assertEqual(checked["artifact_count"], 1)
        self.assertNotEqual(checked["rejected_draft_sha256"], checked["draft_sha256"])
        with self.assertRaises(ValueError):
            ReleaseProbes(released, drafts=DraftReader(source), reference=data,
                workload="candidate-planner", enabled=True, source_run="actual-run", deadline=time.time() + 120)
        with self.assertRaises(ValueError):
            ReleaseProbes(released, drafts=DraftReader(source), reference=data,
                workload="release-reviewer", enabled=False, source_run="actual-run", deadline=time.time() + 120)
