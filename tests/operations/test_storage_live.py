"""Opt-in real storage probes; run under the allocated workload MI, never operator login."""

import asyncio
import os
import time
import unittest
from uuid import uuid4

from azure.core import MatchConditions
from azure.core.exceptions import HttpResponseError

from citadel.evidence.manifests import canonical_bytes
from citadel.evidence import ReferenceData
from citadel.operations import DraftReader, Operations, OperationError, empty_ledger
from citadel.operations.blob import managed_ledger


@unittest.skipUnless(os.environ.get("CITADEL_STORAGE_TESTS") == "1",
                     "real Azure storage opt-in not enabled; no cloud authority established")
class LiveStorageTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        required = ("CITADEL_STORAGE_ACCOUNT_URL", "CITADEL_STORAGE_CONTAINER",
                    "CITADEL_STORAGE_CLIENT_ID", "CITADEL_STORAGE_WORKLOAD")
        if any(not os.environ.get(key) for key in required):
            self.fail("Explicit workload identity/container configuration is required")
        self.context = managed_ledger(
            account_url=os.environ["CITADEL_STORAGE_ACCOUNT_URL"],
            container=os.environ["CITADEL_STORAGE_CONTAINER"],
            client_id=os.environ["CITADEL_STORAGE_CLIENT_ID"],
            blob_name=f"acceptance-{uuid4().hex}.json",
            control_plane=True,
        )
        self.ledger = await self.context.__aenter__()
        self.addAsyncCleanup(self.context.__aexit__, None, None, None)
        await self.ledger.initialize()
        # Keep isolated probe artifacts for inventory-scoped manual teardown/evidence.
        self.ops = Operations(self.ledger, workload=os.environ["CITADEL_STORAGE_WORKLOAD"])

    async def test_real_etag_race_has_one_winner_and_restart_preserves_status(self):
        document, etag = await self.ledger.read()
        left, right = empty_ledger(), empty_ledger()
        left["probe"] = "left"
        right["probe"] = "right"
        results = await asyncio.gather(
            self.ledger.commit(left, etag, deadline=time.time() + 90),
            self.ledger.commit(right, etag, deadline=time.time() + 90),
            return_exceptions=True,
        )
        self.assertEqual(sum(result is None for result in results), 1)
        failure = next(result for result in results if result is not None)
        self.assertIsInstance(failure, OperationError)
        self.assertEqual(failure.code, "conflict")
        actual, _ = await self.ledger.read()
        self.assertIn(actual["probe"], ("left", "right"))
        deadline = time.time() + 120
        await self.ops.accept("operator", "probe", "op1", {}, run_id="probe1", deadline=deadline)
        owner = await self.ops.claim("operator", "probe", "op1", worker="probe1")
        await self.ops.complete(owner)
        restarted = Operations(self.ledger, workload=os.environ["CITADEL_STORAGE_WORKLOAD"])
        self.assertEqual((await restarted.status("operator", "probe", "op1"))["state"], "succeeded")

    async def test_real_commit_response_loss_reconciles_without_reissuing_write(self):
        await self.ops.accept("operator", "probe", "op1", {}, run_id="probe1", deadline=time.time() + 120)
        owner = await self.ops.claim("operator", "probe", "op1", worker="probe1")

        class DropCommittedResponse:
            async def read(inner):
                return await self.ledger.read()

            async def commit(inner, *args, **kwargs):
                await self.ledger.commit(*args, **kwargs)
                raise OperationError("indeterminate", "Fixed-purpose committed-response fault")

        faulted = Operations(DropCommittedResponse(), workload=os.environ["CITADEL_STORAGE_WORKLOAD"])
        with self.assertRaises(OperationError):
            await faulted.complete(owner)
        self.assertEqual((await self.ops.status("operator", "probe", "op1"))["state"], "succeeded")
        with self.assertRaises(OperationError):
            await self.ops.retry("operator", "probe", "op1")

    async def test_service_rejects_expired_lease_even_when_etag_is_unchanged(self):
        _, etag = await self.ledger.read()
        lease = await self.ledger.client.acquire_lease(lease_duration=15)
        await asyncio.sleep(17)
        with self.assertRaises(HttpResponseError) as caught:
            await self.ledger.client.upload_blob(
                canonical_bytes(empty_ledger()), overwrite=True, lease=lease,
                etag=etag, match_condition=MatchConditions.IfNotModified,
            )
        self.assertEqual(caught.exception.status_code, 412)


@unittest.skipUnless(os.environ.get("CITADEL_RELEASE_STORAGE_TESTS") == "1",
                     "real reviewer/draft fixture opt-in not enabled")
class LiveReleaseTests(unittest.IsolatedAsyncioTestCase):
    async def test_distinct_operations_release_one_real_exact_draft(self):
        required = (
            "CITADEL_STORAGE_ACCOUNT_URL", "CITADEL_STORAGE_CONTAINER", "CITADEL_STORAGE_CLIENT_ID",
            "CITADEL_DRAFT_CONTAINER", "CITADEL_DRAFT_ID", "CITADEL_DRAFT_VERSION",
            "CITADEL_DRAFT_SHA256", "CITADEL_REFERENCE_BUNDLE", "CITADEL_RUN_DEADLINE",
        )
        if any(not os.environ.get(key) for key in required):
            self.fail("Reviewer identity, exact committed draft, bundle and inherited deadline are required")
        data = ReferenceData.from_bundle(
            os.environ["CITADEL_REFERENCE_BUNDLE"], fixture=os.environ.get("CITADEL_FIXTURE", "base-source"),
        )
        options = {"account_url": os.environ["CITADEL_STORAGE_ACCOUNT_URL"],
                   "client_id": os.environ["CITADEL_STORAGE_CLIENT_ID"], "control_plane": True}
        async with managed_ledger(
            **options, container=os.environ["CITADEL_DRAFT_CONTAINER"],
        ) as draft_ledger, managed_ledger(
            **options, container=os.environ["CITADEL_STORAGE_CONTAINER"],
            blob_name=f"release-acceptance-{uuid4().hex}.json",
        ) as release_ledger:
            await release_ledger.initialize()
            drafts = DraftReader(draft_ledger)
            ref = {"artifact_id": os.environ["CITADEL_DRAFT_ID"],
                   "version": int(os.environ["CITADEL_DRAFT_VERSION"]),
                   "sha256": os.environ["CITADEL_DRAFT_SHA256"]}
            draft = await drafts.get_draft(ref["artifact_id"], ref["version"], ref["sha256"])
            reviewer = Operations(release_ledger, workload="release-reviewer")
            owners = []
            for op in ("approve1", "approve2"):
                await reviewer.accept("evidence-assessor", "release", op, {"draft": ref},
                                      run_id=draft["run_id"], deadline=float(os.environ["CITADEL_RUN_DEADLINE"]))
                owners.append(await reviewer.claim("evidence-assessor", "release", op, worker=op))
            results = await asyncio.gather(*[
                reviewer.release(owner, ref, drafts=drafts, reference=data) for owner in owners
            ])
            self.assertEqual(results[0]["result"], results[1]["result"])
            finding = await reviewer.get_finding(results[0]["result"]["artifact_id"], ref["version"])
            self.assertEqual(finding["draft"], ref)
            self.assertNotIn("private_notes", finding)
