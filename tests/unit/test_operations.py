import unittest
import asyncio

from citadel.operations import DraftReader, Operations, OperationError
from citadel.operations.testing import MemoryLedger
from citadel.evidence import EvidenceError, ReferenceData
from citadel.evidence.manifests import sha256


def reference(width="80"):
    return ReferenceData.from_rows(
        airports=[{"id": "1", "ident": "EB01", "name": "Fictional", "type": "small_airport",
                   "latitude_deg": "51", "longitude_deg": "4", "iso_country": "BE",
                   "iso_region": "BE-VAN"}],
        runways=[{"id": "1", "airport_ref": "1", "airport_ident": "EB01",
                  "length_ft": "1200", "width_ft": width, "surface": "grass",
                  "closed": "0", "lighted": "0"}],
        countries=[{"code": "BE", "name": "Belgium"}],
        regions=[{"code": "BE-VAN", "name": "Antwerp", "iso_country": "BE"}],
    )


class OperationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.now = 1000.0
        self.store = MemoryLedger(clock=lambda: self.now)
        self.ops = Operations(self.store, workload="evidence-assessor", clock=lambda: self.now)

    async def test_authenticated_owner_action_and_input_bind_durable_identity(self):
        accepted = await self.ops.accept("candidate-planner", "assess", "op1",
                                         {"airport": "EB01"}, run_id="run1", deadline=1900)
        self.assertEqual(accepted["state"], "pending")
        restarted = Operations(self.store, workload="evidence-assessor", clock=lambda: self.now)
        self.assertEqual(await restarted.accept("candidate-planner", "assess", "op1",
                                               {"airport": "EB01"}, run_id="run1", deadline=1900),
                         accepted)
        with self.assertRaises(OperationError) as caught:
            await restarted.accept("candidate-planner", "assess", "op1",
                                   {"airport": "OTHER"}, run_id="run1", deadline=1900)
        self.assertEqual(caught.exception.code, "conflict")
        self.assertEqual((await restarted.status("operator", "assess", "op1"))["state"], "missing")
        self.assertNotIn("inputs", accepted)

    async def test_concurrent_different_approval_ids_publish_one_exact_projection(self):
        data = reference()
        draft = {"artifact_id": "draft1", "version": 1, "schema_version": 1,
                 "run_id": "run1", "operation_id": "draft-op", "airport_ident": "EB01",
                 "private_notes": "never public", **data.assess_airport("EB01")}
        await self.ops.accept("candidate-planner", "submit-draft", "draft-op",
                              {"draft": draft, "expected_version": 0}, run_id="run1", deadline=1900)
        owner = await self.ops.claim("candidate-planner", "submit-draft", "draft-op", worker="worker1")
        await self.ops.submit_draft(owner, draft, expected_version=0, reference=data)
        releases = MemoryLedger(clock=lambda: self.now)
        reviewer = Operations(releases, workload="release-reviewer", clock=lambda: self.now)
        ref = {"artifact_id": "draft1", "version": 1, "sha256": sha256(draft)}
        owners = []
        for op in ("approve1", "approve2"):
            await reviewer.accept("evidence-assessor", "release", op, {"draft": ref},
                                  run_id="run1", deadline=1900)
            owners.append(await reviewer.claim("evidence-assessor", "release", op, worker=op))
        barrier = asyncio.Barrier(2)
        count = 0

        async def competing_commit():
            nonlocal count
            count += 1
            if count <= 2:
                await barrier.wait()

        releases.before_commit = competing_commit
        results = await asyncio.gather(*[
            reviewer.release(owner, ref, drafts=DraftReader(self.store), reference=data)
            for owner in owners
        ])
        self.assertEqual(results[0]["result"], results[1]["result"])
        result = results[0]["result"]
        finding = await reviewer.get_finding(result["artifact_id"], result["version"])
        self.assertEqual(finding["draft"], ref)
        self.assertEqual(finding["reviewer"], "release-reviewer")
        self.assertNotIn("never public", str(finding))
        self.assertEqual(finding["caveats"], draft["caveats"])

    async def test_crashed_worker_is_not_replayed_and_fenced_retry_rejects_old_owner(self):
        await self.ops.accept("candidate-planner", "assess", "op1", {}, run_id="run1", deadline=1900)
        old = await self.ops.claim("candidate-planner", "assess", "op1", worker="worker1", lease_seconds=30)
        restarted = Operations(self.store, workload="evidence-assessor", clock=lambda: self.now)
        with self.assertRaises(OperationError):
            await restarted.claim("candidate-planner", "assess", "op1", worker="worker2")
        self.now += 31
        fenced = await restarted.fence("candidate-planner", "assess", "op1")
        self.assertEqual(fenced["state"], "failed_no_commit")
        await restarted.retry("candidate-planner", "assess", "op1")
        current = await restarted.claim("candidate-planner", "assess", "op1", worker="worker2")
        with self.assertRaises(OperationError) as caught:
            await self.ops.complete(old)
        self.assertEqual(caught.exception.code, "fenced")
        await restarted.complete(current)
        self.assertEqual((await restarted.status("candidate-planner", "assess", "op1"))["state"], "succeeded")

    async def test_draft_versions_commit_with_result_and_lost_response_reconciles(self):
        data = reference()
        draft = {"artifact_id": "draft1", "version": 1, "schema_version": 1,
                 "run_id": "run1", "operation_id": "op1", "airport_ident": "EB01",
                 "private_notes": "never public", **data.assess_airport("EB01")}
        await self.ops.accept("candidate-planner", "submit-draft", "op1",
                              {"draft": draft, "expected_version": 0}, run_id="run1", deadline=1900)
        owner = await self.ops.claim("candidate-planner", "submit-draft", "op1", worker="worker1")
        self.store.lose_response = True
        with self.assertRaises(OperationError) as caught:
            await self.ops.submit_draft(owner, draft, expected_version=0, reference=data)
        self.assertEqual(caught.exception.code, "indeterminate")
        status = await self.ops.status("candidate-planner", "submit-draft", "op1")
        self.assertEqual(status["state"], "succeeded")
        self.assertEqual(status["result"], {"kind": "draft", "artifact_id": "draft1",
                                          "version": 1, "sha256": sha256(draft)})
        self.assertNotIn("never public", str(status))
        self.assertEqual(await self.ops.get_draft("draft1", 1, sha256(draft)), draft)
        changes = {**draft, "version": 2, "operation_id": "op2", "private_notes": "corrected"}
        await self.ops.accept("candidate-planner", "submit-draft", "op2",
                              {"draft": changes, "expected_version": 0}, run_id="run1", deadline=1900)
        owner2 = await self.ops.claim("candidate-planner", "submit-draft", "op2", worker="worker2")
        with self.assertRaises(OperationError) as caught:
            await self.ops.submit_draft(owner2, changes, expected_version=0, reference=data)
        self.assertEqual(caught.exception.code, "conflict")

    async def test_ambiguous_external_invocation_never_becomes_retryable_on_restart(self):
        await self.ops.accept("candidate-planner", "assess", "op1", {}, run_id="run1", deadline=1900)
        owner = await self.ops.claim("candidate-planner", "assess", "op1", worker="worker1")
        await self.ops.begin_external(owner, "review1", "a" * 64)
        await self.ops.reconcile_external(owner, "review1", {"state": "missing"})
        with self.assertRaises(OperationError):
            await self.ops.complete(owner)
        self.now += 61
        self.assertEqual((await self.ops.fence("candidate-planner", "assess", "op1"))["state"],
                         "indeterminate")
        with self.assertRaises(OperationError):
            await self.ops.retry("candidate-planner", "assess", "op1")

    async def test_conflicting_draft_updates_are_conditional_not_last_writer_wins(self):
        data = reference()
        drafts, owners = [], []
        for op in ("op1", "op2"):
            draft = {"artifact_id": "draft1", "version": 1, "schema_version": 1,
                     "run_id": "run1", "operation_id": op, "airport_ident": "EB01",
                     "private_notes": op, **data.assess_airport("EB01")}
            drafts.append(draft)
            await self.ops.accept("candidate-planner", "submit-draft", op,
                                  {"draft": draft, "expected_version": 0}, run_id="run1", deadline=1900)
            owners.append(await self.ops.claim("candidate-planner", "submit-draft", op, worker=op))
        barrier = asyncio.Barrier(2)
        self.store.before_commit = barrier.wait
        results = await asyncio.gather(*[
            self.ops.submit_draft(owner, draft, expected_version=0, reference=data)
            for owner, draft in zip(owners, drafts)
        ], return_exceptions=True)
        self.assertEqual(sum(isinstance(result, OperationError) for result in results), 1)
        winner = next(result for result in results if isinstance(result, dict))
        self.assertEqual(winner["state"], "succeeded")
        losing = next(result for result in results if isinstance(result, OperationError))
        self.assertEqual(losing.code, "conflict")
        saved = await self.ops.get_draft("draft1", 1, winner["result"]["sha256"])
        self.assertIn(saved, drafts)

    async def test_late_inflight_completion_is_rejected_by_storage_fence(self):
        await self.ops.accept("candidate-planner", "assess", "op1", {}, run_id="run1", deadline=1900)
        owner = await self.ops.claim("candidate-planner", "assess", "op1", worker="worker1")

        async def delayed_request():
            self.now = 1901

        self.store.before_commit = delayed_request
        with self.assertRaises(OperationError) as caught:
            await self.ops.complete(owner)
        self.assertEqual(caught.exception.code, "deadline")
        self.assertEqual((await self.ops.status("candidate-planner", "assess", "op1"))["state"], "running")
        self.store.before_commit = None
        self.assertEqual((await self.ops.fence("candidate-planner", "assess", "op1"))["state"],
                         "failed_no_commit")

    async def test_operation_cannot_accept_deadline_beyond_run_ceiling(self):
        with self.assertRaises(OperationError) as caught:
            await self.ops.accept("candidate-planner", "assess", "op1", {}, run_id="run1", deadline=1901)
        self.assertEqual(caught.exception.code, "deadline")

    async def test_completed_work_product_and_status_become_visible_in_one_commit(self):
        planner = Operations(self.store, workload="candidate-planner", clock=lambda: self.now)
        await planner.accept("operator", "plan", "op1", {}, run_id="run1", deadline=1900)
        owner = await planner.claim("operator", "plan", "op1", worker="planner1")
        with self.assertRaises(OperationError):
            await planner.completed_result("operator", "plan", "op1")
        product = {"outcome": "bounded_pool_exhausted", "selected": []}
        self.store.lose_response = True
        with self.assertRaises(OperationError):
            await planner.complete(owner, product=product)
        self.assertEqual(await planner.completed_result("operator", "plan", "op1"), product)
        self.assertEqual((await planner.status("operator", "plan", "op1"))["state"], "succeeded")
        with self.assertRaises(OperationError):
            await planner.completed_result("briefing-author", "plan", "op1")

    async def test_concurrent_same_input_acceptance_returns_existing_operation(self):
        barrier = asyncio.Barrier(2)
        self.store.before_commit = barrier.wait
        results = await asyncio.gather(*[
            self.ops.accept("candidate-planner", "assess", "op1", {"airport": "EB01"},
                            run_id="run1", deadline=1900)
            for _ in range(2)
        ])
        self.assertEqual(results[0], results[1])

    async def test_other_operations_in_same_run_cannot_reset_absolute_deadline(self):
        await self.ops.accept("candidate-planner", "assess", "op1", {}, run_id="run1", deadline=1900)
        self.now += 100
        with self.assertRaises(OperationError) as caught:
            await self.ops.accept("candidate-planner", "assess", "op2", {}, run_id="run1", deadline=2000)
        self.assertEqual(caught.exception.code, "conflict")

    async def test_one_run_cannot_mix_evidence_provenance(self):
        for number, data in enumerate((reference(), reference(width=""))):
            op = f"op{number}"
            draft = {"artifact_id": f"draft{number}", "version": 1, "schema_version": 1,
                     "run_id": "run1", "operation_id": op, "airport_ident": "EB01",
                     **data.assess_airport("EB01")}
            await self.ops.accept("candidate-planner", "submit-draft", op,
                                  {"draft": draft, "expected_version": 0}, run_id="run1", deadline=1900)
            owner = await self.ops.claim("candidate-planner", "submit-draft", op, worker=op)
            if number == 0:
                await self.ops.submit_draft(owner, draft, expected_version=0, reference=data)
            else:
                with self.assertRaises(OperationError) as caught:
                    await self.ops.submit_draft(owner, draft, expected_version=0, reference=data)
                self.assertEqual(caught.exception.code, "conflict")

    async def test_explicit_reconciliation_of_fenced_nonexecution_allows_retry_not_replay(self):
        await self.ops.accept("candidate-planner", "assess", "op1", {}, run_id="run1", deadline=1900)
        owner = await self.ops.claim("candidate-planner", "assess", "op1", worker="worker1")
        await self.ops.begin_external(owner, "review1", "a" * 64)
        self.now += 61
        await self.ops.fence("candidate-planner", "assess", "op1")
        result = await self.ops.recover_external("candidate-planner", "assess", "op1",
                                                {"review1": {"state": "failed_no_commit",
                                                             "input_hash": "a" * 64}})
        self.assertEqual(result["state"], "failed_no_commit")
        with self.assertRaises(OperationError):
            await self.ops.complete(owner)
        self.assertEqual((await self.ops.retry("candidate-planner", "assess", "op1"))["state"], "pending")

    async def test_insufficient_release_lost_response_and_corrected_draft_preserve_binding(self):
        data = reference(width="")
        drafts = []
        for version in (1, 2):
            draft = {"artifact_id": "draft1", "version": version, "schema_version": 1,
                     "run_id": "run1", "operation_id": f"draft{version}", "airport_ident": "EB01",
                     "private_notes": f"correction{version}", **data.assess_airport("EB01")}
            drafts.append(draft)
            await self.ops.accept("candidate-planner", "submit-draft", f"draft{version}",
                                  {"draft": draft, "expected_version": version - 1},
                                  run_id="run1", deadline=1900)
            owner = await self.ops.claim("candidate-planner", "submit-draft", f"draft{version}",
                                        worker=f"worker{version}")
            await self.ops.submit_draft(owner, draft, expected_version=version - 1, reference=data)
        for draft in drafts:
            self.assertEqual(await self.ops.get_draft("draft1", draft["version"], sha256(draft)), draft)
        store = MemoryLedger(clock=lambda: self.now)
        reviewer = Operations(store, workload="release-reviewer", clock=lambda: self.now)
        ref = {"artifact_id": "draft1", "version": 1, "sha256": sha256(drafts[0])}
        await reviewer.accept("evidence-assessor", "release", "approve1", {"draft": ref},
                              run_id="run1", deadline=1900)
        owner = await reviewer.claim("evidence-assessor", "release", "approve1", worker="reviewer1")
        with self.assertRaises(OperationError) as caught:
            await self.ops.release(owner, ref, drafts=DraftReader(self.store), reference=data)
        self.assertEqual(caught.exception.code, "forbidden")
        with self.assertRaises(OperationError) as caught:
            await reviewer.release(owner, {**ref, "sha256": sha256(drafts[1])},
                                   drafts=DraftReader(self.store), reference=data)
        self.assertEqual(caught.exception.code, "conflict")
        with self.assertRaises(EvidenceError):
            await reviewer.release(owner, ref, drafts=DraftReader(self.store), reference=reference())
        store.lose_response = True
        with self.assertRaises(OperationError) as caught:
            await reviewer.release(owner, ref, drafts=DraftReader(self.store), reference=data)
        self.assertEqual(caught.exception.code, "indeterminate")
        result = await reviewer.status("evidence-assessor", "release", "approve1")
        self.assertEqual(result["state"], "succeeded")
        finding = await reviewer.get_finding(result["result"]["artifact_id"], 1)
        self.assertEqual(finding["classification"], "insufficient_evidence")
        self.assertEqual(finding["caveats"], drafts[0]["caveats"])
        self.assertEqual(finding["draft"], ref)
        with self.assertRaises(OperationError):
            await reviewer.get_finding(result["result"]["artifact_id"], 2)
        self.assertEqual(await reviewer.release(owner, ref, drafts=DraftReader(self.store), reference=data),
                         result)
        await reviewer.accept("evidence-assessor", "release", "approve2", {"draft": ref},
                              run_id="run2", deadline=1900)
        owner2 = await reviewer.claim("evidence-assessor", "release", "approve2", worker="reviewer2")
        repeated = await reviewer.release(owner2, ref, drafts=DraftReader(self.store), reference=data)
        self.assertEqual(repeated["result"], result["result"])


if __name__ == "__main__":
    unittest.main()
