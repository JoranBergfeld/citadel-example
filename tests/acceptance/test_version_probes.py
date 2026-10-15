import time
import unittest

from citadel.evidence.manifests import sha256
from citadel.operations import DraftReader, OperationError
from citadel.operations.testing import MemoryLedger
from tests.operations.test_operations import reference


class VersionProbeTests(unittest.IsolatedAsyncioTestCase):
    async def test_actual_draft_cas_race_keeps_original_and_commits_exactly_one_next_version(self):
        from citadel.acceptance.version_probes import VersionProbes
        data, ledger = reference(), MemoryLedger(clock=time.time)
        source = {"artifact_id": "source", "version": 1, "schema_version": 1,
            "run_id": "comparison", "operation_id": "source-assessment", "airport_ident": "EB01",
            "private_notes": "Never export this assessment", **data.assess_airport("EB01")}
        original = sha256(source)
        probe = VersionProbes(ledger, reference=data, workload="evidence-assessor", enabled=True,
                              run_id="version-worker", deadline=time.time() + 120)
        result = await probe.concurrent_version(source, operation_id="version-race")
        self.assertEqual(result["states"], ["running", "succeeded"])
        self.assertEqual(result["responses"], ["conflict", "succeeded"])
        self.assertEqual(result["artifact_count"], 2)
        self.assertEqual(result["simultaneous_commits"], 2)
        self.assertGreaterEqual(result["conditional_conflicts"], 1)
        self.assertEqual([row["version"] for row in result["drafts"]], [1, 2])
        self.assertEqual(result["before_sha256"], result["after_sha256"])
        self.assertEqual(sha256(source), original)
        self.assertNotIn("Never export this assessment", str(result))
        for ref in result["drafts"]:
            draft = await DraftReader(ledger).get_draft(ref["artifact_id"], ref["version"], ref["sha256"])
            self.assertEqual(draft["run_id"], "version-worker")
            self.assertEqual(draft["airport_ident"], "EB01")
        for workload, enabled in (("release-reviewer", True), ("evidence-assessor", False)):
            with self.assertRaises(ValueError):
                VersionProbes(ledger, reference=data, workload=workload, enabled=enabled,
                              run_id="version-worker", deadline=time.time() + 120)
        class UnknownStorage(MemoryLedger):
            writes = 0
            async def commit(self, document, etag, *, deadline):
                self.writes += 1
                if self.writes == 8:
                    raise OperationError("indeterminate", "External ambiguous storage response")
                return await super().commit(document, etag, deadline=deadline)
        probe = VersionProbes(UnknownStorage(clock=time.time), reference=data, workload="evidence-assessor",
                              enabled=True, run_id="uncertain-worker", deadline=time.time() + 120)
        with self.assertRaises(OperationError) as error:
            await probe.concurrent_version(source, operation_id="uncertain")
        self.assertEqual(error.exception.code, "indeterminate")
