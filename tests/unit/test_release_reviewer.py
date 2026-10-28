import unittest

from agent_fixtures import AgentCase, PeerResponses, reference
from citadel.evidence.manifests import sha256
from citadel.operations import OperationError


class ReleaseReviewerTests(AgentCase, unittest.IsolatedAsyncioTestCase):
    async def test_approval_publishes_only_requested_immutable_draft_not_latest_private_version(self):
        ref = await self.save_draft()
        await self.save_draft(version=2, expected_version=1)
        runtime = await self.agent("release-reviewer", draft=ref)
        status, result = await self.execute(runtime)
        self.assertEqual(status["state"], "succeeded")
        self.assertEqual(result["kind"], "collaboration")
        saved = result["finding"]
        finding = await self.finding_store.get_finding(saved["artifact_id"], saved["version"])
        self.assertEqual(finding["draft"], ref)
        self.assertEqual(finding["classification"], "complete")
        self.assertEqual(finding["reviewer"], "release-reviewer")
        self.assertNotIn("private_notes", finding)
        self.assertNotIn("Private unit-fixture", str(result))
        self.assertIn("not operational suitability", finding["caveats"])

    async def test_changed_evidence_rejects_exact_draft_without_publishing_a_finding(self):
        ref = await self.save_draft()
        self.peers = PeerResponses(reference("missing-width-replacement"))
        runtime = await self.agent("release-reviewer", draft=ref, fixture="missing-width-replacement")
        status, result = await self.execute(runtime)
        self.assertEqual(status["state"], "succeeded")
        self.assertEqual(result["kind"], "rejected")
        self.assertEqual(result["reason"], "draft_evidence_mismatch")
        with self.assertRaises(OperationError) as caught:
            await self.finding_store.get_finding(sha256({"draft_id": "draft1"}), 1)
        self.assertEqual(caught.exception.code, "not_found")
        self.assertEqual(len(self.model_requests), 1)

    async def test_forged_draft_hash_cannot_trigger_recheck_model_or_publication(self):
        ref = await self.save_draft()
        runtime = await self.agent("release-reviewer", draft=ref | {"sha256": "0" * 64})
        status, result = await self.execute(runtime)
        self.assertEqual(status["state"], "indeterminate")
        self.assertEqual(status["result"]["code"], "conflict")
        self.assertIsNone(result)
        self.assertEqual(self.peers.calls, [])
        self.assertEqual(self.model_requests, [])
        with self.assertRaises(OperationError) as caught:
            await self.finding_store.get_finding(sha256({"draft_id": "draft1"}), 1)
        self.assertEqual(caught.exception.code, "not_found")
