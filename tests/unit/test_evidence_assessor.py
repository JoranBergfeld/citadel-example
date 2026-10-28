import unittest

from agent_fixtures import AgentCase
from citadel.evidence.manifests import sha256
from citadel.operations import OperationError


class EvidenceAssessorTests(AgentCase, unittest.IsolatedAsyncioTestCase):
    async def test_private_draft_is_saved_and_exact_version_sent_to_reviewer_even_when_rejected(self):
        runtime = await self.agent("evidence-assessor", airport_ident="EB01")
        status, result = await self.execute(runtime)
        self.assertEqual(status["state"], "succeeded")
        self.assertEqual(result["kind"], "rejected")
        self.assertEqual(result["reason"], "draft_evidence_mismatch")
        review = next(arguments for role, arguments in self.peers.calls if role == "release-reviewer")
        ref = review["draft"]
        draft = await self.draft_store.get_draft(ref["artifact_id"], ref["version"], ref["sha256"])
        self.assertEqual(draft["classification"], "complete")
        self.assertEqual(draft["assessment_prose"], "Fictional unit-fixture prose; source accuracy unverified.")
        self.assertNotIn(draft["assessment_prose"], str(status))
        self.assertEqual(draft["airport_ident"], "EB01")
        self.assertNotIn("private_notes", str(review))
        with self.assertRaises(OperationError) as caught:
            await self.finding_store.get_finding(sha256({"draft_id": ref["artifact_id"]}), 1)
        self.assertEqual(caught.exception.code, "not_found")

    async def test_model_failure_neither_saves_a_draft_nor_requests_release(self):
        self.model_status = 503
        runtime = await self.agent("evidence-assessor", airport_ident="EB01")
        status, result = await self.execute(runtime)
        self.assertEqual(status["state"], "indeterminate")
        self.assertIsNone(result)
        self.assertEqual(self.peers.calls, [("reference", "EB01")])
        with self.assertRaises(OperationError) as caught:
            await self.draft_store.get_draft(sha256({"run": "run1", "airport": "EB01"}), 1, "0" * 64)
        self.assertEqual(caught.exception.code, "not_found")
        self.assertEqual(len(self.model_requests), 1)
