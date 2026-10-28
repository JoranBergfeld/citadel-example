import unittest

from agent_fixtures import AgentCase
from agent_fixtures import PeerResponses, reference


class CandidatePlannerTests(AgentCase, unittest.IsolatedAsyncioTestCase):
    async def test_complete_released_candidates_produce_a_saved_plan_and_exact_author_input(self):
        runtime = await self.agent("candidate-planner")
        status, product = await self.execute(runtime)
        self.assertEqual(status["state"], "succeeded")
        self.assertEqual(product["selected_identifiers"], ["EB01", "EB02", "EB03"])
        self.assertEqual(product["status"], "complete")
        self.assertEqual(self.peers.authored["findings"], self.peers.references[:3])
        self.assertNotIn("private_notes", str(product))

    async def test_missing_width_is_skipped_for_a_complete_replacement_without_hiding_the_gap(self):
        self.peers = PeerResponses(reference("missing-width-replacement"))
        runtime = await self.agent("candidate-planner", fixture="missing-width-replacement")
        status, product = await self.execute(runtime)
        self.assertEqual(status["state"], "succeeded")
        self.assertEqual(product["selected_identifiers"], ["EB02", "EB03", "EB04"])
        self.assertEqual(product["assessed"][0]["classification"], "insufficient_evidence")
        self.assertIn("runway[1].width_ft: synthetic_missing_width", product["assessed"][0]["gap_reasons"])
        self.assertEqual(product["provenance"]["evidence_origin"], "synthetic-overlay")

    async def test_exhausted_pool_preserves_rejection_and_never_invokes_author(self):
        self.peers = PeerResponses(reference("no-alternative"))
        self.peers.rejected.add("EB02")
        runtime = await self.agent("candidate-planner", fixture="no-alternative")
        status, product = await self.execute(runtime)
        self.assertEqual(status["state"], "succeeded")
        self.assertEqual(product["status"], "bounded_pool_exhausted")
        self.assertEqual(len(product["assessed"]), 4)
        self.assertEqual(product["assessed"][1]["classification"], "release_rejected")
        self.assertNotIn("brief", product)
        self.assertIsNone(self.peers.authored)

    async def test_model_outage_remains_incomplete_without_peer_dispatch_or_automatic_replay(self):
        self.model_status = 503
        runtime = await self.agent("candidate-planner")
        status, product = await self.execute(runtime)
        self.assertEqual(status["state"], "indeterminate")
        self.assertEqual(status["result"], {"kind": "incomplete", "code": "unavailable"})
        self.assertIsNone(product)
        self.assertEqual(self.peers.calls, [])
        await runtime.accept(self.caller, self.payload)
        self.assertEqual(len(self.model_requests), 1)
