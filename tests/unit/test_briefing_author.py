import unittest

from agent_fixtures import AgentCase


class BriefingAuthorTests(AgentCase, unittest.IsolatedAsyncioTestCase):
    async def author(self, **changes):
        return await self.agent("briefing-author",
            **({"findings": self.peers.references[:3], "read_scopes": self.peers.scopes[:3]} | changes))

    async def test_saved_brief_uses_exact_released_citations_prose_and_mandatory_caveats(self):
        runtime = await self.author()
        status, brief = await self.execute(runtime)
        self.assertEqual(status["state"], "succeeded")
        self.assertTrue(brief["fictional"])
        self.assertEqual(brief["narrative"], "Fictional unit-fixture prose; source accuracy unverified.")
        self.assertEqual(brief["citations"], self.peers.references[:3])
        self.assertEqual(brief["caveats"], ["fictional comparison", "not operational suitability",
            "source accuracy unverified", "recorded runway length is not usable landing distance"])
        self.assertEqual([kind for kind, _ in self.peers.calls], ["finding"] * 3)
        self.assertEqual(len(self.model_requests), 1)

    async def test_duplicate_citations_are_rejected_before_any_read_or_inference(self):
        runtime = await self.author(findings=[self.peers.references[0]] * 3)
        status, brief = await self.execute(runtime)
        self.assertEqual(status["state"], "indeterminate")
        self.assertEqual(status["result"]["code"], "invalid_input")
        self.assertIsNone(brief)
        self.assertEqual(self.peers.calls, [])
        self.assertEqual(self.model_requests, [])

    async def test_approved_but_incomplete_finding_cannot_authorize_a_complete_brief(self):
        self.peers.findings["finding2"]["classification"] = "insufficient_evidence"
        runtime = await self.author()
        status, brief = await self.execute(runtime)
        self.assertEqual(status["state"], "indeterminate")
        self.assertEqual(status["result"]["code"], "conflict")
        self.assertIsNone(brief)
        self.assertEqual(self.model_requests, [])
