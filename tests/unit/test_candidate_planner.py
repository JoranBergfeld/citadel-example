import unittest

from agent_fixtures import AgentCase
from agent_fixtures import PeerResponses, reference


class CandidatePlannerTests(AgentCase, unittest.IsolatedAsyncioTestCase):
    async def test_unavailable_assessed_projection_writes_do_not_fail_or_replay_execution(self):
        from citadel.operations.testing import MemoryLedger
        from citadel.runtime.observation import DeploymentReads, RunIndex, empty_index
        runtime = await self.agent("candidate-planner")
        ledger = MemoryLedger(clock=self.clock)
        ledger.document = empty_index()
        reads = DeploymentReads(ledger.ticket_store, "fixture1", clock=self.clock)
        reads.capacities = {"observation": 1, "recovery-proof": 1}
        await ledger.ticket_store.open_pool(reads.scope("observation"))
        runtime.run_index = RunIndex(ledger, reads, clock=self.clock)
        status, product = await self.execute(runtime)
        self.assertEqual(status["state"], "succeeded")
        self.assertEqual(product["selected_identifiers"], ["EB01", "EB02", "EB03"])
        self.assertEqual(len([c for c in self.peers.calls if c[0] == "evidence-assessor"]), 3)

    async def test_saved_assessed_bindings_survive_later_author_failure_without_claiming_unassessed_pool(self):
        from citadel.operations import OperationError
        from citadel.operations.testing import MemoryLedger
        from citadel.runtime.observation import DeploymentReads, RunIndex, empty_index
        from citadel.runtime.reference_observation import ReferenceObservation
        runtime = await self.agent("candidate-planner")
        ledger = MemoryLedger(clock=self.clock)
        ledger.document = empty_index()
        reads = DeploymentReads(ledger.ticket_store, "fixture1", clock=self.clock)
        await ledger.ticket_store.open_pool(reads.scope("observation"))
        runtime.run_index = RunIndex(ledger, reads, clock=self.clock)
        child = self.peers.child

        async def fail_author(*args):
            if args[3] == "briefing-author":
                raise OperationError("unavailable", "Fixture author unavailable after assessments")
            return await child(*args)

        self.peers.child = fail_author
        status, product = await self.execute(runtime)
        self.assertEqual(status["state"], "indeterminate")
        self.assertIsNone(product)
        observed = await ReferenceObservation(ledger, reads, {"base-source": reference()}).observe("run1")
        self.assertEqual(observed["state"], "ok")
        self.assertEqual([x["airport_ident"] for x in observed["candidates"]], ["EB01", "EB02", "EB03"])

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
