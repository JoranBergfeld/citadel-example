"""Saved Planner products, never a fixture production playback."""

import unittest

from citadel.evidence import CAVEATS
from citadel.operations import Operations
from citadel.operations.testing import MemoryLedger
from citadel.runtime.observation import DeploymentReads, RunIndex, empty_index
from citadel.runtime.state import ScopedLedger
from citadel.operator.web import history_content
from citadel.operator.observation import Observed
from tests.unit.agent_fixtures import reference


class ScenarioSummaryTests(unittest.IsolatedAsyncioTestCase):
    async def observe_product(self, fixture, product):
        index_ledger = MemoryLedger(clock=lambda: 1000)
        index_ledger.document = empty_index()
        reads = DeploymentReads(index_ledger.ticket_store, "fixture1", clock=lambda: 1000)
        await index_ledger.ticket_store.open_pool(reads.scope("observation"))
        index = RunIndex(index_ledger, reads, clock=lambda: 1000)
        payload = {"run_id": "saved1", "operation_id": "saved1", "fixture": fixture}
        await index.register("operator", payload)
        workload = MemoryLedger(clock=lambda: 1000)
        ops = Operations(workload, workload="candidate-planner", clock=lambda: 1000)
        await ops.accept("operator", "invoke", "saved1", payload, run_id="saved1", deadline=1800)
        owner = await ops.claim("operator", "invoke", "saved1", worker="fixture")
        await ops.complete(owner, product=product)
        async with reads.request():
            return await index.observe("saved1", ScopedLedger(workload))

    async def test_saved_replacement_shows_gap_separate_overlay_and_actual_brief_without_private_fields(self):
        data = reference("missing-width-replacement")
        product = {"status": "complete", "selected_identifiers": ["EB02", "EB03", "EB04"],
                   "assessed": [{"airport_ident": ident, **data.assess_airport(ident),
                                 "private_notes": "secret draft"} for ident in ("EB01", "EB02", "EB03", "EB04")],
                   "pool_count": 4, "provenance": data.provenance, "caveats": list(CAVEATS),
                   "brief": {"status": "complete", "narrative": "Saved fictional comparison.",
                             "citations": [{"artifact_id": "finding1", "version": 2, "sha256": "a" * 64}],
                             "private_notes": "secret draft", "read_scopes": [{"secret": "pool"}]}}
        observed = await self.observe_product("missing-width-replacement", product)
        self.assertEqual(observed["summary"]["selected_identifiers"], ["EB02", "EB03", "EB04"])
        self.assertEqual(observed["summary"]["brief"]["narrative"], "Saved fictional comparison.")
        self.assertNotIn("secret", str(observed))
        html = history_content(Observed(observed, 1000, "ok"), "csrf", "saved1", None)
        for value in ("synthetic_missing_width", "Saved fictional comparison.", "skipped",
                      "overlay", "unchanged", "finding1", "version 2"):
            self.assertIn(value, html)

    async def test_exhaustion_and_missing_brief_are_not_manufactured_success(self):
        data = reference("no-alternative")
        product = {"status": "bounded_pool_exhausted", "selected_identifiers": [],
                   "assessed": [{"airport_ident": "EB01", **data.assess_airport("EB01")},
                                {"airport_ident": "EB02", "classification": "release_rejected"}],
                   "pool_count": 4, "provenance": data.provenance, "caveats": list(CAVEATS)}
        observed = await self.observe_product("no-alternative", product)
        self.assertIsNone(observed["summary"]["brief"])
        html = history_content(Observed(observed, 1000, "ok"), "csrf", "saved1", None)
        for value in ("Expected bounded-pool exhaustion", "No saved brief", "Release rejected",
                      "insufficient_evidence"):
            self.assertIn(value, html)
        product.update(status="complete", selected_identifiers=["EB01", "EB02", "EB03"])
        partial = await self.observe_product("base-source", product)
        self.assertEqual(partial["state"], "partial")
        self.assertIsNone(partial["summary"]["brief"])
