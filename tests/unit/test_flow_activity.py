"""Actual owner handlers with controlled pending model I/O, not staged playback."""

import asyncio
import unittest

import httpx

from agent_fixtures import AgentCase
from citadel.operations import OperationError
from citadel.operations.testing import MemoryLedger
from citadel.runtime.agents import agent_application
from citadel.runtime.observation import DeploymentReads
from tests.unit.gateway_fixtures import signed, trust


class FlowActivityTests(AgentCase, unittest.IsolatedAsyncioTestCase):
    async def test_each_team_owner_reports_only_its_own_run_bound_pending_call(self):
        draft = await self.save_draft()
        for role, projection, inputs in (
            ("evidence-assessor", "drafts", {"airport_ident": "EB01"}),
            ("release-reviewer", "releases", {"draft": draft}),
            ("briefing-author", "brief", {"findings": self.peers.references[:3],
                                         "read_scopes": self.peers.scopes[:3]}),
        ):
            with self.subTest(owner=role):
                self.ledger = MemoryLedger(clock=self.clock)
                runtime = await self.agent(role, **inputs)
                entered, release = asyncio.Event(), asyncio.Event()

                class Model:
                    async def explain(self, *args):
                        entered.set()
                        await release.wait()
                        raise OperationError("unavailable", "Labelled controlled pending I/O")

                runtime.model = Model()
                reads = DeploymentReads(runtime.ticket_store, "fixture1", clock=self.clock)
                await reads.store.open_pool(reads.scope("observation"))
                runtime.observation_reads = reads
                await runtime.accept(self.caller, self.payload)
                await entered.wait()
                path = f"/operator/runs/run1/{projection}"
                try:
                    async with httpx.AsyncClient(transport=httpx.ASGITransport(
                            app=agent_application(runtime, trust(role)))) as client:
                        response = await client.get("https://gateway.test" + path,
                            headers=signed(b"", role, path, "operator-web", "GET"))
                        self.assertEqual(response.status_code, 200)
                        self.assertEqual(response.json()["activity"], {
                            "owner": role, "run_id": "run1", "target": "model",
                            "kind": "inflight", "observed_at": 1000, "expires_at": 1015})
                        other_path = path.replace("run1", "other-run")
                        other = await client.get("https://gateway.test" + other_path,
                            headers=signed(b"", role, other_path, "operator-web", "GET"))
                        self.assertIsNone(other.json()["activity"])
                        release.set()
                        await asyncio.gather(*runtime.tasks)
                        done = await client.get("https://gateway.test" + path,
                            headers=signed(b"", role, path, "operator-web", "GET"))
                        self.assertIsNone(done.json()["activity"])
                finally:
                    release.set()
                    await runtime.shutdown()
