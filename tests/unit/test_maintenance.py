"""Administrative changes and hosted/CLI execution share one durable admission."""

from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from azure.core.exceptions import AzureError, HttpResponseError

from citadel.operations import OperationError
from citadel.operator.rotation import rotate_command
from citadel.operator.state import Blocked
from tests.unit.agent_fixtures import AgentCase


class MaintenanceTests(AgentCase, unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.runtime = await self.agent("candidate-planner")
        self.effects = []
        account = "/subscriptions/test/resourceGroups/planning/providers/Microsoft.Storage/storageAccounts/planningtest"
        subscription = "/subscriptions/test/subscriptions/operator-web"
        self.lifecycle = SimpleNamespace(
            id="fixture1", config={"subscriptionId": "test"},
            value={"phase": "deployed_unverified", "runs": {},
                   "inventory": [account, account + "/blobServices/default/containers/planner-operations"],
                   "outputs": {"inventory": {"gateway": {"subscriptions": [subscription]}}}},
            inventory=lambda: None,
            credentials=lambda: {"callerStates": {"operator-web": "active"}},
            state=SimpleNamespace(directory=Path("tests/unit/nonexistent-maintenance-fixture"),
                                  save=lambda: None, event=lambda *args: None))

        def rest(method, *args):
            self.effects.append(method)
            return {"properties": {"state": "suspended"}}

        @contextmanager
        def blob(*args):
            yield self.ledger.ticket_store

        self.lifecycle.native = SimpleNamespace(rest=rest, blob=blob)
        store = self.ledger.ticket_store

        class Lease:
            def __init__(self, client, lease_id):
                self.id = lease_id

            def acquire(self, **kwargs):
                if store.active is not None:
                    error = HttpResponseError("Fixture occupied admission")
                    error.status_code = 409
                    raise error
                store.active = self.id

            def release(self, **kwargs):
                if store.active != self.id:
                    raise AssertionError("Maintenance released another owner")
                store.active = None

            def renew(self, **kwargs):
                if store.active != self.id:
                    raise HttpResponseError("Fixture exact maintenance owner not present")

        self.enterContext(patch("azure.storage.blob.BlobLeaseClient", Lease))
        self.enterContext(patch("citadel.operator.rotation.write_private"))
        self.args = SimpleNamespace(command="revoke", caller="operator-web")

    async def test_live_hosted_run_absent_from_cli_state_blocks_credential_maintenance(self):
        await self.runtime.accept("operator", self.payload)
        with self.assertRaises(Blocked):
            rotate_command(self.lifecycle, self.args)
        self.assertEqual(self.effects, [])
        self.assertEqual(self.ledger.ticket_store.active, "operator/invoke/run1")

    async def test_maintenance_holds_admission_against_concurrent_ui_cli_and_retry_generation(self):
        from citadel.operator.quiescence import maintenance
        from citadel.operations.testing import MemoryLedger
        from citadel.runtime.observation import DeploymentReads, RunIndex, empty_index
        from citadel.runtime.submission import ScenarioSubmission
        ledger = MemoryLedger(clock=self.clock)
        ledger.document = empty_index()
        reads = DeploymentReads(ledger.ticket_store, "fixture1", clock=self.clock)
        self.runtime.run_index = RunIndex(ledger, reads, clock=self.clock)
        with maintenance(self.lifecycle):
            held = self.ledger.ticket_store.active
            with maintenance(self.lifecycle):
                self.assertEqual(self.ledger.ticket_store.active, held)
            self.assertEqual(self.ledger.ticket_store.active, held)
            with self.assertRaises(OperationError):
                await self.runtime.accept("operator", self.payload)
            result = await ScenarioSubmission(self.runtime.run_index, self.runtime.accept).submit(
                "during-maintenance", "comparison")
            self.assertEqual(result["reason"], "active_run_blocker")
            with self.assertRaises(OperationError):
                await self.ledger.ticket_store.acquire_run("operator/invoke/run1", generation=3)
            self.assertEqual(self.ledger.ticket_store.active, held)
            self.assertEqual(self.runtime.tasks, set())
        self.assertIsNone(self.ledger.ticket_store.active)
        await self.runtime.accept("operator", self.payload)
        self.assertEqual(self.ledger.ticket_store.active, "operator/invoke/run1")

    async def test_ambiguous_maintenance_acquisition_never_changes_credentials_or_releases_ownership(self):
        class LostLease:
            def __init__(inner, client, lease_id):
                inner.id = lease_id

            def acquire(inner, **kwargs):
                self.ledger.ticket_store.active = inner.id
                raise AzureError("Fixture lease response lost")

            def release(inner, **kwargs):
                raise AssertionError("Ambiguous acquisition must not authorize a release")

        with patch("azure.storage.blob.BlobLeaseClient", LostLease):
            with self.assertRaises(Blocked):
                rotate_command(self.lifecycle, self.args)
        self.assertEqual(self.lifecycle.value["maintenance"]["state"], "unknown")
        self.assertEqual(self.effects, [])
        with self.assertRaises(OperationError):
            await self.runtime.accept("operator", self.payload)

    async def test_interrupted_mutation_keeps_exclusion_and_only_exact_owned_resumption_can_release(self):
        from citadel.operator.quiescence import maintenance
        owner = {"command": "fixture-maintenance"}
        with self.assertRaises(OperationError):
            with maintenance(self.lifecycle, owner=owner) as held:
                held["changed"] = True
                raise OperationError("indeterminate", "Fixture mutation response lost")
        previous = self.ledger.ticket_store.active
        with self.assertRaises(Blocked):
            with maintenance(self.lifecycle, owner={"command": "other"}):
                self.fail("An unrelated command cannot inherit maintenance ownership")
        with self.assertRaises(OperationError):
            await self.runtime.accept("operator", self.payload)
        with maintenance(self.lifecycle, owner=owner):
            self.assertEqual(self.ledger.ticket_store.active, previous)
        self.assertIsNone(self.ledger.ticket_store.active)
