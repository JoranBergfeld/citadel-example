import hashlib
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from uuid import UUID

from citadel.acceptance.console import ConsoleProbe
from citadel.acceptance.coverage import CONTAINERS, STORAGE
from citadel.acceptance.probes import AGENTS
from citadel.acceptance.revision import RevisionProbe
from citadel.acceptance.storage_harness import StorageAcceptance
from citadel.acceptance.storage_probes import storage_target
from citadel.operator.state import Blocked
from tests.acceptance.storage_fixture import storage_inventory
from tests.acceptance.test_storage_controls import BlobProvider


class StorageSelectionTests(unittest.TestCase):
    def setUp(self):
        self.native, self.calls = BlobProvider(), []
        self.lifecycle = SimpleNamespace(id="deployment", native=self.native,
            state=SimpleNamespace(save=lambda: None),
            value={"inventory": storage_inventory(planning="planningfixture"), "outputs": {
                "appInventory": [{"app": "/deployment-" + actor,
                    "identityPrincipalId": str(UUID(int=index + 1))}
                    for index, actor in enumerate(("reference-data", *AGENTS))]}})

    def worker(self, driver, app, actor, run_id, *, storage, **options):
        self.calls.append(actor)
        principal = hashlib.sha256(app["identityPrincipalId"].encode()).hexdigest()
        return {"schema_version": 1, "run_id": run_id, "state": "complete", "observations": [
            {"check_id": f"storage.{actor}.{container}.{action}", "caller": actor,
             "runtime_identity": principal, "container": container, "action": action,
             "run_id": run_id, "suite_id": storage["suite_id"],
             "operation_id": f"{run_id}-{index}-{action}",
             "target": hashlib.sha256(
                 f"{storage['accounts'][container]}/{container}/{storage_target(storage['suite_id'])}".encode()).hexdigest()}
            for index, container in enumerate(CONTAINERS) for action in ("read", "write")]}

    def test_selected_agents_use_existing_storage_implementation_without_console_dispatch(self):
        report = {"run_id": "suite1", "operation_ids": []}
        with patch.object(RevisionProbe, "execute", autospec=True, side_effect=self.worker), \
                patch.object(ConsoleProbe, "execute", autospec=True, side_effect=self.worker) as console:
            try:
                StorageAcceptance(self.lifecycle).execute(report, workloads=frozenset(AGENTS))
            except TypeError as error:
                self.fail("Storage workload selection is missing: " + str(error))
        self.assertEqual(set(self.calls), set(AGENTS))
        self.assertEqual(len(self.calls), 4)
        console.assert_not_called()
        self.assertEqual(report["storage_phase"]["state"], "observed")
        self.assertEqual(report["storage_phase"]["workloads"], sorted(AGENTS))

    def test_full_storage_default_still_observes_all_five_workloads(self):
        report = {"run_id": "suite1", "operation_ids": []}
        with patch.object(RevisionProbe, "execute", autospec=True, side_effect=self.worker), \
                patch.object(ConsoleProbe, "execute", autospec=True, side_effect=self.worker) as console:
            StorageAcceptance(self.lifecycle).execute(report)
        self.assertEqual(set(self.calls), set(STORAGE))
        self.assertEqual(len(self.calls), 5)
        self.assertEqual(console.call_count, 1)
        self.assertEqual(report["storage_phase"]["state"], "observed")

    def test_empty_unknown_or_mutable_selections_fail_before_storage_effects(self):
        for selected in (frozenset(), frozenset({"unknown"}), list(AGENTS)):
            with self.subTest(selected=selected), self.assertRaises(Blocked):
                StorageAcceptance(self.lifecycle).execute(
                    {"run_id": "suite1", "operation_ids": []}, workloads=selected)
        self.assertEqual(self.native.requests, [])

    def test_missing_selected_workload_cannot_complete_an_observation(self):
        self.lifecycle.value["outputs"]["appInventory"] = [
            app for app in self.lifecycle.value["outputs"]["appInventory"]
            if not app["app"].endswith("-briefing-author")]
        report = {"run_id": "suite1", "operation_ids": []}
        with patch.object(RevisionProbe, "execute", autospec=True, side_effect=self.worker), \
                patch.object(ConsoleProbe, "execute", autospec=True, side_effect=self.worker) as console:
            with self.assertRaises(Blocked):
                StorageAcceptance(self.lifecycle).execute(report, workloads=frozenset(AGENTS))
        console.assert_not_called()
        self.assertEqual(report["storage_phase"]["state"], "blocked")

    def test_duplicate_or_unknown_inventory_is_blocked_before_storage_effects(self):
        inventory = self.lifecycle.value["outputs"]["appInventory"]
        for app in (dict(inventory[0]), {"app": "/deployment-unknown"}):
            with self.subTest(app=app):
                self.lifecycle.value["outputs"]["appInventory"] = inventory + [app]
                report = {"run_id": "suite1", "operation_ids": []}
                with self.assertRaises(Blocked):
                    StorageAcceptance(self.lifecycle).execute(report, workloads=frozenset(AGENTS))
                self.assertEqual(report["storage_phase"]["state"], "blocked")
                self.assertEqual(self.native.requests, [])
