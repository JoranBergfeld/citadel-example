"""Offline management-boundary tests; no Azure credentials or external calls."""

from types import SimpleNamespace
import unittest

from citadel.operator.lifecycle import Lifecycle
from citadel.operator.state import Blocked


class ObservationDeploymentTests(unittest.TestCase):
    def lifecycle(self):
        lifecycle = object.__new__(Lifecycle)
        lifecycle.id = "fixture1"
        lifecycle.subscription = "/subscriptions/11111111-1111-4111-8111-111111111111"
        lifecycle.groups = {"platform": "citadel-fixture1-platform"}
        lifecycle.value = {"bootstrap": {}, "outputs": {"operatorInventory": {
            "accountingBlobUrl": "https://fixture.blob.core.windows.net"}}}
        lifecycle.state = SimpleNamespace(save=lambda: None)
        return lifecycle

    def test_explicit_bootstrap_reconciles_descriptors_but_never_refunds_markers_or_missing_state(self):
        lifecycle = self.lifecycle()
        blobs, created, leases = {}, [], []

        def create(account, container, name, content):
            self.assertNotIn(name, blobs)
            blobs[name] = content
            created.append(name)

        lifecycle.native = SimpleNamespace(
            blob_read=lambda account, container, name: blobs.get(name),
            blob_create=create,
            blob_pool_lease=lambda *args: leases.append(args))
        lifecycle.bootstrap_observation()
        blobs["read-tickets/test-spent/000.json"] = b"spent"
        lifecycle.bootstrap_observation()
        self.assertEqual(len(created), 2)
        self.assertEqual(len(leases), 4)
        self.assertEqual(blobs["read-tickets/test-spent/000.json"], b"spent")
        del blobs[created[0]]
        with self.assertRaises(Blocked) as caught:
            lifecycle.bootstrap_observation()
        self.assertEqual(caught.exception.code, "existing_observation_descriptor_missing")
        self.assertEqual(len(created), 2)

    def test_manual_teardown_removes_only_inventoried_marker_roles_before_the_custom_role(self):
        lifecycle = self.lifecycle()
        prefix = lifecycle.subscription + "/resourceGroups/citadel-fixture1-platform/providers/"
        container = prefix + "Microsoft.Storage/storageAccounts/observefixture/blobServices/default/containers/read-accounting"
        role = prefix + "Microsoft.Authorization/roleDefinitions/fixture-role"
        assignment = container + "/providers/Microsoft.Authorization/roleAssignments/fixture-assignment"
        accounting = {"resources": [container, role], "assignments": [assignment]}
        lifecycle.value["outputs"]["operatorInventory"]["accounting"] = accounting
        lifecycle.value["inventory"] = [container, role, assignment]
        deleted = []
        lifecycle.native = SimpleNamespace(rest=lambda method, resource, api: deleted.append(resource))
        lifecycle.teardown_accounting_roles()
        self.assertEqual(deleted, [assignment, role])
        deleted.clear()
        accounting["assignments"] = [prefix + "Microsoft.Authorization/roleAssignments/foreign"]
        with self.assertRaises(Blocked):
            lifecycle.teardown_accounting_roles()
        self.assertEqual(deleted, [])
