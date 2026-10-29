"""Telemetry export selects workspaces, not their extension resources."""

from datetime import datetime, timezone
from pathlib import Path
import shutil
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from citadel.operator.lifecycle import Lifecycle
from citadel.operator.native import Native


class TelemetryTests(unittest.TestCase):
    def test_collection_does_not_read_workspace_role_assignment_as_workspace(self):
        directory = Path(__file__).parent / ("scratch-telemetry-" + uuid4().hex)
        directory.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree, directory)
        group = "/subscriptions/test/resourceGroups/demo-platform"
        workspace = group + "/providers/Microsoft.OperationalInsights/workspaces/logs"
        assignment = workspace + "/providers/Microsoft.Authorization/roleAssignments/collector"
        native = Mock(spec=Native)
        native.rest.side_effect = lambda method, resource, api: (
            {"properties": {"customerId": "workspace-customer"}} if resource == workspace
            else self.fail("Only a workspace may be read with the workspace API")
        )
        native.telemetry.return_value = {"tables": [{"name": "PrimaryResult", "rows": []}]}
        lifecycle = SimpleNamespace(
            id="demo",
            config={"subscriptionId": "test", "publisherEmail": "test@example.test"},
            value={
                "inventory": [workspace, assignment], "active": [group],
                "created": datetime.now(timezone.utc).isoformat(),
                "software": "test-software", "phase": "deployed_unverified",
                "events": [], "runs": {}, "bootstrap": {}, "externalResources": [],
            },
            state=SimpleNamespace(directory=directory, save=Mock()),
            native=native, inventory=Mock(), credentials=Mock(),
        )
        with patch("citadel.operator.plan.observation_summary", return_value={"status": "blocked"}):
            result = Lifecycle.collect_with_deadline(lifecycle, time.monotonic() + 30)
        self.assertEqual(result["status"], "partial_evidence")
        native.rest.assert_called_once_with("get", workspace, "2022-10-01")
        self.assertEqual(native.telemetry.call_args.args, ("workspace-customer",))
