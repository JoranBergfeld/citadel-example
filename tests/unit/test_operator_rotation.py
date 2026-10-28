"""Separate Operator application allocation; no management or gateway calls leave fixtures."""

import hashlib
import time
from types import SimpleNamespace
import unittest

import httpx

from citadel.acceptance.rotation_harness import capture_retired_secret
from citadel.acceptance.rotation_controls import rotation_read
from citadel.operator.rotation import restart
from citadel.operator.state import Blocked


class OperatorRotationTests(unittest.TestCase):
    def setUp(self):
        self.subscription = "/subscriptions/test"
        self.group = self.subscription + "/resourceGroups/citadel-fixture-platform"
        self.app = self.group + "/providers/Microsoft.App/containerApps/fixture-operator-web"
        self.secret = self.group + "/providers/Microsoft.KeyVault/vaults/fixturevault/secrets/subscription-operator-web"
        self.uri = "https://fixturevault.vault.azure.net/secrets/subscription-operator-web/" + "a" * 32
        self.calls, self.status = [], "Running"
        self.lifecycle = SimpleNamespace(
            id="fixture", subscription=self.subscription, groups={"platform": "citadel-fixture-platform"},
            config={"subscriptionId": "test"}, inventory=lambda: None,
            state=SimpleNamespace(event=lambda *args: None),
            value={"inventory": [self.app, self.secret],
                   "outputs": {"appInventory": [], "operatorInventory": {
                       "application": {"app": self.app}, "foundation": {"secrets": [self.secret]}}}},
            native=SimpleNamespace(rest=self.rest, az=self.az))

    def rest(self, method, resource, api, body=None):
        self.calls.append((method, resource))
        if resource == self.app:
            return {"tags": {"citadel-deployment": "fixture"}, "properties": {
                "runningStatus": self.status, "template": {"containers": [{"env": []}]},
                "configuration": {"secrets": [
                    {"name": "operator-subscription", "keyVaultUrl": self.uri}]}}}
        if resource == self.app + "/stop":
            self.status = "Stopped"
        elif resource == self.app + "/start":
            if self.status != "Stopped":
                raise AssertionError("Overlapping Operator replacement")
            self.status = "Running"
        else:
            raise AssertionError("Unallocated management effect")

    def az(self, *args):
        self.calls.append(args)
        if args[:3] != ("keyvault", "secret", "show"):
            raise AssertionError("Unexpected secret operation")
        return {"id": self.uri, "value": "fixture-key"}

    def test_operator_retired_secret_uses_separate_exact_allocated_version(self):
        result = capture_retired_secret(self.lifecycle, "subscription", "operator-web",
            {"callerKeys": {"operator-web": {"primary": "fixture-key"}}})
        self.assertEqual(result, self.uri)
        self.assertIn("--version", self.calls[-1])
        self.assertEqual(self.calls[-1][-1], "a" * 32)

    def test_operator_restart_confirms_stop_before_start_without_team_revision_restart(self):
        restart(self.lifecycle, "operator-web")
        self.assertIn(("post", self.app + "/stop"), self.calls)
        self.assertIn(("post", self.app + "/start"), self.calls)
        self.assertLess(self.calls.index(("post", self.app + "/stop")),
                        self.calls.index(("post", self.app + "/start")))

    def test_foreign_or_unversioned_secret_allocation_cannot_supply_retired_material(self):
        for uri in (self.uri.replace("fixturevault", "foreign"),
                    self.uri.rsplit("/", 1)[0], self.uri + "?version=latest"):
            with self.subTest(uri=uri):
                original, self.uri = self.uri, uri
                with self.assertRaises(Blocked):
                    capture_retired_secret(self.lifecycle, "subscription", "operator-web",
                        {"callerKeys": {"operator-web": {"primary": "fixture-key"}}})
                self.uri = original
                self.assertFalse(any(call[:3] == ("keyvault", "secret", "show") for call in self.calls))


class OperatorRotationControlTests(unittest.IsolatedAsyncioTestCase):
    async def test_control_uses_only_operator_observation_not_workload_discovery(self):
        dispatched, charges = [], []

        async def service(request):
            dispatched.append(request)
            return httpx.Response(200, json={"state": "empty", "runs": [], "next_cursor": None})

        async def admit():
            charges.append(1)

        control = {"kind": "subscription", "target": "candidate-planner",
                   "credential_sha256": hashlib.sha256(b"fixture-key").hexdigest(),
                   "secret_version": None, "projection": "run-list"}
        async with httpx.AsyncClient(transport=httpx.MockTransport(service)) as client:
            row = await rotation_read(workload="operator-web", gateway="https://gateway.test",
                key="fixture-key", request={"rotation": control, "deadline": time.time() + 30,
                    "run_id": "rotation1"}, client=client, admit=admit)
        self.assertEqual(dispatched[0].url.path, "/candidate-planner/operator/runs")
        self.assertEqual(row["actual"], "read_only_control")
        self.assertEqual(charges, [1])
        self.assertNotIn("runtime_identity", row)

    async def test_control_cannot_expand_operator_authority_or_treat_retired_key_as_allowed(self):
        dispatched = []

        async def service(request):
            dispatched.append(request)
            return httpx.Response(401)

        async def admit():
            return None

        control = {"kind": "subscription", "target": "candidate-planner",
                   "credential_sha256": hashlib.sha256(b"fixture-key").hexdigest(),
                   "secret_version": "a" * 32, "projection": "run-list"}
        async with httpx.AsyncClient(transport=httpx.MockTransport(service)) as client:
            for change in ({"target": "release-reviewer"}, {"kind": "context"}, {"projection": "discovery"}):
                with self.subTest(change=change), self.assertRaises(ValueError):
                    await rotation_read(workload="operator-web", gateway="https://gateway.test",
                        key="fixture-key", request={"rotation": {**control, **change},
                            "deadline": time.time() + 30, "run_id": "rotation1"},
                        client=client, admit=admit)
            self.assertEqual(dispatched, [])
            row = await rotation_read(workload="operator-web", gateway="https://gateway.test",
                key="fixture-key", request={"rotation": control, "deadline": time.time() + 30,
                    "run_id": "rotation1"}, client=client, admit=admit)
        self.assertEqual(row["status_code"], 401)
        self.assertEqual(row["actual"], "unverified_response")
