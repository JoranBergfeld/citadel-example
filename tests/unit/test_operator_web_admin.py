"""Private CLI lifecycle with a controlled Azure management transport."""

import io
import json
from pathlib import Path
import shutil
import unittest
from unittest.mock import patch
from uuid import uuid4

from citadel.operator import main
from citadel.operator.lifecycle import Lifecycle
from citadel.operator.native import Native
from citadel.operator.state import Blocked, State, read_private, write_private
from citadel.operator.web import hash_passphrase
from citadel.operator.web_admin import verify


ROOT = Path(__file__).resolve().parents[2]
SUBSCRIPTION = "/subscriptions/11111111-1111-4111-8111-111111111111"
GROUP = SUBSCRIPTION + "/resourceGroups/citadel-webtest-platform"
APP = GROUP + "/providers/Microsoft.App/containerApps/webtest-operator-web"


class Management:
    def __init__(self):
        self.calls = []
        self.status = "Running"
        self.app_document = {"id": APP, "type": "Microsoft.App/containerApps",
                         "tags": {"citadel-deployment": "webtest"}}

    def az(self, *args, **kwargs):
        self.calls.append(args)
        if args[:2] == ("group", "list"):
            return [{"id": GROUP, "name": "citadel-webtest-platform", "tags": self.app_document["tags"]}]
        if args[:2] == ("resource", "list"):
            return [self.app_document]
        if args[:3] == ("role", "assignment", "list"):
            return []
        if args[:3] == ("deployment", "sub", "create"):
            if self.status != "Stopped":
                raise AssertionError("Replacement attempted while old app is serving")
            self.parameters = read_private(args[args.index("--parameters") + 1][1:])
            return {"properties": {"provisioningState": "Succeeded"}}
        raise AssertionError("Unexpected management command")

    def document(self, value):
        return Native({"tools": {}}, self.directory).document(value)

    def rest(self, method, resource, api, body=None):
        self.calls.append((method, resource, api))
        if method == "post" and resource == APP + "/stop":
            self.status = "Stopped"
            return {}
        if method == "get" and resource == APP:
            return {**self.app_document, "properties": {
                **self.app_document.get("properties", {}), "runningStatus": self.status,
            }}
        raise AssertionError("Unexpected management effect")


class AdministrationTests(unittest.TestCase):
    def setUp(self):
        self.directory = ROOT / "tests/unit" / ("scratch-web-" + uuid4().hex)
        self.directory.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree, self.directory)
        self.state = self.directory / "state"
        self.config = self.directory / "config.json"
        write_private(self.config, {
            "deploymentId": "webtest", "subscriptionId": SUBSCRIPTION.split("/")[-1],
            "tenantId": "22222222-2222-4222-8222-222222222222",
            "publisherEmail": "test@example.test",
            "collectorPrincipalIds": ["33333333-3333-4333-8333-333333333333"],
            "location": "westeurope", "modelCapacity": 1, "modelTokensPerMinute": 1000,
            "createResourceGroups": True, "bundleDir": str(self.directory / "bundle"),
            "tools": {"azurePython": "/not-used"},
        })
        self.assertEqual(self.cli("init", "--config", str(self.config))[0], 0)
        value = read_private(self.state / "state.json")
        value["inventory"] = [GROUP, APP]
        value["outputs"] = {"operatorInventory": {"application": {"app": APP}}}
        write_private(self.state / "state.json", value)
        self.management = Management()
        self.management.directory = self.state

    def cli(self, *args, **kwargs):
        output = io.StringIO()
        code = main([*args, "--state-dir", str(self.state)], stdout=output, **kwargs)
        return code, output.getvalue()

    def test_setup_stops_existing_app_before_private_prompts_and_never_restarts_it(self):
        def prompt(label):
            self.assertEqual(self.management.status, "Stopped")
            return "test-user" if "username" in label else "labelled test passphrase"

        with patch("sys.stdin.isatty", return_value=True), patch("getpass.getpass", side_effect=prompt):
            code, output = self.cli("configure-web-login", adapter=self.management)
        self.assertEqual(code, 0, output)
        auth = read_private(self.state / "operator-web-auth.json")
        self.assertEqual(auth["username"], "test-user")
        self.assertNotIn("labelled test passphrase", json.dumps(auth))
        self.assertIn("$argon2id$", auth["passwordHash"])
        self.assertNotIn(auth["username"], output)
        self.assertNotIn(auth["passwordHash"], output)
        self.assertEqual(self.management.status, "Stopped")
        self.assertNotIn("/start", str(self.management.calls))
        self.assertEqual((self.state / "operator-web-auth.json").stat().st_mode & 0o777, 0o600)

    def test_invalid_replacement_leaves_no_old_configuration_or_running_app(self):
        write_private(self.state / "operator-web-auth.json", {"username": "old", "passwordHash": "old"})
        with patch("sys.stdin.isatty", return_value=True), patch("getpass.getpass", side_effect=["test", "too short", "too short"]):
            code, _ = self.cli("configure-web-login", adapter=self.management)
        self.assertEqual(code, 2)
        self.assertEqual(self.management.status, "Stopped")
        self.assertFalse((self.state / "operator-web-auth.json").exists())

    def test_foreign_app_is_never_stopped_or_reconfigured(self):
        self.management.app_document["tags"] = {"citadel-deployment": "foreign"}
        with patch("getpass.getpass") as prompt:
            code, _ = self.cli("configure-web-login", adapter=self.management)
        self.assertEqual(code, 2)
        prompt.assert_not_called()
        self.assertNotIn(("post", APP + "/stop", "2025-01-01"), self.management.calls)

    def test_foundation_secret_replacement_waits_for_stop_and_uses_private_parameters(self):
        auth = {"username": "labelled-test-user", "passwordHash": hash_passphrase("labelled test passphrase")}
        write_private(self.state / "operator-web-auth.json", auth)
        with State(self.state).locked() as state:
            lifecycle = Lifecycle(state, self.management)
            lifecycle.arm("create")
        self.assertEqual(self.management.parameters["parameters"]["operatorAuth"]["value"], auth)
        self.assertEqual(self.management.status, "Stopped")
        self.assertEqual(list(self.state.glob("request-*.json")), [])
        self.assertNotIn(auth["passwordHash"], str(self.management.calls))

    def test_unconfirmed_stop_denies_configuration_and_arm_replacement(self):
        transport = self.management.rest

        def delayed_stop(method, resource, api, body=None):
            if method == "post" and resource.endswith("/stop"):
                return {}
            return transport(method, resource, api, body)

        with State(self.state).locked() as state:
            lifecycle = Lifecycle(state, self.management)
            with patch.object(self.management, "rest", side_effect=delayed_stop), patch(
                "citadel.operator.web_admin.time.monotonic", side_effect=[0, 121],
            ):
                with self.assertRaisesRegex(Blocked, "operator_web_stop_not_confirmed"):
                    lifecycle.arm("create")
        self.assertFalse(any(call[:2] == ("deployment", "sub") for call in self.management.calls))
        self.assertFalse((self.state / "operator-web-auth.json").exists())

    def test_deployed_operator_rejects_scaling_and_extra_authority(self):
        identity = GROUP + "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/webtest-operator-web"
        image = "test.azurecr.io/runtime@sha256:" + "a" * 64
        value = read_private(self.state / "state.json")
        value["outputs"]["operatorInventory"].update({
            "foundation": {"identity": identity, "clientId": "11111111-1111-4111-8111-111111111111"},
            "origin": "https://operator.test",
            "accounting": {"resources": [], "assignments": []},
            "accountingBlobUrl": "https://observe.blob.core.windows.net",
        })
        value["outputs"]["gatewayUrl"] = "https://gateway.test"
        value["outputs"]["operatorInventory"]["application"]["image"] = image
        value["outputs"]["appInventory"] = [{"identity": GROUP + f"/team-{i}"} for i in range(5)]
        write_private(self.state / "state.json", value)
        self.management.app_document.update({
            "identity": {"userAssignedIdentities": {identity: {}}},
            "properties": {
                "provisioningState": "Succeeded",
                "configuration": {"activeRevisionsMode": "Single", "ingress": {
                    "allowInsecure": False, "external": True, "fqdn": "operator.test", "targetPort": 8000,
                }},
                "template": {"scale": {"minReplicas": 1, "maxReplicas": 1}, "containers": [{
                    "name": "operator-web", "image": image,
                    "command": ["python", "-m", "citadel.operator.web"], "args": [],
                    "env": [
                        {"name": "AZURE_CLIENT_ID", "value": "11111111-1111-4111-8111-111111111111"},
                        {"name": "CITADEL_DEPLOYMENT_ID", "value": "webtest"},
                        {"name": "CITADEL_GATEWAY_URL", "value": "https://gateway.test"},
                        {"name": "CITADEL_OBSERVATION_BLOB_URL", "value": "https://observe.blob.core.windows.net"},
                        {"name": "CITADEL_OPERATOR_SUBSCRIPTION", "secretRef": "operator-subscription"},
                        {"name": "CITADEL_OPERATOR_USERNAME", "secretRef": "operator-username"},
                        {"name": "CITADEL_OPERATOR_PASSWORD_HASH", "secretRef": "operator-password-hash"},
                        {"name": "CITADEL_OPERATOR_ORIGIN", "value": "https://operator.test"},
                    ],
                }]},
            },
        })
        with State(self.state).locked() as state:
            lifecycle = Lifecycle(state, self.management)
            verify(lifecycle)
            template = self.management.app_document["properties"]["template"]
            template["scale"]["maxReplicas"] = 2
            with self.assertRaises(Blocked):
                verify(lifecycle)
            template["scale"]["maxReplicas"] = 1
            template["containers"][0]["env"].append({"name": "CITADEL_BLOB_URL", "value": "not permitted"})
            with self.assertRaises(Blocked):
                verify(lifecycle)
