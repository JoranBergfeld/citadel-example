import copy
from contextlib import contextmanager
import json
import os
from pathlib import Path
import unittest

from citadel.evidence.preparation import prepare_bundle
from citadel.operator.native import Native
from citadel.operator.state import Blocked
import test_cli


class AzureFixture:
    """Strict native Azure/Docker protocol fixture; no private lifecycle calls."""
    def __init__(self, config, directory):
        self.config, self.directory = config, directory
        self.calls, self.parameters, self.blobs = [], [], {}
        self.groups, self.resources = [], {}
        self.fail_delete = None
        self.false_success = False
        self.subscription = "/subscriptions/" + config["subscriptionId"]
        self.root = self.subscription + "/resourceGroups/citadel-test19-"
        self.platform = self.root + "platform/providers/"
        self.registry = self.platform + "Microsoft.ContainerRegistry/registries/actualcreated"
        self.workspace = self.platform + "Microsoft.OperationalInsights/workspaces/citadel-test19-logs"
        self.center = self.platform + "Microsoft.ApiCenter/services/inventory"
        self.gateway = "https://actual-gateway.azure-api.net"
        self.outputs = {
            "inventory": {"deploymentId": "test19", "platform": {"resources": [self.registry, self.center, self.workspace]},
                          "capabilities": {"service": self.center, "workspace": self.center + "/workspaces/default",
                                           "restCapabilities": [self.center + "/workspaces/default/apis/released-findings",
                                                                self.center + "/workspaces/default/apis/released-findings/deployments/gateway"]},
                          "gateway": {"subscriptions": []}},
            "teamInventory": [
                {"resources": {"team": t, "resources": [self.root + t +
                    "/providers/Microsoft.Storage/storageAccounts/" + t + "fixture"]}}
                for t in ("reference", "evidence", "planning")],
            "appInventory": [], "gatewayUrl": self.gateway,
        }
        self.environments = []
        self.app_documents = {}

    @contextmanager
    def document(self, value):
        with Native(self.config, self.directory).document(value) as path:
            yield path

    def verify_plan_read_contract(self):
        # Exercise downstream command contracts, not actual Free-plan proof.
        return None

    def run(self, args, **kwargs):
        self.calls.append(tuple(args))
        if args[0] in ("uv", "azd", "bicep") and args[-1] == ("version" if args[0] == "azd" else "--version"):
            return {"uv": "uv 0.12.21", "azd": "azd version 1.35.1",
                    "bicep": "Bicep CLI version 0.48.1 (fixture)"}[args[0]]
        if args[:2] == ["bicep", "build"]:
            self.bicep_path = args[2]
            return '{"parameters":{}}'
        if args[0] == "docker":
            if args[1] == "info":
                return "linux/x86_64"
            if args[1:3] == ["image", "inspect"]:
                if args[3:5] == ["--format", "{{.Id}}"]:
                    return "sha256:" + "b" * 64
                return '["actualcreated.azurecr.io/citadel/runtime@sha256:' + "a" * 64 + '"]'
            return ""
        raise AssertionError("Unexpected process command " + str(args[:2]))

    def az(self, *args, **kwargs):
        self.calls.append(args)
        if args == ("version",):
            return {"azure-cli": "2.91.0"}
        if args[:2] == ("account", "show"):
            return {"id": self.config["subscriptionId"], "tenantId": self.config["tenantId"], "state": "Enabled"}
        if args[:2] == ("group", "list"):
            return copy.deepcopy(self.groups)
        if args[:2] == ("provider", "list"):
            return [{"namespace": name, "registrationState": "Registered"} for name in (
                "Microsoft.Resources", "Microsoft.Authorization", "Microsoft.App", "Microsoft.ManagedIdentity",
                "Microsoft.ContainerRegistry", "Microsoft.Storage", "Microsoft.KeyVault", "Microsoft.ApiManagement",
                "Microsoft.CognitiveServices", "Microsoft.ApiCenter", "Microsoft.Insights", "Microsoft.OperationalInsights")]
        if args[:3] == ("policy", "assignment", "list"):
            return []
        if args[:3] == ("cognitiveservices", "model", "list"):
            return [{"model": {"name": "gpt-4.1-mini", "version": "2025-04-14"}, "skus": [{
                "name": "Standard", "rateLimits": [{"key": "token", "count": 1000, "renewalPeriod": 60}]}]}]
        if args[:3] == ("cognitiveservices", "usage", "list"):
            return [{"name": {"value": "OpenAI.Standard.gpt-4.1-mini"}, "currentValue": 0, "limit": 120}]
        if args[:3] == ("deployment", "sub", "list"):
            return []
        if args[:2] == ("deployment", "sub"):
            values = json.loads(Path(args[args.index("--parameters") + 1][1:]).read_text())["parameters"]
            params = {k: v["value"] for k, v in values.items()}
            self.parameters.append((args[2], copy.deepcopy(params)))
            if args[2] == "create":
                if self.false_success:
                    return {"properties": {"provisioningState": "Succeeded", "outputs": {}}}
                self.groups = [{"name": "citadel-test19-" + t, "id": self.root + t,
                                "tags": {"citadel-deployment": "test19"}} for t in (
                                    "platform", "reference", "evidence", "planning")]
                self.outputs["inventory"]["groups"] = [g["id"] for g in self.groups]
                if params["deployRuntime"]:
                    self.runtime(params)
                for group in self.groups:
                    self.resources.setdefault(group["name"], [])
                result = {k: {"value": copy.deepcopy(v)} for k, v in self.outputs.items()}
                return {"properties": {"provisioningState": "Succeeded", "outputs": result}}
            return {"properties": {"provisioningState": "Succeeded"}}
        if args[:2] == ("acr", "login"):
            return {"accessToken": "fixture-never-print"}
        if args[:3] == ("acr", "repository", "show"):
            return {"digest": "sha256:" + "a" * 64}
        if args[:3] == ("acr", "repository", "update"):
            return {"changeableAttributes": {"writeEnabled": False, "deleteEnabled": False}}
        if args[:3] == ("acr", "repository", "show-tags"):
            return []
        if args[:3] == ("acr", "repository", "list"):
            return []
        if args[:2] == ("resource", "list"):
            return self.resources[args[args.index("--resource-group") + 1]]
        if args[:3] == ("role", "assignment", "list"):
            return []
        if args[:2] == ("group", "delete"):
            name = args[args.index("--name") + 1]
            if name == self.fail_delete:
                raise Blocked("azure_command_failed")
            self.groups = [g for g in self.groups if g["name"] != name]
            return None
        if args[:2] == ("keyvault", "list-deleted"):
            return []
        if args[:4] == ("monitor", "log-analytics", "workspace", "list-deleted-workspaces"):
            return []
        raise AssertionError("Unexpected Azure command " + str(args[:3]))

    def runtime(self, params):
        self.outputs["appInventory"] = []
        self.environments = []
        teams = {"reference-data": "reference", "evidence-assessor": "evidence", "release-reviewer": "evidence",
                 "candidate-planner": "planning", "briefing-author": "planning"}
        for name, app in params["applications"].items():
            prefix = self.root + teams[name] + "/providers/"
            aid = prefix + "Microsoft.App/containerApps/test19-" + name
            identity = prefix + "Microsoft.ManagedIdentity/userAssignedIdentities/test19-" + name
            self.outputs["appInventory"].append({"app": aid, "identity": identity, "image": app["image"]})
            self.environments.append({"name": name, "properties": {"customProperties": {
                "workload": aid, "identity-resource-id": identity,
                "gateway-address": self.gateway + "/" + name + ("/mcp" if name == "reference-data" else "/a2a"),
                "protocol": "MCP" if name == "reference-data" else "A2A",
                "protocol-version": "2025-11-25" if name == "reference-data" else "1.0.0",
                "team": {"reference": "Reference Data", "evidence": "Evidence Review", "planning": "Exercise Planning"}[teams[name]],
                "identity-kind": "Azure user-assigned managed identity; not Entra Agent ID"},
                "kind": "testing", "server": {"type": "Azure compute service"}}})
            self.app_documents[aid] = {"identity": {"userAssignedIdentities": {identity: {}}},
                "properties": {"provisioningState": "Succeeded", "template": {"containers": [{
                    "image": app["image"], "command": app["command"], "args": app["args"],
                    "env": [{"name": "CITADEL_TARGET", "value": name},
                            {"name": "CITADEL_MODEL_TOKENS_PER_MINUTE", "value": str(app["modelTokensPerMinute"])}]}]}}}

    def collection(self, resource, api):
        self.calls.append(("collection", resource, api))
        if resource.endswith("/permissions"):
            return [{"actions": ["*"], "dataActions": ["*"]}]
        if resource.endswith("/environments"):
            return self.environments
        raise AssertionError("Unexpected collection")

    def rest(self, method, resource, api, body=None):
        self.calls.append(("rest", method, resource, api))
        if resource == self.center:
            return {"properties": {"provisioningState": "Succeeded"}}
        if resource == self.workspace:
            return {"properties": {"customerId": "fixture-workspace"}}
        if resource.endswith("/apis/released-findings"):
            return {"properties": {"kind": "rest"}}
        if resource.endswith("/apis/released-findings/deployments/gateway"):
            return {"properties": {"environmentId": "/workspaces/default/environments/release-reviewer",
                                    "server": {"runtimeUri": [self.gateway + "/release-reviewer"]}}}
        if resource in self.app_documents:
            return self.app_documents[resource]
        raise AssertionError("Unexpected REST resource")

    def blob_read(self, account, container, name):
        return self.blobs.get((account, container, name))

    def blob_create(self, account, container, name, content):
        key = account, container, name
        if key in self.blobs:
            raise AssertionError("Attempt to overwrite existing state")
        self.blobs[key] = content

    def telemetry(self, workspace, **kwargs):
        return {"tables": [{"name": "PrimaryResult", "columns": [], "rows": []}]}


@unittest.skipUnless(os.environ.get("CITADEL_EVIDENCE_DATA"), "retained exact source required")
class DeploymentTests(test_cli.CliCase):
    def setUp(self):
        super().setUp()
        prepare_bundle(os.environ["CITADEL_EVIDENCE_DATA"], self.values["bundleDir"])
        self.assertEqual(self.cli("init", "--config", str(self.config), "--state-dir", str(self.state))[0], 0)
        self.fixture = AzureFixture(self.values, self.state)

    def deploy(self):
        return self.cli("deploy", "--state-dir", str(self.state), "--confirm-paid", adapter=self.fixture)

    def assert_deployed_blocked_on_plan(self):
        code, report = self.deploy()
        self.assertEqual((code, report.get("code")), (2, "api_center_plan_read_contract_unresolved"), report)

    def test_foundation_actual_created_registry_digest_runtime_and_fifteen_bootstrap_objects(self):
        code, result = self.deploy()
        self.assertEqual((code, result["code"]), (2, "api_center_plan_read_contract_unresolved"))
        creates = [p for action, p in self.fixture.parameters if action == "create"]
        self.assertFalse(creates[0]["deployRuntime"])
        self.assertTrue(creates[1]["deployRuntime"])
        self.assertEqual(len(creates[1]["applications"]), 5)
        for application in creates[1]["applications"].values():
            self.assertEqual(application["image"], "actualcreated.azurecr.io/citadel/runtime@sha256:" + "a" * 64)
            self.assertEqual(application["command"], ["python", "-m", "citadel.runtime"])
            self.assertEqual(application["modelTokensPerMinute"], 1000)
        self.assertEqual(len(self.fixture.blobs), 15)
        self.assertEqual(sum(k[2] == "ledger-v1.json" for k in self.fixture.blobs), 6)
        self.assertTrue(self.fixture.bicep_path.endswith("/infra/main.bicep"))
        self.assertNotIn(self.values["subscriptionId"], json.dumps(result))

    def test_same_identity_repair_preserves_live_ledgers_and_reconciles_foundation(self):
        self.assert_deployed_blocked_on_plan()
        key = next(k for k in self.fixture.blobs if k[1] == "planner-operations" and k[2] == "ledger-v1.json")
        ledger = json.loads(self.fixture.blobs[key])
        ledger["operations"]["live-fixture"] = {"state": "running"}
        changed = json.dumps(ledger).encode()
        self.fixture.blobs[key] = changed
        self.assert_deployed_blocked_on_plan()
        self.assertEqual(self.fixture.blobs[key], changed)
        creates = [p for action, p in self.fixture.parameters if action == "create"]
        self.assertEqual(len(creates), 4, "repair must really reconcile foundation, not skip it")

    def test_nominal_arm_success_without_outputs_is_not_deployment_success(self):
        self.fixture.false_success = True
        code, result = self.deploy()
        self.assertEqual((code, result["code"]), (2, "deployment_inventory_outputs_missing"))
        self.assertEqual(self.fixture.blobs, {})

    def test_missing_preinitialized_live_state_is_never_reset_on_repair(self):
        self.assert_deployed_blocked_on_plan()
        key = next(k for k in self.fixture.blobs if k[2] == "active-run-slot.json")
        del self.fixture.blobs[key]
        code, result = self.deploy()
        self.assertEqual((code, result["code"]), (2, "existing_identity_bootstrap_state_missing"))
        self.assertNotIn(key, self.fixture.blobs)

    def test_manual_teardown_reports_partial_failure_and_preserves_foreign_resources(self):
        self.assert_deployed_blocked_on_plan()
        self.fixture.fail_delete = "citadel-test19-evidence"
        code, result = self.cli("teardown", "--state-dir", str(self.state),
            "--confirm-deployment", "test19", adapter=self.fixture)
        self.assertEqual(code, 1, result)
        self.assertEqual(result["failedDeletions"], ["evidence"])
        self.assertGreater(result["activeCount"], 0)
        self.assertTrue((self.state / "evidence.json").is_file())
        self.assertTrue((self.state / "evidence.md").read_text().startswith("# Citadel lifecycle evidence"))

    def test_new_foreign_resource_prevents_group_deletion(self):
        self.assert_deployed_blocked_on_plan()
        group = "citadel-test19-planning"
        self.fixture.resources[group] = [{"id": self.fixture.root +
            "planning/providers/Microsoft.Storage/storageAccounts/unrelated", "tags": {}}]
        code, result = self.cli("teardown", "--state-dir", str(self.state),
            "--confirm-deployment", "test19", adapter=self.fixture)
        self.assertEqual((code, result["code"]), (2, "unrelated_resource_protection"))
        self.assertFalse(any(c[:2] == ("group", "delete") for c in self.fixture.calls))

    def test_read_only_contributor_permissions_never_assume_role_assignment(self):
        original = self.fixture.collection
        def permission(resource, api):
            if resource.endswith("/permissions"):
                return [{"actions": ["Microsoft.Resources/*", "Microsoft.Storage/*", "Microsoft.KeyVault/*"],
                         "dataActions": ["Microsoft.Storage/*"]}]
            return original(resource, api)
        self.fixture.collection = permission
        code, result = self.deploy()
        self.assertEqual((code, result["code"]), (2, "scoped_deployment_role_or_identity_permissions_missing"))
        self.assertEqual(self.fixture.parameters, [])

    def test_existing_image_tag_without_owned_push_state_cannot_be_overwritten(self):
        original = self.fixture.az
        def existing(*args, **kwargs):
            if args[:3] == ("acr", "repository", "list"):
                return ["citadel/runtime"]
            if args[:3] == ("acr", "repository", "show-tags"):
                state = json.loads((self.state / "state.json").read_text())
                return [state["software"][:24]]
            return original(*args, **kwargs)
        self.fixture.az = existing
        code, result = self.deploy()
        self.assertEqual((code, result["code"]), (2, "unrecorded_registry_tag_conflict"))
        self.assertFalse(any(c[:2] == ("docker", "build") for c in self.fixture.calls))

    def test_staged_operator_key_rotation_preserves_old_key_until_live_proof(self):
        self.assert_deployed_blocked_on_plan()
        original = json.loads((self.state / "credentials.json").read_text())
        args = ("rotate", "subscription", "--target", "operator", "--stage", "prepare",
                "--state-dir", str(self.state))
        code, report = self.cli(*args, adapter=self.fixture)
        self.assertEqual(code, 0, report)
        pending = json.loads((self.state / "rotation.json").read_text())
        current = json.loads((self.state / "credentials.json").read_text())
        self.assertTrue(pending["old"]["callerKeys"]["operator"] == original["callerKeys"]["operator"])
        self.assertTrue(current["callerKeys"]["operator"]["secondary"] == original["callerKeys"]["operator"]["primary"])
        self.assertTrue(current["callerKeys"]["operator"]["primary"] != original["callerKeys"]["operator"]["primary"])
        self.assertEqual(self.cli(*args, adapter=self.fixture)[0], 0)
        code, report = self.cli("rotate", "subscription", "--target", "operator", "--stage", "finalize",
                                "--state-dir", str(self.state), adapter=self.fixture)
        self.assertEqual((code, report["code"]), (2, "task20_acceptance_harness_required"))

    def test_production_plan_gate_stops_before_target_lookup_and_any_paid_effect(self):
        self.fixture.verify_plan_read_contract = Native(self.values, self.state).verify_plan_read_contract
        code, report = self.deploy()
        self.assertEqual((code, report["code"]), (2, "api_center_plan_read_contract_unresolved"))
        self.assertFalse(any(c[:2] in (("account", "show"), ("deployment", "sub")) for c in self.fixture.calls))

    def test_missing_native_protocol_metadata_never_passes_inventory_validation(self):
        original = self.fixture.runtime
        def incomplete(params):
            original(params)
            self.fixture.environments[0]["properties"]["customProperties"].pop("protocol")
        self.fixture.runtime = incomplete
        code, report = self.deploy()
        self.assertEqual((code, report["code"]), (2, "api_center_identity_or_gateway_metadata_mismatch"))
