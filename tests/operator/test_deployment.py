import copy
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import UUID

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
        self.fail_after_center_create = False
        self.subscription = "/subscriptions/" + config["subscriptionId"]
        self.root = self.subscription + "/resourceGroups/citadel-test19-"
        self.platform = self.root + "platform/providers/"
        self.registry = self.platform + "Microsoft.ContainerRegistry/registries/actualcreated"
        self.workspace = self.platform + "Microsoft.OperationalInsights/workspaces/citadel-test19-logs"
        self.center = self.platform + "Microsoft.ApiCenter/services/citadel-test19-inventory"
        self.vaults = {self.root + team + "/providers/Microsoft.KeyVault/vaults/" + team + "vault": {
            "properties": {"enableRbacAuthorization": True, "enableSoftDelete": True,
                           "softDeleteRetentionInDays": 7}}
            for team in ("platform", "reference", "evidence", "planning")}
        self.center_created = "2026-01-01T00:00:00Z"
        self.gateway = "https://actual-gateway.azure-api.net"
        self.outputs = {
            "inventory": {"deploymentId": "test19", "platform": {"resources": [
                              self.registry, self.center, self.workspace, next(iter(self.vaults))]},
                          "capabilities": {"service": self.center, "workspace": self.center + "/workspaces/default",
                                           "restCapabilities": [self.center + "/workspaces/default/apis/released-findings",
                                                                self.center + "/workspaces/default/apis/released-findings/deployments/gateway"]},
                          "gateway": {"subscriptions": []}},
            "teamInventory": [
                {"resources": {"team": t, "resources": [
                    self.root + t + "/providers/Microsoft.KeyVault/vaults/" + t + "vault",
                    self.root + t +
                    "/providers/Microsoft.Storage/storageAccounts/" + t + "fixture", *[
                        self.root + t + "/providers/Microsoft.Storage/storageAccounts/" + t
                        + "fixture/blobServices/default/containers/" + container for container in {
                            "reference": ("reference",),
                            "evidence": ("drafts", "findings", "assessor-operations", "reviewer-operations"),
                            "planning": ("candidate-lists", "briefs", "planner-operations", "author-operations"),
                        }[t]]]}}
                for t in ("reference", "evidence", "planning")],
            "appInventory": [], "gatewayUrl": self.gateway,
        }
        self.environments = []
        self.app_documents = {}

    @contextmanager
    def document(self, value):
        with Native(self.config, self.directory).document(value) as path:
            yield path

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
                "Microsoft.CognitiveServices", "Microsoft.ApiCenter", "microsoft.insights", "Microsoft.OperationalInsights")]
        if args[:3] == ("policy", "assignment", "list"):
            return []
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
                else:
                    self.outputs["appInventory"] = []
                    self.outputs["inventory"]["capabilities"] = {"state": "not_configured"}
                for group in self.groups:
                    self.resources.setdefault(group["name"], [])
                center_exists = any(row["id"] == self.center for row in
                                    self.resources["citadel-test19-platform"])
                if params.get("createApiCenter", True) and center_exists:
                    raise Blocked("api_center_update_requires_undocumented_sku")
                if not center_exists:
                    self.resources["citadel-test19-platform"].append({
                        "id": self.center, "type": "Microsoft.ApiCenter/services",
                        "tags": {"citadel-deployment": "test19"}})
                if self.fail_after_center_create:
                    self.fail_after_center_create = False
                    raise Blocked("azure_command_failed")
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
        self.outputs["inventory"]["capabilities"] = {
            "service": self.center, "workspace": self.center + "/workspaces/default",
            "restCapabilities": [self.center + "/workspaces/default/apis/released-findings",
                                 self.center + "/workspaces/default/apis/released-findings/deployments/gateway"]}
        self.outputs["appInventory"] = []
        self.environments = []
        teams = {"reference-data": "reference", "evidence-assessor": "evidence", "release-reviewer": "evidence",
                 "candidate-planner": "planning", "briefing-author": "planning"}
        for name, app in params["applications"].items():
            prefix = self.root + teams[name] + "/providers/"
            aid = prefix + "Microsoft.App/containerApps/test19-" + name
            identity = prefix + "Microsoft.ManagedIdentity/userAssignedIdentities/test19-" + name
            principal, client = str(UUID(int=len(self.environments) + 1)), str(UUID(int=len(self.environments) + 11))
            self.outputs["appInventory"].append({"app": aid, "identity": identity, "image": app["image"],
                                                 "identityPrincipalId": principal, "identityClientId": client})
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
                            {"name": "AZURE_PRINCIPAL_ID", "value": principal},
                            {"name": "AZURE_CLIENT_ID", "value": client},
                            {"name": "CITADEL_MODEL_TOKENS_PER_MINUTE", "value": str(app["modelTokensPerMinute"])}]}]}}}

    def collection(self, resource, api):
        self.calls.append(("collection", resource, api))
        if resource.endswith("/permissions"):
            return [{"actions": ["*"], "dataActions": ["*"]}]
        if resource.endswith("/environments"):
            return self.environments
        if resource.endswith("/locations/westeurope/models"):
            return [{"kind": "OpenAI", "model": {
                "name": "gpt-4.1-mini", "version": "2025-04-14", "skus": [{
                    "name": "Standard", "usageName": "OpenAI.Standard.gpt4.1-mini",
                    "rateLimits": [{"key": "request", "count": 1, "renewalPeriod": 60},
                                   {"key": "token", "count": 1000, "renewalPeriod": 60}]}]}}]
        if resource.endswith("/locations/westeurope/usages"):
            return [{"name": {"value": "OpenAI.Standard.gpt4.1-mini"}, "currentValue": 0, "limit": 120}]
        raise AssertionError("Unexpected collection")

    def rest(self, method, resource, api, body=None):
        self.calls.append(("rest", method, resource, api))
        if resource in self.vaults:
            return copy.deepcopy(self.vaults[resource])
        if resource == self.center:
            return {"id": self.center, "location": "westeurope",
                    "tags": {"citadel-deployment": "test19"},
                    "systemData": {"createdAt": self.center_created},
                    "properties": {"provisioningState": "Succeeded"}}
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

    def test_preflight_uses_pinned_raw_model_catalog_and_sku_usage_name(self):
        code, report = self.cli("preflight", "--state-dir", str(self.state), adapter=self.fixture)
        self.assertEqual((code, report.get("status")), (0, "preflight_pass"), report)
        for suffix in ("models", "usages"):
            self.assertIn(("collection", self.fixture.subscription
                + "/providers/Microsoft.CognitiveServices/locations/westeurope/" + suffix,
                "2024-10-01"), self.fixture.calls)

    def test_partial_foundation_retry_reuses_owned_api_center_without_skipping_portal_gate(self):
        self.fixture.fail_after_center_create = True
        code, report = self.deploy()
        self.assertEqual((code, report.get("code")), (2, "azure_command_failed"), report)
        self.assertTrue(next(params for action, params in self.fixture.parameters
                             if action == "create").get("createApiCenter", True))
        self.assertNotIn("outputs", json.loads((self.state / "state.json").read_text()))
        code, report = self.deploy()
        self.assertEqual((code, report.get("code")), (2, "api_center_portal_observation_required"), report)
        creates = [params for action, params in self.fixture.parameters if action == "create"]
        self.assertFalse(creates[-1]["createApiCenter"])
        self.assertFalse(any(params["deployRuntime"] for params in creates))
        self.assertEqual(self.fixture.blobs, {})

    def test_existing_api_center_conflicts_block_before_another_arm_request(self):
        self.fixture.fail_after_center_create = True
        self.assertEqual(self.deploy()[0], 2)
        requests = len(self.fixture.parameters)
        original = self.fixture.rest
        for change in (
            {"id": self.fixture.center + "-other"},
            {"tags": {"citadel-deployment": "other"}},
            {"location": "eastus"},
            {"properties": {"provisioningState": "Failed"}},
        ):
            with self.subTest(change=change):
                def changed(method, resource, api, body=None):
                    result = original(method, resource, api, body)
                    if resource == self.fixture.center:
                        result.update(change)
                    return result
                self.fixture.rest = changed
                code, report = self.deploy()
                self.assertEqual((code, report.get("code")),
                                 (2, "existing_api_center_configuration_conflict"), report)
                self.assertEqual(len(self.fixture.parameters), requests)
        self.fixture.rest = original

    def test_foundation_checks_actual_vault_flags_before_requesting_portal_observation(self):
        vault = next(iter(self.fixture.vaults.values()))["properties"]
        vault["enablePurgeProtection"] = True
        code, report = self.deploy()
        self.assertEqual((code, report.get("code")), (2, "vault_retention_or_authorization_conflict"), report)
        self.assertFalse((self.state / "api-center-plan-request.json").exists())
        vault["enablePurgeProtection"] = False
        code, report = self.deploy()
        self.assertEqual((code, report.get("code")), (2, "api_center_portal_observation_required"), report)

    def test_inventory_verifies_provider_alert_scope_even_after_it_is_known(self):
        self.assertEqual(self.deploy()[0], 2)
        component = self.fixture.platform + "Microsoft.Insights/components/owned"
        alert = self.fixture.platform + "Microsoft.AlertsManagement/smartDetectorAlertRules/generated"
        self.fixture.resources["citadel-test19-platform"] += [
            {"id": component, "type": "Microsoft.Insights/components",
             "tags": {"citadel-deployment": "test19"}},
            {"id": alert, "type": "microsoft.alertsmanagement/smartDetectorAlertRules"}]
        self.fixture.app_documents[alert] = {"id": alert, "properties": {
            "scope": [component], "detector": {"id": "FailureAnomaliesDetector"}}}
        code, report = self.cli("inventory", "--state-dir", str(self.state), adapter=self.fixture)
        self.assertEqual((code, report.get("status")), (0, "inventory"), report)
        self.assertIn(("rest", "get", alert, "2021-04-01"), self.fixture.calls)
        self.fixture.app_documents[alert]["properties"]["scope"].append(component + "-foreign")
        code, report = self.cli("inventory", "--state-dir", str(self.state), adapter=self.fixture)
        self.assertEqual((code, report.get("code")), (2, "provider_created_alert_ownership_conflict"), report)

    def record_observation(self, **changes):
        request = json.loads((self.state / "api-center-plan-request.json").read_text())
        evidence = self.directory / "portal-capture.txt"
        evidence.write_bytes(b"TEST FIXTURE ONLY: operator observed Free in the actual resource portal")
        evidence.chmod(0o600)
        observation = {k: request[k] for k in ("requestId", "deploymentId", "resourceId", "resourceCreatedAt")}
        observation.update(observedAt=datetime.now(timezone.utc).isoformat(), observedPlan="Free",
                           evidenceSha256=hashlib.sha256(evidence.read_bytes()).hexdigest())
        observation.update(changes)
        path = self.directory / "portal-observation.json"
        path.write_text(json.dumps(observation))
        path.chmod(0o600)
        return self.cli("record-plan-observation", "--state-dir", str(self.state),
                        "--observation", str(path), "--evidence", str(evidence), adapter=self.fixture)

    def test_matching_recorded_portal_evidence_allows_explicit_same_id_resume(self):
        self.assertEqual(self.deploy()[0], 2)
        before = len(self.fixture.parameters)
        code, report = self.record_observation()
        self.assertEqual((code, report.get("status")), (0, "api_center_free_observation_recorded"), report)
        self.assertEqual(len(self.fixture.parameters), before, "recording must not deploy automatically")
        for name in ("api-center-plan-proof.json", "api-center-plan-evidence.bin"):
            self.assertEqual((self.state / name).stat().st_mode & 0o777, 0o600)
        self.assertNotIn(self.values["subscriptionId"], json.dumps(report))
        self.assertNotIn(self.fixture.center, json.dumps(report))
        code, report = self.deploy()
        self.assertEqual((code, report.get("status")), (0, "deployed_unverified"), report)
        creates = [p for action, p in self.fixture.parameters if action == "create"]
        self.assertEqual([p["deployRuntime"] for p in creates], [False, False, True])
        self.assertEqual([p["createApiCenter"] for p in creates], [True, False, False])
        self.assertEqual(len(self.fixture.blobs), 15)

    def test_wrong_non_free_or_unbound_observations_never_unlock_runtime(self):
        self.assertEqual(self.deploy()[0], 2)
        for changes in (
            {"deploymentId": "another"},
            {"resourceId": self.fixture.center + "-foreign"},
            {"resourceCreatedAt": "2026-01-02T00:00:00+00:00"},
            {"requestId": "previous-request"},
            {"observedPlan": "Standard"},
            {"observedPlan": True},
            {"observedAt": "2025-01-01T00:00:00Z"},
            {"observedAt": "2099-01-01T00:00:00Z"},
            {"observedAt": "2026-01-01T00:00:00"},
            {"evidenceSha256": "0" * 64},
        ):
            with self.subTest(changes=changes):
                code, report = self.record_observation(**changes)
                self.assertEqual(code, 2, report)
        code, report = self.deploy()
        self.assertEqual((code, report.get("code")), (2, "api_center_portal_observation_required"))
        self.assertFalse(any(p["deployRuntime"] for _, p in self.fixture.parameters))

    def test_acceptance_provider_cannot_run_without_current_incarnation_proof(self):
        self.assertEqual(self.deploy()[0], 2)
        calls = []
        def acceptance(**kwargs):
            calls.append(kwargs["check_id"])
            return {"status": "pass", "run_id": kwargs["run_id"], "evidence_sha256": "f" * 64}
        args = ("acceptance", "--state-dir", str(self.state), "--run-id", "fixture-acceptance")
        with patch.dict(sys.modules, {"citadel.acceptance.operator_hooks": SimpleNamespace(run=acceptance)}):
            code, report = self.cli(*args, adapter=self.fixture)
            self.assertEqual((code, report.get("code")), (2, "api_center_portal_observation_required"), report)
            self.assertEqual(calls, [])
            self.assertEqual(self.record_observation()[0], 0)
            self.assertEqual(self.deploy()[0], 0)
            self.assertEqual(self.cli(*args, adapter=self.fixture)[0], 0)
            self.fixture.center_created = "2026-01-02T00:00:00Z"
            code, report = self.cli(*args, adapter=self.fixture)
            self.assertEqual((code, report.get("code")), (2, "api_center_portal_observation_required"))
            self.assertEqual(calls, ["full-acceptance"])
            self.assertEqual(self.deploy()[0], 2)
            self.assertEqual(self.record_observation()[0], 0)
            self.assertEqual(self.deploy()[0], 0)
            self.assertEqual(self.cli(*args, adapter=self.fixture)[0], 0)
            self.assertEqual(calls, ["full-acceptance", "full-acceptance"])

    def test_recreation_during_image_build_blocks_runtime_arm_activation(self):
        self.assertEqual(self.deploy()[0], 2)
        self.assertEqual(self.record_observation()[0], 0)
        original = self.fixture.run
        def recreate(args, **kwargs):
            result = original(args, **kwargs)
            if args[:2] == ["docker", "build"]:
                self.fixture.center_created = "2026-01-02T00:00:00Z"
            return result
        self.fixture.run = recreate
        code, report = self.deploy()
        self.assertEqual((code, report.get("code")), (2, "api_center_portal_observation_required"), report)
        self.assertFalse(any(p["deployRuntime"] for _, p in self.fixture.parameters),
                         "runtime validate/create must recheck the live incarnation immediately before ARM")

    def test_export_records_only_plan_evidence_hashes_not_private_capture_or_resource_id(self):
        self.observe_fixture_plan()
        code, result = self.cli("collect", "--state-dir", str(self.state), adapter=self.fixture)
        self.assertEqual(code, 0, result)
        report = json.loads((self.state / "evidence.json").read_text())
        self.assertEqual(report.get("apiCenterPlan", {}).get("status"), "human_observed_free")
        self.assertEqual(report["apiCenterPlan"]["evidenceSha256"],
                         hashlib.sha256((self.state / "api-center-plan-evidence.bin").read_bytes()).hexdigest())
        self.assertNotIn(self.values["subscriptionId"], json.dumps(report))
        self.assertNotIn("TEST FIXTURE ONLY", json.dumps(report))
        self.assertNotIn(self.fixture.center, json.dumps(report))

    def test_recreated_resource_rejects_prior_observation_even_with_same_arm_id(self):
        self.observe_fixture_plan()
        old = json.loads((self.state / "api-center-plan-request.json").read_text())
        self.fixture.center_created = "2026-01-02T00:00:00Z"
        code, report = self.cli("record-plan-observation", "--state-dir", str(self.state),
            "--observation", str(self.directory / "portal-observation.json"),
            "--evidence", str(self.directory / "portal-capture.txt"), adapter=self.fixture)
        self.assertEqual((code, report.get("code")), (2, "api_center_observation_resource_mismatch"))
        current = json.loads((self.state / "api-center-plan-request.json").read_text())
        self.assertEqual(current["resourceId"], old["resourceId"])
        self.assertNotEqual(current["requestId"], old["requestId"])
        self.assertNotEqual(current["resourceCreatedAt"], old["resourceCreatedAt"])
        self.assertEqual(self.deploy()[0], 2)
        self.assertFalse(any(p["deployRuntime"] for _, p in self.fixture.parameters))
        self.assertEqual(self.record_observation()[0], 0)
        self.assertEqual(self.deploy()[0], 0)

    def test_missing_or_changed_private_proof_cannot_activate_runtime(self):
        self.observe_fixture_plan()
        for filename in ("api-center-plan-proof.json", "api-center-plan-evidence.bin"):
            path = self.state / filename
            original = path.read_bytes()
            for problem in ("missing", "changed", "public"):
                with self.subTest(filename=filename, problem=problem):
                    if problem == "missing":
                        path.unlink()
                    elif problem == "changed":
                        path.write_bytes(b'{"status":"Free"}')
                    else:
                        path.chmod(0o644)
                    code, report = self.deploy()
                    self.assertEqual(code, 2, report)
                    self.assertFalse(any(p["deployRuntime"] for _, p in self.fixture.parameters))
                    path.write_bytes(original)
                    path.chmod(0o600)
        self.assertEqual(self.deploy()[0], 0)

    def test_non_free_reobservation_revokes_previous_free_gate(self):
        self.observe_fixture_plan()
        code, report = self.record_observation(observedPlan="Standard")
        self.assertEqual((code, report.get("code")), (2, "api_center_observed_plan_not_free"))
        code, report = self.deploy()
        self.assertEqual((code, report.get("code")), (2, "api_center_portal_observation_required"))
        self.assertFalse(any(p["deployRuntime"] for _, p in self.fixture.parameters))

    def test_missing_creation_identity_cannot_be_replaced_with_a_local_timestamp(self):
        self.fixture.center_created = None
        code, report = self.deploy()
        self.assertEqual((code, report.get("code")), (2, "api_center_creation_identity_unavailable"))
        self.assertFalse((self.state / "api-center-plan-request.json").exists())
        self.assertFalse(any(p["deployRuntime"] for _, p in self.fixture.parameters))

    def test_unobserved_partial_foundation_can_export_and_teardown_with_partial_failure(self):
        self.assertEqual(self.deploy()[0], 2)
        self.fixture.fail_delete = "citadel-test19-evidence"
        args = ("teardown", "--state-dir", str(self.state), "--confirm-deployment", "test19")
        code, report = self.cli(*args, adapter=self.fixture)
        self.assertEqual((code, report.get("status")), (1, "teardown_partial"), report)
        self.assertEqual(report["failedDeletions"], ["evidence"])
        exported = json.loads((self.state / "evidence.json").read_text())
        self.assertEqual(exported["apiCenterPlan"]["code"], "api_center_portal_observation_required")
        self.assertFalse((self.state / "api-center-plan-proof.json").exists())
        self.fixture.fail_delete = None
        code, report = self.cli(*args, adapter=self.fixture)
        self.assertEqual((code, report.get("status")), (0, "deleted_recoverable"), report)
        self.assertEqual(report["activeCount"], 0)

    def test_deployed_lifecycle_cannot_export_acceptance_inside_a_checkout(self):
        self.assert_deployed()
        code, report = self.cli("acceptance", "--state-dir", str(self.state), adapter=self.fixture)
        self.assertEqual((code, report.get("code")), (2, "evidence_directory_must_be_outside_vcs"))

    def observe_fixture_plan(self):
        code, report = self.deploy()
        self.assertEqual((code, report.get("code")), (2, "api_center_portal_observation_required"), report)
        code, report = self.record_observation()
        self.assertEqual(code, 0, report)

    def assert_deployed(self):
        if not (self.state / "api-center-plan-proof.json").exists():
            self.observe_fixture_plan()
        code, report = self.deploy()
        self.assertEqual((code, report.get("status")), (0, "deployed_unverified"), report)

    def test_inventory_acceptance_uses_actual_queried_documents_and_bound_private_plan(self):
        from citadel.acceptance.inventory import inventory_inputs, observe_inventory, CHECKS
        from citadel.acceptance.proof_gate import evaluate_check
        from citadel.evidence.manifests import sha256
        from citadel.operator.lifecycle import Lifecycle
        from citadel.operator.state import State
        self.assert_deployed()
        with State(self.state).locked() as state:
            lifecycle = Lifecycle(state, adapter=self.fixture)
            documents = lifecycle.verify_inventory()
            self.assertIsInstance(documents, dict)
            self.assertEqual(len(documents["applications"]), 5)
            self.assertEqual(documents["center"]["id"], self.fixture.center)
            expected = inventory_inputs(lifecycle)
            actual = observe_inventory(lifecycle, documents)
            report = {"evidence": [], "inventory_inputs": expected, "inputs": {"inventory": sha256(expected)},
                      "runtime_identities": {row["name"]: row["runtime_identity"] for row in expected["applications"]}}
            for identifier in CHECKS:
                check = {"check_id": identifier, "expected": "evidence", "actual": actual}
                self.assertEqual(evaluate_check(check, report)["status"], "pass")

    def test_acceptance_fingerprints_bind_each_business_container_to_its_actual_team_account(self):
        from citadel.acceptance.operator_hooks import fingerprints
        from citadel.operator.lifecycle import Lifecycle
        from citadel.operator.state import State
        self.assert_deployed()
        with State(self.state).locked() as state:
            lifecycle = Lifecycle(state, adapter=self.fixture)
            lifecycle.value["inventory"] += [
                self.fixture.platform + "Microsoft.Insights/components/insights",
                self.fixture.platform + "Microsoft.ApiManagement/service/gateway/diagnostics/applicationinsights",
                self.fixture.platform + "Microsoft.CognitiveServices/accounts/model/deployments/citadel-gpt-41-mini",
            ]
            proof = fingerprints(lifecycle)
            for container, team in (("planner-operations", "planning"), ("author-operations", "planning"),
                                    ("assessor-operations", "evidence"), ("reviewer-operations", "evidence"),
                                    ("drafts", "evidence"), ("findings", "evidence")):
                expected = "https://" + team + "fixture.blob.core.windows.net/" + container + "/ledger-v1.json"
                self.assertEqual(proof["storage_targets"][container], hashlib.sha256(expected.encode()).hexdigest())

    def test_foundation_actual_created_registry_digest_runtime_and_fifteen_bootstrap_objects(self):
        self.observe_fixture_plan()
        code, result = self.deploy()
        self.assertEqual((code, result["status"]), (0, "deployed_unverified"))
        creates = [p for action, p in self.fixture.parameters if action == "create"]
        self.assertFalse(creates[0]["deployRuntime"])
        self.assertFalse(creates[1]["deployRuntime"])
        self.assertTrue(creates[2]["deployRuntime"])
        self.assertEqual(len(creates[2]["applications"]), 5)
        for application in creates[2]["applications"].values():
            self.assertEqual(application["image"], "actualcreated.azurecr.io/citadel/runtime@sha256:" + "a" * 64)
            self.assertEqual(application["command"], ["python", "-m", "citadel.runtime"])
            self.assertEqual(application["modelTokensPerMinute"], 1000)
        self.assertEqual(len(self.fixture.blobs), 15)
        self.assertEqual(sum(k[2] == "ledger-v1.json" for k in self.fixture.blobs), 6)
        self.assertTrue(self.fixture.bicep_path.endswith("/infra/main.bicep"))
        self.assertNotIn(self.values["subscriptionId"], json.dumps(result))

    def test_same_identity_repair_preserves_live_ledgers_and_reconciles_foundation(self):
        self.assert_deployed()
        key = next(k for k in self.fixture.blobs if k[1] == "planner-operations" and k[2] == "ledger-v1.json")
        ledger = json.loads(self.fixture.blobs[key])
        ledger["operations"]["live-fixture"] = {"state": "running"}
        changed = json.dumps(ledger).encode()
        self.fixture.blobs[key] = changed
        self.assert_deployed()
        self.assertEqual(self.fixture.blobs[key], changed)
        creates = [p for action, p in self.fixture.parameters if action == "create"]
        self.assertEqual(len(creates), 5, "repair must really reconcile foundation, not skip it")

    def test_nominal_arm_success_without_outputs_is_not_deployment_success(self):
        self.fixture.false_success = True
        code, result = self.deploy()
        self.assertEqual((code, result["code"]), (2, "deployment_inventory_outputs_missing"))
        self.assertEqual(self.fixture.blobs, {})

    def test_missing_preinitialized_live_state_is_never_reset_on_repair(self):
        self.assert_deployed()
        key = next(k for k in self.fixture.blobs if k[2] == "active-run-slot.json")
        del self.fixture.blobs[key]
        code, result = self.deploy()
        self.assertEqual((code, result["code"]), (2, "existing_identity_bootstrap_state_missing"))
        self.assertNotIn(key, self.fixture.blobs)

    def test_manual_teardown_reports_partial_failure_and_preserves_foreign_resources(self):
        self.assert_deployed()
        self.fixture.fail_delete = "citadel-test19-evidence"
        code, result = self.cli("teardown", "--state-dir", str(self.state),
            "--confirm-deployment", "test19", adapter=self.fixture)
        self.assertEqual(code, 1, result)
        self.assertEqual(result["failedDeletions"], ["evidence"])
        self.assertGreater(result["activeCount"], 0)
        self.assertTrue((self.state / "evidence.json").is_file())
        self.assertTrue((self.state / "evidence.md").read_text().startswith("# Citadel lifecycle evidence"))

    def test_new_foreign_resource_prevents_group_deletion(self):
        self.assert_deployed()
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
        self.observe_fixture_plan()
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
        self.assert_deployed()
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
        self.assertEqual((code, report["code"]), (2, "evidence_directory_must_be_outside_vcs"))
        self.assertEqual(json.loads((self.state / "credentials.json").read_text()), current)
        self.assertEqual(json.loads((self.state / "rotation.json").read_text())["phase"], "staged")

    def test_foundation_stops_for_private_portal_observation_before_bootstrap_or_runtime(self):
        code, report = self.deploy()
        self.assertEqual((code, report["code"]), (2, "api_center_portal_observation_required"))
        creates = [p for action, p in self.fixture.parameters if action == "create"]
        self.assertEqual(len(creates), 1)
        self.assertFalse(creates[0]["deployRuntime"])
        self.assertEqual(self.fixture.blobs, {})
        request_path = self.state / "api-center-plan-request.json"
        request = json.loads(request_path.read_text())
        self.assertEqual(request["resourceId"], self.fixture.center)
        self.assertEqual(request["deploymentId"], "test19")
        self.assertEqual(request["portalUrl"], "https://portal.azure.com/#@"
                         + self.values["tenantId"] + "/resource" + self.fixture.center + "/overview")
        self.assertEqual(request_path.stat().st_mode & 0o777, 0o600)
        state = json.loads((self.state / "state.json").read_text())
        self.assertIn(self.fixture.center, state["inventory"])
        self.assertEqual(state["phase"], "foundation_pending_runtime")
        self.assertFalse((self.state / "api-center-plan-proof.json").exists())
        self.assertNotIn(self.values["subscriptionId"], json.dumps(report))

    def test_missing_native_protocol_metadata_never_passes_inventory_validation(self):
        self.observe_fixture_plan()
        original = self.fixture.runtime
        def incomplete(params):
            original(params)
            self.fixture.environments[0]["properties"]["customProperties"].pop("protocol")
        self.fixture.runtime = incomplete
        code, report = self.deploy()
        self.assertEqual((code, report["code"]), (2, "api_center_identity_or_gateway_metadata_mismatch"))

    def test_repair_does_not_accept_boolean_ledger_schema_version(self):
        self.assert_deployed()
        key = next(k for k in self.fixture.blobs if k[2] == "ledger-v1.json")
        ledger = json.loads(self.fixture.blobs[key])
        ledger["schema_version"] = True
        altered = json.dumps(ledger).encode()
        self.fixture.blobs[key] = altered
        code, report = self.deploy()
        self.assertEqual((code, report["code"]), (2, "existing_ledger_invalid"))
        self.assertEqual(self.fixture.blobs[key], altered)

    def test_generated_certificate_survives_small_clock_regression_with_exact_90_days(self):
        with patch("citadel.operator.rotation.datetime") as clock:
            clock.now.side_effect = lambda zone: datetime.now(zone) + timedelta(seconds=2)
            self.assert_deployed()
        credentials = json.loads((self.state / "credentials.json").read_text())
        metadata = credentials["gatewayCertificates"][0]
        self.assertEqual(datetime.fromisoformat(metadata["not_after"]) -
                         datetime.fromisoformat(metadata["not_before"]), timedelta(days=90))
