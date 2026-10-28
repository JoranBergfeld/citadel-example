import json
import os
from pathlib import Path
import re
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]


class TemplateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        executable = os.environ["BICEP_EXECUTABLE"]
        version = subprocess.check_output([executable, "--version"], text=True)
        if "version 0.48.1 " not in version:
            raise AssertionError(f"Wrong compiler: {version}")
        compiled = subprocess.check_output(
            [executable, "build", str(ROOT / "infra/main.bicep"), "--stdout"], text=True,
        )
        def normalize(value):
            if isinstance(value, dict):
                return {key: [normalize(item) for item in child.values()]
                        if key == "resources" and isinstance(child, dict) and all(isinstance(item, dict) and "type" in item for item in child.values())
                        else normalize(child) for key, child in value.items()}
            if isinstance(value, list):
                return [normalize(item) for item in value]
            return value
        cls.template = normalize(json.loads(compiled))

    def test_subscription_template_creates_exact_team_groups_and_secure_inputs(self):
        groups = [r for r in self.template["resources"] if r["type"] == "Microsoft.Resources/resourceGroups"]
        self.assertEqual(len(groups), 4)
        self.assertEqual({r["apiVersion"] for r in groups}, {"2022-09-01"})
        for key in ("callerKeys", "contextKeys", "gatewayCertificatePfx"):
            self.assertIn(self.template["parameters"][key]["type"].lower(), {"secureobject", "securestring"})
        self.assertEqual(self.template["parameters"]["location"]["allowedValues"], ["westeurope"])

    def test_operator_accounting_roles_cannot_read_or_delete_team_or_supporting_data(self):
        accounting = self.module("observation-")
        role = next(r for r in accounting["resources"] if r["type"] == "Microsoft.Authorization/roleDefinitions")
        self.assertEqual(role["properties"]["permissions"], [{
            "actions": [], "notActions": [],
            "dataActions": ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write"],
            "notDataActions": [],
        }])
        assignment = next(r for r in accounting["resources"] if r["type"] == "Microsoft.Authorization/roleAssignments")
        self.assertIn("read-accounting", assignment["scope"])
        self.assertNotIn("team", assignment["scope"])
        gateway = self.module("gateway-")
        self.assertIn("operator-web", gateway["variables"]["callers"])
        operator = self.module("operator-web-")
        app = next(r for r in operator["resources"] if r["type"] == "Microsoft.App/containerApps")
        env = app["properties"]["template"]["containers"][0]["env"]
        self.assertIn("CITADEL_OBSERVATION_BLOB_URL", {entry["name"] for entry in env})
        self.assertFalse(any(entry["name"] in ("CITADEL_BLOB_URL", "CITADEL_MODEL_DEPLOYMENT") for entry in env))

    def module(self, name):
        for resource in self.template["resources"]:
            if resource["type"] == "Microsoft.Resources/deployments" and resource["name"].startswith(f"[format('{name}"):
                return resource["properties"]["template"]
        self.fail(f"Missing module {name}")

    def test_exact_warm_application_and_identity_only_storage_boundaries(self):
        app = self.module("app-")
        resource = next(r for r in app["resources"] if r["type"] == "Microsoft.App/containerApps")
        self.assertEqual(resource["apiVersion"], "2025-01-01")
        self.assertEqual(resource["identity"]["type"], "UserAssigned")
        self.assertEqual(resource["properties"]["template"]["scale"], {"minReplicas": 1, "maxReplicas": 1})
        self.assertEqual(resource["properties"]["template"]["containers"][0]["resources"], {"cpu": "[json('0.5')]", "memory": "1Gi"})
        self.assertEqual(resource["properties"]["configuration"]["ingress"]["clientCertificateMode"], "accept")
        self.assertFalse(resource["properties"]["configuration"]["ingress"]["allowInsecure"])
        team = self.module("team-")
        grants = team["variables"]["grantsByTeam"]
        self.assertEqual(grants["reference"], [{"actor": "reference-data", "container": "reference", "role": "reader"}])
        self.assertEqual(grants["evidence"], [
            {"actor": "evidence-assessor", "container": "drafts", "role": "contributor"},
            {"actor": "release-reviewer", "container": "drafts", "role": "reader"},
            {"actor": "release-reviewer", "container": "findings", "role": "contributor"},
            {"actor": "evidence-assessor", "container": "assessor-operations", "role": "contributor"},
            {"actor": "release-reviewer", "container": "reviewer-operations", "role": "contributor"},
        ])
        for grant in grants["planning"]:
            self.assertNotIn(grant["container"], {"drafts", "findings", "reference"})
        roles = next(r["properties"]["template"] for r in team["resources"] if r["type"] == "Microsoft.Resources/deployments" and "data-" in r["name"])
        assignment = roles["resources"][0]
        self.assertEqual(assignment["type"], "Microsoft.Authorization/roleAssignments")
        self.assertIn("Microsoft.Storage/storageAccounts/blobServices/containers", assignment["scope"])

    def test_model_gateway_only_authority_and_unsampled_thirty_day_telemetry(self):
        platform = self.module("platform-")
        resources = {r["type"]: r for r in platform["resources"]}
        model = resources["Microsoft.CognitiveServices/accounts"]
        self.assertTrue(model["properties"]["disableLocalAuth"])
        deployment = resources["Microsoft.CognitiveServices/accounts/deployments"]
        self.assertEqual(deployment["properties"]["model"], {"format": "OpenAI", "name": "gpt-4.1-mini", "version": "2025-04-14"})
        self.assertEqual(deployment["properties"]["versionUpgradeOption"], "NoAutoUpgrade")
        self.assertEqual(deployment["sku"]["name"], "Standard")
        self.assertEqual(resources["Microsoft.ApiManagement/service"]["sku"], {"name": "BasicV2", "capacity": 1})
        self.assertEqual(resources["Microsoft.ContainerRegistry/registries"]["sku"], {"name": "Basic"})
        self.assertFalse(resources["Microsoft.ContainerRegistry/registries"]["properties"]["adminUserEnabled"])
        workspace = resources["Microsoft.OperationalInsights/workspaces"]["properties"]
        self.assertEqual(workspace["retentionInDays"], 30)
        self.assertEqual(workspace["workspaceCapping"]["dailyQuotaGb"], -1)
        table = resources["Microsoft.OperationalInsights/workspaces/tables"]["properties"]
        self.assertEqual(table, {"plan": "Analytics", "retentionInDays": 30, "totalRetentionInDays": 30})
        self.assertIn("ContainerAppHTTPLogs", platform["variables"]["tableNames"])
        self.assertIn("ContainerAppConsoleLogs", platform["variables"]["tableNames"])
        self.assertIn("ContainerAppSystemLogs", platform["variables"]["tableNames"])
        self.assertNotIn("AzureDiagnostics", platform["variables"]["tableNames"])
        self.assertFalse(any(name.endswith("_CL") for name in platform["variables"]["tableNames"]))
        environment_diagnostics = next(r for r in platform["resources"]
            if r["type"] == "Microsoft.Insights/diagnosticSettings"
            and any(log["category"] == "ContainerAppConsoleLogs" for log in r["properties"].get("logs", [])))
        self.assertEqual(environment_diagnostics["properties"]["logAnalyticsDestinationType"], "Dedicated")
        self.assertTrue(any({"category": "ContainerAppHTTPLogs", "enabled": True}
            in resource["properties"].get("logs", []) for resource in platform["resources"]
            if resource["type"] == "Microsoft.Insights/diagnosticSettings"))
        diag = resources["Microsoft.ApiManagement/service/diagnostics"]["properties"]
        self.assertEqual(diag["sampling"], {"samplingType": "fixed", "percentage": 100})
        for side in ["frontend", "backend"]:
            for direction in ["request", "response"]:
                self.assertEqual(diag[side][direction], {"headers": [], "body": {"bytes": 0}})
        for resource in platform["resources"]:
            if resource["type"] == "Microsoft.Insights/diagnosticSettings":
                self.assertEqual(resource["apiVersion"], "2021-05-01-preview")
        model_roles = [r for r in platform["resources"] if r["type"] == "Microsoft.Authorization/roleAssignments" and "5e0bd9bd" in r["properties"]["roleDefinitionId"]]
        self.assertEqual(len(model_roles), 1)
        self.assertIn(model_roles[0]["properties"]["principalId"], {
            "[reference('apim', '2024-05-01', 'full').identity.principalId]",
            "[reference(resourceId('Microsoft.ApiManagement/service', format('citadel-{0}-gateway', parameters('suffix'))), '2024-05-01', 'full').identity.principalId]",
        })

    def test_new_vaults_omit_irreversible_purge_flag_and_keep_seven_day_soft_delete(self):
        for name in ("platform-", "team-"):
            vault = next(r for r in self.module(name)["resources"] if r["type"] == "Microsoft.KeyVault/vaults")
            self.assertNotIn("enablePurgeProtection", vault["properties"])
            self.assertTrue(vault["properties"]["enableSoftDelete"])
            self.assertTrue(vault["properties"]["enableRbacAuthorization"])
            self.assertEqual(vault["properties"]["softDeleteRetentionInDays"], 7)

    def test_team_storage_public_endpoint_requires_rbac_https_and_no_anonymous_or_shared_key_access(self):
        storage = next(r for r in self.module("team-")["resources"]
                       if r["type"] == "Microsoft.Storage/storageAccounts")
        properties = storage["properties"]
        self.assertEqual(properties.get("publicNetworkAccess"), "Enabled")
        self.assertFalse(properties["allowBlobPublicAccess"])
        self.assertFalse(properties["allowSharedKeyAccess"])
        self.assertTrue(properties["defaultToOAuthAuthentication"])
        self.assertTrue(properties["supportsHttpsTrafficOnly"])
        self.assertEqual(properties["minimumTlsVersion"], "TLS1_2")

    def test_team_extension_role_inventory_preserves_its_named_variable_loop_index(self):
        copies = self.module("team-")["variables"]["copy"]
        readers = next(row for row in copies if row["name"] == "readerInventory")
        self.assertIn("copyIndex('readerInventory')", readers["input"])
        for row in copies:
            self.assertNotIn("copyIndex()", json.dumps(row), row["name"])

    def test_gateway_has_no_wildcard_routes_and_verifies_every_backend_tls_identity(self):
        gateway = self.module("gateway-")
        for resource in gateway["resources"]:
            if resource["type"] == "Microsoft.ApiManagement/service/backends":
                self.assertEqual(resource["properties"]["tls"], {
                    "validateCertificateChain": True, "validateCertificateName": True,
                })
        apis = next(r["properties"]["template"] for r in gateway["resources"] if r["type"] == "Microsoft.Resources/deployments")
        variables = apis["variables"]
        self.assertEqual(
            [(r["name"], r["method"], r["path"]) for r in variables["agentOperations"]],
            [("a2a", "POST", "/a2a"), ("discovery", "GET", "/.well-known/agent-card.json"),
             ("status", "GET", "/operations/{operationId}")],
        )
        self.assertEqual(
            [(r["name"], r["method"], r["path"]) for r in variables["findingOperations"]],
            [("findings-read", "GET", "/findings/{findingId}/versions/{version}")],
        )
        self.assertEqual([(r["method"], r["path"]) for r in variables["mcpOperations"]],
                         [("POST", "/mcp"), ("GET", "/mcp"), ("DELETE", "/mcp")])
        api = next(r for r in apis["resources"] if r["type"] == "Microsoft.ApiManagement/service/apis")
        self.assertTrue(api["properties"]["subscriptionRequired"])
        self.assertEqual(api["properties"]["protocols"], ["https"])

    def test_no_resource_module_outputs_secret_values(self):
        def inspect(template):
            for name, output in template.get("outputs", {}).items():
                self.assertNotIn(output["type"].lower(), {"securestring", "secureobject"})
                value = json.dumps(output).lower()
                for forbidden in ("connectionstring", "instrumentationkey", "primarykey", "secondarykey", "certificatepfx"):
                    self.assertNotIn(forbidden, value, f"Secret output {name}")
            for resource in template["resources"]:
                if resource["type"] == "Microsoft.Resources/deployments":
                    inspect(resource["properties"]["template"])
        inspect(self.template)

    def test_api_center_uses_stable_service_without_inventing_a_plan_or_native_kind(self):
        platform = self.module("platform-")
        centers = [r for r in platform["resources"] if r["type"] == "Microsoft.ApiCenter/services"]
        self.assertEqual(len(centers), 1)
        self.assertEqual(centers[0]["apiVersion"], "2024-03-01")
        self.assertEqual(centers[0]["condition"], "[parameters('createApiCenter')]")
        self.assertTrue(self.template["parameters"]["createApiCenter"]["defaultValue"])
        module = next(r for r in self.template["resources"]
                      if r["type"] == "Microsoft.Resources/deployments"
                      and r["name"].startswith("[format('platform-"))
        self.assertEqual(module["properties"]["parameters"]["createApiCenter"],
                         {"value": "[parameters('createApiCenter')]"})
        workspace = next(r for r in platform["resources"]
                         if r["type"] == "Microsoft.ApiCenter/services/workspaces")
        self.assertNotIn("condition", workspace)
        self.assertNotIn("sku", centers[0])
        self.assertNotIn("sku", centers[0].get("properties", {}))
        self.assertEqual([r for r in platform["resources"] if r["type"].endswith("/apis")], [])

    def test_approved_inventory_declares_five_real_workloads_with_seven_flat_strings(self):
        inventory = self.module("inventory-")
        schemas = next(r for r in inventory["resources"] if r["type"] == "Microsoft.ApiCenter/services/metadataSchemas")
        self.assertEqual(schemas["apiVersion"], "2024-03-01")
        self.assertEqual(json.loads(schemas["properties"]["schema"]), {"type": "string"})
        self.assertEqual(schemas["properties"]["assignedTo"], [{"entity": "environment", "required": True}])
        expected = {"workload", "protocol", "protocol-version", "team", "gateway-address", "identity-kind", "identity-resource-id"}
        self.assertEqual(set(inventory["variables"]["metadataNames"]), expected)
        environment = next(r for r in inventory["resources"] if r["type"] == "Microsoft.ApiCenter/services/workspaces/environments")
        properties = environment["properties"]
        self.assertEqual(environment["apiVersion"], "2024-03-01")
        self.assertEqual(properties["kind"], "testing")
        self.assertEqual(properties["server"]["type"], "Azure compute service")
        self.assertEqual(set(properties["customProperties"]), expected)
        self.assertTrue(all(isinstance(v, str) for v in properties["customProperties"].values()))
        self.assertIn("not native A2A/MCP", properties["description"])
        self.assertEqual(properties["customProperties"]["identity-kind"], "Azure user-assigned managed identity; not Entra Agent ID")
        module = next(r for r in self.template["resources"] if r["type"] == "Microsoft.Resources/deployments" and r["name"].startswith("[format('inventory-"))
        self.assertEqual(module["condition"], "[parameters('deployRuntime')]")
        workloads = self.template["variables"]["workloads"]
        if isinstance(workloads, str):
            referenced = re.fullmatch(r"\[variables\('([^']+)'\)\]", workloads).group(1)
            workloads = self.template["variables"][referenced]
        self.assertEqual({w["name"] for w in workloads}, {
            "reference-data", "evidence-assessor", "release-reviewer", "candidate-planner", "briefing-author",
        })
        binding = module["properties"]["parameters"]["workloads"]["copy"][0]
        self.assertEqual(binding["count"], "[length(variables('workloads'))]")
        self.assertIn(".outputs.inventory.value.app", binding["input"])
        self.assertIn(".outputs.inventory.value.identity", binding["input"])
        self.assertEqual(environment["copy"]["count"], "[length(parameters('workloads'))]")
        expected_protocols = {name: {"name": "A2A", "version": "1.0.0", "path": "/a2a"} for name in {
            "evidence-assessor", "release-reviewer", "candidate-planner", "briefing-author",
        }}
        expected_protocols["reference-data"] = {"name": "MCP", "version": "2025-11-25", "path": "/mcp"}
        self.assertEqual(inventory["variables"]["protocols"], expected_protocols)
        self.assertEqual(inventory["variables"]["teamNames"], {
            "reference": "Reference Data", "evidence": "Evidence Review", "planning": "Exercise Planning",
        })

    def test_only_genuine_rest_finding_capability_is_registered_against_reviewer_environment(self):
        inventory = self.module("inventory-")
        apis = [r for r in inventory["resources"] if r["type"] == "Microsoft.ApiCenter/services/workspaces/apis"]
        self.assertEqual(len(apis), 1)
        self.assertEqual(apis[0]["apiVersion"], "2024-03-01")
        self.assertEqual(apis[0]["properties"]["kind"], "rest")
        self.assertEqual(apis[0]["properties"]["title"], "Released findings")
        self.assertIn("GET /findings/{findingId}/versions/{version}", apis[0]["properties"]["description"])
        self.assertIn("not agent invocation", apis[0]["properties"]["description"])
        deployments = [r for r in inventory["resources"] if r["type"] == "Microsoft.ApiCenter/services/workspaces/apis/deployments"]
        self.assertEqual(len(deployments), 1)
        deployment = deployments[0]
        self.assertEqual(deployment["apiVersion"], "2024-03-01")
        self.assertEqual(deployment["properties"]["environmentId"], "/workspaces/default/environments/release-reviewer")
        self.assertEqual(deployment["properties"]["server"]["runtimeUri"], ["[format('{0}/release-reviewer', parameters('gatewayUrl'))]"])
        self.assertNotIn("state", deployment["properties"], "Declaration must not claim verified operational status")
        self.assertTrue(deployment["dependsOn"], "Association waits for real workload environments")

    def test_findings_deployment_references_real_declared_definition_without_import_claim(self):
        inventory = self.module("inventory-")
        versions = [r for r in inventory["resources"]
                    if r["type"] == "Microsoft.ApiCenter/services/workspaces/apis/versions"]
        definitions = [r for r in inventory["resources"]
                       if r["type"] == "Microsoft.ApiCenter/services/workspaces/apis/versions/definitions"]
        self.assertEqual(len(versions), 1)
        self.assertEqual(len(definitions), 1)
        self.assertEqual(versions[0]["apiVersion"], "2024-03-01")
        self.assertEqual(versions[0]["properties"], {"title": "1.0.0", "lifecycleStage": "testing"})
        self.assertEqual(definitions[0]["apiVersion"], "2024-03-01")
        self.assertEqual(set(definitions[0]["properties"]), {"title", "description"})
        self.assertIn("no imported specification", definitions[0]["properties"]["description"])
        deployment = next(r for r in inventory["resources"]
                          if r["type"] == "Microsoft.ApiCenter/services/workspaces/apis/deployments")
        self.assertEqual(deployment["properties"].get("definitionId"),
                         "/workspaces/default/apis/released-findings/versions/v1-0-0/definitions/declared-rest")
        self.assertNotIn("versionId", deployment["properties"], "Use the documented pinned API field")
        self.assertTrue(any("versions/definitions" in value for value in deployment["dependsOn"]))
        self.assertIn("versions/definitions", json.dumps(inventory["outputs"]["inventory"]))


if __name__ == "__main__":
    unittest.main()
