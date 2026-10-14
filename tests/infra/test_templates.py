import json
import os
from pathlib import Path
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
        self.assertEqual(resource["properties"]["configuration"]["ingress"]["clientCertificateMode"], "require")
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
        self.assertNotIn("sku", centers[0])
        self.assertNotIn("sku", centers[0].get("properties", {}))
        self.assertEqual([r for r in platform["resources"] if r["type"].endswith("/apis")], [])


if __name__ == "__main__":
    unittest.main()
