import copy
import hashlib
import unittest
from types import SimpleNamespace
from uuid import UUID

from citadel.evidence.manifests import sha256
from citadel.acceptance.coverage import STORAGE
from citadel.acceptance.proof_gate import evaluate_check
from citadel.acceptance.reports import sanitize


def fixture():
    root = "/subscriptions/fixture/resourceGroups/fixture/providers/"
    center = root + "Microsoft.ApiCenter/services/inventory"
    gateway = "https://allocated.azure-api.net"
    roles = list(STORAGE)
    apps, environments, deployed = [], [], {}
    teams = {"reference-data": "Reference Data", "evidence-assessor": "Evidence Review",
             "release-reviewer": "Evidence Review", "candidate-planner": "Exercise Planning",
             "briefing-author": "Exercise Planning"}
    for index, role in enumerate(roles, 1):
        app = {"app": root + "Microsoft.App/containerApps/d-" + role,
               "identity": root + "Microsoft.ManagedIdentity/userAssignedIdentities/d-" + role,
               "identityPrincipalId": str(UUID(int=index)), "identityClientId": str(UUID(int=index + 10)),
               "image": "allocated.azurecr.io/runtime@sha256:" + "a" * 64}
        apps.append(app)
        environments.append({"name": role, "properties": {"kind": "testing",
            "server": {"type": "Azure compute service"}, "customProperties": {
                "workload": app["app"], "identity-resource-id": app["identity"],
                "identity-kind": "Azure user-assigned managed identity; not Entra Agent ID",
                "team": teams[role], "protocol": "MCP" if role == "reference-data" else "A2A",
                "protocol-version": "2025-11-25" if role == "reference-data" else "1.0.0",
                "gateway-address": gateway + "/" + role + ("/mcp" if role == "reference-data" else "/a2a")}}})
        deployed[role] = {"identity": {"userAssignedIdentities": {app["identity"]: {}}},
            "properties": {"provisioningState": "Succeeded", "template": {"containers": [{
                "image": app["image"], "command": ["python", "-m", "citadel.runtime"], "args": [],
                "env": [{"name": key, "value": value} for key, value in {
                    "CITADEL_TARGET": role, "AZURE_PRINCIPAL_ID": app["identityPrincipalId"],
                    "AZURE_CLIENT_ID": app["identityClientId"], "CITADEL_MODEL_TOKENS_PER_MINUTE": "120000"}.items()]}]}}}
    request = {"requestId": "portal-request", "deploymentId": "d", "resourceId": center,
               "resourceCreatedAt": "2026-01-01T00:00:00+00:00", "requestedAt": "2026-01-02T00:00:00+00:00"}
    proof = {"source": "human-azure-portal", "recordedAt": "2026-01-03T00:00:00+00:00",
             "observation": {key: value for key, value in request.items() if key != "requestedAt"} | {
                 "observedAt": "2026-01-02T12:00:00+00:00", "observedPlan": "Free", "evidenceSha256": "e" * 64}}
    lifecycle = SimpleNamespace(id="d", config={"modelTokensPerMinute": 120000}, value={
        "planRequest": request, "planProof": sha256(proof), "outputs": {"appInventory": apps,
            "gatewayUrl": gateway, "inventory": {"capabilities": {"service": center}}}})
    documents = {"center": {"id": center, "properties": {"provisioningState": "Succeeded"},
            "systemData": {"createdAt": request["resourceCreatedAt"]}}, "environments": environments,
        "applications": deployed, "finding": {"properties": {"kind": "rest"}},
        "deployment": {"properties": {"environmentId": "/workspaces/default/environments/release-reviewer",
                                      "server": {"runtimeUri": [gateway + "/release-reviewer"]}}},
        "plan": proof}
    return lifecycle, documents


class InventoryTests(unittest.TestCase):
    def test_actual_metadata_and_private_portal_proof_bind_exact_incarnation_and_five_workloads(self):
        from citadel.acceptance.inventory import inventory_inputs, observe_inventory
        lifecycle, documents = fixture()
        expected = inventory_inputs(lifecycle)
        observed = observe_inventory(lifecycle, documents)
        report = {"runtime_identities": {app["app"].rsplit("/", 1)[1].removeprefix("d-"):
            hashlib.sha256(app["identityPrincipalId"].encode()).hexdigest()
            for app in lifecycle.value["outputs"]["appInventory"]}, "evidence": [],
            "inventory_inputs": expected, "inputs": {"inventory": sha256(expected)}}
        for identifier in ("inventory.five-environments-and-rest", "inventory.actual-free-plan"):
            check = {"check_id": identifier, "expected": "evidence", "actual": observed}
            self.assertEqual(evaluate_check(check, report)["status"], "pass")
            self.assertEqual(evaluate_check(sanitize(check), sanitize(report))["status"], "pass")
        self.assertNotIn("/subscriptions/", str(sanitize(observed)))
        for mutate in (
            lambda value: value["environments"].append(value["environments"][0]),
            lambda value: value["environments"][0]["properties"]["customProperties"].update(
                **{"identity-kind": "Entra Agent ID"}),
            lambda value: value["finding"]["properties"].update(kind="a2a"),
            lambda value: value["deployment"]["properties"].update(environmentId="/wrong"),
        ):
            changed = copy.deepcopy(documents)
            mutate(changed)
            actual = observe_inventory(lifecycle, changed)
            check = {"check_id": "inventory.five-environments-and-rest", "expected": "evidence", "actual": actual}
            self.assertEqual(evaluate_check(check, report)["status"], "fail")
        for mutate in (
            lambda value: value["plan"]["observation"].update(observedPlan="Standard"),
            lambda value: value["plan"].update(source="inferred-from-missing-sku"),
            lambda value: value["center"]["systemData"].update(createdAt="2026-02-01T00:00:00+00:00"),
        ):
            changed = copy.deepcopy(documents)
            mutate(changed)
            actual = observe_inventory(lifecycle, changed)
            check = {"check_id": "inventory.actual-free-plan", "expected": "evidence", "actual": actual}
            self.assertNotEqual(evaluate_check(check, report)["status"], "pass")
