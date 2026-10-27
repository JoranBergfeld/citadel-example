import copy
import unittest
from types import SimpleNamespace

from citadel.acceptance.proof_gate import evaluate_check
from citadel.acceptance.reports import sanitize
from citadel.evidence.manifests import sha256
from tests.acceptance.test_telemetry_proof import application_report


class RetentionTests(unittest.TestCase):
    def test_actual_arm_retention_sampling_privacy_and_complete_ingested_counts_are_all_required(self):
        from citadel.acceptance.retention import telemetry_inputs, observe_retention
        root = "/subscriptions/fixture/resourceGroups/fixture/providers/"
        ids = {"workspace": root + "Microsoft.OperationalInsights/workspaces/logs",
               "insights": root + "Microsoft.Insights/components/logs",
               "gateway": root + "Microsoft.ApiManagement/service/gateway/diagnostics/applicationinsights"}
        privacy = {"request": {"headers": [], "body": {"bytes": 0}},
                   "response": {"headers": [], "body": {"bytes": 0}}}
        documents = {
            ids["workspace"]: {"id": ids["workspace"], "properties": {
                "retentionInDays": 30, "workspaceCapping": {"dailyQuotaGb": -1}}},
            ids["insights"]: {"id": ids["insights"], "properties": {
                "WorkspaceResourceId": ids["workspace"], "SamplingPercentage": 100, "DisableLocalAuth": True}},
            ids["gateway"]: {"id": ids["gateway"], "properties": {
                "sampling": {"samplingType": "fixed", "percentage": 100}, "alwaysLog": "allErrors",
                "httpCorrelationProtocol": "W3C", "logClientIp": False, "verbosity": "information",
                "frontend": copy.deepcopy(privacy), "backend": copy.deepcopy(privacy)}},
        }
        tables = [{"name": name, "properties": {"plan": "Analytics", "retentionInDays": 30,
                                               "totalRetentionInDays": 30}} for name in (
            "AppRequests", "AppDependencies", "AppTraces", "AppExceptions", "AppEvents", "AppMetrics",
            "StorageBlobLogs", "ApiManagementGatewayLogs", "ContainerAppConsoleLogs",
            "ContainerAppSystemLogs", "ContainerAppHTTPLogs", "AZKVAuditLogs")]
        calls = []

        def rest(method, resource, version):
            calls.append((method, resource, version))
            return copy.deepcopy(documents[resource])

        lifecycle = SimpleNamespace(value={"inventory": list(ids.values())}, native=SimpleNamespace(rest=rest))
        expected = telemetry_inputs(lifecycle)
        report = application_report() | {"telemetry_inputs": expected, "inputs": {"telemetry": sha256(expected)}}
        observed = observe_retention(lifecycle, documents[ids["workspace"]], tables)
        self.assertEqual(calls, [("get", ids["insights"], "2020-02-02"),
                                 ("get", ids["gateway"], "2024-05-01")])
        check = {"check_id": "telemetry.retention-and-unsampled", "expected": "evidence", "actual": observed}
        self.assertEqual(evaluate_check(sanitize(check), sanitize(report))["status"], "pass")
        self.assertNotIn("/subscriptions/", str(sanitize(observed)))
        for mutate in (
            lambda: documents[ids["insights"]]["properties"].update(SamplingPercentage=50),
            lambda: documents[ids["gateway"]]["properties"]["frontend"]["request"]["body"].update(bytes=100),
            lambda: tables.pop(),
        ):
            original, before_tables = copy.deepcopy(documents), copy.deepcopy(tables)
            mutate()
            changed = check | {"actual": observe_retention(lifecycle, documents[ids["workspace"]], tables)}
            self.assertEqual(evaluate_check(changed, report)["status"], "fail")
            documents, tables = original, before_tables
        self.assertEqual(evaluate_check(check, report | {"evidence": []})["status"], "blocked")
