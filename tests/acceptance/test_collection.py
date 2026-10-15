import unittest

from citadel.acceptance.collection import Collector, normalize_tables, verify_retention, query_for_window


class QueryFixture:
    def __init__(self):
        self.calls = []

    def query(self, query, timeout):
        self.calls.append((query, timeout))
        return {"tables": [{"columns": [{"name": key} for key in
                  ("source", "request_id", "status_code", "runtime_identity", "observed")],
                "rows": [["storage", "actual-id", 403, "a" * 64, 100.0]]}]}


class CollectionTests(unittest.TestCase):
    def test_one_total_collection_deadline_not_a_new_allowance_per_query(self):
        now = [100.0]
        provider = QueryFixture()
        collector = Collector(provider, started=100, finished=101, clock=lambda: now[0])
        self.assertEqual(len(collector.poll()), 1)
        now[0] = 699
        collector.poll()
        self.assertEqual(provider.calls[-1][1], 1)
        now[0] = 700
        with self.assertRaises(TimeoutError):
            collector.poll()
        self.assertEqual(len(provider.calls), 2)

    def test_missing_partial_or_oversized_query_results_block(self):
        for response in ({}, {"error": {"code": "PartialError"}},
                         {"tables": [{"columns": [], "rows": [[]] * 100001}]},
                         {"tables": [{"columns": [{"name": "request_id"}], "rows": [["id"]]}]}):
            with self.subTest(response=list(response)):
                with self.assertRaises(ValueError):
                    normalize_tables(response)

    def test_actual_retention_and_unsampled_settings_required(self):
        workspace = {"retentionInDays": 30, "workspaceCapping": {"dailyQuotaGb": -1}}
        tables = [{"name": name, "properties": {"plan": "Analytics", "retentionInDays": 30,
                                                "totalRetentionInDays": 30}}
                  for name in ("AppRequests", "AppDependencies", "AppTraces", "StorageBlobLogs",
                               "ApiManagementGatewayLogs", "ContainerAppConsoleLogs_CL")]
        self.assertTrue(verify_retention(workspace, tables))
        tables[0]["properties"]["plan"] = "Basic"
        self.assertFalse(verify_retention(workspace, tables))
        self.assertFalse(verify_retention(workspace, []))

    def test_resume_keeps_previous_records_and_refuses_contradictory_service_results(self):
        provider = QueryFixture()
        first = Collector(provider, started=100, finished=101).poll()
        resumed = Collector(provider, started=100, finished=101, prior=first, budget_seconds=5)
        provider.query = lambda query, timeout: {"tables": [{"columns": [
            {"name": k} for k in first[0]], "rows": []}]}
        self.assertEqual(resumed.poll(), first)
        contradictory = first[0] | {"status_code": 200}
        provider.query = lambda query, timeout: {"tables": [{"columns": [
            {"name": k} for k in contradictory], "rows": [list(contradictory.values())]}]}
        with self.assertRaises(ValueError):
            resumed.poll()

    def test_storage_query_uses_published_fields_without_fabricating_service_ids(self):
        query = query_for_window(100, 101)
        self.assertNotIn("RequestIdHeader", query)
        self.assertIn("request_id=tostring(CorrelationId), client_request_id=tostring(ClientRequestId)", query)
        self.assertIn('target=hash_sha256(extract(@"^[^?]+",0,tostring(Uri)))', query)

    def test_application_ingestion_queries_insights_and_keeps_console_supplemental(self):
        provider = QueryFixture()
        provider.query = lambda query, timeout: (
            provider.calls.append((query, timeout)) or {"tables": [{
                "columns": [{"name": key} for key in
                    ("source", "request_id", "status_code", "runtime_identity", "observed")],
                "rows": [["console", "actual-id", 403, "a" * 64, 100.0]]}]})
        records = Collector(provider, started=100, finished=101).poll()
        self.assertEqual(records[0]["source"], "console")
        query = provider.calls[0][0]
        self.assertIn("(AppTraces | where TimeGenerated between (begin .. end)", query)
        self.assertIn("e=parse_json(Message)", query)
        console_query = query.split("(ContainerAppConsoleLogs_CL", 1)[1]
        self.assertIn("source='console'", console_query)
        self.assertNotIn("source='application'", console_query)
