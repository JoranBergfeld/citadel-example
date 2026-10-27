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

    def test_wire_encoded_dynamic_facts_are_parsed_without_treating_unknown_metadata_as_false(self):
        columns = [{"name": key} for key in
                   ("source", "request_id", "status_code", "runtime_identity", "observed", "facts")]
        response = {"tables": [{"columns": columns,
            "rows": [["gateway", "real-id", 403, "", 100.0, '{"backend_dispatched":false}']]}]}
        self.assertIs(normalize_tables(response)[0]["facts"]["backend_dispatched"], False)
        for malformed in ("[]", "not-json", '{"backend_dispatched":false,"excess":"' + "x" * 4096 + '"}'):
            response["tables"][0]["rows"][0][-1] = malformed
            with self.subTest(malformed=malformed[:10]), self.assertRaises(ValueError):
                normalize_tables(response)

    def test_actual_retention_and_unsampled_settings_required(self):
        workspace = {"retentionInDays": 30, "workspaceCapping": {"dailyQuotaGb": -1}}
        tables = [{"name": name, "properties": {"plan": "Analytics", "retentionInDays": 30,
                                                "totalRetentionInDays": 30}}
                  for name in ("AppRequests", "AppDependencies", "AppTraces", "AppExceptions", "AppEvents",
                               "AppMetrics", "StorageBlobLogs", "ApiManagementGatewayLogs",
                               "ContainerAppConsoleLogs", "ContainerAppSystemLogs", "ContainerAppHTTPLogs",
                               "AZKVAuditLogs")]
        self.assertTrue(verify_retention(workspace, tables))
        self.assertFalse(verify_retention(workspace, tables[:-1]))
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
        self.assertIn(
            r'target=hash_sha256(replace_regex(extract(@"^[^?]+",0,tostring(Uri)),'
            r'@"^(https://[^/:?#]+):443(/|$)",@"\1\2"))', query)

    def test_ingress_queries_only_observed_service_ids_targets_and_individual_windows(self):
        query = query_for_window(90, 110, ingress=[{
            "request_id": "actual-ingress-id", "target": "a" * 64, "started": 100, "finished": 101}])
        self.assertIn("ContainerAppHTTPLogs", query)
        self.assertIn("request_id == 'actual-ingress-id'", query)
        self.assertIn("target == '" + "a" * 64 + "'", query)
        self.assertIn("UpstreamRequestAttemptCount", query)
        self.assertIn("ResponseCodeDetails", query)
        self.assertNotIn("XForwardedFor", query)
        self.assertNotIn("UserAgent", query)
        self.assertIn("where false", query_for_window(90, 110))
        for row in ({"request_id": "x' | take 99", "target": "a" * 64, "started": 100, "finished": 101},
                    {"request_id": "actual-id", "target": "not-a-hash", "started": 100, "finished": 101},
                    {"request_id": "actual-id", "target": "a" * 64, "started": 100, "finished": 1001}):
            with self.subTest(row=row), self.assertRaises(ValueError):
                query_for_window(90, 110, ingress=[row])

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
        self.assertIn("(AppTraces | where TimeGenerated between (begin .. healthEnd)", query)
        self.assertIn("let healthEnd=end+15s;", query)
        self.assertEqual(query.count("TimeGenerated <= end or e.method == 'exporter.health'"), 2)
        self.assertEqual(query.count("stream_id=tostring(e.stream_id), sequence=tolong(e.sequence)"), 2)
        self.assertIn("e=parse_json(Message)", query)
        console_query = query.split("(ContainerAppConsoleLogs |", 1)[1]
        self.assertIn("e=parse_json(Log)", console_query)
        self.assertIn("source='console'", console_query)
        self.assertNotIn("source='application'", console_query)

    def test_gateway_query_preserves_allocated_credential_binding_without_exporting_resource_ids(self):
        query = query_for_window(100, 101)
        self.assertIn('caller=extract(@"([^/]+)$",1,tostring(ApimSubscriptionId))', query)
        self.assertNotIn("tostring(SubscriptionId)", query)
        self.assertIn("replace_string(tostring(toguid(CorrelationId)),'-','')", query)
        self.assertIn("credential_sha256=hash_sha256(tolower(strcat(_ResourceId,'/subscriptions/',", query)
        provider = QueryFixture()
        provider.query = lambda query, timeout: {"tables": [{
            "columns": [{"name": key} for key in
                ("source", "request_id", "status_code", "runtime_identity", "observed", "credential_sha256")],
            "rows": [["gateway", "actual-id", 200, "", 100.0, "a" * 64]]}]}
        self.assertEqual(Collector(provider, started=100, finished=101).poll()[0]["credential_sha256"], "a" * 64)

    def test_gateway_query_preserves_destination_hash_and_explicit_backend_dispatch_metadata(self):
        query = query_for_window(100, 101)
        self.assertIn('target=hash_sha256(extract(@"^[^?]+",0,tostring(Url)))', query)
        for column in ("BackendUrl", "BackendMethod", "BackendResponseCode", "BackendTime"):
            self.assertIn(column, query)
        self.assertIn("'backend_dispatched'", query)
        self.assertIn("bool(null)", query)
        self.assertNotIn("RequestBody", query)
        self.assertNotIn("RequestHeaders", query)

    def test_model_protocol_query_retains_actual_query_free_backend_target_method_and_status(self):
        query = query_for_window(100, 101)
        self.assertIn("'backend_target',iff(isnotempty(BackendUrl),", query)
        self.assertIn('hash_sha256(extract(@"^[^?]+",0,tostring(BackendUrl)))', query)
        self.assertIn("'backend_method',tostring(BackendMethod)", query)
        self.assertIn("'backend_status',toint(BackendResponseCode)", query)
        for payload in ("RequestBody", "ResponseBody", "RequestHeaders", "ResponseHeaders"):
            self.assertNotIn(payload, query)
