"""Bounded incremental queries of actual service-side tables, never stdout fixtures."""

import math
import time
from datetime import datetime, timezone

from .oracle import SOURCES


TABLES = {"AppRequests", "AppDependencies", "AppTraces", "StorageBlobLogs",
          "ApiManagementGatewayLogs", "ContainerAppConsoleLogs_CL"}
ROW_FIELDS = {"source", "request_id", "status_code", "runtime_identity", "observed",
              "run_id", "operation_id", "caller", "method", "target", "event_id", "facts", "client_request_id"}


def verify_retention(workspace, tables):
    if (workspace.get("retentionInDays") != 30 or
            workspace.get("workspaceCapping", {}).get("dailyQuotaGb") != -1):
        return False
    by_name = {t["name"]: t.get("properties", {}) for t in tables}
    return TABLES <= by_name.keys() and all(
        by_name[name].get("plan") == "Analytics"
        and by_name[name].get("retentionInDays") == 30
        and by_name[name].get("totalRetentionInDays") == 30 for name in TABLES)


def normalize_tables(response):
    if response.get("error") or not response.get("tables"):
        raise ValueError("Incomplete telemetry response")
    records = []
    for table in response["tables"]:
        columns = [c["name"] for c in table["columns"]]
        if (not {"source", "request_id", "status_code", "runtime_identity", "observed"} <= set(columns)
                or len(columns) != len(set(columns)) or len(table["rows"]) > 100000):
            raise ValueError("Missing correlation columns or export limit exceeded")
        for row in table["rows"]:
            if len(row) != len(columns):
                raise ValueError("Malformed telemetry row")
            record = {k: v for k, v in zip(columns, row) if k in ROW_FIELDS}
            if (record["source"] not in SOURCES or type(record["status_code"]) is not int
                    or type(record["observed"]) not in (float, int)
                    or not math.isfinite(record["observed"])):
                raise ValueError("Malformed service evidence")
            records.append(record)
    if len(records) > 100000:
        raise ValueError("Evidence export bound exceeded")
    return records


def query_for_window(started, finished):
    start = datetime.fromtimestamp(started - 5, timezone.utc).isoformat()
    end = datetime.fromtimestamp(finished + 5, timezone.utc).isoformat()
    return f"""
let begin=datetime({start}); let end=datetime({end});
union
(ApiManagementGatewayLogs | where TimeGenerated between (begin .. end)
 | project source='gateway', request_id=tostring(CorrelationId),
 status_code=toint(ResponseCode), runtime_identity='', observed=todouble(datetime_diff('millisecond',TimeGenerated,datetime(1970-01-01)))/1000,
 caller=tostring(SubscriptionId), method=tostring(Method)),
(StorageBlobLogs | where TimeGenerated between (begin .. end)
 | project source='storage', request_id=tostring(CorrelationId), client_request_id=tostring(ClientRequestId),
 status_code=toint(StatusCode), runtime_identity=hash_sha256(tolower(tostring(RequesterObjectId))),
 observed=todouble(datetime_diff('millisecond',TimeGenerated,datetime(1970-01-01)))/1000,
 method=tostring(OperationName), target=hash_sha256(extract(@"^[^?]+",0,tostring(Uri)))),
(AppTraces | where TimeGenerated between (begin .. end)
 | extend e=parse_json(Message) | where e.schema == 'citadel.telemetry.v1'
 | project source='application', request_id=tostring(e.request_id),
 status_code=toint(e.status_code), runtime_identity=tostring(e.runtime_identity),
 observed=todouble(datetime_diff('millisecond',TimeGenerated,datetime(1970-01-01)))/1000,
 run_id=tostring(e.run_id), operation_id=tostring(e.operation_id), caller=tostring(e.caller),
 method=tostring(e.method), target=tostring(e.target), event_id=tostring(e.event_id), facts=e.facts),
(ContainerAppConsoleLogs_CL | where TimeGenerated between (begin .. end)
 | extend e=parse_json(Log_s) | where e.schema == 'citadel.telemetry.v1'
 | project source='console', request_id=tostring(e.request_id),
 status_code=toint(e.status_code), runtime_identity=tostring(e.runtime_identity),
 observed=todouble(datetime_diff('millisecond',TimeGenerated,datetime(1970-01-01)))/1000,
 run_id=tostring(e.run_id), operation_id=tostring(e.operation_id), caller=tostring(e.caller),
 method=tostring(e.method), target=tostring(e.target), event_id=tostring(e.event_id), facts=e.facts)
| take 100001
"""


class Collector:
    def __init__(self, provider, *, started, finished, clock=time.monotonic, budget_seconds=600, prior=None):
        if (type(started) not in (float, int) or type(finished) not in (float, int)
                or not math.isfinite(started) or not math.isfinite(finished)
                or finished < started or type(budget_seconds) not in (int, float)
                or not math.isfinite(budget_seconds) or not 0 < budget_seconds <= 600):
            raise ValueError("A bounded measured run window is required")
        self.provider, self.clock = provider, clock
        self.deadline = clock() + budget_seconds
        self.query = query_for_window(started, finished)
        self.records = {}
        if prior is not None:
            if not isinstance(prior, list) or len(prior) > 100000 or any(not isinstance(r, dict) for r in prior):
                raise ValueError("Invalid retained evidence")
            columns = sorted(ROW_FIELDS)
            normalized = normalize_tables({"tables": [{"columns": [{"name": c} for c in columns],
                "rows": [[r.get(c) for c in columns] for r in prior]}]})
            self._merge([{k: v for k, v in record.items() if k in original}
                         for record, original in zip(normalized, prior)])

    def poll(self):
        remaining = self.deadline - self.clock()
        if remaining <= 0:
            raise TimeoutError("Evidence collection expired")
        records = normalize_tables(self.provider.query(self.query, timeout=min(remaining, 120)))
        if self.clock() > self.deadline:
            raise TimeoutError("Evidence returned after collection deadline")
        self._merge(records)
        return list(self.records.values())

    def _merge(self, records):
        for record in records:
            key = (record["source"], record["request_id"], record.get("event_id", ""),
                   record["observed"])
            if key in self.records and self.records[key] != record:
                raise ValueError("Contradictory service evidence")
            self.records[key] = record
        if len(self.records) > 100000:
            raise ValueError("Evidence export bound exceeded")


class AzureQuery:
    def __init__(self, native, workspace_id):
        from uuid import UUID
        self.native, self.workspace_id = native, str(UUID(workspace_id))

    def query(self, query, timeout):
        with self.native.document({"query": query}) as path:
            return self.native.az("rest", "--method", "post", "--url",
                "https://api.loganalytics.azure.com/v1/workspaces/" + self.workspace_id + "/query",
                "--resource", "https://api.loganalytics.io", "--body", "@" + path,
                timeout=timeout)
