"""Bounded, unsampled metadata delivery using the approved official exporter."""

import hashlib
import json
import logging
import os
import threading
import time
from collections import deque
from urllib.parse import urlsplit
from uuid import UUID

from azure.identity import ManagedIdentityCredential
from opentelemetry._logs import LogRecord, SeverityNumber
from opentelemetry.sdk._logs import ReadableLogRecord
from opentelemetry.sdk._logs.export import LogRecordExportResult
from opentelemetry.sdk.resources import Resource

from .oracle import hash_value
from .telemetry import ACTORS, FACTS, METHODS, opaque


QUEUE_CAPACITY = 4096
BATCH_SIZE = 128
MAX_RECORD_BYTES = 4096


class MonitorExporter:
    def __init__(self, workload, *, client_id, principal_id, connection_string,
                 credential_factory=ManagedIdentityCredential, transport=None):
        if workload not in ACTORS - {"operator"}:
            raise ValueError("An allocated workload is required")
        client_id = str(UUID(client_id))
        self.identity = hashlib.sha256(str(UUID(principal_id)).encode()).hexdigest()
        parts = {}
        for pair in connection_string.split(";"):
            if pair:
                key, value = pair.split("=", 1)
                key = key.lower()
                if key in parts:
                    raise ValueError("Duplicate monitor connection setting")
                parts[key] = value
        key = str(UUID(parts["instrumentationkey"]))
        endpoint = urlsplit(parts["ingestionendpoint"])
        if (endpoint.scheme != "https" or not endpoint.hostname
                or not endpoint.hostname.endswith(".in.applicationinsights.azure.com")
                or endpoint.username or endpoint.password or endpoint.port not in (None, 443)
                or endpoint.query or endpoint.fragment or endpoint.path not in ("", "/")):
            raise ValueError("Only the allocated public Azure Monitor ingestion endpoint is allowed")
        host = "https://" + endpoint.hostname
        self.destination = host + "/v2.1/track"
        for name in ("APPLICATIONINSIGHTS_STATSBEAT_DISABLED_ALL",
                     "APPLICATIONINSIGHTS_SDKSTATS_DISABLED", "APPLICATIONINSIGHTS_CONTROLPLANE_DISABLED"):
            os.environ[name] = "true"
        for name in ("azure.monitor.opentelemetry.exporter", "azure.core", "azure.identity"):
            logger = logging.getLogger(name)
            logger.handlers = [logging.NullHandler()]
            logger.propagate = False
        from azure.monitor.opentelemetry.exporter import AzureMonitorLogExporter
        from azure.core.pipeline.transport import RequestsTransport
        self.credential = credential_factory(client_id=client_id, retry_total=0,
            retry_connect=0, retry_read=0, retry_status=0, connection_timeout=5, read_timeout=5)
        self.exporter = AzureMonitorLogExporter(
            connection_string=f"InstrumentationKey={key};IngestionEndpoint={host};AADAudience=https://monitor.azure.com/",
            credential=self.credential, api_version="v2.1", disable_offline_storage=True,
            max_envelopes_per_second=0, retry_total=0, retry_connect=0, retry_read=0,
            retry_status=0, redirect_max=0, timeout=5, read_timeout=5,
            logging_enable=False, tracing_enable=False,
            transport=transport or RequestsTransport(use_env_settings=False),
            raw_request_hook=self._request, raw_response_hook=self._response)
        self.workload, self.resource = workload, Resource({"service.name": workload})
        self.condition, self.queue = threading.Condition(), deque()
        self.accepting, self.inflight = True, False
        self.counts = {"submitted_records": 0, "acknowledged_records": 0,
                       "failed_records": 0, "dropped_records": 0, "delivery_attempts": 0}
        self.receipt = {"request_id": None, "status_code": 0}
        self.worker = threading.Thread(target=self._deliver, name="citadel-monitor", daemon=True)
        self.worker.start()

    def emit(self, record):
        fields = {"schema", "event_id", "workload", "runtime_identity", "method", "request_id",
                  "status_code", "facts", "run_id", "operation_id", "caller", "target", "stream_id", "sequence"}
        if (not isinstance(record, dict) or set(record) - fields
                or not fields - {"run_id", "operation_id", "caller", "target", "stream_id", "sequence"} <= set(record)
                or record.get("schema") != "citadel.telemetry.v1"
                or record.get("workload") != self.workload or record.get("runtime_identity") != self.identity
                or not isinstance(record.get("method"), str) or record["method"] not in METHODS
                or type(record.get("status_code")) is not int
                or not 0 <= record["status_code"] <= 599
                or not isinstance(record.get("facts"), dict) or set(record["facts"]) - FACTS
                or not isinstance(record.get("caller", self.workload), str)
                or record.get("caller", self.workload) not in ACTORS
                or "target" in record and not hash_value(record["target"])
                or ("stream_id" in record) != ("sequence" in record)
                or "sequence" in record and (type(record["sequence"]) is not int or record["sequence"] < 1)):
            raise ValueError("Only owned allowlisted telemetry metadata may be exported")
        for name in ("event_id", "run_id", "operation_id", "request_id", "stream_id"):
            if name in record and (name != "request_id" or record[name]):
                opaque(record[name])
        for value in record["facts"].values():
            if isinstance(value, str):
                opaque(value)
            elif type(value) not in (int, float, bool):
                raise ValueError("Telemetry facts cannot contain payloads")
        body = json.dumps(record, sort_keys=True, allow_nan=False, separators=(",", ":"))
        if len(body.encode()) > MAX_RECORD_BYTES:
            raise ValueError("Telemetry record bound exceeded")
        log = ReadableLogRecord(LogRecord(timestamp=time.time_ns(), body=body,
            severity_number=SeverityNumber.INFO, severity_text="INFO", trace_id=0, span_id=0, attributes={}),
            self.resource)
        with self.condition:
            self.counts["submitted_records"] += 1
            if not self.accepting or len(self.queue) >= QUEUE_CAPACITY:
                self.counts["dropped_records"] += 1
                return False
            self.queue.append(log)
            self.condition.notify_all()
        return True

    def _request(self, request):
        if self.sent or request.http_request.method != "POST" or request.http_request.url != self.destination:
            raise ValueError("Telemetry replay or destination change refused")
        self.sent = True
        with self.condition:
            self.counts["delivery_attempts"] += 1

    def _response(self, response):
        response_id = response.http_response.headers.get("x-ms-request-id") or response.http_response.headers.get("Request-Id")
        try:
            response_id = opaque(response_id)
        except ValueError:
            response_id = None
        with self.condition:
            self.receipt = {"request_id": response_id, "status_code": response.http_response.status_code}
        data = response.http_response.body()
        if len(data) <= 65536 and response.http_response.status_code == 200:
            body = json.loads(data)
            self.acknowledged = (isinstance(body, dict)
                and type(body.get("itemsReceived")) is int and body["itemsReceived"] == self.batch_count
                and type(body.get("itemsAccepted")) is int and body["itemsAccepted"] == self.batch_count
                and not body.get("errors"))

    def _deliver(self):
        while True:
            with self.condition:
                self.condition.wait_for(lambda: self.queue or not self.accepting)
                if not self.queue:
                    return
                batch = [self.queue.popleft() for _ in range(min(len(self.queue), BATCH_SIZE))]
                self.inflight = True
            self.sent, self.acknowledged, self.batch_count = False, False, len(batch)
            try:
                result = self.exporter.export(batch)
                success = result == LogRecordExportResult.SUCCESS and self.acknowledged
            except Exception:
                success = False
            with self.condition:
                self.counts["acknowledged_records" if success else "failed_records"] += len(batch)
                self.inflight = False
                self.condition.notify_all()

    def flush(self, timeout=15):
        if type(timeout) not in (int, float) or not 0 <= timeout <= 15:
            raise ValueError("Telemetry flush must remain bounded")
        with self.condition:
            self.condition.wait_for(lambda: not self.queue and not self.inflight, timeout=timeout)
            return self.counts | self.receipt | {"queued_records": len(self.queue), "inflight": self.inflight,
                                 "ingestion_verified": False}

    def close(self, timeout=15):
        started = time.monotonic()
        with self.condition:
            self.accepting = False
            self.condition.notify_all()
        health = self.flush(timeout)
        self.worker.join(timeout=max(0, timeout - (time.monotonic() - started)))
        if not self.worker.is_alive():
            self.exporter.shutdown()
            self.exporter.client.close()
            self.credential.close()
        return health
