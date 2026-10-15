"""Payload-free application records for the existing ACA Azure Monitor exporter.

Writing a record is not delivery proof. Only the collector's cloud query may
establish ingestion; lost or missing records block acceptance.
"""

import hashlib
import json
import re
import sys
from contextlib import contextmanager
from contextvars import ContextVar
from uuid import UUID, uuid4


ACTORS = {"operator", "candidate-planner", "evidence-assessor", "release-reviewer",
          "briefing-author", "reference-data"}
METHODS = {"SendMessage", "GetTask", "discovery", "status", "findings-read", "initialize",
           "tools/call", "search_airports", "lookup_airport", "list_runways", "chat.completions",
           "storage.read", "storage.write", "storage.lease", "execution", "probe",
           "mcp.GET", "mcp.DELETE", "ping", "tools/list", "notifications/initialized"}
FACTS = {"generation", "read_attempts", "agent_executions", "model_attempts", "input_tokens",
         "output_tokens", "tokens", "deadline", "retry", "artifact_count", "sha256",
         "business_state", "probe_id", "status_code", "before_sha256", "after_sha256"}
_correlation = ContextVar("citadel_evidence_correlation", default={})
_exporter = None


def opaque(value):
    if not isinstance(value, str) or not re.fullmatch("[A-Za-z0-9_.:-]{1,128}", value):
        raise ValueError("Expected bounded nonsecret identifier")
    return value


@contextmanager
def correlate(run_id, operation_id, caller):
    if caller not in ACTORS:
        raise ValueError("Unknown caller")
    token = _correlation.set({"run_id": opaque(run_id), "operation_id": opaque(operation_id),
                              "caller": caller})
    try:
        yield
    finally:
        _correlation.reset(token)


class Telemetry:
    def __init__(self, workload, principal_id, *, output=None):
        if workload not in ACTORS - {"operator"}:
            raise ValueError("Unknown runtime")
        self.workload = workload
        self.identity = hashlib.sha256(str(UUID(principal_id)).encode()).hexdigest()
        self.output = output or sys.stdout

    def emit(self, method, *, request_id, status_code, facts=None, target=None):
        if method not in METHODS or type(status_code) is not int or not 0 <= status_code <= 599:
            raise ValueError("Invalid telemetry metadata")
        clean = {}
        for key, value in (facts or {}).items():
            if key not in FACTS:
                continue
            if type(value) in (int, float, bool):
                clean[key] = value
            elif isinstance(value, str):
                clean[key] = opaque(value)
        record = {"schema": "citadel.telemetry.v1", "event_id": uuid4().hex,
                  "workload": self.workload, "runtime_identity": self.identity,
                  "method": method, "request_id": opaque(request_id) if request_id else "",
                  "status_code": status_code, "facts": clean, **_correlation.get()}
        if target is not None:
            if not isinstance(target, str) or not re.fullmatch("[a-f0-9]{64}", target):
                raise ValueError("Only a hashed service target may enter telemetry")
            record["target"] = target
        self.output.write(json.dumps(record, sort_keys=True, allow_nan=False) + "\n")
        self.output.flush()


def configure(workload, principal_id):
    global _exporter
    _exporter = Telemetry(workload, principal_id)


def emit(method, *, request_id=None, status_code=0, facts=None, target=None):
    if _exporter is not None:
        _exporter.emit(method, request_id=request_id, status_code=status_code, facts=facts, target=target)


def correlation_headers():
    current = _correlation.get()
    return {f"x-citadel-{key.replace('_', '-')}": value for key, value in current.items()
            if key in ("run_id", "operation_id")}


def storage_response(response):
    if _exporter is None:
        return
    headers = response.http_response.headers
    method = response.http_request.method
    emit("storage.read" if method in ("GET", "HEAD") else "storage.write",
         request_id=headers.get("x-ms-request-id"),
         status_code=response.http_response.status_code,
         target=hashlib.sha256(response.http_request.url.split("?", 1)[0].encode()).hexdigest())
