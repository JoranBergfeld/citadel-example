"""Spend existing durable tickets on real reads; never prepay or refill a pool."""

import asyncio
import hashlib
import json
import math
import re
import time

from citadel.evidence.manifests import sha256
from citadel.operations import OperationError, identity
from .operation_oracle import _matched
from .oracle import hash_value


async def read_boundary(container, pool, *, enabled, workload, run_id, operation_id, deadline):
    if (enabled is not True or workload != "candidate-planner" or pool.capacity != 512
            or pool.scope != "acceptance/" + identity(run_id)
            or type(deadline) not in (int, float) or not math.isfinite(deadline)
            or not time.time() < deadline <= time.time() + 900):
        raise ValueError("A fresh allocated Candidate Planner read boundary is required")
    operation = identity(operation_id)
    blob = container.get_blob_client(f"acceptance/{run_id}/ledger-v1.json")
    steps = []
    for index in range(513):
        try:
            physical_deadline = await pool.admit()
        except OperationError as exc:
            return {"operation_id": operation, "deadline": deadline, "steps": steps,
                    "read_attempts": len(steps), "response": exc.code}
        row = {"operation_id": identity(f"{operation}-read{index:03}"),
               "target": hashlib.sha256(blob.url.encode()).hexdigest(), "started": time.time()}
        sent = False

        def once(request):
            nonlocal sent
            if sent or time.time() >= min(deadline, physical_deadline):
                raise OperationError("deadline", "Late or repeated physical read refused")
            sent = True
            request.http_request.headers["x-ms-client-request-id"] = row["operation_id"]

        def received(response):
            row.update(request_id=response.http_response.headers.get("x-ms-request-id"),
                       status_code=response.http_response.status_code,
                       etag=response.http_response.headers.get("ETag"))

        async with asyncio.timeout(max(0, min(deadline, physical_deadline) - time.time())):
            download = await blob.download_blob(timeout=5, raw_request_hook=once, raw_response_hook=received)
            if download.size > 4096:
                raise OperationError("result_limit", "Read control exceeds its fixed empty-ledger envelope")
            document = json.loads(await download.readall())
        row.update(finished=time.time(), sha256=sha256(document))
        steps.append(row)
    return {"operation_id": operation, "deadline": deadline, "steps": steps,
            "read_attempts": len(steps), "response": "unexpected_success"}


def read_snapshot(document):
    collections = ("operations", "drafts", "findings", "budgets", "runs")
    if (not isinstance(document, dict) or type(document.get("schema_version")) is not int
            or document["schema_version"] != 1
            or any(not isinstance(document.get(key), dict) for key in collections)):
        raise ValueError("Malformed independently observed read-boundary ledger")
    return {"artifact_count": sum(len(document[key]) for key in collections),
            "business_sha256": sha256(document)}


def evaluate_read_boundary(observation, snapshot, evidence, *, runtime_identity, observer_identity):
    blocked = {"check_id": observation.get("check_id") if isinstance(observation, dict) else None,
               "status": "blocked", "reason": "read_boundary_state_or_service_correlation_missing"}
    if (not isinstance(observation, dict) or not isinstance(snapshot, dict)
            or not isinstance(evidence, list) or any(not isinstance(row, dict) for row in evidence)
            or observation.get("check_id") != "limit.read_attempts_run"
            or observation.get("probe_id") != "limit.read_attempts_run"
            or observation.get("caller") != "candidate-planner"
            or observation.get("runtime_identity") != runtime_identity or runtime_identity == observer_identity
            or any(not isinstance(observation.get(key), str)
                   or not re.fullmatch("[A-Za-z0-9_-]{1,64}", observation[key]) for key in ("operation_id", "run_id"))
            or observation.get("status_code") != 201 or snapshot.get("status_code") not in (200, 206)
            or not hash_value(snapshot.get("sha256"))
            or not _matched(observation, evidence, "storage", runtime_identity, "PutBlob",
                            client_request_id=observation["operation_id"])
            or not _matched(snapshot, evidence, "storage", observer_identity, "GetBlob",
                            client_request_id=snapshot.get("operation_id"))
            or snapshot["started"] < observation["finished"]):
        return blocked
    actual = observation.get("actual")
    if (not isinstance(actual, dict) or actual.get("operation_id") != observation["operation_id"]
            or not isinstance(actual.get("steps"), list)
            or any(not isinstance(row, dict) for row in actual["steps"])):
        return blocked
    events = [row for row in evidence if isinstance(row.get("facts"), dict)
              and row["facts"].get("sha256") == sha256(actual)
              and row["facts"].get("probe_id") == "limit.read_attempts_run"]
    if not _matched(observation, events, "application", runtime_identity, "execution",
        run_id=observation["run_id"], operation_id=observation["operation_id"], caller="candidate-planner"):
        return blocked
    steps = actual["steps"]
    if (len(steps) != 512 or actual.get("response") != "exhausted"
            or type(actual.get("read_attempts")) is not int or actual["read_attempts"] != 512
            or any(row.get("operation_id") != observation["operation_id"] + f"-read{index:03}"
                or row.get("target") != snapshot["target"] or row.get("status_code") not in (200, 206)
                or not _matched(row, evidence, "storage", runtime_identity, "GetBlob",
                                client_request_id=row.get("operation_id"))
                or row["finished"] - row["started"] > 30
                or not observation["started"] <= row["started"] <= row["finished"] <= observation["finished"]
                for index, row in enumerate(steps))
            or len({row["request_id"] for row in steps}) != 512
            or any(steps[index]["started"] < steps[index - 1]["finished"] for index in range(1, 512))):
        return blocked
    physical = {row["request_id"] for row in evidence if row.get("source") == "storage"
        and row.get("method") == "GetBlob" and row.get("target") == snapshot["target"]
        and row.get("runtime_identity") == runtime_identity and isinstance(row.get("request_id"), str)
        and type(row.get("observed")) in (int, float)
        and observation["started"] - 5 <= row["observed"] <= observation["finished"] + 5}
    valid = (physical == {row["request_id"] for row in steps}
        and type(snapshot.get("artifact_count")) is int and snapshot["artifact_count"] == 0
        and hash_value(snapshot.get("business_sha256")) and snapshot["business_sha256"] == snapshot["sha256"]
        and all(row.get("sha256") == snapshot["sha256"] for row in steps)
        and type(actual.get("deadline")) in (int, float) and math.isfinite(actual["deadline"])
        and observation["finished"] <= actual["deadline"] <= observation["started"] + 900)
    return blocked | {"status": "pass" if valid else "fail", "business_state": "read_only",
        "reason": "verified_durable_read_boundary" if valid else "read_boundary_invariant_failed"}
