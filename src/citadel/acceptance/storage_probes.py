"""Actual-MI Blob boundary probes against isolated, known disposable objects."""

import asyncio
import hashlib
import json
import math
import re
import time
from uuid import UUID, uuid4

from azure.core import MatchConditions
from azure.core.exceptions import AzureError, HttpResponseError, ResourceNotFoundError
from azure.storage.blob.aio import BlobClient

from citadel.evidence.manifests import canonical_bytes, sha256
from citadel.operations import OperationError, identity
from citadel.operations.blob import API_VERSION, MAX_LEDGER_BYTES
from citadel.runtime.configuration import endpoint, OPERATIONS
from .coverage import CONTAINERS, STORAGE
from .oracle import evaluate_control, hash_value
from .telemetry import correlate, storage_response


def storage_target(suite_id):
    return f"acceptance/{identity(suite_id)}/storage-boundary-v1.json"


def _target(value):
    if (not isinstance(value, dict) or not hash_value(value.get("sha256"))
            or not isinstance(value.get("etag"), str) or not 1 <= len(value["etag"]) <= 128
            or any(c in value["etag"] for c in "\r\n")):
        raise ValueError("A known, hashed, conditionally writable disposable object is required")


def validate_storage_manifest(manifest):
    if (not isinstance(manifest, dict) or set(manifest) != {"suite_id", "targets"}
            or not isinstance(manifest["targets"], dict) or set(manifest["targets"]) != set(CONTAINERS)):
        raise ValueError("An exact fixed-container manifest is required")
    storage_target(manifest["suite_id"])
    for target in manifest["targets"].values():
        if not isinstance(target, dict) or set(target) != {"sha256", "etag"}:
            raise ValueError("Storage manifests cannot supply payloads, credentials or destinations")
        _target(target)


class StorageProbe:
    def __init__(self, *, account, credential, workload, principal_id, enabled, run_id,
                 suite_id, deadline, admit, transport=None):
        if enabled is not True or workload not in STORAGE:
            raise ValueError("Storage probes require explicit mode and an allocated workload")
        if (type(deadline) not in (float, int) or not math.isfinite(deadline)
                or not time.time() < deadline <= time.time() + 900 or not callable(admit)):
            raise ValueError("Storage probes require bounded admission")
        self.account = endpoint(account, ".blob.core.windows.net")
        self.credential, self.workload, self.deadline = credential, workload, deadline
        self.principal = hashlib.sha256(str(UUID(principal_id)).encode()).hexdigest()
        self.run_id, self.name = identity(run_id), storage_target(suite_id)
        self.suite_id = identity(suite_id)
        self.admit, self.transport, self.known = admit, transport, {}

    async def observe(self, container, action, target):
        if container not in CONTAINERS or action not in ("read", "write"):
            raise ValueError("Only fixed storage-boundary capabilities may be probed")
        _target(target)
        if time.time() >= self.deadline:
            raise OperationError("deadline", "No probe dispatch after its inherited deadline")
        await self.admit()
        operation = uuid4().hex
        record = {"check_id": f"storage.{self.workload}.{container}.{action}",
                  "run_id": self.run_id, "operation_id": operation, "caller": self.workload,
                  "runtime_identity": self.principal, "container": container, "action": action,
                  "suite_id": self.suite_id,
                  "target": hashlib.sha256(f"{self.account}/{container}/{self.name}".encode()).hexdigest(),
                  "started": time.time(), "status": "blocked", "reason": "service_response_missing"}
        sent = False

        def once(request):
            nonlocal sent
            if sent or time.time() >= self.deadline:
                raise OperationError("deadline" if not sent else "exhausted",
                                     "Hidden retry or late storage probe dispatch refused")
            sent = True
            request.http_request.headers["x-ms-client-request-id"] = operation

        def observed(response):
            storage_response(response)
            record.update(request_id=response.http_response.headers.get("x-ms-request-id"),
                          status_code=response.http_response.status_code,
                          reason=response.http_response.headers.get("x-ms-error-code", "observed"))

        options = {"transport": self.transport} if self.transport is not None else {}
        try:
            async with BlobClient(self.account, container, self.name, credential=self.credential,
                    api_version=API_VERSION, retry_total=0, retry_connect=0, retry_read=0, retry_status=0,
                    connection_timeout=5, read_timeout=30, max_single_get_size=MAX_LEDGER_BYTES + 1,
                    max_single_put_size=MAX_LEDGER_BYTES, **options) as client:
                with correlate(self.run_id, operation, self.workload):
                    async with asyncio.timeout(max(0, min(30, self.deadline - time.time()))):
                        if action == "read":
                            download = await client.download_blob(
                                offset=0, length=MAX_LEDGER_BYTES + 1, max_concurrency=1, timeout=30,
                                raw_request_hook=once, raw_response_hook=observed)
                            content = await download.readall()
                            if len(content) > MAX_LEDGER_BYTES:
                                raise OperationError("result_limit", "Probe target exceeds ledger bound")
                            digest = hashlib.sha256(content).hexdigest()
                            record.update(sha256=digest, etag=download.properties.etag)
                            if digest == target["sha256"]:
                                self.known[container] = content
                            else:
                                record["reason"] = "known_target_changed"
                        else:
                            content = self.known.get(container, canonical_bytes({
                                "schema_version": 1, "kind": "disposable-boundary-write",
                                "run_id": self.run_id}))
                            result = await client.upload_blob(
                                content, overwrite=True, etag=target["etag"],
                                match_condition=MatchConditions.IfNotModified, max_concurrency=1,
                                timeout=30, raw_request_hook=once, raw_response_hook=observed)
                            record["etag"] = result.get("etag")
        except HttpResponseError:
            # Raw service code/ID above, never exception text or target contents.
            pass
        except (AzureError, TimeoutError, OperationError):
            record["reason"] = "storage_outcome_unavailable_or_ambiguous"
        record["finished"] = time.time()
        return record


class StorageControls:
    """Operator observes/seeds isolated copies; never impersonates a workload."""

    def __init__(self, native, *, account, suite_id, admit):
        self.native, self.account, self.suite_id, self.admit = native, endpoint(
            account, ".blob.core.windows.net"), identity(suite_id), admit
        self.name = storage_target(suite_id)

    def _record(self, container, action, name):
        if container not in CONTAINERS:
            raise ValueError("Unallocated observer target")
        record = {"caller": "operator", "suite_id": self.suite_id, "container": container,
                  "action": action, "operation_id": uuid4().hex, "started": time.time(),
                  "target": hashlib.sha256(f"{self.account}/{container}/{name}".encode()).hexdigest()}
        sent = False

        def once(request):
            nonlocal sent
            if sent:
                raise OperationError("exhausted", "Hidden observer retry refused")
            self.admit()
            sent = True
            request.http_request.headers["x-ms-client-request-id"] = record["operation_id"]

        def received(response):
            record.update(request_id=response.http_response.headers.get("x-ms-request-id"),
                          status_code=response.http_response.status_code)

        return record, once, received

    def _read(self, container, name):
        record, once, received = self._record(container, "read", name)
        with self.native.blob(self.account, container, name) as blob:
            result = blob.download_blob(offset=0, length=MAX_LEDGER_BYTES + 1, max_concurrency=1,
                                        raw_request_hook=once, raw_response_hook=received, timeout=30)
            content = result.readall()
            if len(content) > MAX_LEDGER_BYTES:
                raise OperationError("result_limit", "Observer target exceeds ledger bound")
            record.update(sha256=hashlib.sha256(content).hexdigest(), etag=result.properties.etag,
                          count=1, finished=time.time())
        return record, content

    def prepare(self):
        seeds = {}
        for container in CONTAINERS:
            original = "bundle-manifest.json" if container == "reference" else "ledger-v1.json"
            _, content = self._read(container, original)
            if container in ("drafts", "findings"):
                try:
                    source = json.loads(content)
                except (ValueError, UnicodeError):
                    raise OperationError("missing", "Source product ledger is invalid") from None
                if (not isinstance(source, dict) or not isinstance(source.get(container), dict)
                        or not source[container]):
                    raise OperationError("missing", "Known real disposable draft/finding products are required")
            record, once, received = self._record(container, "write", self.name)
            with self.native.blob(self.account, container, self.name) as blob:
                blob.upload_blob(content, overwrite=False, max_concurrency=1, timeout=30,
                                 raw_request_hook=once, raw_response_hook=received)
            record.update(sha256=hashlib.sha256(content).hexdigest(), count=1, finished=time.time())
            seeds[container] = record
        return seeds

    def snapshot(self):
        return {container: self._read(container, self.name)[0] for container in CONTAINERS}

    def operation_state(self, run_id):
        record, content = self._read("planner-operations",
                                     f"acceptance/{identity(run_id)}/ledger-v1.json")
        try:
            document = json.loads(content)
            if (not isinstance(document, dict) or document.get("schema_version") != 1
                    or any(not isinstance(document.get(key), dict)
                           for key in ("operations", "drafts", "findings", "budgets", "runs"))):
                raise ValueError()
        except (ValueError, UnicodeError):
            raise OperationError("data_integrity", "Disposable operation state is malformed") from None
        return record, document

    def products(self):
        records = {}
        for container in ("drafts", "findings"):
            record, content = self._read(container, "ledger-v1.json")
            try:
                document = json.loads(content)
            except (ValueError, UnicodeError):
                raise OperationError("missing", "Business product snapshot is invalid") from None
            if not isinstance(document, dict) or not isinstance(document.get(container), dict):
                raise OperationError("missing", "Business product snapshot is invalid")
            record["count"] = len(document[container])
            records[container] = record
        return records

    def release_source(self, run_ids):
        from .release_probes import validate_source
        if not isinstance(run_ids, list) or not 0 < len(run_ids) <= 4:
            raise ValueError("Bounded completed scenario runs required")
        for run_id in run_ids:
            identity(run_id)
        record, content = self._read("findings", "ledger-v1.json")
        try:
            document = json.loads(content)
            if document["schema_version"] != 1 or not isinstance(document["findings"], dict):
                raise ValueError()
            for versions in document["findings"].values():
                if not isinstance(versions, dict):
                    raise ValueError()
                for finding in versions.values():
                    if not isinstance(finding, dict):
                        raise ValueError()
                    if finding.get("run_id") in run_ids and finding.get("reviewer") == "release-reviewer":
                        source = validate_source({"run_id": finding["run_id"], "draft": finding["draft"]})
                        return {"release_source": source, "observation": record,
                            "projection_sha256": sha256({
                                key: value for key, value in finding.items() if key != "operation_id"})}
        except (KeyError, TypeError, ValueError, UnicodeError):
            raise OperationError("data_integrity", "Observed release source is malformed") from None
        raise OperationError("missing", "A genuine released comparison draft is required")

    def release_state(self, run_id, operation_id):
        record, content = self._read("findings",
            f"acceptance/{identity(run_id)}/releases/{identity(operation_id)}.json")
        try:
            document = json.loads(content)
            if (not isinstance(document, dict) or document.get("schema_version") != 1
                    or any(not isinstance(document.get(key), dict)
                           for key in ("operations", "drafts", "findings", "budgets", "runs"))):
                raise ValueError()
        except (ValueError, UnicodeError):
            raise OperationError("data_integrity", "Isolated release state is malformed") from None
        return record, document

    def route_context(self, run_ids):
        from .route_context import build_route_context
        if not isinstance(run_ids, list) or not 0 < len(run_ids) <= 4:
            raise ValueError("Approved scenario run identities are required")
        for run_id in run_ids:
            identity(run_id)
        documents, observations = {}, []
        for actor, container in {**OPERATIONS, "findings": "findings"}.items():
            record, content = self._read(container, "ledger-v1.json")
            try:
                document = json.loads(content)
                if not isinstance(document, dict) or document.get("schema_version") != 1:
                    raise ValueError()
            except (ValueError, UnicodeError):
                raise OperationError("data_integrity", "Actual route control ledger is malformed") from None
            documents[actor] = document
            observations.append(record)
        from citadel.runtime.tickets import CAPACITY
        from citadel.gateway.trust import INVOCATION_CALLERS
        available, tickets = {}, []
        for actor in ("evidence-assessor", "release-reviewer"):
            owner = next(iter(INVOCATION_CALLERS[actor]))
            rows = [row for key, row in documents[actor].get("operations", {}).items()
                if isinstance(row, dict) and row.get("state") == "succeeded" and row.get("run_id") in run_ids
                and isinstance(row.get("operation_id"), str)
                and key == owner + "/invoke/" + row["operation_id"]]
            if not 0 < len(rows) <= 20:
                raise ValueError("Bounded completed owner pools are required")
            available[actor] = set()
            for row in rows:
                operation = identity(row["operation_id"])
                scope = owner + "/invoke/" + operation
                name = f"read-tickets/{sha256(scope)}/{CAPACITY[actor] - 1:03}.json"
                record, once, received = self._record(OPERATIONS[actor], "read", name)
                try:
                    with self.native.blob(self.account, OPERATIONS[actor], name) as blob:
                        content = blob.download_blob(offset=0, length=10, max_concurrency=1,
                            raw_request_hook=once, raw_response_hook=received, timeout=30).readall()
                    if content not in (b"spent", b"delegated"):
                        raise ValueError("Existing ticket marker is malformed")
                    record.update(state="spent", sha256=hashlib.sha256(content).hexdigest(), count=1)
                except ResourceNotFoundError:
                    if record.get("status_code") != 404:
                        raise ValueError("Missing marker requires an actual service response") from None
                    record.update(state="unspent", count=0)
                    available[actor].add(operation)
                record["finished"] = time.time()
                tickets.append(record)
        return {"context": build_route_context(documents, run_ids=run_ids, available=available),
                "observations": observations, "ticket_reads": tickets}


def _correlated(record, evidence, expected_identity, *, application=False):
    required = ("request_id", "status_code", "started", "finished", "operation_id")
    if (any(key not in record for key in required) or not hash_value(expected_identity)
            or any(not isinstance(record.get(key), str)
                   or re.fullmatch("[A-Za-z0-9_.:-]{1,128}", record[key]) is None
                   for key in ("request_id", "operation_id"))
            or type(record["status_code"]) is not int or not 100 <= record["status_code"] <= 599
            or record.get("action") not in ("read", "write")
            or any(type(record[k]) not in (int, float) or not math.isfinite(record[k])
                   for k in ("started", "finished"))
            or not 0 <= record["finished"] - record["started"] <= 900):
        return False
    return any(item.get("source") == ("application" if application else "storage")
               and item.get("request_id") == record["request_id"]
               and item.get("runtime_identity") == expected_identity
               and hash_value(record.get("target")) and item.get("target") == record["target"]
               and item.get("method") == (
                   "storage." + record["action"] if application else
                   "GetBlob" if record.get("action") == "read" else "PutBlob")
               and item.get("status_code") == record["status_code"]
               and item.get("operation_id" if application else "client_request_id") == record["operation_id"]
               and type(item.get("observed")) in (int, float)
               and record["started"] - 5 <= item["observed"] <= record["finished"] + 5
               and (not application or (item.get("run_id") == record.get("run_id")
                    and item.get("operation_id") == record.get("operation_id")
                    and item.get("caller") == record.get("caller")))
               for item in evidence)


def evaluate_storage(observation, control, snapshots, evidence, identities):
    blocked = {"check_id": observation.get("check_id"), "status": "blocked",
               "reason": "storage_control_or_snapshot_missing"}
    actor, container, action = (observation.get(k) for k in ("caller", "container", "action"))
    if (not isinstance(actor, str) or actor not in STORAGE
            or container not in CONTAINERS or action not in ("read", "write")):
        return blocked
    expected_id = f"storage.{actor}.{container}.{action}"
    if observation.get("check_id") != expected_id or observation.get("runtime_identity") != identities.get(actor):
        return blocked
    allowed = STORAGE[actor].get(container) == "write" or action == "read" and container in STORAGE[actor]
    if (not allowed and type(observation.get("status_code")) is int
            and 200 <= observation["status_code"] < 300
            and all(_correlated(observation, evidence, identities[actor], application=application)
                    for application in (False, True))):
        return blocked | {"status": "fail", "reason": "forbidden_storage_capability_succeeded"}
    control_actor = control.get("caller")
    if not isinstance(control_actor, str):
        return blocked
    grant = STORAGE.get(control_actor, {}).get(container)
    if (control.get("container") != container or control.get("action") != action
            or not observation.get("suite_id") or control.get("suite_id") != observation["suite_id"]
            or control.get("target") != observation.get("target")
            or not (grant == "write" or action == "read" and grant == "read"
                    or container == "reference" and control_actor == "operator")
            or control.get("request_id") == observation.get("request_id")
            or not _correlated(control, evidence, identities.get(control_actor))):
        return blocked
    before, after = snapshots.get("before", {}), snapshots.get("after", {})
    for snapshot in (before, after):
        if (snapshot.get("container") != container or not hash_value(snapshot.get("sha256"))
                or snapshot.get("action") != "read" or snapshot.get("status_code") not in (200, 206)
                or snapshot.get("suite_id") != observation["suite_id"]
                or snapshot.get("target") != observation.get("target")
                or type(snapshot.get("count")) is not int or snapshot["count"] != 1
                or not _correlated(snapshot, evidence, identities.get("operator"))):
            return blocked
    if (before["finished"] > observation.get("started", 0)
            or after["started"] < observation.get("finished", float("inf"))):
        return blocked | {"reason": "no_effect_snapshot_order_unverified"}
    if action == "read" and control.get("sha256") != before["sha256"]:
        return blocked | {"status": "fail", "reason": "working_control_target_mismatch"}
    for record, caller in ((observation, actor), (control, control_actor)):
        if not _correlated(record, evidence, identities.get(caller), application=caller != "operator"):
            return blocked | {"reason": "storage_runtime_correlation_missing"}
    if action == "read" and allowed and observation.get("sha256") != before["sha256"]:
        return blocked | {"status": "fail", "reason": "known_target_read_mismatch"}
    if before["sha256"] != after["sha256"]:
        return blocked | {"status": "fail", "reason": "disposable_target_changed"}
    proof = observation | {
        "expected": "allow" if allowed else "deny", "control_request_id": control["request_id"],
        "control_status": control["status_code"], "control_identity": identities[control_actor],
        "before_sha256": before["sha256"], "after_sha256": after["sha256"],
        "before_count": before["count"], "after_count": after["count"], "sources": ["storage"],
        "started": min(r["started"] for r in (observation, control, before, after)),
        "finished": max(r["finished"] for r in (observation, control, before, after))}
    return evaluate_control(proof, evidence)
