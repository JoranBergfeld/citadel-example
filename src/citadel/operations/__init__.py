"""Durable workload-local operations. Caller arguments come from gateway authentication."""

import asyncio
import math
import re
import time
from copy import deepcopy
from dataclasses import dataclass

from citadel.evidence.manifests import sha256


class OperationError(RuntimeError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def identity(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value):
        raise OperationError("invalid_input", "Expected a bounded opaque identity")
    return value


def operation_key(caller, action, operation_id):
    return "/".join(identity(value) for value in (caller, action, operation_id))


def empty_ledger():
    return {"schema_version": 1, "operations": {}, "drafts": {}, "findings": {}, "budgets": {},
            "runs": {}}


def bind_run(document, run_id, deadline):
    run = document["runs"].setdefault(run_id, {"deadline": deadline, "provenance": None})
    if run["deadline"] != deadline:
        raise OperationError("conflict", "A run cannot reset its inherited absolute deadline")
    return run


@dataclass(frozen=True)
class Ownership:
    key: str
    worker: str
    generation: int


class Operations:
    """One ledger per authority boundary; no process-local correctness state."""

    def __init__(self, ledger, *, workload, clock=time.time):
        self.ledger, self.workload, self.clock = ledger, identity(workload), clock

    def _deadline(self, deadline):
        if (type(deadline) not in (int, float) or not math.isfinite(deadline)
                or deadline <= self.clock()):
            raise OperationError("deadline", "The inherited absolute deadline has expired")

    @staticmethod
    def _status(record):
        return deepcopy({key: record[key] for key in (
            "operation_id", "run_id", "state", "input_hash", "deadline", "generation", "result",
        )})

    async def accept(self, caller, action, operation_id, inputs, *, run_id, deadline):
        key = operation_key(caller, action, operation_id)
        identity(run_id)
        binding = sha256({"inputs": inputs, "run_id": run_id, "deadline": deadline})
        document, etag = await self.ledger.read()
        record = document["operations"].get(key)
        if record:
            if record["input_hash"] != binding:
                raise OperationError("conflict", "Operation identity is bound to different input")
            return self._status(record)
        self._deadline(deadline)
        if deadline > self.clock() + 900:
            raise OperationError("deadline", "Operation cannot extend the 900-second run ceiling")
        bind_run(document, run_id, deadline)
        record = {
            "operation_id": operation_id, "run_id": run_id, "input_hash": binding,
            "state": "pending", "deadline": deadline, "generation": 0, "result": None,
            "worker": None, "lease_until": None,
            "external": {},
        }
        document["operations"][key] = record
        try:
            await self.ledger.commit(document, etag, deadline=deadline)
        except OperationError as exc:
            if exc.code != "conflict":
                raise
            current, _ = await self.ledger.read()
            existing = current["operations"].get(key)
            if existing is None or existing["input_hash"] != binding:
                raise
            return self._status(existing)
        return self._status(record)

    async def status(self, caller, action, operation_id):
        document, _ = await self.ledger.read()
        record = document["operations"].get(operation_key(caller, action, operation_id))
        return self._status(record) if record else {"state": "missing", "result": None}

    @staticmethod
    def _record(document, key):
        record = document["operations"].get(key)
        if record is None:
            raise OperationError("missing", "Missing status is not proof of non-execution")
        return record

    def _owned(self, document, ownership):
        record = self._record(document, ownership.key)
        if (record["state"] != "running" or record["worker"] != ownership.worker
                or record["generation"] != ownership.generation
                or self.clock() >= record["lease_until"]):
            raise OperationError("fenced", "Execution no longer owns this operation")
        self._deadline(record["deadline"])
        return record

    async def claim(self, caller, action, operation_id, *, worker, lease_seconds=60):
        identity(worker)
        if type(lease_seconds) is not int or not 1 <= lease_seconds <= 180:
            raise OperationError("invalid_input", "Execution lease must be 1–180 seconds")
        key = operation_key(caller, action, operation_id)
        document, etag = await self.ledger.read()
        record = self._record(document, key)
        self._deadline(record["deadline"])
        if record["state"] != "pending":
            raise OperationError("conflict", "Only pending work may be claimed; no crash replay")
        record.update(state="running", worker=worker, generation=record["generation"] + 1,
                      lease_until=min(record["deadline"], self.clock() + lease_seconds))
        await self.ledger.commit(document, etag, deadline=record["lease_until"])
        return Ownership(key, worker, record["generation"])

    async def renew(self, ownership, *, lease_seconds=60):
        if type(lease_seconds) is not int or not 1 <= lease_seconds <= 180:
            raise OperationError("invalid_input", "Execution lease must be 1–180 seconds")
        document, etag = await self.ledger.read()
        record = self._owned(document, ownership)
        old_expiry = record["lease_until"]
        record["lease_until"] = min(record["deadline"], self.clock() + lease_seconds)
        await self.ledger.commit(document, etag, deadline=min(old_expiry, record["lease_until"]))

    async def complete(self, ownership, *, product=None):
        document, etag = await self.ledger.read()
        record = self._owned(document, ownership)
        self._resolved(record)
        if product is not None:
            if self.workload not in ("candidate-planner", "briefing-author"):
                raise OperationError("forbidden", "Only planning workloads publish planning work products")
            if not isinstance(product, dict):
                raise OperationError("invalid_input", "Expected structured work product")
            record["product"] = deepcopy(product)
            record["result"] = {
                "kind": "work-product", "artifact_id": sha256(ownership.key),
                "version": 1, "sha256": sha256(product),
            }
        record["state"] = "succeeded"
        await self.ledger.commit(document, etag, deadline=min(record["deadline"], record["lease_until"]))
        return self._status(record)

    async def completed_result(self, caller, action, operation_id):
        document, _ = await self.ledger.read()
        record = self._record(document, operation_key(caller, action, operation_id))
        if record["state"] != "succeeded" or "product" not in record:
            raise OperationError("incomplete", "No atomically committed completed work product")
        return deepcopy(record["product"])

    async def fence(self, caller, action, operation_id):
        """Explicit recovery, never a restart replay. External ambiguity remains incomplete."""
        document, etag = await self.ledger.read()
        record = self._record(document, operation_key(caller, action, operation_id))
        if record["state"] in ("succeeded", "failed_no_commit", "indeterminate"):
            return self._status(record)
        if self.clock() < (record["lease_until"] or record["deadline"]):
            raise OperationError("conflict", "A live owner cannot be recovered")
        record["generation"] += 1
        record["state"] = ("indeterminate" if any(
            item["state"] != "failed_no_commit" for item in record["external"].values()
        ) else "failed_no_commit")
        # Recovery changes only status/fences, never business artifacts, after the run deadline.
        await self.ledger.commit(document, etag, deadline=self.clock() + 30)
        return self._status(record)

    @staticmethod
    def _resolved(record):
        if any(item["state"] not in ("succeeded", "failed_no_commit")
               for item in record["external"].values()):
            raise OperationError("indeterminate", "External effects remain unresolved")

    async def begin_external(self, ownership, request_id, input_hash):
        """Persist before invoking. An ambiguous admission response must not dispatch."""
        identity(request_id)
        if not isinstance(input_hash, str) or not re.fullmatch("[a-f0-9]{64}", input_hash):
            raise OperationError("invalid_input", "Expected exact downstream operation input hash")
        document, etag = await self.ledger.read()
        record = self._owned(document, ownership)
        if request_id in record["external"]:
            raise OperationError("conflict", "Do not replay an external invocation")
        record["external"][request_id] = {"input_hash": input_hash, "state": "indeterminate"}
        await self.ledger.commit(document, etag, deadline=min(record["deadline"], record["lease_until"]))

    async def reconcile_external(self, ownership, request_id, status):
        """Status must come from its separately authorized downstream status capability."""
        document, etag = await self.ledger.read()
        record = self._owned(document, ownership)
        external = record["external"].get(request_id)
        if external is None:
            raise OperationError("missing", "No admitted external request")
        if status.get("state") not in ("succeeded", "failed_no_commit"):
            return
        if status.get("input_hash") != external["input_hash"]:
            raise OperationError("conflict", "Reconciliation response belongs to different inputs")
        external["state"] = status["state"]
        await self.ledger.commit(document, etag, deadline=min(record["deadline"], record["lease_until"]))

    async def retry(self, caller, action, operation_id):
        document, etag = await self.ledger.read()
        record = self._record(document, operation_key(caller, action, operation_id))
        self._deadline(record["deadline"])
        if record["state"] != "failed_no_commit":
            raise OperationError("conflict", "Only fenced failed_no_commit permits explicit retry")
        record.update(state="pending", worker=None, lease_until=None)
        await self.ledger.commit(document, etag, deadline=record["deadline"])
        return self._status(record)

    async def recover_external(self, caller, action, operation_id, statuses):
        """Explicit post-fence reconciliation; each status comes from its authenticated owner route."""
        document, etag = await self.ledger.read()
        record = self._record(document, operation_key(caller, action, operation_id))
        if record["state"] != "indeterminate":
            raise OperationError("conflict", "Only fenced indeterminate work needs recovery")
        if not isinstance(statuses, dict) or statuses.keys() - record["external"].keys():
            raise OperationError("invalid_input", "Unknown downstream request")
        for request_id, status in statuses.items():
            external = record["external"][request_id]
            if status.get("state") not in ("succeeded", "failed_no_commit"):
                continue
            if (status.get("input_hash") != external["input_hash"]
                    or (external["state"] in ("succeeded", "failed_no_commit")
                        and external["state"] != status["state"])):
                raise OperationError("conflict", "Downstream receipt conflicts with recorded execution")
            external["state"] = status["state"]
        if all(item["state"] == "failed_no_commit" for item in record["external"].values()):
            record["state"] = "failed_no_commit"
        await self.ledger.commit(document, etag, deadline=self.clock() + 30)
        return self._status(record)

    def _authority(self, workload):
        if self.workload != workload:
            raise OperationError("forbidden", "This workload does not own that capability")

    @staticmethod
    def _bound(record, inputs):
        if sha256({"inputs": inputs, "run_id": record["run_id"],
                   "deadline": record["deadline"]}) != record["input_hash"]:
            raise OperationError("conflict", "Commit does not match the accepted input")

    @staticmethod
    def _provenance(document, record, provenance):
        run = bind_run(document, record["run_id"], record["deadline"])
        if run["provenance"] is not None and sha256(run["provenance"]) != sha256(provenance):
            raise OperationError("conflict", "Source/profile/fixture are fixed for this run")
        run["provenance"] = deepcopy(provenance)

    async def submit_draft(self, ownership, draft, *, expected_version, reference):
        self._authority("evidence-assessor")
        reference.shareable_projection(draft)
        document, etag = await self.ledger.read()
        record = self._owned(document, ownership)
        self._resolved(record)
        self._bound(record, {"draft": draft, "expected_version": expected_version})
        self._provenance(document, record, draft["provenance"])
        if draft["run_id"] != record["run_id"] or draft["operation_id"] != record["operation_id"]:
            raise OperationError("conflict", "Draft must belong to the accepted operation and run")
        versions = document["drafts"].setdefault(draft["artifact_id"], {})
        latest = max(map(int, versions), default=0)
        if (type(expected_version) is not int or expected_version != latest
                or draft["version"] != latest + 1):
            raise OperationError("conflict", "Expected preceding draft version differs")
        versions[str(draft["version"])] = deepcopy(draft)
        record.update(state="succeeded", result={
            "kind": "draft", "artifact_id": draft["artifact_id"],
            "version": draft["version"], "sha256": sha256(draft),
        })
        await self.ledger.commit(document, etag, deadline=min(record["deadline"], record["lease_until"]))
        return self._status(record)

    async def get_draft(self, artifact_id, version, digest):
        if self.workload not in ("evidence-assessor", "release-reviewer"):
            raise OperationError("forbidden", "Draft access is private to Evidence Review")
        return await DraftReader(self.ledger).get_draft(artifact_id, version, digest)

    async def release(self, ownership, draft_ref, *, drafts, reference):
        self._authority("release-reviewer")
        if not isinstance(draft_ref, dict) or draft_ref.keys() != {"artifact_id", "version", "sha256"}:
            raise OperationError("invalid_input", "Release requires an exact draft reference")
        draft = await drafts.get_draft(draft_ref["artifact_id"], draft_ref["version"], draft_ref["sha256"])
        projection = reference.shareable_projection(draft)
        finding_id = sha256({"draft_id": draft_ref["artifact_id"]})
        version = str(draft_ref["version"])
        # Only definitive precondition failures can repeat a conditional write.
        for attempt in range(3):
            document, etag = await self.ledger.read()
            record = self._record(document, ownership.key)
            self._bound(record, {"draft": draft_ref})
            if record["state"] == "succeeded":
                return self._status(record)
            self._owned(document, ownership)
            self._resolved(record)
            self._provenance(document, record, draft["provenance"])
            versions = document["findings"].setdefault(finding_id, {})
            finding = versions.get(version)
            if finding and finding["draft"] != draft_ref:
                raise OperationError("conflict", "A different hash already owns this draft version")
            if finding is None:
                if draft["run_id"] != record["run_id"]:
                    raise OperationError("conflict", "Initial release must belong to the draft's run")
                finding = {
                    **projection, "artifact_id": finding_id, "version": draft_ref["version"],
                    "operation_id": record["operation_id"], "reviewer": self.workload,
                }
                versions[version] = finding
            record.update(state="succeeded", result={
                "kind": "finding", "artifact_id": finding_id,
                "version": draft_ref["version"], "sha256": sha256(finding),
            })
            try:
                await self.ledger.commit(document, etag,
                                         deadline=min(record["deadline"], record["lease_until"]))
                return self._status(record)
            except OperationError as exc:
                if exc.code != "conflict" or attempt == 2:
                    raise
                await asyncio.sleep(2 ** attempt)

    async def get_finding(self, artifact_id, version):
        self._authority("release-reviewer")
        identity(artifact_id)
        if type(version) is not int or version < 1:
            raise OperationError("invalid_input", "An exact positive version is required")
        document, _ = await self.ledger.read()
        finding = document["findings"].get(artifact_id, {}).get(str(version))
        if finding is None:
            raise OperationError("not_found", "Finding version has not been released")
        return deepcopy(finding)


class DraftReader:
    """Use a read-only, reviewer-scoped Blob client on the assessor draft container."""

    def __init__(self, ledger):
        self.ledger = ledger

    async def get_draft(self, artifact_id, version, digest):
        identity(artifact_id)
        if type(version) is not int or version < 1:
            raise OperationError("invalid_input", "An exact positive version is required")
        document, _ = await self.ledger.read()
        draft = document["drafts"].get(artifact_id, {}).get(str(version))
        if draft is None:
            raise OperationError("not_found", "Draft version is not committed")
        if sha256(draft) != digest:
            raise OperationError("conflict", "Exact draft hash differs")
        return deepcopy(draft)
