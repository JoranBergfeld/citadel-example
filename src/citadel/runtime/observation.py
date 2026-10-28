"""Narrow retained-run bindings and deployment-owned physical read admission."""

import asyncio
from contextlib import asynccontextmanager
from copy import deepcopy
import time

from citadel.evidence.manifests import sha256
from citadel.operations import OperationError, identity, operation_key
from .state import ScopedLedger, read_deadline, read_scope, reads
from .tickets import TicketPool


def empty_index():
    return {"schema_version": 1, "retained_runs": {}}


class DeploymentReads:
    capacities = {"observation": 16384, "recovery-proof": 2048}

    def __init__(self, store, deployment, *, clock=time.time):
        self.store, self.deployment, self.clock = store, identity(deployment), clock

    def scope(self, purpose):
        if purpose not in self.capacities:
            raise OperationError("forbidden", "Unknown deployment read purpose")
        return f"deployment/{self.deployment}/{purpose}"

    @asynccontextmanager
    async def request(self, purpose="observation", *, deadline=None):
        end = min(self.clock() + 30, deadline if deadline is not None else self.clock() + 30)
        if end <= self.clock():
            raise OperationError("deadline", "Observation deadline expired")
        pool = TicketPool(self.store, self.scope(purpose), self.capacities[purpose], clock=self.clock)
        async with asyncio.timeout(end - self.clock()):
            # Lease renewal is a write, not a recursive descriptor GET. Startup
            # never creates/funds a missing pool; deployment bootstrap owns it.
            with read_scope(pool, deadline=end):
                try:
                    await self.store.require_pool(pool.scope)
                except OperationError as exc:
                    if exc.code == "missing":
                        raise OperationError("unavailable", "Deployment read descriptor is unavailable") from None
                    raise
                yield

    async def charge(self):
        pool = reads.get()
        if pool is None or pool.scope not in (self.scope(p) for p in self.capacities):
            raise OperationError("forbidden", "A deployment observation scope is required")
        return await pool.admit()


class RunIndex:
    """Planner-owned bounded document; no scans, backfill, or refresh-time writes.

    Capacity is deliberately finite. A full index refuses new submissions rather
    than dropping ambiguous history. Exact input bindings precede run admission.
    """

    capacity = 256

    def __init__(self, ledger, admission, *, clock=time.time):
        self.ledger = ScopedLedger(ledger)
        self.admission, self.clock = admission, clock

    async def _read(self):
        try:
            document, etag = await self.ledger.read()
        except OperationError as exc:
            if exc.code == "missing":
                raise OperationError("unavailable", "Retained index source is unavailable") from None
            raise
        entries = document.get("retained_runs")
        if (type(document.get("schema_version")) is not int or document["schema_version"] != 1
                or not isinstance(entries, dict) or len(entries) > self.capacity):
            raise OperationError("unavailable", "Retained index is invalid")
        return document, etag

    async def register(self, caller, payload):
        run_id = identity(payload["run_id"])
        binding = {"caller": identity(caller), "run_id": run_id,
                   "operation_id": identity(payload["operation_id"]),
                   "fixture": payload["fixture"], "input_hash": sha256(payload),
                   "inputs": deepcopy(payload)}
        async with self.admission.request():
            document, etag = await self._read()
            entries = document["retained_runs"]
            if run_id in entries:
                if entries[run_id]["binding"] != binding:
                    raise OperationError("conflict", "Retained run inputs are immutable")
                return
            self.require_resolved_dispatch(entries)
            if len(entries) >= self.capacity:
                raise OperationError("exhausted", "Retained run index is full")
            entries[run_id] = {"binding": binding, "execution": "unknown",
                               "retained_at": self.clock(), "provenance": None, "assessed": [],
                               "assessed_complete": False}
            await self.ledger.commit(document, etag, deadline=read_deadline.get())

    @staticmethod
    def require_resolved_dispatch(entries):
        for entry in entries.values():
            submission = entry.get("submission", {})
            if (entry["execution"] == "unknown" and submission
                    and submission.get("reason") in ("unknown", "ambiguous_dispatch")):
                raise OperationError("conflict", "Unresolved hosted dispatch blocks new UI and CLI runs")

    async def update(self, run_id, state, *, provenance=None):
        async with self.admission.request():
            document, etag = await self._read()
            entry = document["retained_runs"].get(identity(run_id))
            if entry is None:
                raise OperationError("missing", "No retained binding")
            entry["execution"] = state
            if provenance is not None:
                if entry["provenance"] not in (None, provenance):
                    raise OperationError("conflict", "Original source binding cannot change")
                entry["provenance"] = deepcopy(provenance)
            await self.ledger.commit(document, etag, deadline=read_deadline.get())

    async def recovered_in_scope(self, binding, outcome):
        """Only a persisted safe owner outcome resolves an ambiguous dispatch."""
        expected = {"released_no_commit": "failed_no_commit",
                    "released_quiescent_partial": "indeterminate", "already_complete": "succeeded"}
        state = expected.get(outcome["state"])
        if state is None or outcome["execution"] != state:
            return
        document, etag = await self._read()
        entry = document["retained_runs"].get(binding["run_id"])
        if entry is None or entry["binding"] != binding:
            raise OperationError("conflict", "Recovery differs from the original retained binding")
        entry["execution"] = state
        await self.ledger.commit(document, etag, deadline=read_deadline.get())

    async def assessed(self, run_id, airport_ident, provenance, *, complete=False):
        """Only Planner's completed assessment handoff can extend this context."""
        airport_ident = identity(airport_ident)
        async with self.admission.request(deadline=read_deadline.get()):
            document, etag = await self._read()
            entry = document["retained_runs"].get(identity(run_id))
            if entry is None:
                raise OperationError("missing", "No retained binding")
            if (provenance["fixture"]["id"] != entry["binding"]["fixture"]
                    or entry["provenance"] not in (None, provenance)):
                raise OperationError("conflict", "Assessment source differs from retained inputs")
            candidates = entry.setdefault("assessed", [])
            if airport_ident in candidates:
                return
            if entry.get("assessed_complete"):
                raise OperationError("conflict", "Completed assessed context cannot be extended")
            if len(candidates) >= 20:
                raise OperationError("result_limit", "Assessed candidate bound exceeded")
            entry["provenance"] = deepcopy(provenance)
            candidates.append(airport_ident)
            entry["assessed_complete"] = complete
            await self.ledger.commit(document, etag, deadline=read_deadline.get())

    @staticmethod
    def summary(entry):
        binding = entry["binding"]
        return {"run_id": binding["run_id"], "fixture": binding["fixture"],
                "input_hash": binding["input_hash"], "execution": entry["execution"],
                "retained_at": entry["retained_at"]}

    async def page(self, cursor=None):
        async with self.admission.request():
            return await self.page_in_scope(cursor)

    async def page_in_scope(self, cursor=None):
        document, _ = await self._read()
        entries = document["retained_runs"]
        ids = list(entries)
        if cursor is not None:
            cursor = identity(cursor)
            if cursor not in entries:
                raise OperationError("invalid_input", "Unknown retained-run cursor")
        start = ids.index(cursor) + 1 if cursor else 0
        page = ids[start:start + 20]
        return {"state": "ok" if page else "empty",
                "runs": [self.summary(entries[key]) for key in page],
                "next_cursor": page[-1] if start + 20 < len(ids) else None}

    async def resolve(self, run_id):
        async with self.admission.request():
            return await self.resolve_in_scope(run_id)

    async def resolve_in_scope(self, run_id):
        document, _ = await self._read()
        entry = document["retained_runs"].get(identity(run_id))
        if entry is None:
            raise OperationError("missing", "Run is not in the retained index; no backfill is performed")
        return deepcopy(entry["binding"])

    async def observe(self, run_id, operation_ledger):
        binding = await self.resolve_in_scope(run_id)
        result = {"run_id": binding["run_id"], "fixture": binding["fixture"],
                  "input_hash": binding["input_hash"], "execution": "unknown",
                  "state": "partial", "bindings": {"inputs": binding["input_hash"], "source": None}}
        document, _ = await self._read()
        submission = document["retained_runs"][run_id].get("submission")
        if submission:
            result["submission_reason"] = submission["reason"]
        try:
            document, _ = await operation_ledger.read()
        except OperationError as exc:
            if exc.code in ("missing", "unavailable"):
                result["reason"] = "unavailable_source"
                return result
            raise
        record = document["operations"].get(operation_key(binding["caller"], "invoke", binding["operation_id"]))
        controls = [control for control in document.get("operator_controls", {}).values()
                    if control["binding"]["run_id"] == binding["run_id"]
                    and control["binding"]["operation"] == operation_key(
                        binding["caller"], "invoke", binding["operation_id"])
                    and control["binding"]["input_hash"] == binding["input_hash"]]
        if controls:
            latest = max(reversed(controls), key=lambda control: control["requested_at"])
            outcome = latest.get("outcome")
            result["recovery"] = ({key: outcome[key] for key in (
                "run_id", "request_id", "state", "execution", "reason", "recorded_at", "retryable")}
                if outcome else {"state": "unknown", "reason": "Control intent retained; outcome unknown."})
        if record is None:
            return result
        payload = binding["inputs"]
        expected = sha256({"inputs": payload, "run_id": binding["run_id"], "deadline": record["deadline"]})
        if record["input_hash"] != expected or record["run_id"] != binding["run_id"]:
            raise OperationError("conflict", "Historical operation differs from retained binding")
        result["execution"] = record["state"]
        result["state"] = "ok"
        # Only known-safe summary fields leave the owning service. Products,
        # drafts, receipts and private paths are not generic Operator payloads.
        product = record.get("product") or {}
        if product and (record.get("result") or {}).get("sha256") != sha256(product):
            raise OperationError("conflict", "Saved product differs from its exact immutable binding")
        if product:
            from .scenario_summary import scenario_summary
            result["summary"] = scenario_summary(product)
            if product.get("status") == "complete" and not product.get("brief"):
                result["state"] = "partial"
        elif record["state"] in ("indeterminate", "failed_no_commit"):
            result["outcome"] = "incomplete_execution"
            code = (record.get("result") or {}).get("code")
            result["technical_failure"] = code if code in (
                "unavailable", "deadline", "conflict", "exhausted", "forbidden") else "unknown"
        if product.get("provenance") is not None:
            result["bindings"]["source"] = provenance_projection(product["provenance"])
        else:
            result["state"] = "partial"
        result["bindings"]["operation"] = record["input_hash"]
        if (record.get("result") or {}).get("kind") == "work-product":
            result["bindings"]["product"] = {
                key: record["result"][key] for key in ("artifact_id", "version", "sha256")}
        return result


def provenance_projection(value):
    return {
        "schema_version": value["schema_version"],
        "source": {key: value["source"][key] for key in ("kind", "snapshot", "sha256")},
        "profile": {key: value["profile"][key] for key in ("id", "version", "sha256")},
        "fixture": {key: value["fixture"][key] for key in ("id", "version", "sha256")},
        "evidence_origin": value["evidence_origin"],
    }
