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
    execution_read_capacity = 64

    def __init__(self, ledger, admission, *, clock=time.time, execution_store=None):
        self.ledger = ScopedLedger(ledger)
        self.admission, self.clock = admission, clock
        self.execution_store = execution_store or getattr(ledger, "ticket_store", None)

    @asynccontextmanager
    async def execution(self, run_id):
        if self.execution_store is None:
            raise OperationError("unavailable", "Durable execution-index read storage is required")
        deadline = read_deadline.get()
        end = min(self.clock() + 30, deadline if deadline is not None else self.clock() + 30)
        if end <= self.clock():
            raise OperationError("deadline", "Execution-index read deadline expired")
        pool = TicketPool(self.execution_store, "retained-index/" + identity(run_id),
                          self.execution_read_capacity, clock=self.clock)
        async with asyncio.timeout(max(0, end - self.clock())):
            await self.execution_store.open_pool(pool.scope)
            with read_scope(pool, deadline=end):
                yield

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

    @staticmethod
    def binding(caller, payload):
        run_id = identity(payload["run_id"])
        return {"caller": identity(caller), "run_id": run_id,
                "operation_id": identity(payload["operation_id"]),
                "fixture": payload["fixture"], "input_hash": sha256(payload),
                "inputs": deepcopy(payload)}

    async def reserve(self, caller, payload, *, request_id=None):
        binding = self.binding(caller, payload)
        run_id = binding["run_id"]
        async with self.execution(run_id):
            document, etag = await self._read()
            entries = document["retained_runs"]
            if run_id in entries:
                entry = entries[run_id]
                if (entry["binding"] != binding or request_id is not None
                        and entry.get("submission", {}).get("request_id") != request_id):
                    raise OperationError("conflict", "Retained run inputs are immutable")
                return deepcopy(entry), False
            self.require_resolved_dispatch(entries)
            if len(entries) >= self.capacity:
                raise OperationError("exhausted", "Retained run index is full")
            entries[run_id] = {"binding": binding, "execution": "unknown",
                               "retained_at": self.clock(), "provenance": None, "assessed": [],
                               "assessed_complete": False, "decisions": []}
            if request_id is not None:
                entries[run_id]["submission"] = {
                    "request_id": identity(request_id), "dispatch": "intent", "reason": "unknown"}
            await self.ledger.commit(document, etag, deadline=read_deadline.get())
            return deepcopy(entries[run_id]), True

    async def register(self, caller, payload):
        await self.reserve(caller, payload)

    async def record_submission(self, run_id, execution, reason):
        async with self.execution(run_id):
            document, etag = await self._read()
            entry = document["retained_runs"][identity(run_id)]
            entry["submission"].update(dispatch="recorded", reason=reason)
            if entry["execution"] == "unknown":
                entry["execution"] = execution
            await self.ledger.commit(document, etag, deadline=read_deadline.get())
            return deepcopy(entry)

    @staticmethod
    def require_resolved_dispatch(entries):
        for entry in entries.values():
            submission = entry.get("submission", {})
            if (entry["execution"] == "unknown" and submission
                    and submission.get("reason") in ("unknown", "ambiguous_dispatch")):
                raise OperationError("conflict", "Unresolved hosted dispatch blocks new UI and CLI runs")

    async def update(self, run_id, state, *, provenance=None, generation=None):
        async with self.execution(run_id):
            document, etag = await self._read()
            entry = document["retained_runs"].get(identity(run_id))
            if entry is None:
                raise OperationError("missing", "No retained binding")
            if generation is not None:
                if generation < entry.get("generation", 0):
                    return
                entry["generation"] = generation
            entry["execution"] = state
            if provenance is not None:
                if entry["provenance"] not in (None, provenance):
                    raise OperationError("conflict", "Original source binding cannot change")
                entry["provenance"] = deepcopy(provenance)
            await self.ledger.commit(document, etag, deadline=read_deadline.get())

    async def recovered_in_scope(self, binding, outcome, current):
        """Only a persisted safe owner outcome resolves an ambiguous dispatch."""
        expected = {"released_no_commit": "failed_no_commit",
                    "released_quiescent_partial": "indeterminate", "already_complete": "succeeded",
                    "retry_admitted": "running"}
        state = expected.get(outcome["state"])
        if state is None or outcome["execution"] != state:
            return
        generation = outcome.get("generation")
        if (type(generation) is not int or current["generation"] != generation
                or current["state"] != state):
            return
        document, etag = await self._read()
        entry = document["retained_runs"].get(binding["run_id"])
        if entry is None or entry["binding"] != binding:
            raise OperationError("conflict", "Recovery differs from the original retained binding")
        if generation < entry.get("generation", 0):
            return
        entry["generation"] = generation
        entry["execution"] = state
        await self.ledger.commit(document, etag, deadline=read_deadline.get())

    async def require_resolved_in_scope(self):
        document, _ = await self._read()
        self.require_resolved_dispatch(document["retained_runs"])

    async def assessed(self, run_id, airport_ident, provenance, *, complete=False, decision=None):
        """Only Planner's completed assessment handoff can extend this context."""
        airport_ident = identity(airport_ident)
        async with self.execution(run_id):
            document, etag = await self._read()
            entry = document["retained_runs"].get(identity(run_id))
            if entry is None:
                raise OperationError("missing", "No retained binding")
            if (provenance["fixture"]["id"] != entry["binding"]["fixture"]
                    or entry["provenance"] not in (None, provenance)):
                raise OperationError("conflict", "Assessment source differs from retained inputs")
            candidates = entry.setdefault("assessed", [])
            if decision is not None and decision["airport_ident"] != airport_ident:
                raise OperationError("conflict", "Decision differs from assessed candidate")
            if airport_ident in candidates:
                decisions = entry.setdefault("decisions", [])
                previous = next((item for item in decisions if item["airport_ident"] == airport_ident), None)
                if (previous is not None and decision is not None
                        and previous.get("reason") == "finding_details_unavailable"):
                    if previous["finding"] != decision["finding"]:
                        raise OperationError("conflict", "Assessment finding binding cannot change")
                    decisions[decisions.index(previous)] = deepcopy(decision)
                    entry["assessed_complete"] = complete
                    await self.ledger.commit(document, etag, deadline=read_deadline.get())
                return
            if entry.get("assessed_complete"):
                raise OperationError("conflict", "Completed assessed context cannot be extended")
            if len(candidates) >= 20:
                raise OperationError("result_limit", "Assessed candidate bound exceeded")
            entry["provenance"] = deepcopy(provenance)
            candidates.append(airport_ident)
            if decision is not None:
                entry.setdefault("decisions", []).append(deepcopy(decision))
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
        return (await self.context_in_scope(run_id))["binding"]

    async def context_in_scope(self, run_id):
        document, _ = await self._read()
        entry = document["retained_runs"].get(identity(run_id))
        if entry is None:
            raise OperationError("missing", "Run is not in the retained index; no backfill is performed")
        binding = entry["binding"]
        if (binding["run_id"] != run_id or binding["inputs"]["run_id"] != run_id
                or binding["inputs"]["fixture"] != binding["fixture"]
                or sha256(binding["inputs"]) != binding["input_hash"]):
            raise OperationError("conflict", "Retained inputs differ")
        return deepcopy(entry)

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
        from .retry import require_retry
        result["retryable"] = False
        try:
            require_retry(record, document["budgets"].get(binding["operation_id"]), self.clock())
            result["retryable"] = True
        except OperationError:
            pass
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
