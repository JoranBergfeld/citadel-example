"""Durable, conservatively charged budgets delegated only over existing A2A edges.

The model-admission baton follows one outstanding child at a time. Parent budgets
are charged in full before delegation and never refunded, even after ambiguity.
No workload needs another team's storage identity or a new callback route.
"""

import asyncio
import math
import time
from copy import deepcopy
from threading import Lock
from uuid import uuid4

from citadel.evidence.manifests import sha256
from . import OperationError, bind_run, identity

CEILINGS = {"agents": 42, "models": 128, "tokens": 1_000_000, "reads": 512}
EDGES = {
    "candidate-planner": {"evidence-assessor", "briefing-author"},
    "evidence-assessor": {"release-reviewer"},
    "release-reviewer": set(), "briefing-author": set(),
}


class ReadAllowance:
    """Non-replayable local ticket book, already charged in full in durable storage.

    Never serialize/reconstruct this object. Crash loses its remaining tickets.
    Used at transport boundaries to cover SDK reads, polling and reconciliation.
    """

    def __init__(self, count, deadline, clock):
        self.remaining, self.deadline, self.clock = count, deadline, clock
        self._lock = Lock()

    def take(self):
        with self._lock:
            if self.clock() >= self.deadline:
                raise OperationError("deadline", "Prepaid read deadline expired")
            if self.remaining <= 0:
                raise OperationError("exhausted", "Prepaid read attempts exhausted")
            self.remaining -= 1
            return min(self.deadline, self.clock() + 30)


class Accounting:
    def __init__(self, ledger, *, workload, clock=time.time, tokens_per_minute=120000):
        if workload not in EDGES or type(tokens_per_minute) is not int or not 1 <= tokens_per_minute <= 120000:
            raise OperationError("invalid_input", "Invalid workload or actual model token quota")
        self.ledger, self.workload, self.clock = ledger, workload, clock
        self.tokens_per_minute = tokens_per_minute

    async def _load(self, budget_id, *, active=True):
        document, etag = await self.ledger.read()
        record = document["budgets"].get(identity(budget_id))
        if record is None:
            raise OperationError("missing", "Budget is absent; do not recreate or replay")
        if active and (record["closed"] or self.clock() >= record["deadline"]):
            raise OperationError("deadline", "Budget is closed or its inherited deadline expired")
        return document, etag, record

    async def _save(self, document, etag, record):
        await self.ledger.commit(document, etag, deadline=record["deadline"])

    @staticmethod
    def _idle(record):
        if record["child"] is not None or record["model"] is not None:
            raise OperationError("conflict", "Outstanding child/model owns the run admission baton")

    @staticmethod
    def _charge(record, **charges):
        if any(type(value) is not int or value < 0 or value > record["remaining"][key]
               for key, value in charges.items()):
            raise OperationError("exhausted", "Conservative run allowance exhausted")
        for key, value in charges.items():
            record["remaining"][key] -= value

    def _new(self, run_id, deadline, limits, *, grant=None, history=None):
        return {
            "run_id": run_id, "deadline": deadline, "remaining": deepcopy(limits),
            "agents": {}, "candidates": [], "closed": False, "model": None,
            "child": None, "history": deepcopy(history or []), "grant": deepcopy(grant),
            "grants": [], "tokens_per_minute": self.tokens_per_minute,
        }

    async def start_run(self, run_id, *, deadline=None):
        if self.workload != "candidate-planner":
            raise OperationError("forbidden", "Only Candidate Planner owns root run admission")
        identity(run_id)
        if deadline is not None and (type(deadline) not in (int, float)
                or not math.isfinite(deadline) or deadline <= self.clock()):
            raise OperationError("deadline", "Invalid inherited root deadline")
        document, etag = await self.ledger.read()
        if run_id in document["budgets"] or any(
            not value["closed"] and value["deadline"] > self.clock()
            for value in document["budgets"].values()
        ):
            raise OperationError("conflict", "One logical run at a time; no restart replay")
        started = self.clock()
        record = self._new(run_id, min(deadline if deadline is not None else float("inf"),
                                       started + 900), CEILINGS)
        bind_run(document, run_id, record["deadline"])
        document["budgets"][run_id] = record
        await self._save(document, etag, record)
        from citadel.acceptance.telemetry import emit
        emit("workflow.admitted", status_code=200, facts={
            "started": started, "deadline": record["deadline"], "sha256": sha256(record)})
        return deepcopy(record)

    async def status(self, budget_id):
        _, _, record = await self._load(budget_id, active=False)
        return deepcopy(record)

    async def start_agent(self, budget_id, execution_id):
        identity(execution_id)
        document, etag, record = await self._load(budget_id)
        self._idle(record)
        if execution_id in record["agents"]:
            raise OperationError("conflict", "Agent execution cannot be replayed")
        self._charge(record, agents=1)
        record["agents"][execution_id] = 0
        await self._save(document, etag, record)

    async def candidate(self, budget_id, ident):
        identity(ident)
        document, etag, record = await self._load(budget_id)
        self._idle(record)
        if self.workload != "candidate-planner" or record["grant"] is not None:
            raise OperationError("forbidden", "Only the root planner admits bounded pool members")
        if ident in record["candidates"] or len(record["candidates"]) >= 20:
            raise OperationError("exhausted", "Each of at most twenty pool members is assessed once")
        record["candidates"].append(ident)
        await self._save(document, etag, record)

    async def delegate(self, budget_id, grant_id, child, allowance):
        identity(grant_id)
        if child not in EDGES[self.workload] or allowance.keys() != CEILINGS.keys():
            raise OperationError("forbidden", "Budget delegation must follow the allowed invocation graph")
        document, etag, record = await self._load(budget_id)
        self._idle(record)
        if grant_id in record["grants"]:
            raise OperationError("conflict", "Grant identity cannot be replayed")
        self._charge(record, **allowance)
        grant = {
            "grant_id": grant_id, "parent_id": budget_id, "run_id": record["run_id"],
            "issuer": self.workload, "recipient": child, "deadline": record["deadline"],
            "allowance": deepcopy(allowance), "history": deepcopy(record["history"]),
            "tokens_per_minute": record["tokens_per_minute"],
        }
        record["child"] = deepcopy(grant)
        record["grants"].append(grant_id)
        await self._save(document, etag, record)
        return grant

    async def adopt(self, grant, *, authenticated_issuer):
        """Grant must be received in the authenticated parent request, never end-user input."""
        if (authenticated_issuer != grant["issuer"]
                or self.workload not in EDGES.get(authenticated_issuer, set())
                or grant["recipient"] != self.workload):
            raise OperationError("forbidden", "Authenticated issuer cannot delegate this grant")
        if (type(grant["deadline"]) not in (int, float) or not math.isfinite(grant["deadline"])
                or not self.clock() < grant["deadline"] <= self.clock() + 900):
            raise OperationError("deadline", "Invalid inherited absolute deadline")
        identity(grant["run_id"])
        if (grant["allowance"].keys() != CEILINGS.keys()
                or any(type(value) is not int or not 0 <= value <= CEILINGS[key]
                       for key, value in grant["allowance"].items())):
            raise OperationError("invalid_input", "Malformed delegated allowance")
        document, etag = await self.ledger.read()
        grant_id = identity(grant["grant_id"])
        if grant_id in document["budgets"]:
            raise OperationError("conflict", "Grant already adopted; query status, never replay")
        record = self._new(grant["run_id"], grant["deadline"], grant["allowance"],
                           grant=grant, history=grant["history"])
        bind_run(document, grant["run_id"], grant["deadline"])
        record["tokens_per_minute"] = min(self.tokens_per_minute, grant["tokens_per_minute"])
        document["budgets"][grant_id] = record
        await self._save(document, etag, record)

    async def model(self, budget_id, execution_id, *, input_tokens, output_tokens):
        """Reserve before sending; use conservative upper token bounds, not estimates/refunds."""
        for value, bound in ((input_tokens, 16000), (output_tokens, 2000)):
            if type(value) is not int or not 1 <= value <= bound:
                raise OperationError("exhausted", "Per-attempt token ceiling exceeded")
        document, etag, record = await self._load(budget_id)
        self._idle(record)
        if execution_id not in record["agents"] or record["agents"][execution_id] >= 8:
            raise OperationError("exhausted", "Agent execution/model-attempt allowance exhausted")
        now = self.clock()
        history = [entry for entry in record["history"] if entry["at"] > now - 60]
        tokens = input_tokens + output_tokens
        quota = min(record["tokens_per_minute"], self.tokens_per_minute)
        if (len(history) >= 12 or sum(entry["tokens"] for entry in history) + tokens > quota
                or (history and now - history[-1]["at"] < 5)):
            raise OperationError("rate_limited", "Shared rolling model rate/token admission exhausted")
        self._charge(record, models=1, tokens=tokens)
        record["agents"][execution_id] += 1
        permit = {"attempt_id": uuid4().hex, "deadline": min(record["deadline"], now + 60),
                  "input_tokens": input_tokens, "output_tokens": output_tokens}
        record["model"] = permit
        record["history"] = history + [{"at": now, "tokens": tokens}]
        await self._save(document, etag, record)
        return deepcopy(permit)

    async def finish_model(self, budget_id, attempt_id):
        """Only a definite completed model response releases admission; timeout never does."""
        document, etag, record = await self._load(budget_id)
        if not record["model"] or record["model"]["attempt_id"] != attempt_id:
            raise OperationError("conflict", "Model attempt does not own admission")
        record["history"][-1]["at"] = self.clock()
        record["model"] = None
        await self._save(document, etag, record)

    async def safe_read(self, budget_id, *, retry=0):
        if type(retry) is not int or not 0 <= retry <= 2:
            raise OperationError("exhausted", "At most two automatic safe-read retries")
        document, etag, record = await self._load(budget_id)
        self._charge(record, reads=1)
        started = self.clock()
        deadline = min(record["deadline"], started + 30)
        await self._save(document, etag, record)
        return {"deadline": deadline, "started": started,
                "backoff": 0 if retry == 0 else 2 ** (retry - 1)}

    async def reserve_reads(self, budget_id, count):
        if type(count) is not int or count < 1:
            raise OperationError("invalid_input", "Read reservation must be a positive integer")
        document, etag, record = await self._load(budget_id)
        self._charge(record, reads=count)
        await self._save(document, etag, record)
        return ReadAllowance(count, record["deadline"], self.clock)

    async def read_with_retry(self, budget_id, read):
        """The supplied safe read must disable its SDK retries. Ambiguous writes never enter here."""
        for retry in range(3):
            permit = await self.safe_read(budget_id, retry=retry)
            await asyncio.sleep(permit["backoff"])
            started = self.clock()
            remaining = permit["deadline"] - started
            if remaining <= 0:
                raise OperationError("deadline", "Safe-read deadline elapsed during backoff")
            monotonic_started = asyncio.get_running_loop().time()
            timer = asyncio.timeout_at(monotonic_started + remaining)
            try:
                async with timer:
                    return await read()
            except (TimeoutError, OperationError) as exc:
                if isinstance(exc, TimeoutError) and timer.expired():
                    from citadel.acceptance.telemetry import emit
                    emit("safe_read.timeout", facts={"started": started, "finished": self.clock(),
                        "deadline": permit["deadline"], "retry": retry, "read_operation_id": budget_id,
                        "monotonic_started": monotonic_started, "monotonic_deadline": timer.when(),
                        "monotonic_finished": asyncio.get_running_loop().time()})
                if isinstance(exc, OperationError) and exc.code != "unavailable":
                    raise
                if retry == 2:
                    raise OperationError("unavailable", "Safe-read retries exhausted") from None

    async def exchange_deadline(self, budget_id):
        _, _, record = await self._load(budget_id)
        return min(record["deadline"], self.clock() + 180)

    async def close(self, budget_id):
        document, etag, record = await self._load(budget_id)
        self._idle(record)
        record["closed"] = True
        receipt = {
            "grant_id": budget_id, "grant_hash": sha256(record["grant"]),
            "closed": True, "history": deepcopy(record["history"]), "issuer": self.workload,
        }
        record["receipt"] = receipt
        await self._save(document, etag, record)
        return deepcopy(receipt)

    async def settle(self, budget_id, receipt, *, authenticated_child):
        """Use only a verified response/status from the existing child route, not claimed body identity."""
        document, etag, record = await self._load(budget_id)
        grant = record["child"]
        if (grant is None or authenticated_child != grant["recipient"]
                or receipt["issuer"] != authenticated_child or receipt["closed"] is not True
                or receipt["grant_hash"] != sha256(grant) or receipt["grant_id"] != grant["grant_id"]):
            raise OperationError("forbidden", "Receipt does not close the outstanding authenticated grant")
        record["history"] = deepcopy(receipt["history"])
        record["child"] = None
        await self._save(document, etag, record)
