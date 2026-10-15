"""Explicit, fixed-purpose faults around real conditional storage operations."""

import asyncio
import time
from uuid import uuid4

from citadel.evidence.manifests import sha256
from citadel.operations import Operations, OperationError, identity, operation_key
from citadel.operations.limits import Accounting


async def rejected(callback):
    try:
        await callback()
    except OperationError as exc:
        return exc.code
    return "unexpected_success"


class _DropCommittedResponse:
    def __init__(self, ledger):
        self.ledger, self.armed = ledger, False

    async def read(self):
        return await self.ledger.read()

    async def commit(self, document, etag, *, deadline):
        result = await self.ledger.commit(document, etag, deadline=deadline)
        if self.armed:
            self.armed = False
            raise OperationError("indeterminate", "Acceptance dropped an actual committed response")
        return result


class OperationProbes:
    def __init__(self, ledger, *, workload, enabled, run_id, clock=time.time, sleep=asyncio.sleep,
                 deadline=None):
        if enabled is not True or workload not in ("candidate-planner", "briefing-author"):
            raise ValueError("Fixed planning-operation probes require explicit acceptance mode")
        self.ledger, self.workload, self.run_id = ledger, workload, identity(run_id)
        self.clock, self.sleep = clock, sleep
        self.ops = Operations(ledger, workload=workload, clock=clock)
        self.deadline = min(deadline or clock() + 900, clock() + 900)

    async def safe_read_recovery(self, operation_id=None):
        return await self._safe_read(operation_id, dropped=2)

    async def safe_read_exhaustion(self, operation_id=None):
        return await self._safe_read(operation_id, dropped=3)

    async def _safe_read(self, operation_id, *, dropped):
        if self.workload != "candidate-planner":
            raise OperationError("forbidden", "Only the allocated planner can admit a root probe")
        operation = identity(operation_id or uuid4().hex)
        accounting = Accounting(self.ledger, workload=self.workload, clock=self.clock)
        budget = await accounting.start_run(operation, deadline=self.deadline)
        document, _ = await self.ledger.read()

        def business_hash(value):
            return sha256({key: value[key] for key in ("operations", "drafts", "findings")})

        before = business_hash(document)
        steps = []

        async def read():
            started = self.clock()
            observed, _ = await self.ledger.read()
            discarded = len(steps) < dropped
            steps.append({"started": started, "finished": self.clock(), "sha256": business_hash(observed),
                          "state": "dropped" if discarded else "received"})
            if discarded:
                raise OperationError("unavailable", "Acceptance discarded a successful read response")
            return observed

        try:
            await accounting.read_with_retry(operation, read)
            state = "recovered"
        except OperationError as exc:
            if exc.code != "unavailable":
                raise
            state = "unavailable"
        status = await accounting.status(operation)
        await accounting.close(operation)
        after, _ = await self.ledger.read()
        return {"operation_id": operation, "state": state, "steps": steps,
            "read_attempts": len(steps), "retry": max(0, len(steps) - 1),
            "remaining_reads": status["remaining"]["reads"], "deadline": budget["deadline"],
            "before_sha256": before, "after_sha256": business_hash(after)}

    async def deadline_no_late_effect(self, operation_id=None):
        operation = identity(operation_id or uuid4().hex)
        deadline = self.clock() + 45
        if deadline + 30 >= self.deadline:
            raise OperationError("deadline", "Insufficient remaining probe observation window")
        await self.ops.accept(self.workload, "acceptance", operation, {"probe": "deadline"},
                              run_id=operation, deadline=deadline)
        owner = await self.ops.claim(self.workload, "acceptance", operation,
                                    worker=uuid4().hex, lease_seconds=180)
        before, _ = await self.ledger.read()
        key = operation_key(self.workload, "acceptance", operation)
        await self.sleep(max(0, deadline - self.clock()) + 1)
        response = await rejected(lambda: self.ops.complete(owner, product={"probe": "late"}))
        after, _ = await self.ledger.read()
        return {"operation_id": operation, "state": after["operations"][key]["state"],
            "response": response, "observed": self.clock(), "deadline": deadline,
            "artifact_count": int("product" in after["operations"][key]),
            "before_sha256": sha256(before["operations"][key]),
            "after_sha256": sha256(after["operations"][key])}

    async def _admit(self, ops, operation_id, *, deadline=None):
        end = deadline or self.deadline
        await ops.accept(self.workload, "acceptance", operation_id, {"kind": "fixed-purpose-probe"},
                         run_id=self.run_id, deadline=end)
        return await ops.claim(self.workload, "acceptance", operation_id,
                               worker=uuid4().hex, lease_seconds=180)

    async def committed_response_loss(self, operation_id=None):
        transport = _DropCommittedResponse(self.ledger)
        ops = Operations(transport, workload=self.workload, clock=self.clock)
        operation = identity(operation_id or uuid4().hex)
        owner = await self._admit(ops, operation)
        product = {"kind": "disposable-acceptance-product", "run_id": self.run_id}
        transport.armed = True
        response = await rejected(lambda: ops.complete(owner, product=product))
        # A fresh operation object has no in-memory knowledge of the completed write.
        restarted = Operations(self.ledger, workload=self.workload, clock=self.clock)
        status = await restarted.status(self.workload, "acceptance", operation)
        actual = await restarted.completed_result(self.workload, "acceptance", operation)
        repeat = await restarted.accept(self.workload, "acceptance", operation,
            {"kind": "fixed-purpose-probe"}, run_id=self.run_id, deadline=self.deadline)
        replay = await rejected(lambda: restarted.claim(
            self.workload, "acceptance", operation, worker=uuid4().hex))
        document, _ = await self.ledger.read()
        count = sum(record["operation_id"] == operation and "product" in record
                    for record in document["operations"].values())
        if (status["state"] != "succeeded" or repeat != status or actual != product or replay != "conflict"):
            raise OperationError("data_integrity", "Lost-response reconciliation invariant failed")
        return {"state": status["state"], "artifact_count": count, "sha256": sha256(actual),
                "response": response, "operation_id": operation, "replay": replay,
                "identical_input": repeat == status}

    async def identity_and_incomplete_status(self, operation_id=None):
        operation = identity(operation_id or uuid4().hex)
        pending = await self.ops.accept(self.workload, "acceptance", operation, {"probe": 1},
                                       run_id=self.run_id, deadline=self.deadline)
        changed = await rejected(lambda: self.ops.accept(
            self.workload, "acceptance", operation, {"probe": 2},
            run_id=self.run_id, deadline=self.deadline))
        states = [pending["state"]]
        completions = [await rejected(lambda: self.ops.completed_result(
            self.workload, "acceptance", operation))]
        owner = await self.ops.claim(self.workload, "acceptance", operation,
                                    worker=uuid4().hex, lease_seconds=180)
        states.append((await self.ops.status(self.workload, "acceptance", operation))["state"])
        completions.append(await rejected(lambda: self.ops.completed_result(
            self.workload, "acceptance", operation)))
        await self.ops.begin_external(owner, "ambiguous", "a" * 64)
        await self.ops.mark_incomplete(owner, "acceptance_response_lost")
        states.append((await self.ops.status(self.workload, "acceptance", operation))["state"])
        missing = uuid4().hex
        states.append((await self.ops.status(self.workload, "acceptance", missing))["state"])
        completed = await rejected(lambda: self.ops.completed_result(self.workload, "acceptance", operation))
        completions += [completed, await rejected(lambda: self.ops.completed_result(
            self.workload, "acceptance", missing))]
        retry = await rejected(lambda: self.ops.retry(self.workload, "acceptance", operation))
        return {"operation_id": operation, "states": states, "changed_input": changed,
                "completed": completed == "unexpected_success", "retry": retry,
                "completed_states": completions, "missing_operation_id": missing}

    async def fenced_retry(self, operation_id=None):
        operation = identity(operation_id or uuid4().hex)
        await self.ops.accept(self.workload, "acceptance", operation, {"probe": "fence"},
                              run_id=self.run_id, deadline=self.deadline)
        owner = await self.ops.claim(self.workload, "acceptance", operation,
                                    worker=uuid4().hex, lease_seconds=20)
        await self.sleep(21)
        fenced = await self.ops.fence(self.workload, "acceptance", operation)
        stale = await rejected(lambda: self.ops.complete(owner, product={"probe": "stale"}))
        retried = await self.ops.retry(self.workload, "acceptance", operation)
        current = await self.ops.claim(self.workload, "acceptance", operation,
                                      worker=uuid4().hex, lease_seconds=180)
        result = await self.ops.complete(current, product={"probe": "explicit-retry"})
        document, _ = await self.ledger.read()
        count = sum(record["operation_id"] == operation and "product" in record
                    for record in document["operations"].values())
        return {"operation_id": operation, "fenced": fenced["state"], "stale": stale,
                "retried": retried["state"], "state": result["state"],
                "generation": result["generation"], "artifact_count": count}
