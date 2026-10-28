"""Explicit no-commit retry; a retained intent is never a restart work queue."""

from copy import deepcopy
from uuid import uuid4

from fastapi import Request
from starlette.responses import JSONResponse

from citadel.evidence.manifests import sha256
from citadel.operations import OperationError, identity, operation_key
from .recovery import Recovery
from .state import read_deadline, read_scope, snapshots


def require_retry(record, budget, now):
    if record["state"] != "failed_no_commit":
        raise OperationError("blocked", "Only authoritative failed_no_commit permits retry")
    if (budget is None or budget["run_id"] != record["run_id"]
            or budget["deadline"] != record["deadline"] or budget["grant"] is not None):
        raise OperationError("blocked", "Original root accounting binding unavailable")
    if now >= record["deadline"] or budget["closed"]:
        raise OperationError("deadline", "Original deadline expired or budget closed")
    if (budget["model"] is not None or budget["child"] is not None
            or any(item["state"] != "failed_no_commit" for item in record["external"].values())
            or record.get("product") or budget["candidates"] or budget["grants"]):
        raise OperationError("blocked", "Partial progress or unresolved child/model effects forbid replay")
    # Admission funds the next root agent/model step, not a promise of completion.
    # Every later stage still charges its original allowance at its owning boundary.
    if (any(budget["remaining"][key] < value for key, value in
            {"agents": 1, "models": 1, "tokens": 18000, "reads": 1}.items())
            or budget["agents"].get(record["operation_id"], 0) >= 8):
        raise OperationError("exhausted", "Insufficient remaining original execution accounting")


class Retry(Recovery):
    async def retry_run(self, run_id, request_id):
        identity(request_id)
        binding = await self.resolve_run(run_id)
        key = operation_key(binding["caller"], "invoke", binding["operation_id"])
        document, etag = await self.ledger.read()
        controls = document.setdefault("operator_controls", {})
        bound = {"run_id": run_id, "operation": key, "input_hash": binding["input_hash"],
                 "grant_hash": None}
        existing = controls.get(request_id)
        if existing is not None:
            if existing["binding"] != bound or existing["action"] != "retry":
                raise OperationError("conflict", "Control identity belongs to another action")
            if existing.get("outcome"):
                return deepcopy(existing["outcome"])
            outcome = self.outcome(
                run_id, request_id, "unknown", "unknown",
                "Retry intent retained; dispatch is unknown. Never automatically resubmit.")
            existing["outcome"] = outcome
            await self.ledger.commit(document, etag, deadline=read_deadline.get())
            return outcome
        if len(controls) >= 1024:
            raise OperationError("exhausted", "Retained control audit is full")
        controls[request_id] = {"binding": bound, "action": "retry",
            "requested_by": "operator-web", "requested_at": self.clock(), "outcome": None}
        await self.ledger.commit(document, etag, deadline=read_deadline.get())
        try:
            record = document["operations"].get(key)
            if record is None or record["input_hash"] != sha256({
                    "inputs": binding["inputs"], "run_id": run_id, "deadline": record["deadline"]}):
                raise OperationError("blocked", "Original operation binding unavailable")
            require_retry(record, document["budgets"].get(run_id), self.clock())
            await self.runtime.run_index.require_resolved_in_scope()
            pool = self.runtime.pool("operator", run_id)
            await self.runtime.ticket_store.require_pool(pool.scope)
            # A real, original workflow read proves a remaining physical ticket.
            # It is never funded from the recovery-proof pool or refunded.
            with read_scope(pool, deadline=min(record["deadline"], read_deadline.get())):
                status = await self.runtime.ops.status("operator", "invoke", run_id)
            if status["state"] != "failed_no_commit" or status["generation"] != record["generation"]:
                raise OperationError("blocked", "Original no-commit fence changed")
            generation = record["generation"] + 1
            document, etag = await self.ledger.read()
            document["operator_controls"][request_id]["admission"] = {
                "operation_generation": record["generation"], "generation": generation}
            await self.ledger.commit(document, etag, deadline=read_deadline.get())
            await self.runtime.ticket_store.acquire_run(pool.scope, generation=generation)
            accepted = await self.ops.retry("operator", "invoke", run_id,
                                            admission_generation=generation)
            owner = await self.ops.claim("operator", "invoke", run_id,
                                         worker=uuid4().hex, lease_seconds=180)
            outcome = self.outcome(run_id, request_id, "retry_admitted", "running",
                "Retry admitted once against original inputs, deadline and remaining allowances. "
                "Dispatch/completion is not guaranteed; observe saved state. Never resubmit automatically.")
            outcome["generation"] = owner.generation
            document, etag = await self.ledger.read()
            document["operator_controls"][request_id]["outcome"] = outcome
            await self.ledger.commit(document, etag, deadline=read_deadline.get())
            await self.runtime.run_index.recovered_in_scope(binding, outcome)
        except OperationError as exc:
            outcome = self.outcome(run_id, request_id,
                "unknown" if exc.code in ("indeterminate", "unavailable") else "blocked",
                "unknown", str(exc))
            document, etag = await self.ledger.read()
            document["operator_controls"][request_id]["outcome"] = outcome
            await self.ledger.commit(document, etag, deadline=read_deadline.get())
            return outcome
        # Only this invocation, after confirmed persistence, may schedule. A lost
        # outcome write, duplicate, or restarted process never reaches this point.
        with read_scope(pool, deadline=accepted["deadline"], cache=snapshots.get()):
            self.runtime.schedule("operator", binding["inputs"], owner, accepted["deadline"])
        return outcome


def install_retry_routes(app, runtime):
    if runtime.workload != "candidate-planner":
        return

    @app.post("/operator/runs/{run_id}/retry/{request_id}")
    async def retry_run(run_id: str, request_id: str, request: Request):
        try:
            body = await request.json()
            if not isinstance(body, dict) or body.keys() != {"confirmed"} or body["confirmed"] is not True:
                raise OperationError("invalid_input", "Separate explicit retry confirmation required")
            if runtime.recovery_admission is None:
                raise OperationError("unavailable", "Recovery proof admission unavailable")
            end = float(request.headers.get("x-citadel-recovery-deadline", runtime.clock() + 30))
            async with runtime.recovery_admission.request("recovery-proof", deadline=end):
                result = await Retry(runtime).retry_run(identity(run_id), identity(request_id))
            return JSONResponse(result)
        except OperationError as exc:
            return JSONResponse({"state": "unknown", "execution": "unknown", "reason": str(exc)},
                                status_code=429 if exc.code == "exhausted" else 503)
        except (TimeoutError, ValueError, TypeError, KeyError):
            return JSONResponse({"state": "unknown", "execution": "unknown",
                "reason": "Retry outcome unknown. Observe or check explicitly; never resubmit automatically."},
                status_code=503)
