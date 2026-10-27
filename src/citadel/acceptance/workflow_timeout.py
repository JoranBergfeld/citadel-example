"""One authenticated root held under its real production timer; no supplied duration."""

import asyncio
import json
import math
import time

from citadel.evidence.manifests import sha256
from citadel.operations import OperationError, identity
from citadel.runtime.state import read_scope
from .telemetry import emit


class WorkflowHold:
    def __init__(self, run_id, deadline):
        self.run_id, self.deadline, self.used = run_id, deadline, False
        self.response, self.before_sha256, self.after_sha256 = None, None, None

    @classmethod
    def from_environment(cls, environment, *, workload):
        raw = environment.get("CITADEL_ACCEPTANCE_WORKFLOW_HOLD")
        if raw is None:
            return None
        value = json.loads(raw)
        if (environment.get("CITADEL_ACCEPTANCE_ENABLED") != "true" or workload != "candidate-planner"
                or not isinstance(value, dict) or set(value) != {"run_id", "deadline", "mode"}
                or value["mode"] != "workflow-timeout"
                or type(value["deadline"]) not in (int, float) or not math.isfinite(value["deadline"])
                or not time.time() < value["deadline"] <= time.time() + 1140):
            raise ValueError("Exact private planner workflow hold required")
        return cls(identity(value["run_id"]), value["deadline"])

    def validate(self, payload):
        if (payload != {"operation_id": self.run_id, "run_id": self.run_id, "fixture": "base-source"}
                or time.time() >= self.deadline):
            raise OperationError("forbidden", "Only the fixed independently admitted root may be held")

    async def wait(self, runtime, payload, ownership, deadline):
        self.validate(payload)
        if self.used or not time.time() < deadline <= self.deadline - 120:
            raise OperationError("deadline", "A full new root needs its bounded post-expiry evidence window")
        self.used = True
        budget = await runtime.accounting.status(self.run_id)
        self.original_deadline = budget["deadline"]
        self.before_sha256 = sha256(budget)
        emit("workflow.held", status_code=200, facts={
            "sha256": self.before_sha256, "deadline": budget["deadline"]})
        while True:
            await asyncio.sleep(90)
            await runtime.renew_if_needed(ownership)

    async def finish(self, runtime, payload):
        if not self.used or payload["run_id"] != self.run_id or self.before_sha256 is None:
            raise OperationError("indeterminate", "Only the definitely cancelled held root may be fenced")
        while runtime.clock() < self.original_deadline:
            await asyncio.sleep(min(1, self.original_deadline - runtime.clock()))
        pool = runtime.pool("operator", self.run_id)
        # Metadata observation can read the original budget; it cannot extend it.
        with read_scope(pool, deadline=min(self.deadline, runtime.clock() + 30)):
            try:
                await runtime.accounting.start_agent(self.run_id, self.run_id + "-late")
            except OperationError as exc:
                self.response = exc.code
            else:
                raise OperationError("indeterminate", "Expired root unexpectedly admitted new work")
        if self.response != "deadline":
            raise OperationError("indeterminate", "Actual original-deadline refusal required")
        emit("workflow.refused", status_code=409, facts={
            "reason": self.response, "deadline": self.original_deadline})
        # Existing explicit recovery may change fences/status, never the original
        # budget, ticket capacity, business deadline, products or dispatched work.
        with read_scope(pool, deadline=min(self.deadline, runtime.clock() + 30)):
            document, _ = await runtime.ledger.read()
            budget = document["budgets"][self.run_id]
            record = document["operations"]["operator/invoke/" + self.run_id]
            self.after_sha256 = sha256(budget)
            if (self.before_sha256 != self.after_sha256 or budget["model"] is not None
                    or budget["child"] is not None or record["external"] or "product" in record
                    or runtime.clock() < budget["deadline"]):
                raise OperationError("indeterminate", "Unknown held-root effects retain exclusion")
            result = await runtime.ops.fence("operator", "invoke", self.run_id)
            if result["state"] != "failed_no_commit":
                raise OperationError("indeterminate", "Definite metadata-only recovery required")
            await runtime.ticket_store.release_run(pool.scope)
            emit("workflow.fenced", status_code=200, facts={
                "business_state": result["state"], "reason": self.response,
                "before_sha256": self.before_sha256, "after_sha256": self.after_sha256,
                "deadline": budget["deadline"], "generation": result["generation"]})
