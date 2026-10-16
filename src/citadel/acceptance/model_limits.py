"""Actual framework inference and durable overflow refusals in one finite control run."""

import hashlib
import json
import math
import time

from citadel.evidence.manifests import sha256
from citadel.operations import OperationError, identity
from citadel.operations.limits import Accounting
from citadel.runtime.model import INSTRUCTIONS
from .admission_limits import business_hash
from .faults import rejected
from .telemetry import gateway_request_id


MODEL_BOUNDARY_CHECKS = {"limit.input_tokens_attempt", "limit.output_tokens_attempt", "limit.model_concurrency"}


class ModelLimits:
    def __init__(self, ledger, *, model, enabled, deadline, tokens_per_minute):
        if (enabled is not True or model.workload != "candidate-planner"
                or type(deadline) not in (int, float) or not math.isfinite(deadline)
                or not time.time() < deadline <= time.time() + 900):
            raise ValueError("A bounded actual Candidate Planner model control is required")
        self.ledger, self.model, self.deadline = ledger, model, deadline
        self.accounting = Accounting(ledger, workload="candidate-planner", tokens_per_minute=tokens_per_minute)

    async def boundaries(self, *, operation_id):
        operation = identity(operation_id)
        initial, _ = await self.ledger.read()
        budget = await self.accounting.start_run(operation, deadline=self.deadline)
        await self.accounting.start_agent(operation, operation)
        checks, responses = [], []
        accounting, ledger = self.accounting, self.ledger

        async def refusal(check_id, callback):
            before, _ = await ledger.read()
            response = await rejected(callback)
            after, _ = await ledger.read()
            checks.append({"check_id": check_id, "response": response,
                           "before_sha256": sha256(before), "after_sha256": sha256(after)})

        class ContendedAdmission:
            async def model(self, budget_id, execution_id, *, input_tokens, output_tokens):
                permit = await accounting.model(budget_id, execution_id,
                    input_tokens=input_tokens, output_tokens=output_tokens)
                await refusal("limit.model_concurrency", lambda: accounting.model(
                    budget_id, execution_id, input_tokens=input_tokens, output_tokens=output_tokens))
                return permit

            async def finish_model(self, budget_id, attempt_id):
                await accounting.finish_model(budget_id, attempt_id)

        async def observed(response):
            if response.status_code != 200:
                return
            content = await response.aread()
            if len(content) > 1024 * 1024:
                raise OperationError("result_limit", "Model proof response exceeds its envelope")
            usage = json.loads(content)["usage"]
            if (not isinstance(usage, dict) or any(type(usage.get(key)) is not int
                    or not 0 <= usage[key] <= bound for key, bound in (
                        ("prompt_tokens", 16000), ("completion_tokens", 2000), ("total_tokens", 18000)))
                    or usage["prompt_tokens"] + usage["completion_tokens"] != usage["total_tokens"]):
                raise OperationError("indeterminate", "Actual bounded model usage is required")
            responses.append({"request_id": gateway_request_id(response.headers), "status_code": 200,
                "target": hashlib.sha256(str(response.request.url).encode()).hexdigest(),
                "started": response.request.extensions["citadel_model_started"], "finished": time.time(),
                "input_tokens": usage["prompt_tokens"], "output_tokens": usage["completion_tokens"],
                "tokens": usage["total_tokens"]})

        evidence = {"control": "fictional connectivity only; reply exactly OK", "padding": ""}
        overhead = len((INSTRUCTIONS["candidate-planner"] + json.dumps(
            evidence, sort_keys=True, ensure_ascii=False, allow_nan=False)).encode()) + 1024
        evidence["padding"] = "x" * (16000 - overhead)
        self.model.http.event_hooks["response"].append(observed)
        try:
            await self.model.explain(ContendedAdmission(), operation, operation, evidence)
        finally:
            self.model.http.event_hooks["response"].remove(observed)
        if len(responses) != 1:
            raise OperationError("indeterminate", "Exactly one actual allowed model response required")
        await refusal("limit.input_tokens_attempt",
            lambda: accounting.model(operation, operation, input_tokens=16001, output_tokens=2000))
        await refusal("limit.output_tokens_attempt",
            lambda: accounting.model(operation, operation, input_tokens=16000, output_tokens=2001))
        await accounting.close(operation)
        final, _ = await ledger.read()
        return {"operation_id": operation, "deadline": budget["deadline"], "input_tokens": 16000,
                "output_tokens": 2000, "checks": checks, "model": responses[0],
                "before_sha256": business_hash(initial), "after_sha256": business_hash(final)}


def evaluate_model_boundaries(observation, snapshot, evidence, *, runtime_identity, observer_identity,
                              subscription, target, slot_target):
    from .operation_oracle import _matched
    from .oracle import hash_value
    blocked = {"check_id": observation.get("check_id"), "status": "blocked",
               "reason": "actual_model_boundary_service_and_counter_proof_required"}
    try:
        actual, state = observation["actual"], snapshot["budget_state"]
        if (observation["check_id"] not in MODEL_BOUNDARY_CHECKS
                or observation["probe_id"] != "limit.input_tokens_attempt"
                or observation["caller"] != "candidate-planner" or observation["runtime_identity"] != runtime_identity
                or runtime_identity == observer_identity
                or actual["operation_id"] != observation["operation_id"]
                or observation["status_code"] != 201 or snapshot["status_code"] not in (200, 206)
                or not hash_value(snapshot["sha256"]) or snapshot["started"] < observation["finished"]
                or not all(hash_value(value) for value in (subscription, target, slot_target))
                or not _matched(observation, evidence, "storage", runtime_identity, "PutBlob",
                                client_request_id=observation["operation_id"])
                or not _matched(snapshot, evidence, "storage", observer_identity, "GetBlob",
                                client_request_id=snapshot["operation_id"])):
            return blocked
        events = [row for row in evidence if isinstance(row.get("facts"), dict)
                  and row["facts"].get("sha256") == sha256(actual)
                  and row["facts"].get("probe_id") == "limit.input_tokens_attempt"]
        if not _matched(observation, events, "application", runtime_identity, "execution",
                run_id=observation["run_id"], operation_id=observation["operation_id"], caller="candidate-planner"):
            return blocked
        model = actual["model"]
        if (model["target"] != target or model["status_code"] != 200
                or any(type(model.get(key)) is not int or not 0 <= model[key] <= bound
                       for key, bound in (("input_tokens", 16000), ("output_tokens", 2000), ("tokens", 18000)))
                or model["tokens"] != model["input_tokens"] + model["output_tokens"]
                or not 0 <= model["finished"] - model["started"] <= 60):
            return blocked
        model_events = [row for row in evidence if row.get("source") == "application"
            and row.get("method") == "chat.completions" and row.get("run_id") == observation["run_id"]
            and row.get("operation_id") == observation["operation_id"]]
        if (len(model_events) != 1 or not _matched(model, model_events, "application",
                runtime_identity, "chat.completions", caller="candidate-planner")
                or not isinstance(model_events[0].get("facts"), dict)
                or any(model_events[0]["facts"].get(key) != model[key]
                       for key in ("input_tokens", "output_tokens", "tokens", "started"))
                or not model["started"] <= model_events[0]["facts"]["finished"] <= model["finished"]
                or not any(row.get("source") == "gateway" and row.get("request_id") == model["request_id"]
                    and row.get("status_code") == 200 and row.get("target") == target and row.get("method") == "POST"
                    and row.get("caller") == "candidate-planner" and row.get("credential_sha256") == subscription
                    and row.get("facts", {}).get("backend_dispatched") is True
                    and type(row.get("observed")) in (int, float)
                    and model["started"] - 5 <= row["observed"] <= model["finished"] + 5 for row in evidence)):
            return blocked
        slots = actual["slot"]
        for side, prefix in (("before", observation["operation_id"]), ("after", observation["operation_id"] + "-end")):
            slot = slots[side]
            if (slot["scope_sha256"] != sha256("acceptance/" + observation["run_id"])
                    or len(slot["steps"]) != 3):
                return blocked
            for index, row in enumerate(slot["steps"]):
                if (row.get("operation_id") != f"{prefix}-slot{index}" or row.get("target") != slot_target
                        or row.get("action") != ("acquire" if index == 1 else "renew")
                        or row.get("status_code") != (409 if index == 1 else 200)
                        or not _matched(row, evidence, "storage", runtime_identity, "LeaseBlob",
                                        client_request_id=row["operation_id"])
                        or not observation["started"] <= row["started"] <= row["finished"] <= observation["finished"]
                        or index and row["started"] < slot["steps"][index - 1]["finished"]):
                    return blocked
        if (slots["before"]["steps"][-1]["finished"] + 60 > model["started"]
                or model["finished"] + 60 > slots["after"]["steps"][0]["started"]):
            return blocked
        checks = actual["checks"]
        if (not isinstance(checks, list) or len(checks) != 3
                or {row.get("check_id") for row in checks} != MODEL_BOUNDARY_CHECKS
                or any(not hash_value(row.get(key)) for row in checks for key in ("before_sha256", "after_sha256"))):
            return blocked
        valid = (all(row["before_sha256"] == row["after_sha256"] and row.get("response") ==
                     ("conflict" if row["check_id"] == "limit.model_concurrency" else "exhausted") for row in checks)
            and type(actual["input_tokens"]) is int and actual["input_tokens"] == 16000
            and type(actual["output_tokens"]) is int and actual["output_tokens"] == 2000
            and state["closed"] is True and state["model_active"] is False and state["child_active"] is False
            and state["grant_present"] is False and state["grant_count"] == 0 and state["count"] == 1
            and state["run_id"] == observation["operation_id"] and state["agent_executions"] == 1
            and state["agents_sha256"] == sha256({observation["operation_id"]: 1})
            and state["candidates"] == 0 and state["history_count"] == 1
            and all(type(value) is int for value in state["remaining"].values())
            and state["remaining"] == {"agents": 41, "models": 127, "tokens": 982000, "reads": 512}
            and type(actual["deadline"]) in (int, float) and math.isfinite(actual["deadline"])
            and observation["finished"] <= actual["deadline"] == state["deadline"] <= observation["started"] + 900
            and hash_value(actual["before_sha256"])
            and actual["before_sha256"] == actual["after_sha256"] == snapshot["business_sha256"])
        return blocked | {"status": "pass" if valid else "fail",
                          "reason": "actual_model_boundary_verified" if valid else "model_boundary_invariant_failed"}
    except (KeyError, ValueError, TypeError, AttributeError, IndexError):
        return blocked
