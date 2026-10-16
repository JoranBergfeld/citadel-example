"""Exhaust finite model admission using actual framework responses, never seeded counters."""

import hashlib
import json
import math

from citadel.evidence.manifests import sha256
from citadel.operations import OperationError, identity
from citadel.operations.limits import Accounting
from citadel.runtime.model import INSTRUCTIONS
from .admission_limits import business_hash
from .faults import rejected
from .telemetry import gateway_request_id


COUNTER_CHECKS = {"execution": "limit.model_attempts_execution", "run": "limit.model_attempts_run",
                  "tokens": "limit.tokens_run"}
COUNTER_MODES = {"model-execution-limit": "execution", "model-run-limit": "run", "model-token-limit": "tokens"}


class ModelCounters:
    def __init__(self, ledger, *, model, enabled, deadline, tokens_per_minute):
        if (enabled is not True or model.workload != "candidate-planner"
                or type(deadline) not in (int, float) or not math.isfinite(deadline)
                or not model.clock() < deadline <= model.clock() + 900):
            raise ValueError("Actual bounded Candidate Planner model accounting required")
        self.ledger, self.model, self.deadline = ledger, model, deadline
        self.accounting = Accounting(ledger, workload="candidate-planner", clock=model.clock,
                                     tokens_per_minute=tokens_per_minute)

    async def execute(self, kind, *, operation_id):
        counts = {"execution": 8, "run": 128, "tokens": 55}
        if kind not in counts:
            raise ValueError("Only fixed model counter boundaries are supported")
        operation, execution = identity(operation_id), identity(operation_id + "-e00")
        accounting, model = self.accounting, self.model
        initial, _ = await self.ledger.read()
        budget = await accounting.start_run(operation, deadline=self.deadline)
        reservations, models = [], []
        settled = [None]
        evidence = {"control": "Fictional connectivity only. Reply exactly OK."}
        if kind == "tokens":
            evidence["padding"] = ""
            overhead = len((INSTRUCTIONS["candidate-planner"] + json.dumps(
                evidence, sort_keys=True, ensure_ascii=False, allow_nan=False)).encode()) + 1024
            evidence["padding"] = "x" * (16000 - overhead)

        class Admission:
            async def model(self, budget_id, execution_id, *, input_tokens, output_tokens):
                permit = await accounting.model(budget_id, execution_id,
                    input_tokens=input_tokens, output_tokens=output_tokens)
                reservations.append({"execution_id": execution_id,
                                     "input_bound": input_tokens, "output_bound": output_tokens})
                return permit

            async def finish_model(self, budget_id, attempt_id):
                await accounting.finish_model(budget_id, attempt_id)
                settled[0] = model.clock()

        async def wait_after_model():
            until = settled[0] + 5
            while model.clock() < until:
                if model.clock() >= self.deadline:
                    raise OperationError("deadline", "Model counter control deadline expired")
                await model.sleep(min(5, until - model.clock()))

        async def observed(response):
            if response.status_code != 200:
                return
            content = await response.aread()
            if len(content) > 1024 * 1024:
                raise OperationError("result_limit", "Actual model usage exceeds the finite response envelope")
            usage = json.loads(content)["usage"]
            if (not isinstance(usage, dict) or any(type(usage.get(key)) is not int
                    or not 0 <= usage[key] <= bound for key, bound in (
                        ("prompt_tokens", 16000), ("completion_tokens", 2000), ("total_tokens", 18000)))
                    or usage["prompt_tokens"] + usage["completion_tokens"] != usage["total_tokens"]
                    or len(reservations) != len(models) + 1):
                raise OperationError("indeterminate", "One actual usage receipt per reserved model attempt required")
            models.append(reservations[-1] | {
                "request_id": gateway_request_id(response.headers), "status_code": 200,
                "target": hashlib.sha256(str(response.request.url).encode()).hexdigest(),
                "started": response.request.extensions["citadel_model_started"], "finished": model.clock(),
                "input_tokens": usage["prompt_tokens"], "output_tokens": usage["completion_tokens"],
                "tokens": usage["total_tokens"]})

        model.http.event_hooks["response"].append(observed)
        try:
            for index in range(counts[kind]):
                if index % 8 == 0:
                    execution = identity(f"{operation}-e{index // 8:02}")
                    await accounting.start_agent(operation, execution)
                if models:
                    await wait_after_model()
                await model.explain(Admission(), operation, execution, evidence)
        finally:
            model.http.event_hooks["response"].remove(observed)
        if kind == "run":
            execution = identity(operation + "-e16")
            await accounting.start_agent(operation, execution)
        if kind != "execution":
            await wait_after_model()
        before, _ = await self.ledger.read()
        refusal_started = model.clock()
        response = await rejected(lambda: accounting.model(operation, execution,
            input_tokens=reservations[-1]["input_bound"], output_tokens=2000))
        refusal_finished = model.clock()
        after, _ = await self.ledger.read()
        await accounting.close(operation)
        final, _ = await self.ledger.read()
        return {"operation_id": operation, "deadline": budget["deadline"], "models": models, "counter_kind": kind,
                "response": response, "before_sha256": sha256(before), "after_sha256": sha256(after),
                "refusal_started": refusal_started, "refusal_finished": refusal_finished,
                "business_before_sha256": business_hash(initial), "business_after_sha256": business_hash(final)}


def evaluate_model_counter(observation, snapshot, evidence, *, runtime_identity, observer_identity,
                           subscription, target, slot_target):
    from .operation_oracle import _matched
    from .oracle import hash_value
    blocked = {"check_id": observation.get("check_id"), "status": "blocked",
               "reason": "all_actual_counter_attempts_and_independent_state_required"}
    try:
        actual, state = observation["actual"], snapshot["budget_state"]
        kind = actual["counter_kind"]
        count = {"execution": 8, "run": 128, "tokens": 55}[kind]
        if (observation["check_id"] != COUNTER_CHECKS[kind] or observation["probe_id"] != COUNTER_CHECKS[kind]
                or observation["caller"] != "candidate-planner" or observation["runtime_identity"] != runtime_identity
                or runtime_identity == observer_identity or actual["operation_id"] != observation["operation_id"]
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
                  and row["facts"].get("probe_id") == COUNTER_CHECKS[kind]]
        if not _matched(observation, events, "application", runtime_identity, "execution",
                run_id=observation["run_id"], operation_id=observation["operation_id"], caller="candidate-planner"):
            return blocked
        models = actual["models"]
        if not isinstance(models, list) or len(models) != count:
            return blocked
        application = [row for row in evidence if row.get("source") == "application"
            and row.get("method") == "chat.completions" and row.get("run_id") == observation["run_id"]
            and row.get("operation_id") == observation["operation_id"]]
        if len(application) != count or len({row["request_id"] for row in models}) != count:
            return blocked
        agents, charged = {}, 0
        for index, row in enumerate(models):
            execution = f"{observation['operation_id']}-e{index // 8:02}"
            if (row["target"] != target or row["status_code"] != 200 or row["execution_id"] != execution
                    or type(row["input_bound"]) is not int or not 1 <= row["input_bound"] <= 16000
                    or type(row["output_bound"]) is not int or row["output_bound"] != 2000
                    or kind == "tokens" and row["input_bound"] != 16000
                    or any(type(row.get(key)) is not int or not 0 <= row[key] <= bound
                           for key, bound in (("input_tokens", row["input_bound"]), ("output_tokens", 2000),
                                              ("tokens", row["input_bound"] + 2000)))
                    or row["tokens"] != row["input_tokens"] + row["output_tokens"]
                    or not 0 <= row["finished"] - row["started"] <= 60
                    or index and row["started"] - models[index - 1]["finished"] < 5):
                return blocked
            records = [record for record in application if record.get("request_id") == row["request_id"]]
            if (len(records) != 1 or not _matched(row, records, "application", runtime_identity,
                    "chat.completions", caller="candidate-planner")
                    or any(records[0]["facts"].get(key) != row[key] for key in (
                        "input_tokens", "output_tokens", "tokens", "started"))
                    or not row["started"] <= records[0]["facts"]["finished"] <= row["finished"]):
                return blocked
            gateway = [record for record in evidence if record.get("source") == "gateway"
                       and record.get("request_id") == row["request_id"]]
            if not gateway or any(
                    record.get("status_code") != 200 or record.get("target") != target or record.get("method") != "POST"
                    or record.get("caller") != "candidate-planner" or record.get("credential_sha256") != subscription
                    or record.get("facts", {}).get("backend_dispatched") is not True
                    or type(record.get("observed")) not in (int, float)
                    or not row["started"] - 5 <= record["observed"] <= row["finished"] + 5 for record in gateway):
                return blocked
            agents[execution] = agents.get(execution, 0) + 1
            charged += row["input_bound"] + 2000
        physical = {row.get("request_id") for row in evidence if row.get("source") == "gateway"
            and row.get("target") == target and type(row.get("observed")) in (int, float)
            and models[0]["started"] - 5 <= row["observed"] <= models[-1]["finished"] + 5}
        if physical != {row["request_id"] for row in models}:
            return blocked
        if kind == "run":
            agents[observation["operation_id"] + "-e16"] = 0
        slots = actual["slot"]
        for side, prefix in (("before", observation["operation_id"]), ("after", observation["operation_id"] + "-end")):
            slot = slots[side]
            if slot["scope_sha256"] != sha256("acceptance/" + observation["run_id"]) or len(slot["steps"]) != 3:
                return blocked
            for index, row in enumerate(slot["steps"]):
                if (row["operation_id"] != f"{prefix}-slot{index}" or row["target"] != slot_target
                        or row["action"] != ("acquire" if index == 1 else "renew")
                        or row["status_code"] != (409 if index == 1 else 200)
                        or not _matched(row, evidence, "storage", runtime_identity, "LeaseBlob",
                                        client_request_id=row["operation_id"])
                        or not observation["started"] <= row["started"] <= row["finished"] <= observation["finished"]
                        or index and row["started"] < slot["steps"][index - 1]["finished"]):
                    return blocked
        if (slots["before"]["steps"][-1]["finished"] + 60 > models[0]["started"]
                or models[-1]["finished"] + 60 > slots["after"]["steps"][0]["started"]):
            return blocked
        valid = (actual["response"] == "exhausted" and hash_value(actual["before_sha256"])
            and actual["before_sha256"] == actual["after_sha256"]
            and models[-1]["finished"] + (0 if kind == "execution" else 5)
                <= actual["refusal_started"] <= actual["refusal_finished"] <= observation["finished"]
            and state["closed"] is True and state["model_active"] is False and state["child_active"] is False
            and state["grant_present"] is False and state["grant_count"] == 0 and state["count"] == 1
            and state["run_id"] == observation["operation_id"] and state["agent_executions"] == len(agents)
            and state["agents_sha256"] == sha256(agents) and state["candidates"] == 0
            and all(type(value) is int for value in state["remaining"].values())
            and state["remaining"] == {"agents": 42 - len(agents), "models": 128 - count,
                                      "tokens": 1000000 - charged, "reads": 512}
            and (kind != "run" or 1000000 - charged >= models[-1]["input_bound"] + 2000)
            and type(actual["deadline"]) in (int, float) and math.isfinite(actual["deadline"])
            and observation["finished"] <= actual["deadline"] == state["deadline"] <= observation["started"] + 900
            and hash_value(actual["business_before_sha256"])
            and actual["business_before_sha256"] == actual["business_after_sha256"] == snapshot["business_sha256"])
        return blocked | {"status": "pass" if valid else "fail",
                          "reason": "actual_model_counter_verified" if valid else "model_counter_invariant_failed"}
    except (KeyError, ValueError, TypeError, AttributeError, IndexError):
        return blocked
