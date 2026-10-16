"""Exercise the real model timer without settling or replaying its retained admission."""

import asyncio
import hashlib
import json
import math
import time

from citadel.evidence.manifests import sha256
from citadel.operations import OperationError, identity
from citadel.runtime.model import INSTRUCTIONS
from .admission_limits import business_hash
from .faults import rejected
from .model_limits import ModelLimits
from .telemetry import gateway_request_id


class ModelTimeout(ModelLimits):
    async def execute(self, *, operation_id):
        operation = identity(operation_id)
        initial, _ = await self.ledger.read()
        budget = await self.accounting.start_run(operation, deadline=self.deadline)
        await self.accounting.start_agent(operation, operation)
        accounting, ledger = self.accounting, self.ledger
        models, permits, cancelled = [], [], []

        class ObservedAdmission:
            async def model(self, budget_id, execution_id, *, input_tokens, output_tokens):
                permit = await accounting.model(budget_id, execution_id,
                    input_tokens=input_tokens, output_tokens=output_tokens)
                document, _ = await ledger.read()
                permits.append(permit | {"accepted": document["budgets"][budget_id]["history"][-1]["at"]})
                return permit

            async def finish_model(self, budget_id, attempt_id):
                await accounting.finish_model(budget_id, attempt_id)

        async def observed(response):
            content = await response.aread()
            if response.status_code != 200 or len(content) > 1024 * 1024:
                raise OperationError("indeterminate", "Definite bounded model response required")
            body = json.loads(content)
            usage = body["usage"]
            if (not isinstance(usage, dict) or any(type(usage.get(key)) is not int
                    or not 0 <= usage[key] <= bound for key, bound in (
                        ("prompt_tokens", 16000), ("completion_tokens", 2000), ("total_tokens", 18000)))
                    or usage["prompt_tokens"] + usage["completion_tokens"] != usage["total_tokens"]
                    or not isinstance(body["choices"][0]["message"]["content"], str)
                    or not body["choices"][0]["message"]["content"] or body["choices"][0]["finish_reason"] != "stop"):
                raise OperationError("indeterminate", "Complete actual model response and usage required")
            models.append({"request_id": gateway_request_id(response.headers), "status_code": 200,
                "target": hashlib.sha256(str(response.request.url).encode()).hexdigest(),
                "started": response.request.extensions["citadel_model_started"], "finished": time.time(),
                "input_tokens": usage["prompt_tokens"], "output_tokens": usage["completion_tokens"],
                "tokens": usage["total_tokens"]})
            if len(models) == 2:
                try:
                    await asyncio.sleep(90)
                except asyncio.CancelledError:
                    cancelled.append(True)
                    raise

        evidence = {"control": "Fictional connectivity only. Reply exactly OK.", "padding": ""}
        overhead = len((INSTRUCTIONS["candidate-planner"] + json.dumps(
            evidence, sort_keys=True, ensure_ascii=False, allow_nan=False)).encode()) + 1024
        evidence["padding"] = "x" * (16000 - overhead)
        self.model.http.event_hooks["response"].append(observed)
        try:
            await self.model.explain(ObservedAdmission(), operation, operation, evidence)
            try:
                await self.model.explain(ObservedAdmission(), operation, operation, evidence)
            except TimeoutError:
                if len(models) != 2 or len(permits) != 2 or cancelled != [True]:
                    raise OperationError("indeterminate", "Timeout without two definite responses retains global exclusion")
            else:
                raise OperationError("indeterminate", "Model response escaped the actual sixty-second guard")
        finally:
            self.model.http.event_hooks["response"].remove(observed)
        before, _ = await ledger.read()
        refusal = await rejected(lambda: accounting.model(operation, operation, input_tokens=16000, output_tokens=2000))
        final, _ = await ledger.read()
        retained = final["budgets"][operation]["model"]
        if retained != {key: permits[-1][key] for key in ("attempt_id", "deadline", "input_tokens", "output_tokens")}:
            raise OperationError("indeterminate", "Timed-out model admission was altered")
        return {"operation_id": operation, "deadline": budget["deadline"], "state": "timed_out",
            "models": models, "model": permits[-1],
            "replay": {"response": refusal, "before_sha256": sha256(before), "after_sha256": sha256(final)},
            "before_sha256": business_hash(initial), "after_sha256": business_hash(final)}


def evaluate_model_timeout(observation, snapshot, evidence, *, runtime_identity, observer_identity,
                           subscription, target, slot_target):
    from .operation_oracle import _matched
    from .oracle import hash_value
    blocked = {"check_id": "limit.model_timeout_seconds", "status": "blocked",
               "reason": "actual_model_expiry_retained_admission_and_service_proof_required"}
    try:
        actual, state = observation["actual"], snapshot["budget_state"]
        operation, run = observation["operation_id"], observation["run_id"]
        if (observation["check_id"] != blocked["check_id"] or observation["probe_id"] != blocked["check_id"]
                or observation["caller"] != "candidate-planner" or observation["runtime_identity"] != runtime_identity
                or runtime_identity == observer_identity or actual["operation_id"] != operation
                or observation["status_code"] != 201 or snapshot["status_code"] not in (200, 206)
                or not hash_value(snapshot["sha256"]) or snapshot["started"] < observation["finished"]
                or not all(hash_value(value) for value in (subscription, target, slot_target))
                or not _matched(observation, evidence, "storage", runtime_identity, "PutBlob", client_request_id=operation)
                or not _matched(snapshot, evidence, "storage", observer_identity, "GetBlob",
                                client_request_id=snapshot["operation_id"])):
            return blocked
        publication = [row for row in evidence if isinstance(row.get("facts"), dict)
            and row["facts"].get("sha256") == sha256(actual) and row["facts"].get("probe_id") == blocked["check_id"]]
        if not _matched(observation, publication, "application", runtime_identity, "execution",
                        caller="candidate-planner", run_id=run, operation_id=operation):
            return blocked
        models, permit = actual["models"], actual["model"]
        events = [row for row in evidence if row.get("source") == "application"
            and row.get("method") == "chat.completions" and row.get("run_id") == run
            and row.get("operation_id") == operation]
        if len(models) != 2 or len(events) != 2 or len({row["request_id"] for row in models}) != 2:
            return blocked
        gateway = [row for row in evidence if row.get("source") == "gateway" and row.get("target") == target
            and row.get("caller") == "candidate-planner" and type(row.get("observed")) in (int, float)
            and observation["started"] <= row["observed"] <= observation["finished"]]
        if len(gateway) != 2 or {row.get("request_id") for row in gateway} != {row["request_id"] for row in models}:
            return blocked
        for model in models:
            matches = [row for row in events if row.get("request_id") == model["request_id"]]
            gateways = [row for row in gateway if row["request_id"] == model["request_id"]]
            if (model["target"] != target or model["status_code"] != 200 or len(matches) != 1 or len(gateways) != 1
                    or any(type(model.get(key)) is not int or not 0 <= model[key] <= bound
                           for key, bound in (("input_tokens", 16000), ("output_tokens", 2000), ("tokens", 18000)))
                    or model["tokens"] != model["input_tokens"] + model["output_tokens"]
                    or not 0 <= model["finished"] - model["started"] <= 60
                    or not _matched(model, matches, "application", runtime_identity, "chat.completions",
                                    caller="candidate-planner")
                    or any(matches[0].get("facts", {}).get(key) != model[key]
                           for key in ("input_tokens", "output_tokens", "tokens", "started"))
                    or not model["started"] <= matches[0]["facts"]["finished"] <= model["finished"]
                    or gateways[0].get("status_code") != 200 or gateways[0].get("method") != "POST"
                    or gateways[0].get("credential_sha256") != subscription
                    or gateways[0].get("facts", {}).get("backend_dispatched") is not True
                    or not model["started"] - 5 <= gateways[0]["observed"] <= model["finished"] + 5):
                return blocked
        timers = [row for row in evidence if row.get("source") == "application"
            and row.get("method") == "model.timeout" and row.get("run_id") == run and row.get("operation_id") == operation]
        if len(timers) != 1:
            return blocked
        event, timer = timers[0], timers[0]["facts"]
        if (event.get("runtime_identity") != runtime_identity or event.get("caller") != "candidate-planner"
                or event.get("status_code") != 0 or timer.get("model_attempt_id") != permit["attempt_id"]
                or any(type(timer.get(key)) not in (int, float) or not math.isfinite(timer[key]) for key in
                       ("started", "finished", "deadline", "monotonic_started", "monotonic_deadline", "monotonic_finished"))
                or type(event.get("observed")) not in (int, float)
                or not timer["finished"] - 5 <= event["observed"] <= timer["finished"] + 5
                or timer["deadline"] != permit["deadline"]
                or not models[0]["finished"] <= permit["accepted"] <= timer["started"] <= models[1]["started"]
                       <= models[1]["finished"] <= timer["finished"] <= observation["finished"]
                or not timer["monotonic_started"] < timer["monotonic_deadline"] <= timer["monotonic_finished"]):
            return blocked
        slots = actual["slot"]
        for side, prefix in (("before", operation), ("after", operation + "-end")):
            slot = slots[side]
            if slot["scope_sha256"] != sha256("acceptance/" + run) or len(slot["steps"]) != 3:
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
                or max(models[-1]["finished"] + 60, timer["finished"]) > slots["after"]["steps"][0]["started"]):
            return blocked
        history = state["history"]
        valid = (actual["state"] == "timed_out" and permit["deadline"] - permit["accepted"] == 60
            and math.isclose(timer["monotonic_deadline"] - timer["monotonic_started"],
                             timer["deadline"] - timer["started"], rel_tol=0, abs_tol=1e-6)
            and 0 < timer["monotonic_deadline"] - timer["monotonic_started"] <= 60
            and (permit["input_tokens"], permit["output_tokens"]) == (16000, 2000)
            and state["closed"] is False and state["model_active"] is True and state["child_active"] is False
            and state["grant_present"] is False and state["model"] == {key: permit[key]
                for key in ("attempt_id", "deadline", "input_tokens", "output_tokens")}
            and state["run_id"] == operation and state["deadline"] == actual["deadline"]
            and state["agents_sha256"] == sha256({operation: 2})
            and all(type(state[key]) is int and state[key] == value for key, value in
                (("grant_count", 0), ("count", 1), ("agent_executions", 1), ("candidates", 0), ("history_count", 2)))
            and all(type(value) is int for value in state["remaining"].values())
            and state["remaining"] == {"agents": 41, "models": 126, "tokens": 964000, "reads": 512}
            and len(history) == 2 and all(type(row["tokens"]) is int and row["tokens"] == 18000 for row in history)
            and models[0]["finished"] <= history[0]["at"] <= history[1]["at"] - 5
            and history[1]["at"] == permit["accepted"] and actual["replay"]["response"] == "conflict"
            and hash_value(actual["replay"]["before_sha256"])
            and actual["replay"]["before_sha256"] == actual["replay"]["after_sha256"] == snapshot["sha256"]
            and hash_value(actual["before_sha256"])
            and actual["before_sha256"] == actual["after_sha256"] == snapshot["business_sha256"])
        return blocked | {"status": "pass" if valid else "fail",
            "reason": "actual_model_timer_and_retained_admission_verified" if valid else "model_timeout_invariant_failed"}
    except (KeyError, TypeError, ValueError, AttributeError, IndexError):
        return blocked
