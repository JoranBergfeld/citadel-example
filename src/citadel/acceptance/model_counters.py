"""Exhaust finite model admission using actual framework responses, never seeded counters."""

import hashlib
import json
import math
import time

from citadel.evidence.manifests import sha256
from citadel.operations import OperationError, identity
from citadel.operations.limits import Accounting
from citadel.operator.model_metadata import regional_standard_sku
from citadel.runtime.model import INSTRUCTIONS
from .admission_limits import business_hash
from .faults import rejected
from .telemetry import gateway_request_id


COUNTER_CHECKS = {"execution": "limit.model_attempts_execution", "run": "limit.model_attempts_run",
                  "tokens": "limit.tokens_run"}
COUNTER_MODES = {"model-execution-limit": "execution", "model-run-limit": "run", "model-token-limit": "tokens"}
COUNTER_GROUPS = {"execution": {COUNTER_CHECKS["execution"]},
                  "run": {COUNTER_CHECKS["run"], "limit.model_requests_minute"},
                  "tokens": {COUNTER_CHECKS["tokens"], "limit.model_tokens_minute_target"}}


def quota_inputs(lifecycle):
    deployments = [rid for rid in lifecycle.value["inventory"]
        if "/Microsoft.CognitiveServices/accounts/" in rid and rid.endswith("/deployments/citadel-gpt-41-mini")]
    if len(deployments) != 1:
        raise ValueError("Exactly one allocated model deployment required")
    return {"target": sha256(deployments[0].lower()), "capacity": lifecycle.config["modelCapacity"]}


def observe_model_quota(lifecycle, *, admit, run_id):
    """Two bounded ARM reads; never substitute configured TPM for live SKU metadata."""
    expected = quota_inputs(lifecycle)
    deployment = next(rid for rid in lifecycle.value["inventory"] if sha256(rid.lower()) == expected["target"])
    started = time.time()
    admit()
    regional = lifecycle.native.rest("get",
        lifecycle.subscription + "/providers/Microsoft.CognitiveServices/locations/westeurope/models", "2024-10-01")
    if regional.get("nextLink"):
        raise ValueError("Regional model metadata requires unbudgeted pagination")
    _, sku = regional_standard_sku(regional["value"])
    rates = [rate for rate in sku.get("rateLimits", []) if rate.get("key") == "token"]
    if len(rates) != 1:
        raise ValueError("Exact actual token quota metadata required")
    rate = rates[0]
    admit()
    deployed = lifecycle.native.rest("get", deployment, "2024-10-01")
    capacity, count, period = deployed["sku"]["capacity"], rate["count"], rate["renewalPeriod"]
    if (any(type(value) is not int or value <= 0 for value in (capacity, count, period))
            or count * 60 % period):
        raise ValueError("Finite integral actual TPM metadata required")
    props = deployed["properties"]
    configured = lifecycle.config["modelTokensPerMinute"]
    if (sha256(deployed["id"].lower()) != expected["target"] or capacity != expected["capacity"]
            or type(configured) is not int or not 18000 <= configured <= count * 60 // period * capacity <= 120000
            or (props["model"]["name"], props["model"]["version"], deployed["sku"]["name"],
                props["versionUpgradeOption"]) != ("gpt-4.1-mini", "2025-04-14", "Standard", "NoAutoUpgrade")):
        raise ValueError("Actual model deployment and quota differ from the allocated configuration")
    return {"source": "actual-regional-model-and-deployment", "run_id": run_id,
        "target": sha256(deployed["id"].lower()), "capacity": capacity, "rate_count": count,
        "renewal_seconds": period, "tokens_per_minute": count * 60 // period * capacity,
        "started": started, "finished": time.time(), "name": props["model"]["name"],
        "version": props["model"]["version"], "sku": deployed["sku"]["name"],
        "version_upgrade_option": props["versionUpgradeOption"]}


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
        reservations, models, rate_checks = [], [], []
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
                actual = await accounting.status(budget_id)
                models[-1]["settled_at"] = actual["history"][-1]["at"]
                settled[0] = model.clock()

        async def wait_after_model():
            until = settled[0] + 5
            while model.clock() < until:
                if model.clock() >= self.deadline:
                    raise OperationError("deadline", "Model counter control deadline expired")
                await model.sleep(min(5, until - model.clock()))

        async def rate_refusal(check_id, before):
            record = before["budgets"][operation]
            started = model.clock()
            proposed = reservations[-1]["input_bound"]
            response = await rejected(lambda: accounting.model(
                operation, execution, input_tokens=proposed, output_tokens=2000))
            finished = model.clock()
            after, _ = await self.ledger.read()
            rate_checks.append({"check_id": check_id, "response": response, "started": started, "finished": finished,
                "history": [row for row in record["history"] if row["at"] > started - 60],
                "tokens_per_minute": record["tokens_per_minute"], "input_tokens": proposed, "output_tokens": 2000,
                "remaining": record["remaining"], "model_attempts": record["agents"][execution],
                "model_active": record["model"] is not None, "child_active": record["child"] is not None,
                "closed": record["closed"], "before_sha256": sha256(before), "after_sha256": sha256(after)})
            if response != "rate_limited":
                raise OperationError("indeterminate", "The intended isolated rate refusal was not observed")

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
                if kind == "run" and index == 0:
                    before, _ = await self.ledger.read()
                    await rate_refusal("limit.model_requests_minute", before)
                elif kind == "tokens" and not rate_checks:
                    await wait_after_model()
                    before, _ = await self.ledger.read()
                    record = before["budgets"][operation]
                    recent = [row for row in record["history"] if row["at"] > model.clock() - 60]
                    if (sum(row["tokens"] for row in recent) + 18000 > record["tokens_per_minute"]
                            and len(recent) < 12 and model.clock() - recent[-1]["at"] >= 5):
                        await rate_refusal("limit.model_tokens_minute_target", before)
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
        result = {"operation_id": operation, "deadline": budget["deadline"], "models": models, "counter_kind": kind,
                "response": response, "before_sha256": sha256(before), "after_sha256": sha256(after),
                "refusal_started": refusal_started, "refusal_finished": refusal_finished,
                "business_before_sha256": business_hash(initial), "business_after_sha256": business_hash(final)}
        return result | ({"rate_check": rate_checks[0]} if rate_checks else {})


def evaluate_model_counter(observation, snapshot, evidence, *, runtime_identity, observer_identity,
                           subscription, target, slot_target, tokens_per_minute=None, quota_binding=None):
    from .operation_oracle import _matched
    from .oracle import hash_value
    blocked = {"check_id": observation.get("check_id"), "status": "blocked",
               "reason": "all_actual_counter_attempts_and_independent_state_required"}
    try:
        actual, state = observation["actual"], snapshot["budget_state"]
        kind = actual["counter_kind"]
        count = {"execution": 8, "run": 128, "tokens": 55}[kind]
        if (observation["check_id"] not in COUNTER_GROUPS[kind] or observation["probe_id"] != COUNTER_CHECKS[kind]
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
            and all(type(state[key]) is int for key in ("grant_count", "count", "agent_executions", "candidates"))
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
        if valid and observation["check_id"] != COUNTER_CHECKS[kind]:
            quota = snapshot.get("quota")
            if not isinstance(quota, dict) or not isinstance(quota_binding, dict):
                return blocked
            if (quota["source"] != "actual-regional-model-and-deployment" or quota["run_id"] != observation["run_id"]
                    or not hash_value(quota["target"]) or quota["target"] != quota_binding["target"]
                    or quota["capacity"] != quota_binding["capacity"]
                    or any(type(quota[key]) is not int or quota[key] <= 0 for key in
                           ("capacity", "rate_count", "renewal_seconds", "tokens_per_minute"))
                    or quota["rate_count"] * 60 % quota["renewal_seconds"]
                    or quota["tokens_per_minute"] != quota["rate_count"] * 60 // quota["renewal_seconds"] * quota["capacity"]
                    or type(tokens_per_minute) is not int or not tokens_per_minute <= quota["tokens_per_minute"] <= 120000
                    or (quota["name"], quota["version"], quota["sku"], quota["version_upgrade_option"]) !=
                       ("gpt-4.1-mini", "2025-04-14", "Standard", "NoAutoUpgrade")
                    or not observation["started"] - 900 <= quota["started"] <= quota["finished"] <= observation["started"]):
                return blocked
            return blocked | _rate_proof(observation["check_id"], actual, state, tokens_per_minute)
        return blocked | {"status": "pass" if valid else "fail",
                          "reason": "actual_model_counter_verified" if valid else "model_counter_invariant_failed"}
    except (KeyError, ValueError, TypeError, AttributeError, IndexError):
        return blocked


def _rate_proof(identifier, actual, state, quota):
    from .oracle import hash_value
    blocked = {"status": "blocked", "reason": "actual_rate_refusal_and_quota_binding_required"}
    try:
        check, models = actual["rate_check"], actual["models"]
        if (type(quota) is not int or not 18000 <= quota <= 120000
                or check["check_id"] != identifier or check["tokens_per_minute"] != quota
                or state["tokens_per_minute"] != quota
                or any(type(check[key]) not in (int, float) or not math.isfinite(check[key])
                       for key in ("started", "finished"))):
            return blocked
        prefix = [row for row in models if row["settled_at"] <= check["started"]]
        if not prefix or len(prefix) >= len(models):
            return blocked
        history = [{"at": row["settled_at"], "tokens": row["input_bound"] + 2000}
                   for row in prefix if row["settled_at"] > check["started"] - 60]
        cost = prefix[-1]["input_bound"] + 2000
        remaining = {"agents": 42 - len({row["execution_id"] for row in prefix}), "models": 128 - len(prefix),
                     "tokens": 1000000 - sum(row["input_bound"] + 2000 for row in prefix), "reads": 512}
        if (check["history"] != history or not history or check["remaining"] != remaining
                or check["input_tokens"] != prefix[-1]["input_bound"] or check["output_tokens"] != 2000
                or check["model_attempts"] != sum(row["execution_id"] == prefix[-1]["execution_id"] for row in prefix)
                or not 0 < check["model_attempts"] < 8 or remaining["models"] < 1 or remaining["tokens"] < cost
                or check["closed"] is not False or check["model_active"] is not False or check["child_active"] is not False
                or not hash_value(check["before_sha256"]) or not hash_value(check["after_sha256"])):
            return blocked
        rapid = identifier == "limit.model_requests_minute"
        elapsed = check["started"] - history[-1]["at"]
        reason_bound = (0 <= elapsed < 5 and len(history) < 12 and sum(row["tokens"] for row in history) + cost <= quota
                        if rapid else elapsed >= 5 and len(history) < 12
                        and sum(row["tokens"] for row in history) + cost > quota)
        if not reason_bound or not check["started"] <= check["finished"] <= prefix[-1]["finished"] + 60:
            return blocked
        for index, row in enumerate(models):
            if (type(row["settled_at"]) not in (int, float) or not math.isfinite(row["settled_at"])
                    or not row["finished"] <= row["settled_at"]
                    or index and row["started"] - models[index - 1]["settled_at"] < 5):
                return blocked
            recent = [prior for prior in models[:index] if prior["settled_at"] > row["started"] - 60]
            if len(recent) >= 12 or sum(prior["input_bound"] + 2000 for prior in recent) + row["input_bound"] + 2000 > quota:
                return {"status": "fail", "reason": "actual_rolling_model_admission_exceeded"}
        valid = check["response"] == "rate_limited" and check["before_sha256"] == check["after_sha256"]
        return {"status": "pass" if valid else "fail",
                "reason": "actual_rate_and_token_admission_verified" if valid else "actual_rate_refusal_failed"}
    except (KeyError, ValueError, TypeError, AttributeError, IndexError):
        return blocked
