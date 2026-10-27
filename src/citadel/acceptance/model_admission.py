"""Private operator control tickets; never workload grants or inference authority."""

import math
import time
from copy import deepcopy

from citadel.operations import OperationError, identity
from citadel.operator.state import Blocked
from .coverage import STORAGE
from .model_probes import AUTH_ERRORS, INPUT_BOUND, OUTPUT_BOUND
from .telemetry import opaque


class ModelAdmission:
    def __init__(self, phase, *, save, tokens_per_minute, clock=time.time):
        if (not isinstance(phase, dict) or not callable(save)
                or type(tokens_per_minute) is not int or not 1 <= tokens_per_minute <= 120000):
            raise ValueError("Actual bounded model quota and persistent control state required")
        identity(phase["run_id"])
        deadline = phase.get("deadline")
        if (type(deadline) not in (int, float) or not math.isfinite(deadline)
                or not clock() < deadline <= clock() + 900):
            raise OperationError("deadline", "Control window is expired or malformed")
        self.phase, self.save, self.quota, self.clock = phase, save, tokens_per_minute, clock
        keys = {"remaining", "model_active", "model_history", "model_tickets", "tokens_per_minute"}
        if not keys & phase.keys():
            phase.update(remaining={"models": 128, "tokens": 1000000, "agents": 42},
                model_active=None, model_history=[], model_tickets={}, tokens_per_minute=tokens_per_minute)
        elif not keys <= phase.keys() or phase["tokens_per_minute"] != tokens_per_minute:
            raise Blocked("model_control_state_requires_reconciliation")

    def reserve(self, workload, *, operation_id):
        operation = identity(operation_id)
        phase, now = self.phase, self.clock()
        if workload not in (*STORAGE, "operator"):
            raise OperationError("forbidden", "Only actual allocated workload controls")
        if now >= phase["deadline"]:
            raise OperationError("deadline", "Control window expired")
        if phase["model_active"] is not None or workload in phase["model_tickets"]:
            raise OperationError("conflict", "Outstanding or already dispatched control cannot replay")
        if any(row["operation_id"] == operation for row in phase["model_tickets"].values()):
            raise OperationError("conflict", "Control operation identity already spent")
        history = [row for row in phase["model_history"] if row["at"] > now - 60]
        tokens = INPUT_BOUND + OUTPUT_BOUND
        if (len(history) >= 12 or sum(row["tokens"] for row in history) + tokens > self.quota
                or history and now - history[-1]["at"] < 5):
            raise OperationError("rate_limited", "Actual shared control rate or token quota exhausted")
        if (phase["remaining"]["models"] < 1 or phase["remaining"]["tokens"] < tokens
                or phase["remaining"]["agents"] < 1):
            raise OperationError("exhausted", "Finite model control envelope exhausted")
        permit = {"run_id": phase["run_id"], "operation_id": operation, "caller": workload,
                  "started": now, "deadline": phase["deadline"],
                  "input_tokens": INPUT_BOUND, "output_tokens": OUTPUT_BOUND}
        phase["remaining"]["models"] -= 1
        phase["remaining"]["agents"] -= 1
        phase["remaining"]["tokens"] -= tokens
        phase["model_active"] = deepcopy(permit)
        phase["model_tickets"][workload] = deepcopy(permit)
        phase["model_history"] = history + [{"at": now, "tokens": tokens}]
        self.save()
        return permit

    def settle(self, permit, observation):
        phase, now = self.phase, self.clock()
        if (phase["model_active"] != permit or not isinstance(observation, dict)
                or any(observation.get(key) != permit[key] for key in ("run_id", "operation_id", "caller"))
                or observation.get("state") != "observed"
                or not isinstance(observation.get("request_id"), str)
                or type(observation.get("status_code")) is not int
                or not (
                    observation["status_code"] in (401, 403) and observation.get("reason") in AUTH_ERRORS
                    or permit["caller"] == "operator" and observation["status_code"] == 403
                    and observation.get("reason") == "model_caller_denied"
                    or observation["status_code"] == 200
                    and observation.get("reason") == "unauthorized_model_succeeded")
                or any(type(observation.get(key)) not in (int, float)
                       or not math.isfinite(observation[key]) for key in ("started", "finished"))
                or not permit["started"] <= observation["started"] <= observation["finished"] <= now
                or now >= phase["deadline"] or observation["finished"] - observation["started"] > 60):
            raise Blocked("model_control_outcome_requires_reconciliation")
        opaque(observation["request_id"])
        phase["model_tickets"][permit["caller"]]["request_id"] = observation["request_id"]
        phase["model_history"][-1]["at"] = now
        phase["model_active"] = None
        self.save()
