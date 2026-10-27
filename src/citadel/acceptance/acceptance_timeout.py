"""Private fixed cached-root response hold; no new work, impersonation or read pool."""

import asyncio
import copy
import json
import math
import time

from citadel.operations import OperationError, identity
from citadel.evidence.manifests import sha256
from citadel.operator.state import Blocked
from .revision import template


class CachedAcceptanceHold:
    def __init__(self, run_id, deadline):
        self.run_id, self.deadline, self.used = run_id, deadline, False

    @classmethod
    def from_environment(cls, environment, *, workload):
        raw = environment.get("CITADEL_ACCEPTANCE_HOLD")
        if raw is None:
            return None
        try:
            request = json.loads(raw)
            if (environment.get("CITADEL_ACCEPTANCE_ENABLED") != "true" or workload != "candidate-planner"
                    or set(request) != {"run_id", "deadline", "mode"} or request["mode"] != "cached-acceptance"
                    or type(request["deadline"]) not in (int, float) or not math.isfinite(request["deadline"])
                    or not time.time() < request["deadline"] <= time.time() + 900):
                raise ValueError("Exact live private cached acceptance control required")
            return cls(identity(request["run_id"]), request["deadline"])
        except (OperationError, TypeError, KeyError):
            raise ValueError("Invalid cached acceptance control") from None

    async def wait(self, caller, payload, status):
        if payload["run_id"] != self.run_id:
            return
        if (caller != "operator" or status["state"] != "succeeded"
                or payload != {"operation_id": self.run_id, "run_id": self.run_id, "fixture": "base-source"}
                or status["operation_id"] != self.run_id or status["run_id"] != self.run_id
                or self.used or time.time() >= self.deadline):
            raise OperationError("indeterminate", "Only one definite completed-root hold is permitted")
        self.used = True
        await asyncio.sleep(20)


class CachedAcceptanceRevision:
    environment_name = "CITADEL_ACCEPTANCE_HOLD"

    def __init__(self, lifecycle, *, operation_id, run_id, deadline, admit):
        self.lifecycle, self.operation_id, self.admit = lifecycle, operation_id, admit
        self.request = {"run_id": run_id, "deadline": deadline, "mode": "cached-acceptance"}
        apps = [app for app in lifecycle.value["outputs"]["appInventory"]
            if app["app"].rsplit("/", 1)[-1] == lifecycle.id + "-candidate-planner"]
        if len(apps) != 1:
            raise Blocked("exact_owned_planner_application_required")
        self.app = apps[0]

    def start(self):
        intents = self.lifecycle.value.setdefault("probe_intents", {})
        if self.operation_id in intents:
            raise Blocked("cached_acceptance_revision_must_not_replay")
        self.admit()
        deployed = self.lifecycle.native.rest("get", self.app["app"], "2025-01-01")
        original = template(deployed["properties"]["template"])
        containers = original["containers"]
        if (len(containers) != 1 or containers[0]["image"] != self.app["image"]
                or containers[0].get("command") != ["python", "-m", "citadel.runtime"]
                or any(item["name"].startswith("CITADEL_ACCEPTANCE_") for item in containers[0]["env"])):
            raise Blocked("pinned_normal_runtime_revision_required")
        replacement = copy.deepcopy(original)
        replacement["containers"][0]["env"].extend([
            {"name": "CITADEL_ACCEPTANCE_ENABLED", "value": "true"},
            {"name": self.environment_name, "value": json.dumps(self.request)}])
        self.original, self.replacement = original, replacement
        intents[self.operation_id] = {"state": "dispatching", "original": original,
            "replacement_sha256": sha256(replacement), "deadline": self.request["deadline"],
            "workload": "candidate-planner"}
        self.lifecycle.state.save()
        suffix = "acceptance-" + self.operation_id[:20]
        self.lifecycle.native.rest("patch", self.app["app"], "2025-01-01",
                                   {"properties": {"template": replacement | {"revisionSuffix": suffix}}})
        self._ready(suffix, replacement)

    def _ready(self, suffix, expected_template):
        expected = self.app["app"].rsplit("/", 1)[-1] + "--" + suffix
        for _ in range(40):
            bound = getattr(self, "readiness_deadline", self.request["deadline"])
            if time.time() >= bound:
                raise Blocked("fixed_runtime_revision_readiness_deadline")
            self.admit()
            actual = self.lifecycle.native.rest("get", self.app["app"], "2025-01-01")["properties"]
            if (actual.get("latestRevisionName") == actual.get("latestReadyRevisionName") == expected
                    and template(actual["template"]) == expected_template):
                return
            time.sleep(min(15, max(0, bound - time.time())))
        raise Blocked("cached_acceptance_revision_readiness_unverified")

    def restore(self):
        self.admit()
        current = template(self.lifecycle.native.rest("get", self.app["app"], "2025-01-01")["properties"]["template"])
        if current != self.replacement:
            raise Blocked("concurrent_cached_acceptance_revision_modification")
        suffix = "restored-" + self.operation_id[:20]
        self.lifecycle.native.rest("patch", self.app["app"], "2025-01-01",
                                   {"properties": {"template": self.original | {"revisionSuffix": suffix}}})
        self._ready(suffix, self.original)
        self.lifecycle.value["probe_intents"][self.operation_id]["state"] = "observed"
        self.lifecycle.state.save()
