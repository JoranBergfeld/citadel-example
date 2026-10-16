"""Exercise production budget admission, not fabricated agent/model completions."""

import math
import re
import time
import asyncio
import hashlib

from azure.core.exceptions import AzureError, HttpResponseError

from citadel.evidence.manifests import sha256
from citadel.operations import identity
from citadel.operations.limits import Accounting
from .faults import rejected
from .operation_oracle import _matched
from .oracle import hash_value


ADMISSION_CHECKS = {"limit.concurrent_runs", "limit.candidates", "limit.agent_executions"}


async def global_slot(container, *, run_id, operation_id, deadline):
    """Verify the real shared run lease, without creating a second run or grant."""
    if (type(deadline) not in (int, float) or not math.isfinite(deadline)
            or not time.time() < deadline <= time.time() + 900):
        raise ValueError("Run-slot controls require the inherited bounded deadline")
    from citadel.runtime.tickets import AzureTicketStore
    scope = "acceptance/" + identity(run_id)
    operation = identity(operation_id)
    blob = container.get_blob_client("active-run-slot.json")
    current = AzureTicketStore._lease(blob, scope)
    other = AzureTicketStore._lease(blob, scope + "-overlap")
    steps = []
    for index, (action, lease) in enumerate((("renew", current), ("acquire", other), ("renew", current))):
        row = {"operation_id": identity(f"{operation}-slot{index}"), "action": action,
               "target": hashlib.sha256(blob.url.encode()).hexdigest(), "started": time.time()}
        sent = False
        def once(request):
            nonlocal sent
            if sent or time.time() >= deadline:
                raise ValueError("Late or repeated run-slot probe dispatch refused")
            sent = True
            request.http_request.headers["x-ms-client-request-id"] = row["operation_id"]
        def received(response):
            row.update(request_id=response.http_response.headers.get("x-ms-request-id"),
                       status_code=response.http_response.status_code)
        try:
            async with asyncio.timeout(max(0, min(30, deadline - time.time()))):
                options = {"timeout": 5, "raw_request_hook": once, "raw_response_hook": received}
                if action == "acquire":
                    await lease.acquire(lease_duration=-1, **options)
                else:
                    await lease.renew(**options)
        except HttpResponseError:
            pass
        except (AzureError, TimeoutError):
            row["reason"] = "unavailable"
        row["finished"] = time.time()
        steps.append(row)
        if index == 0 and row.get("status_code") != 200:
            break
    return {"scope_sha256": sha256(scope), "steps": steps}


class AdmissionProbes:
    def __init__(self, ledger, *, workload, enabled, deadline):
        if (enabled is not True or workload != "candidate-planner"
                or type(deadline) not in (int, float) or not math.isfinite(deadline)
                or not time.time() < deadline <= time.time() + 900):
            raise ValueError("Bounded admission probes require the actual enabled Candidate Planner")
        self.ledger, self.deadline = ledger, deadline
        self.accounting = Accounting(ledger, workload=workload)

    async def nonmodel(self, *, operation_id):
        operation = identity(operation_id)
        overlap = identity(operation + "-overlap")
        initial, _ = await self.ledger.read()
        budget = await self.accounting.start_run(operation, deadline=self.deadline)
        checks = []

        async def refusal(check_id, callback):
            before, _ = await self.ledger.read()
            response = await rejected(callback)
            after, _ = await self.ledger.read()
            checks.append({"check_id": check_id, "response": response,
                           "before_sha256": sha256(before), "after_sha256": sha256(after)})

        await refusal("limit.concurrent_runs",
            lambda: self.accounting.start_run(overlap, deadline=self.deadline))
        for index in range(20):
            await self.accounting.candidate(operation, f"candidate{index:02}")
        await refusal("limit.candidates", lambda: self.accounting.candidate(operation, "candidateOverflow"))
        for index in range(42):
            await self.accounting.start_agent(operation, identity(f"{operation}-execution{index:02}"))
        await refusal("limit.agent_executions",
            lambda: self.accounting.start_agent(operation, identity(operation + "-overflow")))
        await self.accounting.close(operation)
        final, _ = await self.ledger.read()
        return {"operation_id": operation, "deadline": budget["deadline"], "checks": checks,
                "before_sha256": business_hash(initial), "after_sha256": business_hash(final)}


def business_hash(document):
    return sha256({key: document[key] for key in ("operations", "drafts", "findings")})


def admission_snapshot(document, result):
    budget = document["budgets"].get(result["operation_id"])
    if not isinstance(budget, dict):
        raise ValueError("Actual admission budget is absent")
    agents, candidates = budget.get("agents"), budget.get("candidates")
    remaining = budget.get("remaining")
    if (not isinstance(agents, dict) or not isinstance(candidates, list)
            or not isinstance(remaining, dict) or set(remaining) != {"agents", "models", "tokens", "reads"}
            or any(type(value) is not int for value in remaining.values())
            or not isinstance(budget.get("history"), list) or not isinstance(budget.get("grants"), list)
            or not {"model", "child", "grant"} <= budget.keys()):
        raise ValueError("Actual admission counters are malformed")
    return {"budget_state": {"run_id": budget.get("run_id"), "closed": budget.get("closed"),
        "deadline": budget.get("deadline"), "agent_executions": len(agents), "candidates": len(candidates),
        "agents_sha256": sha256(agents), "candidates_sha256": sha256(candidates),
        "remaining": remaining, "model_active": budget["model"] is not None,
        "child_active": budget["child"] is not None, "grant_present": budget["grant"] is not None,
        "history_count": len(budget["history"]), "grant_count": len(budget["grants"]),
        "tokens_per_minute": budget.get("tokens_per_minute"),
        "count": len(document["budgets"])},
        "overlap_state": "present" if result["operation_id"] + "-overlap" in document["budgets"] else "missing",
        "business_sha256": business_hash(document)}


def evaluate_admission(observation, snapshot, evidence, *, runtime_identity, observer_identity):
    blocked = {"check_id": observation.get("check_id") if isinstance(observation, dict) else None,
               "status": "blocked", "reason": "admission_state_or_service_correlation_missing"}
    if (any(not isinstance(value, dict) for value in (observation, snapshot))
            or not isinstance(evidence, list) or any(not isinstance(row, dict) for row in evidence)
            or observation.get("probe_id") != "limit.agent_executions"
            or not isinstance(observation.get("check_id"), str) or observation["check_id"] not in ADMISSION_CHECKS
            or observation.get("caller") != "candidate-planner"
            or observation.get("runtime_identity") != runtime_identity or runtime_identity == observer_identity
            or any(not isinstance(observation.get(key), str)
                   or not re.fullmatch("[A-Za-z0-9_-]{1,64}", observation[key]) for key in ("operation_id", "run_id"))
            or not isinstance(observation.get("actual"), dict)
            or observation["actual"].get("operation_id") != observation["operation_id"]
            or not isinstance(snapshot.get("budget_state"), dict)
            or observation.get("status_code") != 201 or snapshot.get("status_code") not in (200, 206)
            or not hash_value(snapshot.get("sha256"))
            or not _matched(observation, evidence, "storage", runtime_identity, "PutBlob",
                            client_request_id=observation["operation_id"])
            or not _matched(snapshot, evidence, "storage", observer_identity, "GetBlob",
                            client_request_id=snapshot.get("operation_id"))
            or snapshot["started"] < observation["finished"]):
        return blocked
    actual, budget = observation["actual"], snapshot["budget_state"]
    events = [row for row in evidence if isinstance(row.get("facts"), dict)
              and row["facts"].get("sha256") == sha256(actual)
              and row["facts"].get("probe_id") == "limit.agent_executions"]
    if not _matched(observation, events, "application", runtime_identity, "execution",
        run_id=observation["run_id"], operation_id=observation["operation_id"], caller="candidate-planner"):
        return blocked
    slot = actual.get("slot")
    if (not isinstance(slot, dict) or slot.get("scope_sha256") != sha256("acceptance/" + observation["run_id"])
            or not isinstance(slot.get("steps"), list) or len(slot["steps"]) != 3):
        return blocked
    slots = slot["steps"]
    if (any(not isinstance(row, dict) or row.get("operation_id") != observation["operation_id"] + f"-slot{index}"
            or not _matched(row, evidence, "storage", runtime_identity, "LeaseBlob",
                            client_request_id=row.get("operation_id"))
            or not observation["started"] <= row["started"] <= row["finished"] <= observation["finished"]
            or row["finished"] - row["started"] > 30 for index, row in enumerate(slots))
            or [row.get("action") for row in slots] != ["renew", "acquire", "renew"]
            or len({row["request_id"] for row in slots}) != 3 or len({row["target"] for row in slots}) != 1
            or any(slots[index]["started"] < slots[index - 1]["finished"] for index in (1, 2))):
        return blocked
    if slots[1]["status_code"] == 201:
        return blocked | {"status": "fail", "reason": "overlapping_global_run_admitted"}
    if [row["status_code"] for row in slots] != [200, 409, 200]:
        return blocked
    checks, remaining = actual.get("checks"), budget.get("remaining")
    operation = observation["operation_id"]
    valid = (isinstance(checks, list) and len(checks) == 3
        and all(isinstance(row, dict) and isinstance(row.get("check_id"), str) for row in checks)
        and {row["check_id"] for row in checks} == ADMISSION_CHECKS
        and all(row.get("response") == ("conflict" if row["check_id"] == "limit.concurrent_runs" else "exhausted")
            and hash_value(row.get("before_sha256")) and row["before_sha256"] == row.get("after_sha256")
            for row in checks)
        and budget.get("closed") is True and budget.get("run_id") == operation
        and type(budget.get("deadline")) in (int, float) and math.isfinite(budget["deadline"])
        and observation["finished"] <= budget["deadline"] <= observation["started"] + 900
        and budget["deadline"] == actual.get("deadline")
        and all(type(budget.get(key)) is int and budget[key] == value
                for key, value in (("agent_executions", 42), ("candidates", 20), ("history_count", 0),
                                   ("grant_count", 0), ("count", 1)))
        and all(budget.get(key) is False for key in ("model_active", "child_active", "grant_present"))
        and budget.get("agents_sha256") == sha256({f"{operation}-execution{index:02}": 0 for index in range(42)})
        and budget.get("candidates_sha256") == sha256([f"candidate{index:02}" for index in range(20)])
        and isinstance(remaining, dict) and all(type(value) is int for value in remaining.values())
        and remaining == {"agents": 0, "models": 128, "tokens": 1000000, "reads": 512}
        and snapshot.get("overlap_state") == "missing"
        and hash_value(actual.get("before_sha256"))
        and actual["before_sha256"] == actual.get("after_sha256") == snapshot.get("business_sha256"))
    return blocked | {"status": "pass" if valid else "fail", "business_state": "budget_admission_only",
        "reason": "verified_nonmodel_admission_boundary" if valid else "admission_boundary_invariant_failed"}
