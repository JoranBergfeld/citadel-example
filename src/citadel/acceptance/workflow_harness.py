"""Bounded operator envelope around one unchanged production 900-second workflow."""

import asyncio
import copy
import json
import time
from uuid import uuid4

import httpx

from citadel.evidence.manifests import sha256
from citadel.operator.state import Blocked
from .acceptance_timeout import CachedAcceptanceRevision
from .collection import AzureQuery, Collector, collection_remaining
from .rotation_controls import LEDGERS
from .storage_probes import StorageControls
from .storage_accounts import storage_accounts
from .workflow_oracle import CHECK, evaluate_workflow


class WorkflowRevision(CachedAcceptanceRevision):
    environment_name = "CITADEL_ACCEPTANCE_WORKFLOW_HOLD"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.request["mode"] = "workflow-timeout"


def without_root(document, run_id):
    result = copy.deepcopy(document)
    result["operations"].pop("operator/invoke/" + run_id, None)
    result["budgets"].pop(run_id, None)
    result["runs"].pop(run_id, None)
    return sha256(result)


def root_reference(document, run_id, before_budget):
    root = document["operations"]["operator/invoke/" + run_id]
    budget = document["budgets"][run_id]
    if (root["external"] or root["result"] is not None or "product" in root
            or budget["model"] is not None or budget["child"] is not None
            or budget["candidates"] or budget["grants"] or budget["history"]
            or set(budget["agents"]) != {run_id}):
        raise Blocked("workflow_root_effect_or_unexpected_admission")
    return {key: root[key] for key in
        ("operation_id", "run_id", "deadline", "state", "generation", "input_hash")} | {
        "business_state": "not_dispatched", "budget_state": {
            "deadline": budget["deadline"], "remaining": budget["remaining"], "closed": budget["closed"],
            "before_sha256": before_budget, "after_sha256": sha256(budget)}}


class WorkflowAcceptance:
    def __init__(self, lifecycle):
        self.lifecycle = lifecycle

    def execute(self, report):
        if "workflow_timeout_phase" in report:
            raise Blocked("workflow_timeout_intent_requires_reconciliation_never_replay")
        lifecycle, started, run = self.lifecycle, time.time(), uuid4().hex
        from citadel.operator.quiescence import runs_quiescent
        if not runs_quiescent(lifecycle):
            raise Blocked("workflow_control_requires_quiescence")
        accounts = storage_accounts(lifecycle)
        phase = {"run_id": run, "state": "dispatching", "started": started, "finished": started,
            "deadline": started + 1140, "read_attempts": 0, "before": [], "after": []}
        report["workflow_timeout_phase"] = phase
        report["operation_ids"].append(run)
        local = {"state": "control_intent", "fixture": "base-source", "scenario": "workflow-timeout",
                 "deadline": None, "reads": 0}
        lifecycle.value["runs"][run] = local
        lifecycle.state.save()
        bound = started + 120

        def admit():
            if phase["read_attempts"] >= 512 or time.time() >= bound:
                raise Blocked("workflow_control_original_envelope_or_reads_exhausted")
            phase["read_attempts"] += 1
            lifecycle.state.save()

        native, previous = lifecycle.native, getattr(lifecycle.native, "deadline", None)

        def native_bound():
            native.deadline = min(previous or float("inf"), time.monotonic() + max(0, bound - time.time()))

        def retain(row):
            report["operation_ids"].append(row["operation_id"])
            lifecycle.state.save()
            return row

        controls = StorageControls(native, account=accounts, suite_id=report["run_id"], admit=admit)

        def snapshot(side):
            for container in LEDGERS:
                row, raw = controls._read(container, "ledger-v1.json")
                document = json.loads(raw)
                if container == "planner-operations":
                    row["business_sha256"] = without_root(document, run)
                    if side == "after":
                        row["control_reference"] = root_reference(document, run, phase["budget_state"]["before_sha256"])
                        phase["control"] = row
                        phase["budget_state"] = row["control_reference"]["budget_state"]
                phase[side].append(retain(row))

        native_bound()
        try:
            snapshot("before")
            revision = WorkflowRevision(lifecycle, operation_id=run, run_id=run,
                deadline=phase["deadline"], admit=admit)
            revision.readiness_deadline = bound
            revision.start()
            phase["before_sha256"] = sha256(revision.original)
            credentials = lifecycle.credentials()
            if credentials["callerStates"]["operator"] != "active":
                raise Blocked("operator_workflow_credential_suspended")

            async def invoke():
                from citadel.operator.scenarios import PlannerClient
                admit()
                async with httpx.AsyncClient(follow_redirects=False, trust_env=False, timeout=30) as http:
                    client = PlannerClient(lifecycle.value["outputs"]["gatewayUrl"],
                        credentials["callerKeys"]["operator"]["primary"], http=http)
                    await client.invoke(run, "base-source", bound)
                    if client.invocation_receipt is None:
                        raise Blocked("actual_workflow_admission_receipt_required")
                    return client.invocation_receipt

            phase["observation"] = asyncio.run(invoke())
            while True:
                row, raw = controls._read("planner-operations", "ledger-v1.json")
                document = json.loads(raw)
                budget = document["budgets"][run]
                root = document["operations"]["operator/invoke/" + run]
                retain(row)
                if run in budget["agents"]:
                    break
                time.sleep(min(1, max(0, bound - time.time())))
            if (not started <= budget["deadline"] - 900 <= started + 120
                    or root["deadline"] != budget["deadline"]
                    or budget["remaining"] != {"agents": 41, "models": 128, "tokens": 1000000, "reads": 512}):
                raise Blocked("full_new_production_workflow_admission_required")
            phase["budget_state"] = {"before_sha256": sha256(budget)}
            row["control_reference"] = root_reference(document, run, sha256(budget))
            phase["allowed"] = row
            local["deadline"] = budget["deadline"]
            lifecycle.state.save()
            bound = min(phase["deadline"], budget["deadline"] + 120)
            native_bound()
            time.sleep(max(0, budget["deadline"] - time.time()) + .05)
            while True:
                row, raw = controls._read("planner-operations", "ledger-v1.json")
                document = json.loads(raw)
                retain(row)
                root = document["operations"]["operator/invoke/" + run]
                if root["state"] == "failed_no_commit":
                    break
                if root["state"] not in ("pending", "running"):
                    raise Blocked("workflow_terminal_state_ambiguous")
                time.sleep(min(1, max(0, bound - time.time())))
            snapshot("after")
            revision.readiness_deadline = bound
            revision.restore()
            phase.update(state="restored", after_sha256=sha256(revision.original), finished=time.time())
            check = {"check_id": CHECK, "expected": "boundary", "actual": phase}
            from .operator_hooks import Harness
            result = evaluate_workflow(check, report)
            from .retention import workspace_resource
            workspace = workspace_resource(lifecycle)
            if collection_remaining(report, time.time()) > 0:
                bound = time.time() + collection_remaining(report, time.time())
                native_bound()
                window = {"started": time.time(), "finished": None}
                report.setdefault("collection_windows", {})["workflow-" + run] = window
                lifecycle.state.save()
                try:
                    while result["status"] != "pass" and time.time() < bound:
                        self._collect(report, phase, workspace, admit, bound)
                        result = evaluate_workflow(check, report)
                        if result["status"] != "pass":
                            time.sleep(min(15, max(0, bound - time.time())))
                finally:
                    window["finished"] = time.time()
                    lifecycle.state.save()
            if result["status"] == "pass":
                local["state"] = "failed_no_commit"
            Harness._replace(report, check | result)
            lifecycle.state.save()
            if result["status"] != "pass":
                raise Blocked("workflow_independent_proof_incomplete_exclusion_retained")
        finally:
            if phase["state"] != "restored":
                phase["finished"] = time.time()
            report["finished"] = phase["finished"]
            native.deadline = previous
            lifecycle.state.save()

    def _collect(self, report, phase, workspace, admit, deadline):
        admit()
        actual = self.lifecycle.native.rest("get", workspace, "2022-10-01")
        remaining = min(600, deadline - time.time())
        report["evidence"] = Collector(
            AzureQuery(self.lifecycle.native, actual["properties"]["customerId"]),
            started=report.get("started", phase["started"]), finished=phase["finished"],
            prior=report["evidence"], budget_seconds=remaining).poll()
