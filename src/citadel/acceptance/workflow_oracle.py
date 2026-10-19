"""Independent evidence for the original production workflow expiry, not a shorter hold."""

import math

from citadel.evidence.manifests import sha256
from .oracle import hash_value
from .rotation_controls import LEDGERS
from .storage_probes import _correlated


CHECK = "limit.workflow_seconds"


def evaluate_workflow(check, report):
    blocked = {"check_id": CHECK, "status": "blocked",
               "reason": "production_workflow_expiry_refusal_restoration_and_no_effect_required"}
    try:
        value, evidence = check["actual"], report["evidence"]
        run, operations = value["run_id"], report["operation_ids"]
        actor = report["runtime_identities"]["candidate-planner"]
        receipt, control, budget = value["observation"], value["control"], value["budget_state"]
        if (run not in operations or value["state"] != "restored"
                or not hash_value(value["before_sha256"])
                or value["before_sha256"] != value["after_sha256"]
                or not 0 < value["deadline"] - value["started"] <= 1140
                or not value["started"] < value["finished"] <= value["deadline"]
                or budget["remaining"] != {"agents": 41, "models": 128, "tokens": 1000000, "reads": 512}
                or budget["closed"] is not False or not hash_value(budget["before_sha256"])
                or budget["before_sha256"] != budget["after_sha256"]):
            return blocked

        def events(method):
            return [row for row in evidence if row.get("source") == "application"
                and row.get("method") == method and row.get("run_id") == run
                and row.get("operation_id") == run and row.get("runtime_identity") == actor
                and row.get("caller") == ("operator" if method == "workflow.admitted" else "candidate-planner")
                and type(row.get("observed")) in (int, float)
                and value["started"] - 5 <= row["observed"] <= value["finished"] + 5]

        selected = {method: events(method) for method in (
            "workflow.admitted", "workflow.held", "workflow.timeout", "workflow.refused", "workflow.fenced")}
        if any(len(rows) != 1 for rows in selected.values()):
            return blocked
        admitted, held, timer, refused, fenced = (
            selected[method][0]["facts"] for method in selected)
        deadline = admitted["deadline"]
        if (deadline - admitted["started"] != 900 or budget["deadline"] != deadline
                or not value["started"] <= admitted["started"] <= value["started"] + 120
                or not deadline <= value["finished"] <= deadline + 120
                or held["sha256"] != budget["before_sha256"] or held["deadline"] != deadline
                or timer["deadline"] != deadline or refused["deadline"] != deadline
                or fenced["deadline"] != deadline or refused["reason"] != "deadline"
                or fenced["business_state"] != "failed_no_commit" or fenced["generation"] != 2
                or fenced["before_sha256"] != budget["before_sha256"]
                or fenced["after_sha256"] != budget["after_sha256"]):
            return blocked
        if (any(type(timer[key]) not in (int, float) or not math.isfinite(timer[key]) for key in (
                    "started", "finished", "monotonic_started", "monotonic_deadline", "monotonic_finished"))
                or not admitted["started"] <= timer["started"] < deadline
                or not deadline <= timer["finished"] <= deadline + 120
                or not 0 <= timer["monotonic_finished"] - timer["monotonic_deadline"] <= 120
                or abs((timer["monotonic_deadline"] - timer["monotonic_started"])
                       - (deadline - timer["started"])) > .05
                or not timer["finished"] - 5 <= selected["workflow.refused"][0]["observed"]
                    <= selected["workflow.fenced"][0]["observed"] + 5):
            return blocked
        if (receipt["run_id"] != run or receipt["operation_id"] != run or receipt["caller"] != "operator"
                or receipt["status_code"] != 200 or receipt["target"] != report["gateway_targets"]["candidate-planner"]
                or receipt["facts"]["accepted_operation_id"] != run
                or receipt["facts"]["business_state"] not in ("TASK_STATE_SUBMITTED", "TASK_STATE_WORKING")
                or not hash_value(receipt["facts"]["task_sha256"])
                or not value["started"] <= receipt["started"] <= receipt["finished"] <= value["started"] + 120):
            return blocked
        gateways = [row for row in evidence if row.get("source") == "gateway"
            and row.get("request_id") == receipt["request_id"] and row.get("target") == receipt["target"]
            and row.get("caller") == "operator" and row.get("method") == "POST"
            and row.get("status_code") == 200
            and row.get("credential_sha256") == report["subscription_bindings"]["operator"]
            and row.get("facts", {}).get("backend_dispatched") is True
            and row.get("facts", {}).get("backend_status") == 200
            and receipt["started"] - 5 <= row.get("observed", -1) <= receipt["finished"] + 5]
        backends = [row for row in evidence if row.get("source") == "application"
            and row.get("request_id") == receipt["request_id"] and row.get("method") == "SendMessage"
            and row.get("runtime_identity") == actor and row.get("run_id") == run
            and row.get("operation_id") == run and row.get("caller") == "operator"
            and row.get("facts", {}).get("accepted_operation_id") == run
            and row.get("facts", {}).get("deadline") == deadline
            and row.get("status_code") == 200
            and receipt["started"] - 5 <= row.get("observed", -1) <= receipt["finished"] + 5]
        if len(gateways) != 1 or len(backends) != 1:
            return blocked
        if any(row.get("source") == "gateway"
               and row.get("caller") in ("operator", *report["runtime_identities"])
               and type(row.get("observed")) in (int, float)
               and receipt["started"] <= row["observed"] <= value["finished"]
               and row.get("request_id") != receipt["request_id"] for row in evidence):
            return blocked
        snapshots = {}
        observer = None
        for side in ("before", "after"):
            rows = value[side]
            if len(rows) != len(LEDGERS) or {row["container"] for row in rows} != set(LEDGERS):
                return blocked
            snapshots[side] = {}
            for row in rows:
                observed_by = {event.get("runtime_identity") for event in evidence
                    if event.get("source") == "storage" and event.get("request_id") == row["request_id"]}
                if len(observed_by) != 1:
                    return blocked
                current_observer = observed_by.pop()
                observer = observer or current_observer
                if (observer != current_observer or observer in report["runtime_identities"].values()
                        or row["operation_id"] not in operations or row["suite_id"] != report["run_id"]
                        or row["caller"] != "operator" or row["action"] != "read"
                        or row["target"] != report["storage_targets"][row["container"]]
                        or row["status_code"] not in (200, 206) or not hash_value(row["sha256"])
                        or not _correlated(row, evidence, observer)
                        or not value["started"] <= row["started"] <= row["finished"] <= value["finished"]
                        or side == "before" and row["finished"] > receipt["started"]
                        or side == "after" and row["started"] < timer["finished"]):
                    return blocked
                snapshots[side][row["container"]] = row
        for container in LEDGERS:
            field = "business_sha256" if container == "planner-operations" else "sha256"
            if (not hash_value(snapshots["before"][container][field])
                    or snapshots["before"][container][field] != snapshots["after"][container][field]):
                return blocked
        allowed = value["allowed"]
        admitted_root = allowed["control_reference"]
        if (allowed["container"] != "planner-operations" or allowed["action"] != "read"
                or allowed["target"] != report["storage_targets"]["planner-operations"]
                or allowed["suite_id"] != report["run_id"] or allowed["caller"] != "operator"
                or allowed["operation_id"] not in operations or allowed["status_code"] not in (200, 206)
                or not _correlated(allowed, evidence, observer)
                or not receipt["started"] <= allowed["started"] <= allowed["finished"] <= value["started"] + 120
                or admitted_root["budget_state"] != budget or admitted_root["state"] != "running"
                or admitted_root["generation"] != 1
                or admitted_root["run_id"] != run or admitted_root["operation_id"] != run
                or admitted_root["deadline"] != deadline or admitted_root["business_state"] != "not_dispatched"):
            return blocked
        root = control["control_reference"]
        expected_input = sha256({"inputs": {"operation_id": run, "run_id": run, "fixture": "base-source"},
                                  "run_id": run, "deadline": deadline})
        if (control["request_id"] != snapshots["after"]["planner-operations"]["request_id"]
                or control["sha256"] != snapshots["after"]["planner-operations"]["sha256"]
                or root["run_id"] != run or root["operation_id"] != run or root["deadline"] != deadline
                or root["state"] != "failed_no_commit" or root["generation"] != 2
                or root["input_hash"] != expected_input or admitted_root["input_hash"] != expected_input
                or root["business_state"] != "not_dispatched"
                or root["budget_state"] != budget):
            return blocked
        return blocked | {"status": "pass", "reason": "production_900_second_expiry_without_replay_verified"}
    except (KeyError, TypeError, ValueError, AttributeError, IndexError):
        return blocked
