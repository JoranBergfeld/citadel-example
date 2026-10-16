"""Observe actual scenario products with six operator reads, never extra workload tickets."""

import json
import time

from azure.core.exceptions import AzureError

from citadel.evidence import EvidenceError
from citadel.operations import OperationError
from citadel.operator.state import Blocked
from citadel.runtime.configuration import OPERATIONS
from .oracle import hash_value
from .scenario_proof import scenario_snapshot, evaluate_scenario_proof
from .scenarios import FIXTURES
from .storage_probes import StorageControls


class ScenarioAcceptance:
    def __init__(self, lifecycle):
        self.lifecycle = lifecycle

    def execute(self, report, scenario, product, *, source, run_id):
        if scenario not in FIXTURES or run_id not in report["operation_ids"]:
            raise Blocked("approved_scenario_identity_required")
        phases = report.setdefault("scenario_phase", {})
        if scenario in phases:
            raise Blocked("scenario_observation_intent_requires_reconciliation")
        run = self.lifecycle.value["runs"][run_id]
        if run["state"] != "succeeded":
            raise Blocked("completed_actual_scenario_required")
        accounts = [resource for resource in self.lifecycle.value["inventory"]
            if "/providers/Microsoft.Storage/storageAccounts/" in resource and "/blobServices/" not in resource]
        if len(accounts) != 1:
            raise Blocked("exact_scenario_storage_inventory_required")
        phase = {"state": "observing", "deadline": run["deadline"], "started": run["deadline"] - 900,
                 "read_attempts": 0, "control": {"observations": []}}
        phases[scenario] = phase
        self.lifecycle.state.save()

        def admit():
            if phase["read_attempts"] >= 6 or time.time() >= phase["deadline"]:
                raise OperationError("exhausted", "Scenario observation allowance exhausted")
            phase["read_attempts"] += 1
            self.lifecycle.state.save()

        native = self.lifecycle.native
        previous = getattr(native, "deadline", None)
        native.deadline = min(previous or float("inf"), time.monotonic() + max(0, phase["deadline"] - time.time()))
        try:
            account = "https://" + accounts[0].rsplit("/", 1)[-1] + ".blob.core.windows.net"
            controls = StorageControls(native, account=account, suite_id=report["run_id"], admit=admit)
            documents = {}
            for actor, container in {**OPERATIONS, "drafts": "drafts", "findings": "findings"}.items():
                record, content = controls._read(container, "ledger-v1.json")
                phase["control"]["observations"].append(record)
                report["operation_ids"].append(record["operation_id"])
                self.lifecycle.state.save()
                documents[actor] = json.loads(content)
            phase["observation"] = scenario_snapshot(source, scenario, product, documents, run_id=run_id)
            for rows in phase["observation"]["operations"].values():
                for row in rows:
                    if row["operation_id"] not in report["operation_ids"]:
                        report["operation_ids"].append(row["operation_id"])
            if scenario == "denied-bypass":
                original = self.lifecycle.value["acceptance_controls"][run_id]
                phase["bypass"] = {key: original[key] for key in (
                    "run_id", "fingerprint", "runtime_identities", "subscription_bindings",
                    "checks", "evidence", "operation_ids", "started", "finished")}
            phase["state"] = "observed"
        except (KeyError, TypeError, ValueError, EvidenceError):
            phase["state"] = "fail"
            raise Blocked("scenario_independent_observation_conflict") from None
        except (AzureError, OperationError, TimeoutError, Blocked):
            phase["state"] = "blocked"
            raise Blocked("scenario_independent_observation_incomplete") from None
        finally:
            phase["finished"] = time.time()
            native.deadline = previous
            self.lifecycle.state.save()

    @staticmethod
    def evaluate(report):
        for scenario, phase in report.get("scenario_phase", {}).items():
            check = {"check_id": "scenario." + scenario, "expected": "semantic"}
            if phase["state"] != "observed":
                yield check | {"status": "fail" if phase["state"] == "fail" else "blocked",
                               "reason": "scenario_independent_observation_incomplete"}
                continue
            reads = phase["control"]["observations"]
            bindings = {(row["request_id"], row["operation_id"], row["target"]) for row in reads}
            operators = {row.get("runtime_identity") for row in report["evidence"]
                if row.get("source") == "storage" and hash_value(row.get("runtime_identity"))
                and (row.get("request_id"), row.get("client_request_id"), row.get("target")) in bindings}
            actual = {key: phase[key] for key in ("observation", "started", "finished")}
            actual["control"] = phase["control"] | {
                "runtime_identity": next(iter(operators)) if len(operators) == 1 else None}
            if "bypass" in phase:
                actual["bypass"] = phase["bypass"]
            check["actual"] = actual
            yield check | evaluate_scenario_proof(check, report)
