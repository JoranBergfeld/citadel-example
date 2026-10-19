"""Reviewer handoff for actual assessor-produced versions, retaining the source deadline."""

import hashlib
import math
import time
from uuid import UUID, uuid4

from azure.core.exceptions import AzureError

from citadel.operations import OperationError, identity
from citadel.operator.state import Blocked
from .immutable_oracle import evaluate_immutable, immutable_snapshot
from .oracle import hash_value
from .release_probes import validate_versions
from .revision import RevisionProbe
from .storage_probes import StorageControls
from .storage_accounts import storage_accounts


class ImmutableAcceptance:
    def __init__(self, lifecycle):
        self.lifecycle = lifecycle

    def execute(self, report):
        if "immutable_phase" in report:
            raise Blocked("immutable_probe_intent_requires_reconciliation")
        prior = report.get("version_phase", {})
        if (prior.get("state") != "observed" or len(prior.get("observations", [])) != 1
                or type(prior.get("deadline")) not in (int, float) or not math.isfinite(prior["deadline"])
                or not time.time() < prior["deadline"] <= time.time() + 900):
            raise Blocked("actual_unexpired_assessor_version_source_required")
        row = prior["observations"][0]
        descriptor = validate_versions({"run_id": row["run_id"], "operation_id": row["operation_id"],
                                        "drafts": row["actual"]["drafts"]})
        accounts = storage_accounts(self.lifecycle)
        apps = [app for app in self.lifecycle.value["outputs"]["appInventory"]
                if app["app"].rsplit("/", 1)[-1] == self.lifecycle.id + "-release-reviewer"]
        if len(apps) != 1:
            raise Blocked("exact_immutable_reviewer_inventory_required")
        phase = {"state": "dispatching", "deadline": prior["deadline"], "read_attempts": 0,
                 "source": {"versions": descriptor}, "observations": [], "snapshots": {}}
        report["immutable_phase"] = phase
        self.lifecycle.state.save()

        def admit():
            if phase["read_attempts"] >= 512 or time.time() >= phase["deadline"]:
                raise OperationError("exhausted", "Immutable control deadline or read allowance exhausted")
            phase["read_attempts"] += 1
            self.lifecycle.state.save()

        native = self.lifecycle.native
        previous = getattr(native, "deadline", None)
        native.deadline = min(previous or float("inf"), time.monotonic() + max(0, phase["deadline"] - time.time()))
        try:
            app, run_id = apps[0], uuid4().hex
            account = accounts["reviewer-operations"]
            principal = hashlib.sha256(str(UUID(app["identityPrincipalId"])).encode()).hexdigest()
            controls = StorageControls(native, account=accounts, suite_id=report["run_id"], admit=admit)
            before, _ = controls.version_state(descriptor["run_id"], descriptor["operation_id"])
            original = prior["snapshots"][descriptor["operation_id"]]
            if before["sha256"] != original["sha256"] or before["target"] != original["target"]:
                raise Blocked("assessor_version_source_changed")
            phase["source"]["draft_before"] = before
            phase["before"] = controls.products()
            report["operation_ids"].extend([run_id, before["operation_id"],
                *[item["operation_id"] for item in phase["before"].values()]])
            self.lifecycle.state.save()
            result = RevisionProbe(self.lifecycle, admit=admit).execute(app, "release-reviewer", run_id,
                mode="immutable-versions", versions=descriptor, deadline=phase["deadline"])
            if (not isinstance(result, dict) or type(result.get("schema_version")) is not int
                    or result["schema_version"] != 1 or result.get("run_id") != run_id
                    or result.get("state") not in ("complete", "blocked")
                    or not isinstance(result.get("observations"), list) or len(result["observations"]) != 1):
                raise Blocked("immutable_worker_result_incomplete")
            observed = result["observations"][0]
            if not isinstance(observed, dict) or not isinstance(observed.get("actual"), dict):
                raise Blocked("immutable_worker_result_shape_conflict")
            operation = identity(observed.get("operation_id"))
            children = [identity(operation + suffix) for suffix in ("-v1", "-v2")]
            if (observed.get("check_id") != "fault.immutable-versions"
                    or observed.get("probe_id") != observed["check_id"]
                    or observed.get("run_id") != run_id or observed.get("caller") != "release-reviewer"
                    or observed.get("runtime_identity") != principal
                    or observed["actual"].get("operation_id") != operation
                    or observed["actual"].get("operation_ids") != children
                    or observed["actual"].get("source_run") != descriptor["run_id"]
                    or observed["actual"].get("drafts") != descriptor["drafts"]
                    or observed.get("target") != hashlib.sha256(
                        f"{account}/reviewer-operations/acceptance/{run_id}/observations/{operation}.json".encode()).hexdigest()
                    or set([operation, *children]) & set(report["operation_ids"])):
                raise Blocked("immutable_worker_authority_or_source_conflict")
            report["operation_ids"].extend([operation, *children])
            phase["observations"] = [observed]
            self.lifecycle.state.save()
            snapshot, document = controls.release_state(run_id, operation)
            phase["snapshots"][operation] = snapshot | immutable_snapshot(document, observed["actual"])
            report["operation_ids"].append(snapshot["operation_id"])
            after, _ = controls.version_state(descriptor["run_id"], descriptor["operation_id"])
            phase["source"]["draft_after"] = after
            phase["after"] = controls.products()
            report["operation_ids"].extend([after["operation_id"],
                *[item["operation_id"] for item in phase["after"].values()]])
            phase["state"] = "observed" if result["state"] == "complete" else "blocked"
        except (AzureError, OperationError, Blocked, ValueError, KeyError, TypeError, TimeoutError):
            phase["state"] = "blocked"
            raise Blocked("immutable_probe_phase_incomplete") from None
        finally:
            native.deadline = previous
            self.lifecycle.state.save()

    @staticmethod
    def evaluate(report, evidence, *, version_results):
        phase, output = report.get("immutable_phase", {}), []
        proof = version_results[0].get("actual", {}) if len(version_results) == 1 else {}
        for row in phase.get("observations", []):
            snapshot = phase.get("snapshots", {}).get(row.get("operation_id"), {})
            observers = {record.get("runtime_identity") for record in evidence
                if record.get("source") == "storage" and hash_value(record.get("runtime_identity"))
                and record.get("request_id") == snapshot.get("request_id")
                and record.get("client_request_id") == snapshot.get("operation_id")
                and record.get("target") == snapshot.get("target")}
            observer = next(iter(observers)) if len(observers) == 1 else None
            snapshot = snapshot | {"runtime_identity": observer}
            source = phase.get("source", {}) | {"version_proof": proof}
            result = evaluate_immutable(row, snapshot, source,
                {side: phase.get(side, {}) for side in ("before", "after")}, evidence,
                identities=report.get("runtime_identities", {}),
                subscriptions=report.get("subscription_bindings", {}), observer_identity=observer)
            output.append(result | {"expected": "fault", "actual": {
                "observation": row, "control": snapshot, "source": source,
                **{side: list(phase.get(side, {}).values()) for side in ("before", "after")}}})
        return output
