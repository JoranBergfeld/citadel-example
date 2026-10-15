"""Operator integration. Cloud execution and human review are never inferred locally."""

import hashlib
import re
import time
import tomllib
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid4

from citadel.evidence import ReferenceData
from citadel.evidence.manifests import sha256
from citadel.operator.state import Blocked, ROOT, read_private, source_fingerprint
from .collection import AzureQuery, Collector, collection_remaining, verify_retention
from .coverage import required_checks
from .reports import acceptance_status, automated_status, confirm_narrative, export_report, report_directory
from .scenarios import FIXTURES, evaluate_scenario


HOOKS = {"full-acceptance", "denied-bypass-controls", "rotation-new-material-allowed",
         "rotation-old-material-denied", "collect-evidence"}


def _valid_run(run_id):
    if not isinstance(run_id, str) or not re.fullmatch("[A-Za-z0-9_-]{1,64}", run_id):
        raise Blocked("invalid_acceptance_run_id")


def fingerprints(lifecycle):
    pins = tomllib.loads((ROOT / "stack.toml").read_text())
    software = source_fingerprint()
    if software != lifecycle.value["software"]:
        raise Blocked("acceptance_software_fingerprint_conflict")
    manifest = Path(lifecycle.config["bundleDir"]) / "bundle-manifest.json"
    actual = hashlib.sha256(manifest.read_bytes()).hexdigest()
    if actual != lifecycle.value["bundle"]:
        raise Blocked("acceptance_bundle_fingerprint_conflict")
    images = sorted({app["image"] for app in lifecycle.value["outputs"]["appInventory"]})
    if not images or any("@sha256:" not in image for image in images):
        raise Blocked("acceptance_immutable_images_required")
    provenance = ReferenceData.from_bundle(lifecycle.config["bundleDir"]).provenance
    result = {"software": software, "configuration": sha256(lifecycle.config),
              "manifest": actual, "image": [image.split("@", 1)[1] for image in images],
              "protocols": pins["protocols"], "model": pins["model"],
              "inputs": {"bundle": actual, **{key: sha256(value) for key, value in provenance.items()}},
              "runtime_identities": {
                  app["app"].split("/")[-1].removeprefix(lifecycle.id + "-"):
                      hashlib.sha256(str(UUID(app["identityPrincipalId"])).encode()).hexdigest()
                  for app in lifecycle.value["outputs"]["appInventory"]},
              "subscription_bindings": {
                  resource.rsplit("/", 1)[-1]: hashlib.sha256(resource.lower().encode()).hexdigest()
                  for resource in lifecycle.value["outputs"]["inventory"]["gateway"]["subscriptions"]}}
    return result | {"fingerprint": sha256(result)}


class Harness:
    def __init__(self, lifecycle):
        self.lifecycle = lifecycle
        self.directory = report_directory(lifecycle.state.directory / "acceptance")
        self.attempts = lifecycle.value.setdefault("acceptance_attempts", {})
        self.order = lifecycle.value.setdefault("acceptance_order", [])

    def save(self, report):
        report["automated_status"] = automated_status(report)
        report["acceptance"] = acceptance_status([self.attempts[key] for key in self.order])
        report["human_status"] = ("pending" if set(report["scenarios"]) - set(report["human_reviews"])
                                  else "recorded")
        result = export_report(self.directory, {k: v for k, v in report.items() if k != "evidence_sha256"})
        report["evidence_sha256"] = result["evidence_sha256"]
        self.lifecycle.state.save()
        return result

    def start(self, run_id):
        if run_id in self.attempts:
            return self.save(self.attempts[run_id])
        proof = fingerprints(self.lifecycle)
        source = ReferenceData.from_bundle(self.lifecycle.config["bundleDir"])
        source.fixture_gate()
        self.lifecycle.verify_inventory()
        for app in self.lifecycle.value["outputs"]["appInventory"]:
            deployed = self.lifecycle.native.rest("get", app["app"], "2025-01-01")
            environment = {e["name"]: e.get("value")
                           for e in deployed["properties"]["template"]["containers"][0]["env"]}
            if (environment.get("AZURE_PRINCIPAL_ID") != app["identityPrincipalId"]
                    or environment.get("AZURE_CLIENT_ID") != app["identityClientId"]):
                raise Blocked("executing_identity_telemetry_mapping_conflict")
        report = {"schema_version": 1, "mode": "cloud", "run_id": run_id, **proof,
                  "required_checks": sorted(required_checks()), "scenarios": {}, "human_reviews": {},
                  "operation_ids": [], "checks": [{"check_id": key, "expected": expected,
                      "status": "blocked", "reason": "required_deployed_proof_missing"}
                      for key, expected in sorted(required_checks().items())],
                  "started": time.time(), "finished": time.time(), "evidence": [],
                  "optional_not_exercised": ["Agent365", "ConditionalAccess", "Defender", "Purview"],
                  "lifecycle_refs": {"fresh_deployment": "required", "repair": "required",
                                     "manual_teardown": "required", "residue": "required"}}
        self.attempts[run_id] = report
        self.order.append(run_id)
        self.save(report)
        try:
            self._set(report, "inventory.five-environments-and-rest", "pass", "provider_inventory_verified")
            self._set(report, "inventory.actual-free-plan", "pass", "bound_human_portal_observation")
            from citadel.operator.scenarios import scenario_command
            for scenario in FIXTURES:
                operation = uuid4().hex
                report["operation_ids"].append(operation)
                self.lifecycle.state.save()
                try:
                    outcome = scenario_command(self.lifecycle, SimpleNamespace(
                        command="demo", scenario=scenario, run_id=operation))
                    checked = evaluate_scenario(source, scenario, outcome["product"])
                    checked["check_id"] = "scenario." + scenario
                    if checked["status"] == "pass":
                        report["scenarios"][scenario] = {
                            "operation_id": operation, "product_sha256": checked["product_sha256"],
                            "semantics_sha256": checked["semantics_sha256"]}
                        checked.update(status="blocked", reason="required_service_correlation_missing")
                    self._replace(report, checked)
                except Blocked as exc:
                    self._set(report, "scenario." + scenario, "blocked", exc.code)
                    if scenario != "denied-bypass":
                        break
                report["finished"] = time.time()
                self.save(report)
            if all(run["state"] in ("succeeded", "failed_no_commit")
                   for run in self.lifecycle.value["runs"].values()):
                from .storage_harness import StorageAcceptance
                StorageAcceptance(self.lifecycle).execute(report)
                report["finished"] = time.time()
                self.save(report)
                from .operation_harness import FaultAcceptance
                FaultAcceptance(self.lifecycle).execute(report)
                report["finished"] = time.time()
                self.save(report)
                from .release_harness import ReleaseAcceptance
                ReleaseAcceptance(self.lifecycle).execute(report)
                report["finished"] = time.time()
                self.save(report)
                ReleaseAcceptance(self.lifecycle).execute(report, mode="draft-versions")
                report["finished"] = time.time()
                self.save(report)
                ReleaseAcceptance(self.lifecycle).execute(report, mode="immutable-versions")
                report["finished"] = time.time()
                self.save(report)
                from .origin_harness import BoundaryAcceptance
                for observed in BoundaryAcceptance(self.lifecycle).execute(report):
                    if observed.get("check_id") in required_checks():
                        self._replace(report, {"check_id": observed["check_id"], "status": "blocked",
                            "reason": "working_control_and_no_effect_proof_required",
                            "actual": observed})
                report["finished"] = time.time()
                self.save(report)
        except (Blocked, ValueError, TimeoutError):
            # Partial attempts remain immutable exports; provider exception text is private.
            report["finished"] = time.time()
            self.save(report)
        return self.collect(run_id)

    @staticmethod
    def _replace(report, check):
        for index, old in enumerate(report["checks"]):
            if old["check_id"] == check["check_id"]:
                report["checks"][index] = old | check
                return
        raise ValueError("Unregistered required check")

    def _set(self, report, check_id, status, reason):
        self._replace(report, {"check_id": check_id, "status": status, "reason": reason})

    def collect(self, run_id):
        if run_id not in self.attempts:
            raise Blocked("acceptance_attempt_required")
        report = self.attempts[run_id]
        if fingerprints(self.lifecycle)["fingerprint"] != report["fingerprint"]:
            raise Blocked("acceptance_deployment_inputs_changed")
        workspace = [rid for rid in self.lifecycle.value["inventory"]
                     if "/Microsoft.OperationalInsights/workspaces/" in rid and "/tables/" not in rid]
        if len(workspace) != 1:
            raise Blocked("exact_acceptance_workspace_required")
        end = report.setdefault("collection_deadline",
                                time.time() + collection_remaining(report, time.time()))
        remaining = end - time.time()
        self.lifecycle.state.save()
        if remaining <= 0:
            self._set(report, "telemetry.application-ingestion", "blocked", "evidence_collection_deadline")
            return self.save(report)
        native = self.lifecycle.native
        previous_deadline = getattr(native, "deadline", None)
        native.deadline = min(previous_deadline or float("inf"), time.monotonic() + remaining)
        try:
            details = self.lifecycle.native.rest("get", workspace[0], "2022-10-01")
            tables = self.lifecycle.native.collection(workspace[0] + "/tables", "2022-10-01")
            retained = verify_retention(details["properties"], tables)
            self._set(report, "telemetry.retention-and-unsampled",
                      "blocked" if retained else "fail",
                      "actual_sampling_exporter_proof_required" if retained else "retention_contract_mismatch")
            collector = Collector(AzureQuery(self.lifecycle.native, details["properties"]["customerId"]),
                                  started=report["started"], finished=report["finished"],
                                  budget_seconds=end - time.time(), prior=report["evidence"],
                                  ingress=[row for row in report.get("boundary_phase", {}).get("origins", [])
                                           if row.get("request_id")])
            report["evidence"] = collector.poll()
            from .storage_harness import StorageAcceptance
            for result in StorageAcceptance.evaluate(report, report["evidence"]):
                self._replace(report, result)
            from .operation_harness import FaultAcceptance
            for result in FaultAcceptance.evaluate(report, report["evidence"]):
                self._replace(report, result)
            from .release_harness import ReleaseAcceptance
            for result in ReleaseAcceptance.evaluate(report, report["evidence"]):
                self._replace(report, result)
            for result in ReleaseAcceptance.evaluate(report, report["evidence"], mode="draft-versions"):
                self._replace(report, result)
            for result in ReleaseAcceptance.evaluate(report, report["evidence"], mode="immutable-versions"):
                self._replace(report, result)
            from .origin_harness import BoundaryAcceptance
            for result in BoundaryAcceptance(self.lifecycle).evaluate(report, report["evidence"]):
                self._replace(report, result)
            # No repeated polling can turn an unimplemented/absent required control into pass.
        except (Blocked, ValueError, TimeoutError):
            self._set(report, "telemetry.application-ingestion", "blocked",
                      "required_telemetry_query_incomplete")
        finally:
            native.deadline = previous_deadline
        return self.save(report)


def run(*, lifecycle, check_id, run_id):
    _valid_run(run_id)
    if check_id not in HOOKS:
        raise Blocked("unknown_acceptance_hook")
    lifecycle.require_plan_observation()
    if lifecycle.value["phase"] != "deployed_unverified":
        raise Blocked("runtime_deployment_required")
    harness = Harness(lifecycle)
    if check_id == "full-acceptance":
        return harness.start(run_id)
    if check_id == "collect-evidence":
        return harness.collect(run_id)
    if check_id == "denied-bypass-controls":
        from .bypass import BypassControls
        return BypassControls(lifecycle, export=lambda report: export_report(
            harness.directory, report)).run(run_id, fingerprints=fingerprints(lifecycle))
    # These hooks cannot authorize retirement/continuation using route discovery,
    # a local contract fixture, or the operator's broader storage credentials.
    obligations = [check_id]
    report = {"schema_version": 1, "run_id": run_id, "mode": "cloud", **fingerprints(lifecycle),
              "acceptance": "blocked", "required_checks": obligations,
              "checks": [{"check_id": key, "status": "blocked",
                          "reason": "actual_identity_control_driver_required"} for key in obligations]}
    return export_report(harness.directory, report)


def review(*, lifecycle, run_id, confirmation):
    _valid_run(run_id)
    harness = Harness(lifecycle)
    if run_id not in harness.attempts:
        raise Blocked("acceptance_attempt_required")
    report = harness.attempts[run_id]
    if set(confirmation) != {"scenario", "product_sha256", "supported", "gaps_visible", "fictional"}:
        raise Blocked("explicit_per_scenario_review_required")
    confirm_narrative(report, **confirmation)
    return harness.save(report)
