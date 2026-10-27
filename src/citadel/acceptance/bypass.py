"""The four storage denials gate a separate, subsequent normal collaboration."""

import time

from citadel.operations import identity
from citadel.operator.state import Blocked
from .collection import AzureQuery, Collector, collection_remaining
from .proof_gate import evaluate_check
from .probes import AGENTS
from .storage_harness import StorageAcceptance


BYPASS_CHECKS = frozenset({
    "storage.candidate-planner.drafts.read", "storage.candidate-planner.findings.write",
    "storage.briefing-author.drafts.read", "storage.briefing-author.findings.write",
})


def bypass_status(report):
    checks = report.get("checks")
    if (not isinstance(checks, list) or len(checks) != len(BYPASS_CHECKS)
            or any(not isinstance(check, dict) or not isinstance(check.get("check_id"), str)
                   for check in checks)
            or {check["check_id"] for check in checks} != BYPASS_CHECKS):
        return "blocked"
    states = {evaluate_check(check, report)["status"] for check in checks}
    if "fail" in states:
        return "fail"
    return "pass" if states == {"pass"} else "blocked"


class BypassControls:
    def __init__(self, lifecycle, *, export, clock=time.time, sleep=time.sleep):
        self.lifecycle, self.export = lifecycle, export
        self.clock, self.sleep = clock, sleep

    def run(self, run_id, *, fingerprints):
        identity(run_id)
        controls = self.lifecycle.value.setdefault("acceptance_controls", {})
        report = controls.get(run_id)
        if report is None:
            from citadel.operator.quiescence import runs_quiescent
            if not runs_quiescent(self.lifecycle):
                raise Blocked("existing_run_requires_reconciliation")
            report = {"schema_version": 1, "mode": "cloud", "scope": "denied-bypass-controls",
                "run_id": run_id, **fingerprints, "required_checks": sorted(BYPASS_CHECKS),
                "checks": [{"check_id": check, "expected": "deny", "status": "blocked",
                            "reason": "actual_identity_control_driver_required"}
                           for check in sorted(BYPASS_CHECKS)],
                "operation_ids": [], "evidence": [], "started": self.clock(),
                "finished": self.clock(), "acceptance": "blocked", "state": "dispatching"}
            controls[run_id] = report
            self.lifecycle.state.save()
            self.export(report)
            try:
                StorageAcceptance(self.lifecycle).execute(report, workloads=frozenset(AGENTS))
                report["state"] = "observed"
            except (Blocked, ValueError, TimeoutError):
                report["state"] = "blocked"
            finally:
                report["finished"] = self.clock()
                self.lifecycle.state.save()
                self.export(report)
        elif report.get("fingerprint") != fingerprints["fingerprint"]:
            raise Blocked("acceptance_deployment_inputs_changed")
        if report["state"] == "observed" and bypass_status(report) == "blocked":
            parents = [parent for parent in self.lifecycle.value.get("acceptance_attempts", {}).values()
                       if run_id in parent.get("operation_ids", [])]
            if len(parents) > 1:
                raise Blocked("acceptance_control_owner_conflict")
            owner = parents[0] if parents else report
            now = self.clock()
            remaining = collection_remaining(owner, now)
            report["collection_deadline"] = min(report.get("collection_deadline", float("inf")),
                                                now + remaining)
            window = owner.setdefault("collection_windows", {}).setdefault(
                run_id, {"started": now, "finished": None})
            window["finished"] = None
            self.lifecycle.state.save()
            try:
                while self.clock() < report["collection_deadline"]:
                    if not self.collect(report) or bypass_status(report) != "blocked":
                        break
                    self.sleep(min(15, max(0, report["collection_deadline"] - self.clock())))
            finally:
                window["finished"] = self.clock()
                self.lifecycle.state.save()
        report["acceptance"] = bypass_status(report)
        self.lifecycle.state.save()
        return self.export(report)

    def collect(self, report):
        end = report["collection_deadline"]
        now = self.clock()
        if (end <= now or report.get("collection_attempts", 0) >= 40
                or now < report.get("last_collection", 0) + 15):
            return False
        report["collection_attempts"] = report.get("collection_attempts", 0) + 1
        report["last_collection"] = now
        self.lifecycle.state.save()
        native = self.lifecycle.native
        previous = getattr(native, "deadline", None)
        native.deadline = min(previous or float("inf"), time.monotonic() + end - now)
        try:
            from .retention import workspace_resource
            details = native.rest("get", workspace_resource(self.lifecycle), "2022-10-01")
            collector = Collector(AzureQuery(native, details["properties"]["customerId"]),
                started=report["started"], finished=report["finished"],
                budget_seconds=end - self.clock(), prior=report["evidence"])
            report["evidence"] = collector.poll()
            evaluated = {row["check_id"]: row for row in StorageAcceptance.evaluate(report, report["evidence"])}
            report["checks"] = [check | evaluated.get(check["check_id"], {}) for check in report["checks"]]
            self.lifecycle.state.save()
            self.export(report)
            return True
        except (Blocked, ValueError, KeyError, TimeoutError):
            return False
        finally:
            native.deadline = previous
