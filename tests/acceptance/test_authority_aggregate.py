import copy
import unittest

from citadel.acceptance.coverage import STORAGE, required_checks
from citadel.acceptance.proof_gate import evaluate_check
from citadel.acceptance.reports import sanitize
from citadel.evidence.manifests import sha256
from citadel.gateway.trust import INVOCATION_CALLERS
from tests.acceptance.test_proof_gate import storage_proof
from tests.acceptance.test_route_oracle import owner_route_proof


def authority_report(kind):
    _, report = storage_proof()
    report.update(checks=[], operation_ids=[], evidence=[], subscription_bindings={},
                  scenarios={"comparison": {"operation_id": "real-run"}})
    dependencies = sorted(key for key in required_checks() if (
        key.startswith("storage.") if kind == "executing-identities" else
        key.startswith("route.") and key.split(".")[-1] in ("status", "task", "findings")))
    for index, key in enumerate(dependencies):
        prefix = f"proof{index}-"
        if kind == "executing-identities":
            check, template = storage_proof()
            _, actor, container, action = key.split(".")
            identities = template["runtime_identities"]
            allowed = required_checks()[key] == "allow"
            control_actor = next((role for role, grants in STORAGE.items()
                if grants.get(container) == "write" or action == "read" and container in grants), "operator")
            observed, control = (check["actual"][name] for name in ("observation", "control"))
            observed.update(check_id=key, caller=actor, container=container, action=action,
                runtime_identity=identities[actor], status_code=(206 if action == "read" else 201) if allowed else 403)
            control.update(caller=control_actor, container=container, action=action,
                runtime_identity=identities.get(control_actor, "c" * 64),
                status_code=206 if action == "read" else 201)
            evidence = []
            for name, row in check["actual"].items():
                row["container"] = container
                row["operation_id"] = prefix + row["operation_id"]
                row["request_id"] = prefix + row["request_id"]
                if "run_id" in row:
                    row["run_id"] = prefix + row["run_id"]
                evidence.append(row | {"source": "storage", "observed": 100.5,
                    "client_request_id": row["operation_id"],
                    "method": "GetBlob" if row["action"] == "read" else "PutBlob"})
                if name in ("observation", "control"):
                    evidence.append(row | {"source": "application", "observed": 100.5,
                        "method": "storage." + action})
            check.update(check_id=key, expected=required_checks()[key])
        else:
            _, actor, target, capability = key.split(".")
            args, context, reads = owner_route_proof(capability)
            observed, control, snapshots, _, identities, _ = args
            report["runtime_identities"] = identities
            subscriptions = {role: str(n + 1) * 64 for n, role in enumerate(("operator", *identities))}
            report["subscription_bindings"] = subscriptions
            owner = "candidate-planner" if capability == "findings" else next(iter(INVOCATION_CALLERS[target]))
            evidence = []
            for row, caller in ((observed, actor), (control, owner)):
                row.update(caller=caller, check_id=f"route.{caller}.{target}.{capability}",
                           request_id=prefix + row["request_id"], operation_id=prefix + row["operation_id"])
                reference = (context["finding_controls"].get(caller, context["finding_controls"]["candidate-planner"])
                    if capability == "findings" else context["operations"][target])
                row["control_reference"] = reference
                permitted = required_checks()[row["check_id"]] == "allow"
                row["status_code"] = 200 if permitted else 403
                if permitted:
                    row.update(actual={"status": "owned_status", "task": "owned_task",
                        "findings": "exact_finding"}[capability],
                        sha256=reference["finding"]["sha256"] if capability == "findings" else
                            reference["result_sha256" if capability == "status" else "task_sha256"])
                evidence.append(row | {"source": "gateway", "observed": row["started"] + .5,
                    "credential_sha256": subscriptions[caller], "method": "POST" if capability == "task" else "GET",
                    "facts": {"backend_dispatched": permitted}})
                evidence.append(row | {"source": "application", "observed": row["started"] + .5,
                    "runtime_identity": identities.get(caller, "f" * 64), "method": "probe",
                    "facts": {"sha256": sha256(row), "probe_id": row["check_id"]}})
                if permitted:
                    evidence.append(row | {"source": "application", "observed": row["started"] + .5,
                        "runtime_identity": identities[target],
                        "method": {"status": "status", "task": "GetTask", "findings": "findings-read"}[capability]})
            for row in [*reads, *[row for side in snapshots.values() for row in side.values()]]:
                evidence.append(row | {"source": "storage", "method": "GetBlob", "observed": row["finished"],
                    "runtime_identity": "f" * 64, "client_request_id": row["operation_id"]})
            check = {"check_id": key, "expected": required_checks()[key], "status": "pass", "actual": {
                "observation": observed, "control": control, "route_context": context, "context_reads": reads,
                **{side: list(rows.values()) for side, rows in snapshots.items()}}}
            report["operation_ids"].extend([row["operation_id"] for row in context["operations"].values()])
            report["operation_ids"].extend(row["read_scope"]["operation_id"]
                for row in context["finding_controls"].values())
        for row in evidence:
            report["operation_ids"].extend(row[name] for name in ("run_id", "operation_id") if name in row)
        report["checks"].append(check)
        report["evidence"].extend(evidence)
    report["operation_ids"] = sorted(set(report["operation_ids"]))
    aggregate = {"check_id": "authority." + kind, "expected": "evidence", "status": "pass",
                 "actual": {"required_checks": dependencies}}
    return aggregate, report


class AuthorityAggregateTests(unittest.TestCase):
    def test_collection_emits_both_obligations_without_dispatching_or_inventing_missing_controls(self):
        from citadel.acceptance.authority import collect_authority
        _, report = authority_report("executing-identities")
        before = copy.deepcopy(report)
        results = {row["check_id"]: row for row in collect_authority(report)}
        self.assertEqual(results["authority.executing-identities"]["status"], "pass")
        self.assertEqual(results["authority.status-owner-scope"]["status"], "blocked")
        self.assertEqual(report, before)
        report["checks"][0]["actual"] = {}
        results = {row["check_id"]: row for row in collect_authority(report)}
        self.assertEqual(results["authority.executing-identities"]["status"], "blocked")

    def test_complete_authority_aggregates_recheck_every_sanitized_service_proof(self):
        for kind in ("executing-identities", "status-owner-scope"):
            check, report = authority_report(kind)
            for child in report["checks"]:
                self.assertEqual(evaluate_check(child, report)["status"], "pass", child["check_id"])
            self.assertEqual(evaluate_check(sanitize(check), sanitize(report))["status"], "pass", kind)
            for source in ("application", "storage", "gateway") if kind == "status-owner-scope" else ("application", "storage"):
                changed = report | {"evidence": [row for row in report["evidence"] if row["source"] != source]}
                self.assertEqual(evaluate_check(check, changed)["status"], "blocked")

    def test_labels_missing_dependencies_duplicates_and_other_identities_cannot_prove_authority(self):
        for kind in ("executing-identities", "status-owner-scope"):
            check, report = authority_report(kind)
            changed = copy.deepcopy(report)
            changed["checks"][0]["actual"] = {}
            self.assertEqual(evaluate_check(check, changed)["status"], "blocked")
            self.assertEqual(evaluate_check(check, report | {"checks": report["checks"][1:]})["status"], "blocked")
            self.assertEqual(evaluate_check(check, report | {"checks": report["checks"] + [report["checks"][0]]})["status"],
                             "blocked")
            self.assertEqual(evaluate_check(check | {"actual": {"required_checks": []}}, report)["status"], "blocked")
            changed = copy.deepcopy(report)
            changed["runtime_identities"]["candidate-planner"] = "9" * 64
            self.assertEqual(evaluate_check(check, changed)["status"], "blocked")

    def test_observed_failure_is_preserved_in_aggregate(self):
        check, report = authority_report("executing-identities")
        report["checks"][0]["status"] = "fail"
        self.assertEqual(evaluate_check(check, report)["status"], "fail")
