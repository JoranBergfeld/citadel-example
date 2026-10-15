import copy
import unittest

from citadel.acceptance.proof_gate import evaluate_check
from citadel.acceptance.reports import sanitize
from tests.acceptance import test_origin_oracle


def storage_proof():
    identities = {"candidate-planner": "a" * 64, "evidence-assessor": "b" * 64,
                  "reference-data": "d" * 64, "release-reviewer": "e" * 64,
                  "briefing-author": "f" * 64}
    base = {"container": "drafts", "suite_id": "suite1", "target": "d" * 64,
            "started": 100.0, "finished": 101.0, "action": "read", "sha256": "e" * 64, "count": 1}
    observation = base | {"check_id": "storage.candidate-planner.drafts.read",
        "caller": "candidate-planner", "runtime_identity": identities["candidate-planner"],
        "run_id": "probe1", "operation_id": "op1", "request_id": "denial",
        "status_code": 403, "reason": "AuthorizationPermissionMismatch"}
    control = base | {"caller": "evidence-assessor", "runtime_identity": identities["evidence-assessor"],
        "run_id": "control1", "operation_id": "controlop1", "request_id": "control", "status_code": 206}
    snapshots = {side: base | {"runtime_identity": "c" * 64, "request_id": side,
        "operation_id": side + "-op", "status_code": 206, "started": when, "finished": when + 1}
        for side, when in (("before", 98.0), ("after", 102.0))}
    evidence = []
    for record in (observation, control, *snapshots.values()):
        evidence.append(record | {"source": "storage", "method": "GetBlob", "observed": 100.5,
                                  "client_request_id": record["operation_id"]})
        if "caller" in record:
            evidence.append(record | {"source": "application", "method": "storage.read", "observed": 100.5})
    check = {"check_id": observation["check_id"], "expected": "deny", "status": "pass",
             "actual": {"observation": observation, "control": control, **snapshots}}
    report = {"run_id": "suite1", "runtime_identities": identities, "evidence": evidence,
              "operation_ids": ["probe1", "op1", "control1", "controlop1"]}
    return check, report


class ProofGateTests(unittest.TestCase):
    def test_origin_report_requires_the_allocated_subscription_not_a_caller_label(self):
        observed, control, snapshots, records = test_origin_oracle.OriginOracleTests().fixture()
        control.update(operation_id="controlop", run_id="controlrun")
        for record in records:
            if record.get("request_id") == control["request_id"]:
                record.update(operation_id="controlop", run_id="controlrun")
                if record["source"] == "gateway":
                    record["credential_sha256"] = "1" * 64
        check = {"check_id": observed["check_id"], "status": "pass", "expected": "deny",
            "actual": {"observation": observed, "control": control,
                      **{side: list(rows.values()) for side, rows in snapshots.items()}}}
        report = {"run_id": "suite1", "operation_ids": ["origin1", "physical1", "controlop", "controlrun"],
            "runtime_identities": {"evidence-assessor": "a" * 64, "candidate-planner": "b" * 64,
                "release-reviewer": "c" * 64, "reference-data": "d" * 64, "briefing-author": "f" * 64},
            "subscription_bindings": {"candidate-planner": "1" * 64}, "evidence": records}
        self.assertEqual(evaluate_check(sanitize(check), sanitize(report))["status"], "pass")
        for key, value in (("credential_sha256", "2" * 64), ("caller", "operator")):
            changed = report | {"evidence": [row | {key: value} if row["source"] == "gateway"
                else row for row in records]}
            self.assertEqual(evaluate_check(check, changed)["status"], "blocked")
        changed = report | {"evidence": [row | {"run_id": "another"} if row.get("method") == "discovery"
            else row for row in records]}
        self.assertEqual(evaluate_check(check, changed)["status"], "blocked")

    def test_exported_storage_proof_is_rechecked_against_pinned_identity_and_real_sources(self):
        check, report = storage_proof()
        self.assertEqual(evaluate_check(sanitize(check), sanitize(report))["status"], "pass")
        for change in ({"expected": "allow"}, {"check_id": "storage.briefing-author.drafts.read"},
                       {"actual": {}}, {"actual": {"status": "pass"}}):
            with self.subTest(change=change):
                self.assertEqual(evaluate_check(check | change, report)["status"], "blocked")
        changed = copy.deepcopy(report)
        changed["runtime_identities"]["candidate-planner"] = "0" * 64
        self.assertEqual(evaluate_check(check, changed)["status"], "blocked")
        changed = report | {"evidence": [row | {"source": "console"}
            if row["source"] == "application" else row for row in report["evidence"]]}
        self.assertEqual(evaluate_check(check, changed)["status"], "blocked")
        changed = copy.deepcopy(check)
        changed["actual"]["after"]["sha256"] = "f" * 64
        self.assertEqual(evaluate_check(changed, report)["status"], "fail")

    def test_malformed_authority_or_operator_impersonation_blocks_instead_of_crashing(self):
        check, report = storage_proof()
        for caller in ([], {}, None):
            changed = copy.deepcopy(check)
            changed["actual"]["control"]["caller"] = caller
            with self.subTest(caller=caller):
                self.assertEqual(evaluate_check(changed, report)["status"], "blocked")
        changed = copy.deepcopy(report)
        changed["runtime_identities"]["reference-data"] = "c" * 64
        self.assertEqual(evaluate_check(check, changed)["status"], "blocked")
