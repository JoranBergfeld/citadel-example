import copy
import unittest

from citadel.acceptance.oracle import evaluate_control


def denial():
    return {
        "run_id": "run1", "check_id": "draft-read-denied", "caller": "candidate-planner",
        "runtime_identity": "a" * 64, "operation_id": "probe1",
        "started": 100.0, "finished": 101.0,
        "expected": "deny", "status_code": 403, "reason": "AuthorizationPermissionMismatch",
        "request_id": "service-denial-1", "control_request_id": "service-control-1",
        "control_identity": "c" * 64,
        "control_status": 200, "before_sha256": "b" * 64, "after_sha256": "b" * 64,
        "before_count": 1, "after_count": 1, "business_state": "denied",
        "sources": ["storage"],
    }


def evidence():
    return [
        {"source": "storage", "request_id": "service-denial-1", "status_code": 403,
         "runtime_identity": "a" * 64, "observed": 100.5},
        {"source": "storage", "request_id": "service-control-1", "status_code": 200,
         "runtime_identity": "c" * 64, "observed": 100.2},
    ]


class ControlOracleTests(unittest.TestCase):
    def test_denial_requires_real_service_rejection_control_and_unchanged_artifact(self):
        result = evaluate_control(denial(), evidence())
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["business_state"], "denied")

    def test_claimed_denial_without_correlated_service_evidence_is_blocked(self):
        for records in ([], [evidence()[0]], [evidence()[1]]):
            with self.subTest(records=records):
                self.assertEqual(evaluate_control(denial(), records)["status"], "blocked")

    def test_console_records_cannot_be_declared_a_required_proof_source(self):
        records = [row | {"source": "console"} for row in evidence()]
        self.assertEqual(evaluate_control(denial() | {"sources": ["console"]}, records)["status"], "blocked")

    def test_unrelated_request_identity_time_or_status_cannot_supply_correlation(self):
        for field, value in (("request_id", "unrelated"), ("runtime_identity", "d" * 64),
                             ("observed", 900), ("status_code", 200)):
            records = copy.deepcopy(evidence())
            records[0][field] = value
            with self.subTest(field=field):
                self.assertEqual(evaluate_control(denial(), records)["status"], "blocked")

    def test_outage_missing_target_and_changed_artifact_are_never_a_passing_denial(self):
        for changes in ({"status_code": 500}, {"status_code": 404}, {"control_status": 404},
                        {"reason": "model_refusal"}, {"after_sha256": "c" * 64},
                        {"after_count": 2}):
            with self.subTest(changes=changes):
                self.assertNotEqual(evaluate_control(denial() | changes, evidence())["status"], "pass")

    def test_wrong_control_identity_and_malformed_proof_types_cannot_pass(self):
        records = evidence()
        records[1]["runtime_identity"] = "d" * 64
        self.assertEqual(evaluate_control(denial(), records)["status"], "blocked")
        for key, value in (("control_status", "200"), ("status_code", True),
                           ("sources", "storage"), ("sources", [None]), ("started", float("nan")),
                           ("before_count", True), ("request_id", ["not-a-service-id"])):
            with self.subTest(key=key, value=value):
                self.assertEqual(evaluate_control(denial() | {key: value}, evidence())["status"], "blocked")
