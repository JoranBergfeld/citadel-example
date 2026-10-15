import copy
import unittest

from citadel.acceptance.coverage import required_checks
from citadel.acceptance.reports import acceptance_status, automated_status, confirm_narrative, sanitize
from citadel.acceptance.scenarios import FIXTURES


def report(run="run1"):
    return {"schema_version": 1, "run_id": run, "fingerprint": "a" * 64,
            "mode": "cloud", "required_checks": sorted(required_checks()), "checks": [
                {"check_id": check, "expected": expected, "status": "pass"}
                for check, expected in sorted(required_checks().items())],
            "scenarios": {name: {"product_sha256": "b" * 64,
                                "semantics_sha256": "c" * 64} for name in FIXTURES},
            "evidence": [{"source": source, "request_id": source + "-request",
                          "status_code": 200, "observed": 100.0, "run_id": run}
                         for source in ("application", "gateway", "storage")],
            "operation_ids": [run], "human_reviews": {}}


def approve(value):
    for scenario in value["scenarios"]:
        confirm_narrative(value, scenario, "b" * 64, supported=True, gaps_visible=True, fictional=True)


class ReportTests(unittest.TestCase):
    def test_complete_automation_stays_pending_until_exact_narrative_review(self):
        value = report()
        self.assertEqual(acceptance_status([value]), "pending_human")
        with self.assertRaises(ValueError):
            confirm_narrative(value, "comparison", "d" * 64, supported=True,
                              gaps_visible=True, fictional=True)
        approve(value)
        self.assertEqual(acceptance_status([value]), "pending_second_pass")
        second = report("run2")
        approve(second)
        self.assertEqual(acceptance_status([value, second]), "pass")

    def test_no_cherry_picking_fingerprints_reused_ids_or_missing_checks(self):
        first, second = report(), report("run2")
        for value in (first, second):
            approve(value)
        for change in ({"mode": "local"}, {"fingerprint": "d" * 64},
                       {"operation_ids": ["run1"]}, {"checks": []},
                       {"required_checks": ["comparison", "storage-denial"]}):
            with self.subTest(change=change):
                self.assertNotEqual(acceptance_status([first, second | change]), "pass")
        failed = report("failed")
        failed["checks"][0]["status"] = "fail"
        self.assertNotEqual(acceptance_status([first, failed, second]), "pass")

    def test_self_declared_reduced_coverage_cannot_remove_required_checks(self):
        value = report()
        value["checks"] = value["checks"][:1]
        value["required_checks"] = [value["checks"][0]["check_id"]]
        self.assertEqual(automated_status(value), "blocked")

    def test_missing_scenario_cannot_avoid_human_review(self):
        first, second = report(), report("run2")
        for value in (first, second):
            del value["scenarios"]["denied-bypass"]
            approve(value)
        self.assertEqual(acceptance_status([first, second]), "blocked")

    def test_all_pass_labels_without_required_service_sources_still_block(self):
        for records in ([], report()["evidence"][:2]):
            with self.subTest(records=records):
                self.assertEqual(automated_status(report() | {"evidence": records}), "blocked")

    def test_malformed_proof_bindings_block_before_confirmation(self):
        for changes in ({"schema_version": True}, {"operation_ids": ["run1", "run1"]},
                        {"operation_ids": "run1"}, {"run_id": "../run1"},
                        {"human_reviews": []},
                        {"scenarios": {key: {} for key in FIXTURES}}):
            with self.subTest(changes=changes):
                self.assertEqual(acceptance_status([report() | changes]), "blocked")

    def test_rejected_prose_never_counts_as_human_approval(self):
        value = report()
        confirm_narrative(value, "comparison", "b" * 64, supported=False,
                          gaps_visible=True, fictional=True)
        self.assertEqual(acceptance_status([value]), "fail")

    def test_sanitization_is_allowlisted_not_a_secret_name_blacklist(self):
        raw = {"run_id": "run1", "status": "pass", "private_notes": "secret",
               "apparently_safe": "Bearer stolen", "prompt": "private prompt",
               "checks": [{"check_id": "comparison", "status": "blocked",
                           "debug": {"Authorization": "secret"}}]}
        self.assertEqual(sanitize(raw), {"run_id": "run1", "status": "pass",
                         "checks": [{"check_id": "comparison", "status": "blocked"}]})

    def test_sanitized_service_records_preserve_recheckable_metadata_without_payloads(self):
        record = {"source": "application", "method": "authorization.denied",
            "event_id": "event1", "request_id": "service1", "status_code": 403,
            "certificate_sha256": "a" * 64,
            "facts": {"reason": "certificate_rejected", "business_state": "not_dispatched",
                      "generation": 2, "read_attempts": 3, "prompt": "private-prompt"}}
        expected = record | {"facts": {key: value for key, value in record["facts"].items() if key != "prompt"}}
        self.assertEqual(sanitize(record), expected)
