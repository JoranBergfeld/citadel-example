import copy
import unittest

from citadel.acceptance.reports import acceptance_status, confirm_narrative, sanitize


def report(run="run1"):
    return {"schema_version": 1, "run_id": run, "fingerprint": "a" * 64,
            "mode": "cloud", "required_checks": ["comparison"], "checks": [
                {"check_id": "comparison", "status": "pass"}],
            "scenarios": {"comparison": {"product_sha256": "b" * 64,
                                        "semantics_sha256": "c" * 64}},
            "operation_ids": [run], "human_reviews": {}}


class ReportTests(unittest.TestCase):
    def test_complete_automation_stays_pending_until_exact_narrative_review(self):
        value = report()
        self.assertEqual(acceptance_status([value]), "pending_human")
        with self.assertRaises(ValueError):
            confirm_narrative(value, "comparison", "d" * 64, supported=True,
                              gaps_visible=True, fictional=True)
        confirm_narrative(value, "comparison", "b" * 64, supported=True,
                          gaps_visible=True, fictional=True)
        self.assertEqual(acceptance_status([value]), "pending_second_pass")
        second = report("run2")
        confirm_narrative(second, "comparison", "b" * 64, supported=True,
                          gaps_visible=True, fictional=True)
        self.assertEqual(acceptance_status([value, second]), "pass")

    def test_no_cherry_picking_fingerprints_reused_ids_or_missing_checks(self):
        first, second = report(), report("run2")
        for value in (first, second):
            confirm_narrative(value, "comparison", "b" * 64, supported=True,
                              gaps_visible=True, fictional=True)
        for change in ({"mode": "local"}, {"fingerprint": "d" * 64},
                       {"operation_ids": ["run1"]}, {"checks": []},
                       {"required_checks": ["comparison", "storage-denial"]}):
            with self.subTest(change=change):
                self.assertNotEqual(acceptance_status([first, second | change]), "pass")
        failed = report("failed")
        failed["checks"][0]["status"] = "fail"
        self.assertNotEqual(acceptance_status([first, failed, second]), "pass")

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
