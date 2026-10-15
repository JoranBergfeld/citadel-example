import unittest

from citadel.operator import parser


class AcceptanceCliTests(unittest.TestCase):
    def test_collection_resume_and_exact_narrative_review_have_explicit_cli_actions(self):
        collect = parser().parse_args(["acceptance", "--state-dir", "private-state",
                                       "--run-id", "r1", "--collect-only"])
        self.assertTrue(collect.collect_only)
        review = parser().parse_args(["review-acceptance", "--state-dir", "private-state",
                                      "--run-id", "r1", "--review", "private-review.json"])
        self.assertEqual(review.command, "review-acceptance")
        self.assertEqual(review.review, "private-review.json")
