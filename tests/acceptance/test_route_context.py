import copy
import unittest

from citadel.acceptance.route_context import build_route_context, validate_route_context
from citadel.evidence.manifests import sha256


def ledgers():
    finding = {"artifact_id": "finding1", "version": 1, "classification": "complete"}
    reference = {"artifact_id": "finding1", "version": 1, "sha256": sha256(finding)}
    scope = {"run_id": "real-run", "operation_id": "review1"}
    references, scopes = [reference], [scope]
    versions = {"finding1": {"1": finding}}
    for index in (2, 3):
        body = finding | {"artifact_id": "finding" + str(index)}
        references.append({"artifact_id": body["artifact_id"], "version": 1, "sha256": sha256(body)})
        scopes.append({"run_id": "real-run", "operation_id": "review" + str(index)})
        versions[body["artifact_id"]] = {"1": body}
    product = {"status": "complete", "citations": references, "read_scopes": scopes,
               "narrative": "private test prose"}
    documents = {"findings": {"findings": versions}}
    for actor, owner, operation in (
            ("candidate-planner", "operator", "real-run"),
            ("evidence-assessor", "candidate-planner", "assess1"),
            ("release-reviewer", "evidence-assessor", "review2"),
            ("briefing-author", "candidate-planner", "author1")):
        result = {"kind": "collaboration", "finding": reference}
        row = {"operation_id": operation, "run_id": "real-run", "state": "succeeded",
               "input_hash": "a" * 64, "result": result}
        if actor in ("candidate-planner", "briefing-author"):
            row["product"] = product
            row["result"] = {"kind": "work-product", "sha256": sha256(product)}
        documents[actor] = {"operations": {owner + "/invoke/" + operation: row}}
    documents["release-reviewer"]["operations"]["evidence-assessor/invoke/review1"] = (
        documents["release-reviewer"]["operations"]["evidence-assessor/invoke/review2"] | {
            "operation_id": "review1", "result": {"kind": "collaboration", "finding": reference, "read_scope": scope}})
    for index, (reference, scope) in enumerate(zip(references, scopes), 1):
        for actor, caller, operation in (("evidence-assessor", "candidate-planner", "assess" + str(index)),
                                       ("release-reviewer", "evidence-assessor", "review" + str(index))):
            documents[actor]["operations"][caller + "/invoke/" + operation] = {
                "operation_id": operation, "run_id": "real-run", "state": "succeeded",
                "input_hash": "a" * 64,
                "result": {"kind": "collaboration", "finding": reference, "read_scope": scope}}
    return documents


class RouteContextTests(unittest.TestCase):
    def test_task_control_selects_only_existing_unspent_pools_without_assuming_observed_counts(self):
        context = build_route_context(ledgers(), run_ids=["real-run"], available={
            "evidence-assessor": {"assess3"}, "release-reviewer": {"review1", "review2", "review3"}})
        self.assertEqual(context["operations"]["evidence-assessor"]["operation_id"], "assess3")
        with self.assertRaises(ValueError):
            build_route_context(ledgers(), run_ids=["real-run"], available={
                "evidence-assessor": {"assess3"}, "release-reviewer": {"review1", "review2"}})

    def test_genuine_completed_state_yields_only_bounded_owner_ids_hashes_and_exact_released_reference(self):
        context = build_route_context(ledgers(), run_ids=["real-run"])
        self.assertEqual(context["operations"]["candidate-planner"]["operation_id"], "real-run")
        self.assertEqual(context["operations"]["release-reviewer"]["operation_id"], "review3")
        self.assertEqual(context["finding_controls"]["briefing-author"]["read_scope"]["operation_id"], "review2")
        self.assertEqual(context["read_scope"], {"run_id": "real-run", "operation_id": "review1"})
        self.assertEqual(context["finding"]["artifact_id"], "finding1")
        self.assertNotIn("private test prose", str(context))
        self.assertNotIn("product", context["operations"]["briefing-author"])
        self.assertIsNone(validate_route_context(context))

    def test_missing_unreleased_or_wrong_run_products_cannot_be_fabricated_as_controls(self):
        for mutate in (
                lambda value: value["findings"]["findings"].clear(),
                lambda value: value["findings"]["findings"].update(finding1=[]),
                lambda value: value["candidate-planner"]["operations"].clear(),
                lambda value: value["briefing-author"]["operations"]["candidate-planner/invoke/author1"].update(
                    state="indeterminate"),
                lambda value: value["release-reviewer"]["operations"].pop("evidence-assessor/invoke/review2"),
                lambda value: value["release-reviewer"]["operations"].pop("evidence-assessor/invoke/review1"),
                lambda value: value["findings"]["findings"]["finding1"]["1"].update(classification="changed")):
            documents = copy.deepcopy(ledgers())
            mutate(documents)
            with self.assertRaises(ValueError):
                build_route_context(documents, run_ids=["real-run"])
        with self.assertRaises(ValueError):
            build_route_context(ledgers(), run_ids=["another-run"])
        context = build_route_context(ledgers(), run_ids=["real-run"])
        for changes in ({"url": "https://other.example"}, {"credential": "forbidden-input"},
                        {"read_scope": {"run_id": "real-run", "operation_id": "../escape"}}):
            with self.subTest(changes=changes), self.assertRaises((ValueError, RuntimeError)):
                validate_route_context(context | changes)
