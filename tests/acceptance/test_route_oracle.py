import copy
import unittest

from citadel.acceptance.route_oracle import evaluate_route
from citadel.evidence.manifests import sha256


def route_proof():
    identities = {"candidate-planner": "a" * 64, "evidence-assessor": "b" * 64,
                  "release-reviewer": "c" * 64, "briefing-author": "d" * 64, "reference-data": "e" * 64}
    subscriptions = {"candidate-planner": "1" * 64, "briefing-author": "2" * 64}
    observed = {"check_id": "route.briefing-author.reference-data.initialize", "caller": "briefing-author",
        "run_id": "denied-run", "operation_id": "denied-op", "request_id": "actual-denial", "status_code": 403,
        "reason": "route_denied", "target": "3" * 64, "started": 100, "finished": 101}
    control = {"check_id": "route.candidate-planner.reference-data.initialize", "caller": "candidate-planner",
        "run_id": "control-run", "operation_id": "control-op", "request_id": "actual-control", "status_code": 200,
        "actual": "mcp_initialized", "target": "3" * 64, "started": 102, "finished": 103}
    evidence = []
    for row in (observed, control):
        evidence.append({"source": "gateway", "request_id": row["request_id"],
            "status_code": row["status_code"], "observed": row["started"] + .5,
            "caller": row["caller"], "credential_sha256": subscriptions[row["caller"]],
            "target": row["target"], "method": "POST", "facts": {"backend_dispatched": row is control}})
        evidence.append(row | {"source": "application", "method": "probe", "observed": row["started"] + .5,
            "runtime_identity": identities[row["caller"]],
            "facts": {"sha256": sha256(row), "probe_id": row["check_id"]}})
    evidence.append(control | {"source": "application", "method": "initialize", "observed": 102.5,
        "runtime_identity": identities["reference-data"]})
    snapshots = {"before": {}, "after": {}}
    for side, when in (("before", 98), ("after", 104)):
        for container in ("drafts", "findings"):
            row = {"container": container, "action": "read", "suite_id": "suite1",
                "target": "4" * 64, "request_id": side + container, "operation_id": side + container,
                "started": when, "finished": when + 1, "status_code": 206, "sha256": "5" * 64, "count": 1}
            snapshots[side][container] = row
            evidence.append(row | {"source": "storage", "method": "GetBlob", "observed": when + .5,
                "client_request_id": row["operation_id"], "runtime_identity": "f" * 64})
    return observed, control, snapshots, evidence, identities, subscriptions


def owner_route_proof(capability):
    from citadel.acceptance.route_context import build_route_context
    from tests.acceptance.test_route_context import ledgers
    observed, control, snapshots, evidence, identities, subscriptions = route_proof()
    context = build_route_context(ledgers(), run_ids=["real-run"])
    target = "release-reviewer" if capability == "findings" else "evidence-assessor"
    reference = ({"finding": context["finding"], "read_scope": context["read_scope"]}
                 if capability == "findings" else context["operations"][target])
    if capability == "findings":
        observed["caller"] = "release-reviewer"
        subscriptions["release-reviewer"] = "2" * 64
    for row, offset in ((observed, 0), (control, 2)):
        row["check_id"] = f"route.{row['caller']}.{target}.{capability}"
        row["control_reference"] = reference
        if row is control:
            row["actual"] = {"status": "owned_status", "task": "owned_task", "findings": "exact_finding"}[capability]
            row["sha256"] = (context["finding"]["sha256"] if capability == "findings"
                             else reference["result_sha256" if capability == "status" else "task_sha256"])
        evidence[offset].update(caller=row["caller"], method="POST" if capability == "task" else "GET")
        evidence[offset + 1].update(row, runtime_identity=identities[row["caller"]],
                                   facts={"sha256": sha256(row), "probe_id": row["check_id"]})
    evidence[4].update(control, runtime_identity=identities[target],
        method={"status": "status", "task": "GetTask", "findings": "findings-read"}[capability])
    reads = []
    for index, container in enumerate(("planner-operations", "assessor-operations", "reviewer-operations",
                                       "author-operations", "findings")):
        row = {"container": container, "action": "read", "suite_id": "suite1", "target": "6" * 64,
            "request_id": "context-" + str(index), "operation_id": "context-" + str(index),
            "started": 90 + index, "finished": 90.5 + index, "status_code": 206, "sha256": "7" * 64, "count": 1}
        reads.append(row)
        evidence.append(row | {"source": "storage", "method": "GetBlob", "observed": row["finished"],
                               "client_request_id": row["operation_id"], "runtime_identity": "f" * 64})
    return (observed, control, snapshots, evidence, identities, subscriptions), context, reads


class RouteOracleTests(unittest.TestCase):
    def test_workflow_status_is_a_real_control_without_refilling_exhausted_operation_tickets(self):
        args, context, reads = owner_route_proof("status")
        observed, control, snapshots, evidence, identities, subscriptions = args
        control.update(observation_kind="workflow", run_id="real-run", started=80, finished=81)
        evidence[2]["observed"] = 80.5
        evidence[3].update(control, observed=80.5, method="status.observed",
                           facts={"probe_id": control["check_id"], "sha256": sha256(control)})
        evidence[4].update(control, observed=80.5)
        self.assertEqual(evaluate_route(observed, control, snapshots, evidence, identities=identities,
            subscriptions=subscriptions, observer_identity="f" * 64, route_context=context,
            context_observations=reads)["status"], "pass")
        self.assertEqual(evaluate_route(control, control, snapshots, evidence, identities=identities,
            subscriptions=subscriptions, observer_identity="f" * 64, route_context=context,
            context_observations=reads)["status"], "pass")
        evidence[3]["method"] = "probe"
        self.assertEqual(evaluate_route(observed, control, snapshots, evidence, identities=identities,
            subscriptions=subscriptions, observer_identity="f" * 64, route_context=context,
            context_observations=reads)["status"], "blocked")

    def evaluate(self, observed, control, snapshots, evidence, identities, subscriptions):
        return evaluate_route(observed, control, snapshots, evidence, identities=identities,
                              subscriptions=subscriptions, observer_identity="f" * 64)

    def test_actual_route_denial_needs_exact_subscription_probe_digest_control_and_no_dispatch(self):
        args = route_proof()
        self.assertEqual(self.evaluate(*args)["status"], "pass")
        for index in range(len(args[3])):
            altered = copy.deepcopy(args)
            altered[3].pop(index)
            with self.subTest(missing=index):
                self.assertEqual(self.evaluate(*altered)["status"], "blocked")
        for index, changes in ((0, {"target": "6" * 64}), (0, {"credential_sha256": "7" * 64}),
                               (0, {"facts": {"backend_dispatched": None}}),
                               (0, {"facts": {"backend_dispatched": True}}),
                               (1, {"runtime_identity": "f" * 64}), (4, {"run_id": "unrelated"})):
            altered = copy.deepcopy(args)
            altered[3][index].update(changes)
            with self.subTest(index=index, changes=changes):
                self.assertEqual(self.evaluate(*altered)["status"], "blocked")
        altered = copy.deepcopy(args)
        altered[0]["reason"] = "observed"
        self.assertEqual(self.evaluate(*altered)["status"], "blocked")
        altered = copy.deepcopy(args)
        altered[2]["after"]["findings"]["sha256"] = "8" * 64
        self.assertEqual(self.evaluate(*altered)["status"], "fail")

    def test_permitted_control_is_independently_usable_without_a_second_invocation_or_new_grant(self):
        observed, control, snapshots, evidence, identities, subscriptions = route_proof()
        self.assertEqual(self.evaluate(control, control, snapshots, evidence, identities, subscriptions)["status"], "pass")
        self.assertEqual(self.evaluate(control | {"actual": "invented"}, control, snapshots,
                                       evidence, identities, subscriptions)["status"], "blocked")

    def test_owner_and_exact_finding_controls_require_genuine_context_reads_and_actual_backend_methods(self):
        for capability in ("status", "task", "findings"):
            args, context, reads = owner_route_proof(capability)
            observed, control, snapshots, evidence, identities, subscriptions = args
            def check(records=evidence, reference=context, observers=reads):
                return evaluate_route(observed, control, snapshots, records, identities=identities,
                    subscriptions=subscriptions, observer_identity="f" * 64,
                    route_context=reference, context_observations=observers)
            with self.subTest(capability=capability):
                self.assertEqual(check()["status"], "pass")
                self.assertEqual(check(reference=None)["status"], "blocked")
                self.assertEqual(check(observers=reads[:-1])["status"], "blocked")
                self.assertEqual(check(records=evidence[:-1])["status"], "blocked")
                for changes in ({"container": []}, {"request_id": []}):
                    malformed = copy.deepcopy(reads)
                    malformed[0].update(changes)
                    self.assertEqual(check(observers=malformed)["status"], "blocked")
                changed = copy.deepcopy(context)
                if capability == "findings":
                    changed["finding"]["sha256"] = "8" * 64
                else:
                    changed["operations"]["evidence-assessor"]["input_hash"] = "8" * 64
                self.assertEqual(check(reference=changed)["status"], "blocked")
                wrong_method = copy.deepcopy(evidence)
                wrong_method[4]["method"] = "made-up"
                self.assertEqual(check(records=wrong_method)["status"], "blocked")
