import copy
import unittest

from citadel.acceptance.origin_probes import evaluate_origin


class OriginOracleTests(unittest.TestCase):
    def fixture(self):
        observed = {"check_id": "origin.evidence-assessor.unrelated-certificate",
            "caller": "evidence-assessor", "run_id": "origin1", "operation_id": "physical1",
            "runtime_identity": "a" * 64, "started": 100, "finished": 101,
            "target": "b" * 64, "request_id": "actual-origin-service-id", "status_code": 403}
        control = {"check_id": "route.candidate-planner.evidence-assessor.discovery",
            "caller": "candidate-planner", "started": 102, "finished": 103,
            "request_id": "actual-gateway-control", "status_code": 200, "actual": "gateway_card"}
        evidence = [
            observed | {"source": "application", "method": "probe", "observed": 100.5},
            {"source": "application", "method": "authorization.denied", "observed": 100.5,
             "request_id": observed["request_id"], "status_code": 403, "runtime_identity": "a" * 64,
             "facts": {"reason": "certificate_rejected", "business_state": "not_dispatched"}},
            {"source": "application", "method": "discovery", "observed": 102.5,
             "request_id": control["request_id"], "status_code": 200, "runtime_identity": "a" * 64,
             "caller": "candidate-planner"},
            {"source": "gateway", "observed": 102.5, "request_id": control["request_id"],
             "status_code": 200, "caller": "candidate-planner"},
        ]
        snapshots = {"before": {}, "after": {}}
        for side, when in (("before", 98), ("after", 104)):
            for container in ("drafts", "findings"):
                record = {"container": container, "action": "read", "target": "c" * 64,
                    "request_id": side + container, "operation_id": side + container,
                    "started": when, "finished": when + 1, "status_code": 206,
                    "sha256": "d" * 64, "count": 1, "suite_id": "suite1"}
                snapshots[side][container] = record
                evidence.append(record | {"source": "storage", "method": "GetBlob", "observed": when + .5,
                    "runtime_identity": "e" * 64, "client_request_id": record["operation_id"]})
        return observed, control, snapshots, evidence

    def evaluate(self, observed, control, snapshots, evidence):
        return evaluate_origin(observed, control, snapshots, evidence,
            runtime_identity="a" * 64, observer_identity="e" * 64,
            subscription_id="/subscriptions/s/resourceGroups/g/providers/Microsoft.ApiManagement/service/a/subscriptions/candidate-planner")

    def test_origin_denial_requires_actual_server_rejection_allowed_gateway_and_no_effects(self):
        observed, control, snapshots, evidence = self.fixture()
        self.assertEqual(self.evaluate(observed, control, snapshots, evidence)["status"], "pass")
        for index in range(len(evidence)):
            with self.subTest(missing=index):
                self.assertEqual(self.evaluate(observed, control, snapshots,
                    evidence[:index] + evidence[index + 1:])["status"], "blocked")
        changed = copy.deepcopy(snapshots)
        changed["after"]["drafts"]["sha256"] = "f" * 64
        self.assertEqual(self.evaluate(observed, control, changed, evidence)["status"], "fail")
        forged = [row | {"runtime_identity": "f" * 64} if row.get("method") == "authorization.denied"
                  else row for row in evidence]
        self.assertEqual(self.evaluate(observed, control, snapshots, forged)["status"], "blocked")
        self.assertEqual(self.evaluate(observed | {"request_id": None},
                                       control, snapshots, evidence)["status"], "blocked")
        for altered in (observed | {"caller": []}, observed | {"operation_id": None}):
            self.assertEqual(self.evaluate(altered, control, snapshots, evidence)["status"], "blocked")
        self.assertEqual(self.evaluate(observed, control | {"caller": []}, snapshots, evidence)["status"], "blocked")

    def test_preapplication_denial_needs_recognized_ingress_reason_zero_upstream_and_all_controls(self):
        observed, control, snapshots, evidence = self.fixture()
        evidence[1] = {"source": "ingress", "method": "GET", "observed": 100.5,
            "request_id": observed["request_id"], "status_code": 403, "runtime_identity": "",
            "target": observed["target"],
            "facts": {"reason": "ingress_rbac_denied", "upstream_attempts": 0}}
        self.assertEqual(self.evaluate(observed, control, snapshots, evidence)["status"], "pass")
        for changes in (
                {"target": "f" * 64}, {"request_id": "unrelated-platform-request"}, {"observed": 110},
                {"method": "POST"}, {"facts": {"reason": "direct_response", "upstream_attempts": 0}},
                {"facts": {"reason": "ingress_rbac_denied", "upstream_attempts": 1}},
                {"facts": {"reason": "ingress_rbac_denied", "upstream_attempts": None}},
                {"facts": {"reason": "ingress_rbac_denied", "upstream_attempts": False}}):
            altered = copy.deepcopy(evidence)
            altered[1].update(changes)
            with self.subTest(changes=changes):
                self.assertEqual(self.evaluate(observed, control, snapshots, altered)["status"], "blocked")
        for index in range(len(evidence)):
            with self.subTest(missing=index):
                self.assertEqual(self.evaluate(observed, control, snapshots,
                    evidence[:index] + evidence[index + 1:])["status"], "blocked")
