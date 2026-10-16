import copy
import unittest

from citadel.acceptance.model_oracle import evaluate_model
from citadel.acceptance.model_probes import INPUT_BOUND, OUTPUT_BOUND


class ModelOracleTests(unittest.TestCase):
    def fixture(self):
        observation = {"check_id": "model.evidence-assessor.direct-denied", "caller": "evidence-assessor",
            "run_id": "phase1", "operation_id": "direct1", "runtime_identity": "a" * 64,
            "started": 100, "finished": 101, "status_code": 403, "request_id": "actual-direct-id",
            "target": "b" * 64, "state": "observed", "reason": "PermissionDenied",
            "input_tokens": INPUT_BOUND, "output_tokens": OUTPUT_BOUND, "model_attempts": 1}
        allowed = {"caller": "evidence-assessor", "run_id": "comparison1", "operation_id": "assess1",
            "runtime_identity": "a" * 64, "started": 90, "finished": 91,
            "request_id": "actual-allowed-id", "status_code": 200, "target": "c" * 64,
            "input_tokens": 100, "output_tokens": 10, "tokens": 110}
        control = {"allowed": allowed, "slot": []}
        evidence = [observation | {"source": "application", "method": "model.direct", "observed": 101,
            "facts": {"reason": "PermissionDenied", "model_attempts": 1,
                      "input_tokens": INPUT_BOUND, "output_tokens": OUTPUT_BOUND}},
            allowed | {"source": "application", "method": "chat.completions", "observed": 91,
                "facts": {key: allowed[key] for key in (
                    "input_tokens", "output_tokens", "tokens", "started", "finished")}},
            allowed | {"source": "gateway", "method": "POST", "observed": 91,
                "credential_sha256": "d" * 64, "facts": {"backend_dispatched": True}}]
        for action, when, status in (("acquire", 30, 201), ("release", 165, 200)):
            row = {"action": action, "operation_id": action + "1", "request_id": action + "-actual",
                   "target": "e" * 64, "started": when, "finished": when + 1, "status_code": status}
            control["slot"].append(row)
            evidence.append(row | {"source": "storage", "method": "LeaseBlob",
                "client_request_id": row["operation_id"], "runtime_identity": "f" * 64,
                "observed": when + .5})
        snapshots = {"before": {}, "after": {}}
        for side, when in (("before", 97), ("after", 103)):
            for container in ("drafts", "findings"):
                row = {"container": container, "action": "read", "target": "1" * 64,
                    "request_id": side + container, "operation_id": side + container,
                    "started": when, "finished": when + 1, "status_code": 206,
                    "sha256": "2" * 64, "count": 1, "suite_id": "suite1"}
                snapshots[side][container] = row
                evidence.append(row | {"source": "storage", "method": "GetBlob", "observed": when + .5,
                    "runtime_identity": "f" * 64, "client_request_id": row["operation_id"]})
        return observation, control, snapshots, evidence

    def evaluate(self, observation, control, snapshots, evidence):
        return evaluate_model(observation, control, snapshots, evidence,
            identities={"evidence-assessor": "a" * 64}, subscription="d" * 64, observer_identity="f" * 64)

    def test_real_denial_needs_ingested_own_identity_allowed_model_receipt_global_slot_and_no_effects(self):
        observation, control, snapshots, evidence = self.fixture()
        self.assertEqual(self.evaluate(observation, control, snapshots, evidence)["status"], "pass")
        for index in range(len(evidence)):
            with self.subTest(missing=index):
                self.assertEqual(self.evaluate(observation, control, snapshots,
                    evidence[:index] + evidence[index + 1:])["status"], "blocked")
        changed = copy.deepcopy(snapshots)
        changed["after"]["drafts"]["sha256"] = "3" * 64
        self.assertEqual(self.evaluate(observation, control, changed, evidence)["status"], "fail")
        for changes in ({"runtime_identity": "3" * 64}, {"reason": "unavailable"},
                        {"state": "indeterminate"}, {"started": 0}, {"model_attempts": True}):
            with self.subTest(changes=changes):
                self.assertEqual(self.evaluate(observation | changes, control, snapshots, evidence)["status"], "blocked")
        changed = copy.deepcopy(evidence)
        changed[2]["facts"]["backend_dispatched"] = False
        self.assertEqual(self.evaluate(observation, control, snapshots, changed)["status"], "blocked")

    def test_observed_unauthorized_inference_fails_instead_of_hiding_behind_missing_controls(self):
        observation, control, snapshots, evidence = self.fixture()
        observation.update(status_code=200, reason="unauthorized_model_succeeded")
        evidence[0].update(status_code=200)
        evidence[0]["facts"]["reason"] = "unauthorized_model_succeeded"
        self.assertEqual(self.evaluate(observation, {}, {}, evidence[:1])["status"], "fail")

    def test_control_phase_cannot_overlap_a_normal_runs_rolling_model_quota(self):
        observation, control, snapshots, evidence = self.fixture()
        control["slot"][0].update(started=95, finished=96)
        evidence[3].update(started=95, finished=96, observed=95.5)
        self.assertEqual(self.evaluate(observation, control, snapshots, evidence)["status"], "blocked")

    def test_sanitized_export_rechecks_all_model_receipts_instead_of_trusting_pass_label(self):
        from citadel.acceptance.proof_gate import evaluate_check
        from citadel.acceptance.reports import sanitize
        from citadel.acceptance.coverage import STORAGE
        observation, control, snapshots, evidence = self.fixture()
        control["runtime_identity"] = "f" * 64
        for side in snapshots.values():
            for row in side.values():
                row["caller"] = "operator"
        check = {"check_id": observation["check_id"], "expected": "deny", "status": "pass",
                 "actual": {"observation": observation, "control": control,
                            "before": list(snapshots["before"].values()),
                            "after": list(snapshots["after"].values())}}
        identities = {actor: str(index + 3) * 64 for index, actor in enumerate(STORAGE)}
        identities["evidence-assessor"] = "a" * 64
        report = {"run_id": "suite1", "runtime_identities": identities,
            "subscription_bindings": {"evidence-assessor": "d" * 64},
            "operation_ids": ["phase1", "direct1", "comparison1", "assess1", "acquire1", "release1",
                              "beforedrafts", "beforefindings", "afterdrafts", "afterfindings"],
            "evidence": evidence}
        self.assertEqual(evaluate_check(sanitize(check), sanitize(report))["status"], "pass")
        report["evidence"] = evidence[1:]
        self.assertEqual(evaluate_check(sanitize(check), sanitize(report))["status"], "blocked")
