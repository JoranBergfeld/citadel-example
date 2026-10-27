import copy
import time
import unittest

from citadel.acceptance.release_probes import ReleaseProbes
from citadel.evidence.manifests import sha256
from citadel.operations import DraftReader, Operations
from citadel.operations.testing import MemoryLedger
from tests.operations.test_operations import reference


class ReleaseOracleTests(unittest.IsolatedAsyncioTestCase):
    def test_missing_or_incomplete_persisted_result_is_observed_without_inventing_success(self):
        from citadel.acceptance.release_oracle import release_snapshot
        from citadel.operations import empty_ledger
        document = empty_ledger()
        document["operations"]["evidence-assessor/release/probe"] = {"state": "running", "result": None}
        snapshot = release_snapshot(document, {"operation_id": "probe"})
        self.assertEqual(snapshot["operation_state"]["states"], ["running"])
        self.assertEqual(snapshot["operation_state"]["result_hashes"], [None])
        self.assertEqual(snapshot["operation_state"]["artifact_count"], 0)
        document["operations"]["evidence-assessor/release/probe"]["result"] = ["private-content"]
        with self.assertRaises(ValueError) as error:
            release_snapshot(document, {"operation_id": "probe"})
        self.assertNotIn("private-content", str(error.exception))

    async def test_release_oracles_require_independent_state_no_business_change_and_all_service_correlations(self):
        from citadel.acceptance.release_oracle import evaluate_release, release_snapshot
        data, drafts = reference(), MemoryLedger(clock=time.time)
        assessor = Operations(drafts, workload="evidence-assessor")
        draft = {"artifact_id": "draft", "version": 1, "schema_version": 1, "run_id": "comparison",
                 "operation_id": "assess", "airport_ident": "EB01", "private_notes": "PRIVATE",
                 **data.assess_airport("EB01")}
        await assessor.accept("candidate-planner", "draft", "assess", {"draft": draft, "expected_version": 0},
                              run_id="comparison", deadline=time.time() + 120)
        owner = await assessor.claim("candidate-planner", "draft", "assess", worker="assessor")
        await assessor.submit_draft(owner, draft, expected_version=0, reference=data)
        ref = {"artifact_id": "draft", "version": 1, "sha256": sha256(draft)}
        identities = {"runtime_identity": "a" * 64, "observer_identity": "b" * 64,
                      "reference_identity": "c" * 64, "subscription": "d" * 64}
        for check in ("fault.dropped-committed-release", "fault.concurrent-exact-draft-release",
                      "fault.concurrent-different-operation-release", "fault.draft-hash-binding"):
            ledger = MemoryLedger(clock=time.time)
            probe = ReleaseProbes(ledger, drafts=DraftReader(drafts), reference=data,
                workload="release-reviewer", enabled=True, source_run="comparison", deadline=time.time() + 120)
            actual = (await probe.hash_binding(ref, operation_id="probe") if "hash-binding" in check else
                      await probe.committed_response_loss(ref, operation_id="probe") if "dropped" in check else
                      await probe.concurrent_release(ref, operation_id="probe",
                          distinct_operations="different" in check))
            document, _ = await ledger.read()
            now = time.time()
            actual["reference_reads"] = [{"method": method, "run_id": "worker", "operation_id": "worker",
                "request_id": method, "status_code": 200, "target": "e" * 64,
                "started": now - 9, "finished": now - 8}
                for method in ("initialize", "lookup_airport", "list_runways")]
            observed = {"check_id": check, "probe_id": check, "run_id": "worker", "operation_id": "probe",
                "caller": "release-reviewer", "runtime_identity": "a" * 64, "actual": actual,
                "request_id": "publish", "target": "f" * 64, "status_code": 201,
                "started": now - 5, "finished": now}
            def read(name, container, started):
                return {"request_id": name, "target": sha256(name), "operation_id": name,
                    "caller": "operator", "runtime_identity": "b" * 64, "container": container,
                    "action": "read", "suite_id": "suite", "status_code": 206,
                    "started": started, "finished": started + .1, "count": 1, "sha256": "0" * 64}
            snapshot = read("snapshot", "findings", now + 1) | release_snapshot(document, actual)
            finding = next(iter(next(iter(document["findings"].values())).values()))
            source = {"release_source": {"run_id": "comparison", "draft": ref},
                "projection_sha256": sha256({key: value for key, value in finding.items() if key != "operation_id"}),
                "observation": read("source", "findings", now - 12)}
            source["observation"]["target"] = sha256("findings")
            snapshots = {side: {container: read(side + container, container,
                        now - 11 if side == "before" else now + 2) for container in ("drafts", "findings")}
                        for side in ("before", "after")}
            for container in ("drafts", "findings"):
                for side in snapshots:
                    snapshots[side][container]["target"] = sha256(container)
            evidence = [{"source": "application", "method": "execution", "runtime_identity": "a" * 64,
                "caller": "release-reviewer", "run_id": "worker", "operation_id": "probe",
                "request_id": "publish", "status_code": 201, "target": "f" * 64, "observed": now,
                "facts": {"sha256": sha256(actual), "probe_id": check}},
                {"source": "storage", "method": "PutBlob", "runtime_identity": "a" * 64,
                 "request_id": "publish", "status_code": 201, "target": "f" * 64, "observed": now,
                 "client_request_id": "probe"}]
            for row in [snapshot, source["observation"],
                        *snapshots["before"].values(), *snapshots["after"].values()]:
                evidence.append({"source": "storage", "method": "GetBlob", "runtime_identity": "b" * 64,
                    "request_id": row["request_id"], "status_code": 206, "target": row["target"],
                    "observed": row["started"], "client_request_id": row["operation_id"]})
            for receipt in actual["reference_reads"]:
                evidence.extend([
                    {"source": "gateway", "method": "POST", "request_id": receipt["request_id"], "status_code": 200,
                     "target": "e" * 64, "credential_sha256": "d" * 64, "caller": "release-reviewer",
                     "observed": now - 8},
                    {"source": "application", "method": receipt["method"], "runtime_identity": "c" * 64,
                     "request_id": receipt["request_id"], "status_code": 200, "caller": "release-reviewer",
                     "run_id": "worker", "operation_id": "worker", "observed": now - 8}])
            def evaluate(rows=evidence, control=snapshot, business=snapshots):
                return evaluate_release(observed, control, source, business, rows, **identities)
            with self.subTest(check=check):
                self.assertEqual(evaluate()["status"], "pass")
                from citadel.acceptance.proof_gate import evaluate_check
                from citadel.acceptance.reports import sanitize
                report = {"run_id": "suite", "operation_ids": list(dict.fromkeys([
                    "worker", "probe", "comparison", *actual.get("operation_ids", []), "source", "snapshot",
                    *([actual["rejected_operation_id"]] if "rejected_operation_id" in actual else []),
                    *[row["operation_id"] for side in snapshots.values() for row in side.values()]])),
                    "runtime_identities": {"release-reviewer": "a" * 64, "reference-data": "c" * 64,
                        "candidate-planner": "1" * 64, "evidence-assessor": "2" * 64, "briefing-author": "3" * 64},
                    "subscription_bindings": {"release-reviewer": "d" * 64}, "evidence": evidence,
                    "scenarios": {"comparison": {"operation_id": "comparison"}}}
                exported = {"check_id": check, "expected": "fault", "status": "pass", "actual": {
                    "observation": observed, "control": snapshot, "source": source,
                    **{side: list(rows.values()) for side, rows in snapshots.items()}}}
                self.assertEqual(evaluate_check(sanitize(exported), sanitize(report))["status"], "pass")
                altered = copy.deepcopy(exported)
                altered["actual"]["source"]["release_source"]["run_id"] = "unrelated"
                self.assertEqual(evaluate_check(sanitize(altered), sanitize(report))["status"], "blocked")
                for kind in ("application", "gateway", "storage"):
                    self.assertEqual(evaluate(rows=[r for r in evidence if r["source"] != kind])["status"], "blocked")
                self.assertEqual(evaluate(rows=[r | {"client_request_id": "forged"}
                    if r["source"] == "storage" else r for r in evidence])["status"], "blocked")
                wrong = copy.deepcopy(snapshot)
                wrong["operation_state"]["artifact_count"] = 2
                self.assertEqual(evaluate(control=wrong)["status"], "fail")
                if "hash-binding" in check:
                    altered_rejection = copy.deepcopy(snapshot)
                    altered_rejection["rejected_state"]["state"] = "succeeded"
                    self.assertEqual(evaluate(control=altered_rejection)["status"], "fail")
                modified = copy.deepcopy(snapshots)
                modified["after"]["drafts"]["sha256"] = "1" * 64
                self.assertEqual(evaluate(business=modified)["status"], "fail")
                self.assertEqual(evaluate_release(observed, snapshot, source, snapshots, evidence,
                    **(identities | {"runtime_identity": "b" * 64}))["status"], "blocked")
                for bad_source, bad_snapshots in (
                    (source | {"release_source": source["release_source"] | {"run_id": None}}, snapshots),
                    (source, snapshots | {"before": []}),
                ):
                    self.assertEqual(evaluate_release(observed, snapshot, bad_source, bad_snapshots, evidence,
                                                      **identities)["status"], "blocked")
                self.assertNotIn("PRIVATE", str(snapshot) + str(source))
