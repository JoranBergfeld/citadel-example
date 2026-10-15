import copy
import time
import unittest

from citadel.acceptance.version_probes import VersionProbes
from citadel.evidence.manifests import sha256
from citadel.operations.testing import MemoryLedger
from tests.operations.test_operations import reference


class VersionOracleTests(unittest.IsolatedAsyncioTestCase):
    async def test_version_race_requires_real_layers_exact_source_unchanged_v1_and_one_v2_winner(self):
        from citadel.acceptance.version_oracle import version_snapshot, evaluate_version, content_hash
        data, ledger = reference(), MemoryLedger(clock=time.time)
        original = {"artifact_id": "source", "version": 1, "schema_version": 1,
            "run_id": "comparison", "operation_id": "assessment", "airport_ident": "EB01",
            "private_notes": "PRIVATE", **data.assess_airport("EB01")}
        actual = await VersionProbes(ledger, reference=data, workload="evidence-assessor", enabled=True,
            run_id="worker", deadline=time.time() + 120).concurrent_version(original, operation_id="probe")
        document, _ = await ledger.read()
        now = time.time()
        check = "fault.concurrent-version-conflict"
        actual["reference_reads"] = [{"method": name, "request_id": name, "target": "f" * 64,
            "status_code": 200, "started": now - 8, "finished": now - 7,
            "run_id": "worker", "operation_id": "worker"}
            for name in ("initialize", "lookup_airport", "list_runways")]
        observed = {"check_id": check, "probe_id": check, "run_id": "worker", "operation_id": "probe",
            "caller": "evidence-assessor", "runtime_identity": "a" * 64, "actual": actual,
            "request_id": "publish", "status_code": 201, "target": "e" * 64, "started": now - 5, "finished": now}
        def read(name, container, started, target=None):
            return {"operation_id": name, "request_id": name, "status_code": 206,
                "target": target or sha256(container), "container": container, "caller": "operator",
                "runtime_identity": "b" * 64, "action": "read", "suite_id": "suite",
                "sha256": "0" * 64, "count": 1, "started": started, "finished": started + .1}
        snapshot = read("snapshot", "drafts", now + 1, sha256("isolated")) | version_snapshot(document, actual)
        source = {"release_source": {"run_id": "comparison", "draft": {
            "artifact_id": "source", "version": 1, "sha256": sha256(original)}},
            "content_sha256": content_hash(original), "observation": read("source", "findings", now - 12),
            "draft_read": read("source-draft", "drafts", now - 11)}
        snapshots = {side: {container: read(side + container, container,
            now - 10 if side == "before" else now + 2) for container in ("drafts", "findings")}
            for side in ("before", "after")}
        evidence = [{"source": "application", "request_id": "publish", "status_code": 201,
            "target": "e" * 64, "runtime_identity": "a" * 64, "method": "execution",
            "run_id": "worker", "operation_id": "probe", "caller": "evidence-assessor", "observed": now,
            "facts": {"sha256": sha256(actual), "probe_id": check}},
            {"source": "storage", "request_id": "publish", "status_code": 201, "target": "e" * 64,
             "runtime_identity": "a" * 64, "method": "PutBlob", "client_request_id": "probe", "observed": now}]
        for row in [snapshot, source["observation"], source["draft_read"],
                    *snapshots["before"].values(), *snapshots["after"].values()]:
            evidence.append({"source": "storage", "request_id": row["request_id"], "status_code": 206,
                "target": row["target"], "runtime_identity": "b" * 64, "method": "GetBlob",
                "client_request_id": row["operation_id"], "observed": row["started"]})
        for receipt in actual["reference_reads"]:
            evidence.extend([
                {"source": "gateway", "request_id": receipt["request_id"], "status_code": 200, "target": "f" * 64,
                 "credential_sha256": "d" * 64, "method": "POST", "caller": "evidence-assessor", "observed": now - 7},
                {"source": "application", "request_id": receipt["request_id"], "status_code": 200,
                 "runtime_identity": "c" * 64, "method": receipt["method"], "caller": "evidence-assessor",
                 "run_id": "worker", "operation_id": "worker", "observed": now - 7}])
        def evaluate(control=snapshot, rows=evidence):
            return evaluate_version(observed, control, source, snapshots, rows,
                runtime_identity="a" * 64, observer_identity="b" * 64, reference_identity="c" * 64, subscription="d" * 64)
        self.assertEqual(evaluate()["status"], "pass")
        from citadel.acceptance.proof_gate import evaluate_check
        from citadel.acceptance.reports import sanitize
        report = {"run_id": "suite", "operation_ids": ["worker", "probe", "comparison", *actual["operation_ids"],
            "snapshot", "source", "source-draft", *[row["operation_id"] for rows in snapshots.values() for row in rows.values()]],
            "runtime_identities": {"evidence-assessor": "a" * 64, "reference-data": "c" * 64,
                "candidate-planner": "1" * 64, "release-reviewer": "2" * 64, "briefing-author": "3" * 64},
            "subscription_bindings": {"evidence-assessor": "d" * 64}, "evidence": evidence,
            "scenarios": {"comparison": {"operation_id": "comparison"}}}
        exported = {"check_id": check, "status": "pass", "expected": "fault", "actual": {
            "observation": observed, "control": snapshot, "source": source,
            **{side: list(rows.values()) for side, rows in snapshots.items()}}}
        self.assertEqual(evaluate_check(sanitize(exported), sanitize(report))["status"], "pass")
        self.assertEqual(evaluate_check(sanitize(exported), sanitize(report | {
            "operation_ids": [name for name in report["operation_ids"] if name != "source-draft"]}))["status"], "blocked")
        for layer in ("application", "gateway", "storage"):
            self.assertEqual(evaluate(rows=[row for row in evidence if row["source"] != layer])["status"], "blocked")
        for altered in (
            snapshot | {"artifact_count": 3},
            snapshot | {"drafts": [snapshot["drafts"][0] | {"sha256": "1" * 64}, snapshot["drafts"][1]]},
        ):
            self.assertEqual(evaluate(control=altered)["status"], "fail")
        tampered = copy.deepcopy(snapshot)
        tampered["operation_state"]["states"] = ["succeeded", "succeeded", "succeeded"]
        self.assertEqual(evaluate(control=tampered)["status"], "fail")
        self.assertNotIn("PRIVATE", str(snapshot))
