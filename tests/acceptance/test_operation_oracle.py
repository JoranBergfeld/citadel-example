import copy
import time
import unittest

from citadel.acceptance.faults import OperationProbes
from citadel.acceptance.operation_oracle import evaluate_operation, operation_snapshot
from citadel.acceptance.proof_gate import evaluate_check
from citadel.acceptance.reports import sanitize
from citadel.evidence.manifests import sha256
from citadel.operations.testing import MemoryLedger


class OperationOracleTests(unittest.IsolatedAsyncioTestCase):
    async def test_read_timeout_gate_requires_actual_timer_expiry_three_service_reads_and_independent_budget(self):
        observed, snapshot, evidence = await self.fixture()
        name, base = "limit.safe_read_timeout_seconds", time.time()
        steps = []
        for index in range(3):
            accepted = base + index * 30.02
            start, end = accepted + index, accepted + 30.01
            mono = 1000 + index * 30.02
            step_id = f"operation1-read{index}"
            steps.append({"operation_id": step_id, "accepted": accepted, "deadline": accepted + 30,
                "started": start, "received": start + .1, "finished": end,
                "monotonic_started": mono + index, "monotonic_finished": mono + 30.01,
                "sha256": "a" * 64, "state": "timed_out"})
            receipt = {"request_id": "physical-" + str(index), "status_code": 206,
                "target": snapshot["target"], "observed": start + .1, "runtime_identity": "a" * 64}
            evidence.extend([
                receipt | {"source": "storage", "method": "GetBlob"},
                receipt | {"source": "application", "method": "storage.read", "run_id": "worker1",
                           "operation_id": step_id, "caller": "candidate-planner"},
                {"source": "application", "method": "safe_read.timeout", "run_id": "worker1",
                 "operation_id": "operation1", "runtime_identity": "a" * 64, "caller": "candidate-planner",
                 "status_code": 0, "request_id": "", "observed": end,
                 "facts": {"read_operation_id": "operation1", "retry": index, "started": start,
                     "finished": end, "deadline": accepted + 30, "monotonic_started": mono + index,
                     "monotonic_deadline": mono + 30, "monotonic_finished": mono + 30.01}}])
        actual = {"operation_id": "operation1", "state": "unavailable", "steps": steps,
            "read_attempts": 3, "retry": 2, "remaining_reads": 509, "deadline": base + 300,
            "before_sha256": "a" * 64, "after_sha256": "a" * 64}
        observed.update(check_id=name, probe_id=name, actual=actual, started=base - 1, finished=base + 91)
        snapshot.update(started=base + 92, finished=base + 93, business_sha256="a" * 64, suite_id="suite1",
            operation_state={"state": "missing", "artifact_count": 0},
            budget_state={"closed": True, "deadline": base + 300, "remaining_reads": 509})
        for row in evidence[:3]:
            row["observed"] = base + (92 if row["request_id"] == snapshot["request_id"] else 91)
            if row["source"] == "application":
                row["facts"] = {"probe_id": name, "sha256": sha256(actual)}
        report = {"run_id": "suite1", "operation_ids": ["worker1", "operation1", "observer1",
            *[step["operation_id"] for step in steps]],
            "runtime_identities": {"candidate-planner": "a" * 64, "reference-data": "d" * 64,
                "evidence-assessor": "e" * 64, "release-reviewer": "f" * 64, "briefing-author": "0" * 64},
            "evidence": evidence}
        check = {"check_id": name, "expected": "boundary", "actual": {"observation": observed, "control": snapshot}}
        self.assertEqual(evaluate_check(sanitize(check), sanitize(report))["status"], "pass")
        for method in ("safe_read.timeout", "GetBlob", "storage.read"):
            changed = report | {"evidence": [row for row in evidence if row["method"] != method]}
            self.assertEqual(evaluate_check(check, changed)["status"], "blocked", method)
        changed = copy.deepcopy(report)
        next(row for row in changed["evidence"] if row["method"] == "safe_read.timeout")["facts"]["monotonic_deadline"] += 1
        self.assertNotEqual(evaluate_check(check, changed)["status"], "pass")
        changed = copy.deepcopy(report)
        extra = next(row for row in changed["evidence"] if row["method"] == "storage.read")
        changed["evidence"].append(extra | {"request_id": "unexpected-extra-read"})
        self.assertEqual(evaluate_check(check, changed)["status"], "blocked")
        for target, field, value in (("budget_state", "remaining_reads", 508),
                                     ("operation_state", "artifact_count", 1)):
            changed_check = copy.deepcopy(check)
            changed_check["actual"]["control"][target][field] = value
            self.assertEqual(evaluate_check(changed_check, report)["status"], "fail")
        changed_check = copy.deepcopy(check)
        changed_check["actual"]["control"]["business_sha256"] = "b" * 64
        self.assertEqual(evaluate_check(changed_check, report)["status"], "fail")
        changed_check, changed_report = copy.deepcopy(check), copy.deepcopy(report)
        changed_actual = changed_check["actual"]["observation"]["actual"]
        changed_actual["steps"][0]["finished"] -= 2
        for row in changed_report["evidence"]:
            if row["method"] == "execution":
                row["facts"]["sha256"] = sha256(changed_actual)
            if row["method"] == "safe_read.timeout" and row["facts"]["retry"] == 0:
                row["facts"]["finished"] -= 2
                row["observed"] -= 2
        self.assertEqual(evaluate_check(changed_check, changed_report)["status"], "pass")

    async def test_exported_fault_proof_rechecks_suite_scope_and_fingerprinted_identity(self):
        observation, snapshot, evidence = await self.fixture()
        snapshot["suite_id"] = "suite1"
        report = {"run_id": "suite1", "operation_ids": ["worker1", "operation1", "observer1"],
            "runtime_identities": {"candidate-planner": "a" * 64, "reference-data": "d" * 64,
                "evidence-assessor": "e" * 64, "release-reviewer": "f" * 64, "briefing-author": "0" * 64},
            "evidence": evidence}
        check = {"check_id": observation["check_id"], "expected": "fault", "status": "pass",
                 "actual": {"observation": observation, "control": snapshot}}
        self.assertEqual(evaluate_check(sanitize(check), sanitize(report))["status"], "pass")
        snapshot["suite_id"] = "unrelated"
        self.assertEqual(evaluate_check(check, report)["status"], "blocked")
        snapshot["suite_id"] = "suite1"
        snapshot["runtime_identity"] = "a" * 64
        self.assertEqual(evaluate_check(check, report)["status"], "blocked")

    async def test_incomplete_sequence_never_proves_completed_or_retriable_work(self):
        ledger = MemoryLedger()
        result = await OperationProbes(ledger, workload="candidate-planner", enabled=True,
            run_id="worker1").identity_and_incomplete_status("operation1")
        document, _ = await ledger.read()
        observed, snapshot, evidence = await self.fixture()
        observed.update(probe_id="fault.pending-incomplete", actual=result)
        snapshot.update(sha256=sha256(document), **operation_snapshot(document, "candidate-planner", result))
        evidence[0]["facts"] = {"sha256": sha256(result), "probe_id": "fault.pending-incomplete"}
        report = {"run_id": "suite1", "operation_ids": ["worker1", "operation1", "observer1", result["missing_operation_id"]],
            "runtime_identities": {"candidate-planner": "a" * 64, "reference-data": "d" * 64,
                "evidence-assessor": "e" * 64, "release-reviewer": "f" * 64, "briefing-author": "0" * 64},
            "evidence": evidence}
        for check in ("pending-incomplete", "running-incomplete", "indeterminate-incomplete",
                      "missing-incomplete", "changed-input-conflict", "partial-not-completed"):
            observed["check_id"] = "fault." + check
            with self.subTest(check=check):
                self.assertEqual(evaluate_operation(observed, snapshot, evidence,
                    runtime_identity="a" * 64, observer_identity="c" * 64)["status"], "pass")
                exported = {"check_id": observed["check_id"], "expected": "fault", "status": "pass",
                    "actual": {"observation": observed, "control": snapshot | {"suite_id": "suite1"}}}
                self.assertEqual(evaluate_check(sanitize(exported), sanitize(report))["status"], "pass")
        snapshot["operation_state"]["artifact_count"] = 1
        self.assertEqual(evaluate_operation(observed, snapshot, evidence,
            runtime_identity="a" * 64, observer_identity="c" * 64)["status"], "fail")

    async def test_fenced_explicit_retry_verifies_generation_and_exact_single_product(self):
        now = [time.time()]

        async def sleep(seconds):
            now[0] += seconds

        ledger = MemoryLedger(clock=lambda: now[0])
        result = await OperationProbes(ledger, workload="candidate-planner", enabled=True,
            run_id="worker1", clock=lambda: now[0], sleep=sleep).fenced_retry("operation1")
        document, _ = await ledger.read()
        observed, snapshot, evidence = await self.fixture()
        observed.update(probe_id="fault.fenced-explicit-retry", actual=result)
        snapshot.update(sha256=sha256(document), **operation_snapshot(document, "candidate-planner", result))
        evidence[0]["facts"] = {"sha256": sha256(result), "probe_id": "fault.fenced-explicit-retry"}
        for check in ("fault.fenced-explicit-retry", "fault.stale-generation-denied"):
            observed["check_id"] = check
            self.assertEqual(evaluate_operation(observed, snapshot, evidence,
                runtime_identity="a" * 64, observer_identity="c" * 64)["status"], "pass")
        snapshot["operation_state"]["generation"] = 1
        self.assertEqual(evaluate_operation(observed, snapshot, evidence,
            runtime_identity="a" * 64, observer_identity="c" * 64)["status"], "fail")

    async def test_late_effect_requires_expired_deadline_and_unchanged_independent_state(self):
        now = [time.time()]

        async def sleep(seconds):
            now[0] += seconds

        ledger = MemoryLedger(clock=lambda: now[0])
        result = await OperationProbes(ledger, workload="candidate-planner", enabled=True,
            run_id="worker1", clock=lambda: now[0], sleep=sleep).deadline_no_late_effect("operation1")
        document, _ = await ledger.read()
        observed, snapshot, evidence = await self.fixture()
        observed.update(check_id="fault.deadline-no-late-effect", probe_id="fault.deadline-no-late-effect",
                        actual=result, started=now[0] - 46, finished=now[0])
        snapshot.update(sha256=sha256(document), started=now[0] + 1, finished=now[0] + 2,
                        **operation_snapshot(document, "candidate-planner", result))
        for row in evidence:
            row["observed"] = now[0] + 1
        evidence[0]["facts"] = {"sha256": sha256(result), "probe_id": "fault.deadline-no-late-effect"}
        self.assertEqual(evaluate_operation(observed, snapshot, evidence,
            runtime_identity="a" * 64, observer_identity="c" * 64)["status"], "pass")
        snapshot["operation_state"]["sha256"] = "f" * 64
        self.assertEqual(evaluate_operation(observed, snapshot, evidence,
            runtime_identity="a" * 64, observer_identity="c" * 64)["status"], "fail")

    async def test_safe_read_recovery_and_exhaustion_bind_actual_backoff_and_persisted_accounting(self):
        for mode in ("recovery", "exhaustion"):
            epoch, beginning = time.time(), time.monotonic()
            clock = lambda: epoch + time.monotonic() - beginning
            ledger = MemoryLedger(clock=clock)
            probe = OperationProbes(ledger, workload="candidate-planner", enabled=True, run_id="worker1", clock=clock)
            started = clock()
            result = await getattr(probe, "safe_read_" + mode)("operation1")
            finished = clock()
            document, _ = await ledger.read()
            observed, snapshot, evidence = await self.fixture()
            group = "fault.safe-read-" + mode
            observed.update(check_id=group, probe_id=group, actual=result, started=started, finished=finished)
            snapshot.update(sha256=sha256(document), started=finished + 1, finished=finished + 2,
                            **operation_snapshot(document, "candidate-planner", result))
            for row in evidence:
                row["observed"] = finished + 1
            evidence[0]["facts"] = {"sha256": sha256(result), "probe_id": group}
            with self.subTest(mode=mode):
                self.assertEqual(evaluate_operation(observed, snapshot, evidence,
                    runtime_identity="a" * 64, observer_identity="c" * 64)["status"], "pass")
                if mode == "exhaustion":
                    limit = observed | {"check_id": "limit.safe_read_retries"}
                    self.assertEqual(evaluate_operation(limit, snapshot, evidence,
                        runtime_identity="a" * 64, observer_identity="c" * 64)["status"], "pass")
                    report = {"run_id": "suite1", "operation_ids": ["worker1", "operation1", "observer1"],
                        "runtime_identities": {"candidate-planner": "a" * 64, "reference-data": "d" * 64,
                            "evidence-assessor": "e" * 64, "release-reviewer": "f" * 64, "briefing-author": "0" * 64},
                        "evidence": evidence}
                    check = {"check_id": "limit.safe_read_retries", "expected": "boundary", "status": "pass",
                        "actual": {"observation": limit, "control": snapshot | {"suite_id": "suite1"}}}
                    self.assertEqual(evaluate_check(sanitize(check), sanitize(report))["status"], "pass")
                snapshot["budget_state"]["remaining_reads"] = 510
                self.assertEqual(evaluate_operation(observed, snapshot, evidence,
                    runtime_identity="a" * 64, observer_identity="c" * 64)["status"], "fail")

    async def test_retry_backoff_uses_actual_elapsed_time_even_when_wall_clock_moves_backwards(self):
        epoch, beginning = time.time(), time.monotonic()

        def clock():
            elapsed = time.monotonic() - beginning
            return epoch + elapsed - (2 if elapsed > .5 else 0)

        ledger = MemoryLedger(clock=clock)
        probe = OperationProbes(ledger, workload="candidate-planner", enabled=True, run_id="worker1", clock=clock)
        started = clock()
        actual = await probe.safe_read_recovery("operation1")
        finished = clock()
        document, _ = await ledger.read()
        observed, snapshot, evidence = await self.fixture()
        group = "fault.safe-read-recovery"
        observed.update(check_id=group, probe_id=group, actual=actual, started=started, finished=finished)
        snapshot.update(sha256=sha256(document), started=finished + 1, finished=finished + 2,
                        **operation_snapshot(document, "candidate-planner", actual))
        for row in evidence:
            row["observed"] = finished + 1
        evidence[0]["facts"] = {"sha256": sha256(actual), "probe_id": group}
        self.assertLess(actual["steps"][1]["started"], actual["steps"][0]["finished"])
        self.assertEqual(evaluate_operation(observed, snapshot, evidence,
            runtime_identity="a" * 64, observer_identity="c" * 64)["status"], "pass")
        missing = actual | {"steps": [
            {key: value for key, value in step.items() if key != "monotonic_started"} for step in actual["steps"]]}
        missing_evidence = [evidence[0] | {"facts": {"sha256": sha256(missing), "probe_id": group}}, *evidence[1:]]
        self.assertEqual(evaluate_operation(observed | {"actual": missing}, snapshot, missing_evidence,
            runtime_identity="a" * 64, observer_identity="c" * 64)["status"], "blocked")
        actual["steps"][1]["monotonic_started"] = actual["steps"][0]["monotonic_finished"] + .5
        evidence[0]["facts"]["sha256"] = sha256(actual)
        self.assertEqual(evaluate_operation(observed, snapshot, evidence,
            runtime_identity="a" * 64, observer_identity="c" * 64)["status"], "fail")

    async def fixture(self):
        ledger = MemoryLedger()
        result = await OperationProbes(ledger, workload="candidate-planner", enabled=True,
                                      run_id="worker1").committed_response_loss("operation1")
        document, _ = await ledger.read()
        now = time.time()
        observation = {"check_id": "fault.dropped-committed-write", "probe_id": "fault.dropped-committed-write",
            "run_id": "worker1", "operation_id": "operation1", "caller": "candidate-planner",
            "runtime_identity": "a" * 64, "started": now - 5, "finished": now,
            "request_id": "published", "status_code": 201, "target": "b" * 64, "actual": result}
        snapshot = {"caller": "operator", "runtime_identity": "c" * 64, "container": "planner-operations",
            "action": "read", "operation_id": "observer1", "request_id": "snapshot", "target": "d" * 64,
            "status_code": 206, "started": now + 1, "finished": now + 2,
            "sha256": sha256(document), **operation_snapshot(document, "candidate-planner", result)}
        evidence = [
            {"source": "application", "request_id": "published", "status_code": 201, "observed": now,
             "method": "execution", "runtime_identity": "a" * 64, "caller": "candidate-planner",
             "run_id": "worker1", "operation_id": "operation1", "target": "b" * 64,
             "facts": {"sha256": sha256(result), "probe_id": "fault.dropped-committed-write"}},
            {"source": "storage", "request_id": "published", "status_code": 201, "observed": now,
             "method": "PutBlob", "runtime_identity": "a" * 64, "client_request_id": "operation1",
             "target": "b" * 64},
            {"source": "storage", "request_id": "snapshot", "status_code": 206, "observed": now + 1,
             "method": "GetBlob", "runtime_identity": "c" * 64, "client_request_id": "observer1",
             "target": "d" * 64},
        ]
        return observation, snapshot, evidence

    async def test_actual_committed_response_loss_needs_state_and_digest_bound_service_receipts(self):
        observed, snapshot, evidence = await self.fixture()

        def evaluate(o=observed, s=snapshot, e=evidence):
            return evaluate_operation(o, s, e, runtime_identity="a" * 64, observer_identity="c" * 64)

        self.assertEqual(evaluate()["status"], "pass")
        for source in ("application", "storage"):
            self.assertEqual(evaluate(e=[row for row in evidence if row["source"] != source])["status"], "blocked")
        altered = copy.deepcopy(observed)
        altered["actual"]["response"] = "unexpected_success"
        self.assertEqual(evaluate(o=altered)["status"], "blocked")
        changed = copy.deepcopy(snapshot)
        changed["operation_state"]["artifact_count"] = 2
        self.assertEqual(evaluate(s=changed)["status"], "fail")
        self.assertEqual(evaluate(e=[row | {"client_request_id": "unrelated"}
            if row["source"] == "storage" else row for row in evidence])["status"], "blocked")
        self.assertEqual(evaluate_operation(observed, snapshot, evidence,
            runtime_identity="c" * 64, observer_identity="c" * 64)["status"], "blocked")
        for change in ({"check_id": []}, {"probe_id": {}}, {"actual": []},
                       {"operation_id": None}, {"run_id": None}):
            with self.subTest(change=change):
                self.assertEqual(evaluate(o=observed | change)["status"], "blocked")
