import unittest
import time
import io
import json
from unittest.mock import patch

from citadel.acceptance.faults import OperationProbes
from citadel.operations.testing import MemoryLedger
from citadel.operations import OperationError
from citadel.operations.limits import Accounting
from citadel.acceptance.telemetry import Telemetry


class FaultTests(unittest.IsolatedAsyncioTestCase):
    async def test_actual_safe_read_timeouts_exhaust_only_three_charged_reads_without_business_effects(self):
        probe = OperationProbes(MemoryLedger(), workload="candidate-planner",
            enabled=True, run_id="timeouts", deadline=time.time() + 300)
        output = io.StringIO()
        telemetry = Telemetry("candidate-planner", "11111111-1111-1111-1111-111111111111", output=output)
        with patch("citadel.acceptance.telemetry._exporter", telemetry):
            result = await probe.safe_read_timeout(operation_id="thirty-seconds")
        self.assertEqual(result["state"], "unavailable")
        self.assertEqual(result["read_attempts"], 3)
        self.assertEqual(result["retry"], 2)
        self.assertEqual(result["remaining_reads"], 509)
        self.assertEqual(result["before_sha256"], result["after_sha256"])
        self.assertEqual([step["state"] for step in result["steps"]], ["timed_out"] * 3)
        timers = [row["facts"] for row in map(json.loads, output.getvalue().splitlines())
                  if row["method"] == "safe_read.timeout"]
        self.assertEqual(len(timers), 3)
        for step, timer in zip(result["steps"], timers, strict=True):
            self.assertEqual(step["deadline"] - step["accepted"], 30)
            self.assertLess(step["received"], step["deadline"])
            self.assertLessEqual(timer["monotonic_started"], step["monotonic_started"])
            self.assertGreaterEqual(step["monotonic_finished"], timer["monotonic_deadline"])
            self.assertGreaterEqual(timer["monotonic_finished"], step["monotonic_finished"])
            self.assertAlmostEqual(timer["monotonic_deadline"] - timer["monotonic_started"],
                                   timer["deadline"] - timer["started"], places=6)

    async def test_fault_waits_observe_wall_deadlines_when_sleep_clock_advances_faster(self):
        for method in ("fenced_retry", "deadline_no_late_effect"):
            with self.subTest(method=method):
                now, sleeps = [1000.0], []

                async def sleep(seconds):
                    sleeps.append(seconds)
                    now[0] += seconds / 2

                probe = OperationProbes(MemoryLedger(clock=lambda: now[0]),
                    workload="candidate-planner", enabled=True, run_id="clock-skew",
                    clock=lambda: now[0], sleep=sleep)
                result = await getattr(probe, method)(operation_id="clock-control")
                self.assertGreater(len(sleeps), 1)
                if method == "fenced_retry":
                    self.assertEqual(result["state"], "succeeded")
                    self.assertEqual(result["stale"], "fenced")
                    self.assertEqual(result["artifact_count"], 1)
                else:
                    self.assertEqual(result["response"], "fenced")
                    self.assertGreater(result["observed"], result["deadline"])
                    self.assertEqual(result["artifact_count"], 0)

    async def test_stalled_probe_clock_has_finite_waits_and_never_replays_owner(self):
        sleeps = []

        async def sleep(seconds):
            sleeps.append(seconds)

        probe = OperationProbes(MemoryLedger(clock=lambda: 1000),
            workload="candidate-planner", enabled=True, run_id="clock-stalled",
            clock=lambda: 1000, sleep=sleep)
        with self.assertRaises(OperationError) as caught:
            await probe.fenced_retry(operation_id="clock-control")
        self.assertEqual(caught.exception.code, "deadline")
        self.assertEqual(len(sleeps), 900)
        status = await probe.ops.status("candidate-planner", "acceptance", "clock-control")
        self.assertEqual(status["state"], "running")
        self.assertEqual(status["generation"], 1)

    async def test_expired_real_ownership_cannot_commit_a_late_product(self):
        now = [1000.0]

        async def sleep(seconds):
            now[0] += seconds

        probe = OperationProbes(MemoryLedger(clock=lambda: now[0]), workload="candidate-planner",
            enabled=True, run_id="late1", clock=lambda: now[0], sleep=sleep)
        result = await probe.deadline_no_late_effect(operation_id="expired")
        self.assertEqual(result["response"], "fenced")
        self.assertEqual(result["state"], "running")
        self.assertGreater(result["observed"], result["deadline"])
        self.assertEqual(result["before_sha256"], result["after_sha256"])
        self.assertEqual(result["artifact_count"], 0)

    async def test_probe_root_deadline_can_only_tighten_the_existing_900_second_bound(self):
        for deadline, expected in ((1100, 1100), (5000, 1900), (None, 1900)):
            accounting = Accounting(MemoryLedger(clock=lambda: 1000), workload="candidate-planner", clock=lambda: 1000)
            result = await accounting.start_run("bounded", deadline=deadline)
            self.assertEqual(result["deadline"], expected)
        for deadline in (True, 1000, float("nan")):
            accounting = Accounting(MemoryLedger(clock=lambda: 1000), workload="candidate-planner", clock=lambda: 1000)
            with self.subTest(deadline=deadline), self.assertRaises(OperationError):
                await accounting.start_run("bounded", deadline=deadline)

    async def test_safe_reads_retry_only_dropped_real_reads_and_never_change_business_state(self):
        probe = OperationProbes(MemoryLedger(), workload="candidate-planner",
                                enabled=True, run_id="reads1", deadline=time.time() + 120)
        recovered = await probe.safe_read_recovery(operation_id="recovered")
        exhausted = await probe.safe_read_exhaustion(operation_id="exhausted")
        self.assertEqual(recovered["state"], "recovered")
        self.assertEqual(exhausted["state"], "unavailable")
        for result in (recovered, exhausted):
            self.assertEqual(result["read_attempts"], 3)
            self.assertEqual(result["retry"], 2)
            self.assertEqual(result["before_sha256"], result["after_sha256"])
            self.assertEqual(result["deadline"], probe.deadline)
            self.assertEqual(result["remaining_reads"], 509)
        self.assertEqual([step["state"] for step in recovered["steps"]], ["dropped", "dropped", "received"])
        self.assertEqual([step["state"] for step in exhausted["steps"]], ["dropped"] * 3)

    async def test_committed_response_loss_reconciles_without_duplicate_product(self):
        probe = OperationProbes(MemoryLedger(), workload="candidate-planner",
                                enabled=True, run_id="loss1")
        result = await probe.committed_response_loss()
        self.assertEqual(result["state"], "succeeded")
        self.assertEqual(result["artifact_count"], 1)
        self.assertEqual(result["response"], "indeterminate")

    async def test_changed_input_and_incomplete_status_never_allow_replay_or_completed_product(self):
        probe = OperationProbes(MemoryLedger(), workload="candidate-planner",
                                enabled=True, run_id="status1")
        result = await probe.identity_and_incomplete_status()
        self.assertEqual(result["changed_input"], "conflict")
        self.assertEqual(result["states"], ["pending", "running", "indeterminate", "missing"])
        self.assertEqual(result["completed"], False)

    async def test_fault_facility_disabled_in_normal_mode(self):
        with self.assertRaises(ValueError):
            OperationProbes(MemoryLedger(), workload="candidate-planner",
                            enabled=False, run_id="disabled")
