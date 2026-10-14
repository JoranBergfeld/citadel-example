import unittest

from citadel.operations import OperationError
from citadel.operations.limits import Accounting, CEILINGS
from citadel.operations.testing import MemoryLedger


class LimitsTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.now = 1000.0
        self.store = MemoryLedger(clock=lambda: self.now)
        self.planner = Accounting(self.store, workload="candidate-planner", clock=lambda: self.now)

    async def test_one_durable_run_inherits_deadline_and_precharges_delegated_budgets(self):
        root = await self.planner.start_run("run1")
        self.assertEqual(root["deadline"], 1900)
        with self.assertRaises(OperationError):
            await self.planner.start_run("run2")
        grant = await self.planner.delegate("run1", "grant1", "evidence-assessor",
                                            {"agents": 2, "models": 8, "tokens": 144000, "reads": 30})
        state = await self.planner.status("run1")
        self.assertEqual(state["remaining"]["models"], 120)
        self.assertEqual(state["remaining"]["tokens"], 856000)
        child = Accounting(MemoryLedger(clock=lambda: self.now), workload="evidence-assessor",
                           clock=lambda: self.now)
        await child.adopt(grant, authenticated_issuer="candidate-planner")
        self.assertEqual((await child.status("grant1"))["deadline"], 1900)
        with self.assertRaises(OperationError):
            await child.adopt(grant, authenticated_issuer="candidate-planner")
        with self.assertRaises(OperationError):
            await self.planner.start_agent("run1", "planner1")
        await child.start_agent("grant1", "assessor1")
        permit = await child.model("grant1", "assessor1", input_tokens=16000, output_tokens=2000)
        self.assertEqual(permit["deadline"], 1060)
        with self.assertRaises(OperationError):
            await child.model("grant1", "assessor1", input_tokens=16000, output_tokens=2000)
        await child.finish_model("grant1", permit["attempt_id"])
        receipt = await child.close("grant1")
        await self.planner.settle("run1", receipt, authenticated_child="evidence-assessor")
        await self.planner.start_agent("run1", "planner1")
        with self.assertRaises(OperationError):
            await self.planner.model("run1", "planner1", input_tokens=16000, output_tokens=2000)
        self.now = 1006
        await self.planner.model("run1", "planner1", input_tokens=16000, output_tokens=2000)
        self.now = 1900
        with self.assertRaises(OperationError):
            await child.safe_read("grant1")

    async def test_exact_agent_candidate_and_read_boundaries_survive_reconstruction(self):
        await self.planner.start_run("run1")
        for number in range(42):
            await self.planner.start_agent("run1", f"agent{number}")
        for number in range(20):
            await self.planner.candidate("run1", f"airport{number}")
        for number in range(512):
            await self.planner.safe_read("run1")
        restarted = Accounting(self.store, workload="candidate-planner", clock=lambda: self.now)
        for operation in (
            restarted.start_agent("run1", "agent43"),
            restarted.candidate("run1", "airport21"),
            restarted.safe_read("run1"),
        ):
            with self.assertRaises(OperationError) as caught:
                await operation
            self.assertEqual(caught.exception.code, "exhausted")

    async def test_model_run_agent_token_and_actual_quota_limits_intersect(self):
        await self.planner.start_run("run1")
        for attempt in range(128):
            agent = f"agent{attempt // 8}"
            if attempt % 8 == 0:
                await self.planner.start_agent("run1", agent)
            permit = await self.planner.model("run1", agent, input_tokens=1, output_tokens=1)
            await self.planner.finish_model("run1", permit["attempt_id"])
            self.now += 5
            if attempt % 8 == 7:
                with self.assertRaises(OperationError) as caught:
                    await self.planner.model("run1", agent, input_tokens=1, output_tokens=1)
                self.assertEqual(caught.exception.code, "exhausted")
        await self.planner.start_agent("run1", "agent17")
        with self.assertRaises(OperationError):
            await self.planner.model("run1", "agent17", input_tokens=1, output_tokens=1)
        await self.planner.close("run1")
        await self.planner.start_run("run2")
        for attempt in range(55):
            agent = f"agent{attempt // 8}"
            if attempt % 8 == 0:
                await self.planner.start_agent("run2", agent)
            permit = await self.planner.model("run2", agent, input_tokens=16000, output_tokens=2000)
            await self.planner.finish_model("run2", permit["attempt_id"])
            self.now += 10
        self.assertEqual((await self.planner.status("run2"))["remaining"]["tokens"], 10000)
        with self.assertRaises(OperationError) as caught:
            await self.planner.model("run2", "agent6", input_tokens=16000, output_tokens=2000)
        self.assertEqual(caught.exception.code, "exhausted")

    async def test_prepaid_read_envelope_counts_ambiguous_attempts_and_burns_on_crash(self):
        await self.planner.start_run("run1")
        pool = await self.planner.reserve_reads("run1", 3)
        self.assertEqual((await self.planner.status("run1"))["remaining"]["reads"], 509)
        pool.take()
        pool.take()
        pool.take()
        with self.assertRaises(OperationError):
            pool.take()
        second = await self.planner.reserve_reads("run1", 509)
        second.take()
        restarted = Accounting(self.store, workload="candidate-planner", clock=lambda: self.now)
        with self.assertRaises(OperationError):
            await restarted.reserve_reads("run1", 1)

    async def test_admission_latency_never_restarts_read_timeout_or_model_rate_window(self):
        await self.planner.start_run("run1")
        await self.planner.start_agent("run1", "agent1")

        async def slow_commit():
            self.now += 5

        self.store.before_commit = slow_commit
        read = await self.planner.safe_read("run1")
        self.assertEqual(read["deadline"], 1030)
        self.store.before_commit = None
        model = await self.planner.model("run1", "agent1", input_tokens=16000, output_tokens=2000)
        self.now += 50
        await self.planner.finish_model("run1", model["attempt_id"])
        with self.assertRaises(OperationError) as caught:
            await self.planner.model("run1", "agent1", input_tokens=16000, output_tokens=2000)
        self.assertEqual(caught.exception.code, "rate_limited")

    async def test_actual_quota_invalid_limits_and_ambiguous_model_admission_fail_closed(self):
        await self.planner.start_run("run1")
        await self.planner.start_agent("run1", "agent1")
        for inputs, outputs in ((16001, 1), (1, 2001), (True, 1), (1, 0)):
            with self.assertRaises(OperationError):
                await self.planner.model("run1", "agent1", input_tokens=inputs, output_tokens=outputs)
        limited = Accounting(self.store, workload="candidate-planner", clock=lambda: self.now,
                             tokens_per_minute=100)
        # Configured quota is bound at run creation, not silently changed on reconstruction.
        await self.planner.close("run1")
        await limited.start_run("run2")
        await limited.start_agent("run2", "agent1")
        with self.assertRaises(OperationError) as caught:
            await limited.model("run2", "agent1", input_tokens=100, output_tokens=1)
        self.assertEqual(caught.exception.code, "rate_limited")
        self.store.lose_response = True
        with self.assertRaises(OperationError) as caught:
            await limited.model("run2", "agent1", input_tokens=10, output_tokens=1)
        self.assertEqual(caught.exception.code, "indeterminate")
        restarted = Accounting(self.store, workload="candidate-planner", clock=lambda: self.now)
        self.assertEqual((await restarted.status("run2"))["remaining"]["models"], 127)
        with self.assertRaises(OperationError):
            await restarted.model("run2", "agent1", input_tokens=1, output_tokens=1)

    async def test_safe_read_exhausts_two_retries_and_never_retries_ambiguous_writes(self):
        await self.planner.start_run("run1")
        attempts = 0

        async def unavailable():
            nonlocal attempts
            attempts += 1
            raise OperationError("unavailable", "Safe read unavailable")

        with self.assertRaises(OperationError):
            await self.planner.read_with_retry("run1", unavailable)
        self.assertEqual(attempts, 3)
        self.assertEqual((await self.planner.status("run1"))["remaining"]["reads"], 509)

        async def ambiguous():
            raise OperationError("indeterminate", "Not a safe read")

        with self.assertRaises(OperationError) as caught:
            await self.planner.read_with_retry("run1", ambiguous)
        self.assertEqual(caught.exception.code, "indeterminate")
        self.assertEqual((await self.planner.status("run1"))["remaining"]["reads"], 508)
