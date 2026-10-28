import copy
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from citadel.operator.quiescence import runs_quiescent
from citadel.operator.state import Blocked, digest


class QuiescenceTests(unittest.TestCase):
    def setUp(self):
        run = {"state": "indeterminate", "deadline": 1000,
               "fixture": "base-source", "scenario": "comparison", "reads": 3}
        self.lifecycle = SimpleNamespace(id="fixture", config={"deploymentId": "fixture"},
            value={"runs": {"partial": run}},
            state=SimpleNamespace(directory=Path("unit-fixture-state-not-opened")))
        self.proof = {"schema_version": 1, "state": "verified_quiescent_partial_commit",
            "deployment_id": "fixture", "configuration": digest(self.lifecycle.config),
            "run_id": "partial", "original_run": copy.deepcopy(run), "verified_at": 1100,
            "approval": "unit-fixture-approval-not-cloud-proof",
            "snapshots": [{"sha256": "a" * 64}, {"sha256": "a" * 64}],
            "admission": {"state": "released_verified", "scope": "operator/invoke/partial"},
            "partial_effects_retained": True, "replayed": False}
        self.reader = self.enterContext(patch("citadel.operator.quiescence.read_private", return_value=self.proof))

    def test_indeterminate_run_requires_bound_private_proof_and_never_becomes_success(self):
        lifecycle = self.lifecycle
        self.assertFalse(runs_quiescent(lifecycle, clock=lambda: 1200))
        lifecycle.value["runs"]["partial"]["quiescenceProof"] = digest(self.proof)
        self.assertTrue(runs_quiescent(lifecycle, clock=lambda: 1200))
        self.assertEqual(lifecycle.value["runs"]["partial"]["state"], "indeterminate")
        lifecycle.value["runs"]["fresh"] = {"state": "dispatch_intent"}
        self.assertFalse(runs_quiescent(lifecycle, clock=lambda: 1200))
        self.assertTrue(runs_quiescent(lifecycle, exclude="fresh", clock=lambda: 1200))

    def test_rebound_mutated_or_ambiguous_proof_never_unlocks_fresh_dispatch(self):
        mutations = (
            lambda p: p.update(state="succeeded"),
            lambda p: p.update(deployment_id="other"),
            lambda p: p.update(configuration="0" * 64),
            lambda p: p["original_run"].update(deadline=2000),
            lambda p: p.update(verified_at=1201),
            lambda p: p.update(verified_at=1000),
            lambda p: p.update(partial_effects_retained=False),
            lambda p: p.update(replayed=True),
            lambda p: p["admission"].update(state="intent"),
            lambda p: p["admission"].update(scope="operator/invoke/other"),
            lambda p: p.update(snapshots=[]),
            lambda p: p["snapshots"][1].update(sha256="b" * 64),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                changed = copy.deepcopy(self.proof)
                mutate(changed)
                self.reader.return_value = changed
                self.lifecycle.value["runs"]["partial"]["quiescenceProof"] = digest(changed)
                with self.assertRaises(Blocked):
                    runs_quiescent(self.lifecycle, clock=lambda: 1200)
        self.reader.return_value = self.proof
        self.lifecycle.value["runs"]["partial"]["quiescenceProof"] = "0" * 64
        with self.assertRaises(Blocked):
            runs_quiescent(self.lifecycle, clock=lambda: 1200)

    def test_only_terminal_success_or_definite_no_commit_need_no_partial_commit_proof(self):
        lifecycle = SimpleNamespace(value={"runs": {"a": {"state": "succeeded"},
                                                   "b": {"state": "failed_no_commit"}}})
        self.assertTrue(runs_quiescent(lifecycle, clock=lambda: 1200))
        for state in ("pending", "running", "dispatch_intent", "accepted"):
            with self.subTest(state=state):
                lifecycle.value["runs"]["unsafe"] = {"state": state, "quiescenceProof": "a" * 64}
                self.assertFalse(runs_quiescent(lifecycle, clock=lambda: 1200))

    def test_quiescence_proof_never_retries_original_operation_or_resets_deadline(self):
        from citadel.operator.scenarios import scenario_command
        lifecycle = self.lifecycle
        run = lifecycle.value["runs"]["partial"]
        run["quiescenceProof"] = digest(self.proof)
        lifecycle.value.update(phase="deployed_unverified", outputs={"gatewayUrl": "https://gateway.test"})
        lifecycle.credentials = lambda: {"callerStates": {"operator": "active"},
                                         "callerKeys": {"operator": {"primary": "fixture-only"}}}
        with (patch("citadel.operator.scenarios.time.time", return_value=1200),
              patch("citadel.operator.scenarios.PlannerClient.invoke", new_callable=AsyncMock) as invoke):
            with self.assertRaises(Blocked) as caught:
                scenario_command(lifecycle, SimpleNamespace(
                    command="demo", scenario="comparison", run_id="partial"))
        self.assertEqual(caught.exception.code, "run_absolute_deadline_expired")
        invoke.assert_not_called()
        self.assertEqual((run["state"], run["deadline"], run["reads"]), ("indeterminate", 1000, 3))
