import copy
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from citadel.operator.state import Blocked, digest, write_private


class QuiescenceTests(unittest.TestCase):
    def fixture(self, directory):
        run = {"state": "indeterminate", "deadline": time.time() - 1000,
               "fixture": "base-source", "scenario": "comparison", "reads": 3}
        lifecycle = SimpleNamespace(id="fixture", config={"deploymentId": "fixture"},
            value={"runs": {"partial": run}}, state=SimpleNamespace(directory=Path(directory)))
        proof = {"schema_version": 1, "state": "verified_quiescent_partial_commit",
                 "deployment_id": lifecycle.id, "configuration": digest(lifecycle.config),
                 "run_id": "partial", "original_run": copy.deepcopy(run),
                 "verified_at": time.time() - 10,
                 "approval": "https://github.com/JoranBergfeld/citadel-example/issues/7#issuecomment-6411703685",
                 "snapshots": [{"sha256": "a" * 64}, {"sha256": "a" * 64}],
                 "admission": {"state": "released_verified", "scope": "operator/invoke/partial"},
                 "partial_effects_retained": True, "replayed": False}
        return lifecycle, proof

    def test_indeterminate_run_requires_bound_private_proof_and_never_becomes_success(self):
        from citadel.operator.quiescence import runs_quiescent
        with tempfile.TemporaryDirectory() as directory:
            lifecycle, proof = self.fixture(directory)
            self.assertFalse(runs_quiescent(lifecycle))
            write_private(Path(directory) / "partial-quiescence.json", proof)
            lifecycle.value["runs"]["partial"]["quiescenceProof"] = digest(proof)
            self.assertTrue(runs_quiescent(lifecycle))
            self.assertEqual(lifecycle.value["runs"]["partial"]["state"], "indeterminate")
            lifecycle.value["runs"]["fresh"] = {"state": "dispatch_intent"}
            self.assertFalse(runs_quiescent(lifecycle))
            self.assertTrue(runs_quiescent(lifecycle, exclude="fresh"))

    def test_rebound_or_mutated_proof_never_unlocks_fresh_dispatch(self):
        from citadel.operator.quiescence import runs_quiescent
        with tempfile.TemporaryDirectory() as directory:
            lifecycle, proof = self.fixture(directory)
            mutations = (
                lambda p: p.update(state="succeeded"),
                lambda p: p.update(deployment_id="other"),
                lambda p: p.update(configuration="0" * 64),
                lambda p: p["original_run"].update(deadline=time.time() + 900),
                lambda p: p.update(verified_at=time.time() + 10),
                lambda p: p.update(verified_at=p["original_run"]["deadline"]),
                lambda p: p.update(partial_effects_retained=False),
                lambda p: p.update(replayed=True),
                lambda p: p["admission"].update(state="intent"),
                lambda p: p["admission"].update(scope="operator/invoke/other"),
                lambda p: p.update(snapshots=[]),
                lambda p: p["snapshots"][1].update(sha256="b" * 64),
            )
            for mutate in mutations:
                with self.subTest(mutation=mutate):
                    changed = copy.deepcopy(proof)
                    mutate(changed)
                    write_private(Path(directory) / "partial-quiescence.json", changed)
                    lifecycle.value["runs"]["partial"]["quiescenceProof"] = digest(changed)
                    with self.assertRaises(Blocked):
                        runs_quiescent(lifecycle)
            write_private(Path(directory) / "partial-quiescence.json", proof)
            lifecycle.value["runs"]["partial"]["quiescenceProof"] = "0" * 64
            with self.assertRaises(Blocked):
                runs_quiescent(lifecycle)

    def test_only_terminal_success_or_definite_no_commit_need_no_partial_commit_proof(self):
        from citadel.operator.quiescence import runs_quiescent
        lifecycle = SimpleNamespace(value={"runs": {"a": {"state": "succeeded"},
                                                   "b": {"state": "failed_no_commit"}}})
        self.assertTrue(runs_quiescent(lifecycle))
        for state in ("pending", "running", "dispatch_intent", "accepted"):
            with self.subTest(state=state):
                lifecycle.value["runs"]["unsafe"] = {"state": state, "quiescenceProof": "a" * 64}
                self.assertFalse(runs_quiescent(lifecycle))

    def test_quiescence_proof_never_retries_the_original_operation_or_resets_its_deadline(self):
        from citadel.operator.scenarios import scenario_command
        with tempfile.TemporaryDirectory() as directory:
            lifecycle, proof = self.fixture(directory)
            write_private(Path(directory) / "partial-quiescence.json", proof)
            run = lifecycle.value["runs"]["partial"]
            run["quiescenceProof"] = digest(proof)
            deadline = run["deadline"]
            lifecycle.value.update(phase="deployed_unverified", outputs={"gatewayUrl": "https://gateway.test"})
            lifecycle.credentials = lambda: {"callerStates": {"operator": "active"},
                                             "callerKeys": {"operator": {"primary": "fixture-only"}}}
            with patch("citadel.operator.scenarios.PlannerClient.invoke", new_callable=AsyncMock) as invoke:
                with self.assertRaises(Blocked) as caught:
                    scenario_command(lifecycle, SimpleNamespace(
                        command="demo", scenario="comparison", run_id="partial"))
            self.assertEqual(caught.exception.code, "run_absolute_deadline_expired")
            invoke.assert_not_called()
            self.assertEqual((run["state"], run["deadline"], run["reads"]),
                             ("indeterminate", deadline, 3))
