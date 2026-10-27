import hashlib
import unittest

from citadel.acceptance.coverage import CONTAINERS
from citadel.acceptance.storage_harness import bind_storage_result
from citadel.acceptance.storage_probes import storage_target
from citadel.operator.state import Blocked


class StorageBindingTests(unittest.TestCase):
    def result(self):
        return {"schema_version": 1, "run_id": "probe1", "state": "complete", "observations": [
            {"check_id": f"storage.candidate-planner.{container}.{action}", "caller": "candidate-planner",
             "container": container, "action": action, "run_id": "probe1", "suite_id": "suite1",
             "operation_id": f"op-{number}-{action}", "runtime_identity": "a" * 64,
             "target": hashlib.sha256(
                 f"https://allocated.blob.core.windows.net/{container}/{storage_target('suite1')}".encode()).hexdigest()}
            for number, container in enumerate(CONTAINERS) for action in ("read", "write")]}

    def bind(self, result):
        return bind_storage_result(result, actor="candidate-planner", run_id="probe1", suite_id="suite1",
                                   principal="a" * 64, account="https://allocated.blob.core.windows.net")

    def test_all_results_bind_the_actual_dispatched_workload_and_disposable_target(self):
        self.assertEqual(len(self.bind(self.result())), 18)
        for change in ({"caller": "operator"}, {"runtime_identity": "b" * 64},
                       {"run_id": "another"}, {"suite_id": "another"},
                       {"target": "c" * 64}, {"operation_id": "../private"}):
            result = self.result()
            result["observations"][0].update(change)
            with self.subTest(change=change), self.assertRaises((Blocked, RuntimeError)):
                self.bind(result)

    def test_partial_or_duplicate_observations_do_not_masquerade_as_complete(self):
        for change in ({"observations": self.result()["observations"][:-1]},
                       {"observations": self.result()["observations"] * 2},
                       {"schema_version": True}, {"state": "pass"}):
            with self.subTest(change=list(change)), self.assertRaises(Blocked):
                self.bind(self.result() | change)
        result = self.result() | {"state": "blocked", "observations": self.result()["observations"][:1]}
        self.assertEqual(len(self.bind(result)), 1)
