import copy
import unittest
from tests.acceptance.storage_fixture import storage_inventory
from contextlib import nullcontext
from types import SimpleNamespace

from citadel.acceptance.bypass import BypassControls, bypass_status
from citadel.acceptance.reports import automated_status
from citadel.operator.state import Blocked
from tests.acceptance.test_proof_gate import storage_proof


def proof():
    check, report = storage_proof()
    checks, evidence, operations = [], [], []
    for actor in ("candidate-planner", "briefing-author"):
        for container, action, controller in (("drafts", "read", "evidence-assessor"),
                                               ("findings", "write", "release-reviewer")):
            item, source = copy.deepcopy(check), copy.deepcopy(report)
            prefix = actor + "-" + container + "-"
            check_id = f"storage.{actor}.{container}.{action}"
            item["check_id"] = check_id
            records = [*item["actual"].values(), *source["evidence"]]
            for row in records:
                row["container"] = container
                for key in ("request_id", "operation_id", "client_request_id", "run_id"):
                    if key in row:
                        row[key] = prefix + row[key]
                if row.get("caller"):
                    row["action"] = action
                    if row["caller"] == "candidate-planner":
                        row.update(caller=actor, check_id=check_id,
                                   runtime_identity=source["runtime_identities"][actor])
                    else:
                        row.update(caller=controller, runtime_identity=source["runtime_identities"][controller])
                        row["status_code"] = 201 if action == "write" else 206
                    if "method" in row:
                        row["method"] = ("storage." + action if row["source"] == "application"
                                         else "PutBlob" if action == "write" else "GetBlob")
            checks.append(item)
            evidence.extend(source["evidence"])
            operations.extend(prefix + operation for operation in source["operation_ids"])
    return report | {"checks": checks, "evidence": evidence, "operation_ids": operations}


class BypassTests(unittest.TestCase):
    def test_unfinished_and_completed_collection_windows_share_one_600_second_allowance(self):
        from citadel.acceptance.collection import collection_remaining
        report = {"collection_windows": {"short": {"started": 100, "finished": 115},
                                          "pending": {"started": 200, "finished": None}}}
        self.assertEqual(collection_remaining(report, 210), 575)
        self.assertEqual(collection_remaining(report, 785), 0)
        self.assertEqual(collection_remaining(report, 900), 0)
        for bad in ({"started": True, "finished": 2},
                    {"started": 300, "finished": None},
                    {"started": 100, "finished": float("nan")}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                collection_remaining({"collection_windows": {"bad": bad}}, 200)

    def test_real_query_resume_waits_for_correlation_and_shares_full_suite_collection_budget(self):
        from citadel.acceptance.collection import ROW_FIELDS
        report = proof() | {"state": "observed", "fingerprint": "a" * 64,
            "started": 98, "finished": 104, "acceptance": "blocked"}
        records = report.pop("evidence")
        report["evidence"] = []
        now, queries = [1000.0], []
        columns = sorted(ROW_FIELDS)

        def az(*arguments, **options):
            queries.append(arguments)
            rows = [] if len(queries) == 1 else [[row.get(key) for key in columns] for row in records]
            return {"tables": [{"columns": [{"name": key} for key in columns], "rows": rows}]}

        parent = {"run_id": "full1", "operation_ids": ["suite1"]}
        lifecycle = SimpleNamespace(value={"acceptance_controls": {"suite1": report},
            "acceptance_attempts": {"full1": parent}, "inventory": [
                "/subscriptions/s/resourceGroups/g/providers/Microsoft.OperationalInsights/workspaces/logs"]},
            state=SimpleNamespace(save=lambda: None), native=SimpleNamespace(
                rest=lambda *args: {"properties": {"customerId": "11111111-1111-1111-1111-111111111111"}},
                document=lambda payload: nullcontext("<private-fixture>"), az=az))
        driver = BypassControls(lifecycle, export=lambda value: {"status": value["acceptance"]},
            clock=lambda: now[0], sleep=lambda seconds: now.__setitem__(0, now[0] + seconds))
        self.assertEqual(driver.run("suite1", fingerprints={"fingerprint": "a" * 64})["status"], "pass")
        self.assertEqual(len(queries), 2)
        self.assertEqual(parent["collection_windows"]["suite1"], {"started": 1000.0, "finished": 1015.0})
        self.assertEqual(report["collection_deadline"], 1600.0)
        self.assertNotEqual(automated_status(report), "pass")

    def test_failed_real_provider_dispatch_is_persisted_and_never_replayed_on_resume(self):
        calls, exports, saves = [], [], []

        def blob(*arguments):
            calls.append(arguments)
            raise Blocked("external_storage_fixture_unavailable")

        lifecycle = SimpleNamespace(value={"inventory": storage_inventory(),
            "runs": {}, "outputs": {"appInventory": []}},
            native=SimpleNamespace(blob=blob), state=SimpleNamespace(save=lambda: saves.append(True)))

        def export(report):
            exports.append(copy.deepcopy(report))
            return {"status": report["acceptance"], "run_id": report["run_id"]}

        driver = BypassControls(lifecycle, export=export)
        fingerprints = {"fingerprint": "a" * 64}
        self.assertEqual(driver.run("suite1", fingerprints=fingerprints)["status"], "blocked")
        self.assertEqual(len(calls), 1)
        self.assertTrue(saves)
        self.assertEqual(driver.run("suite1", fingerprints=fingerprints)["status"], "blocked")
        self.assertEqual(len(calls), 1)
        self.assertEqual(exports[-1]["storage_phase"]["state"], "blocked")
        with self.assertRaises(Blocked):
            driver.run("suite1", fingerprints={"fingerprint": "b" * 64})

    def test_all_four_actual_authority_denials_require_controls_no_effects_and_ingestion(self):
        report = proof()
        self.assertEqual(bypass_status(report), "pass")
        self.assertEqual(automated_status(report), "blocked")
        self.assertEqual(bypass_status(report | {"checks": report["checks"][:-1]}), "blocked")
        self.assertEqual(bypass_status(report | {"evidence": []}), "blocked")
        self.assertEqual(bypass_status(report | {"checks": report["checks"] * 2}), "blocked")
        altered = copy.deepcopy(report)
        altered["checks"][0]["actual"]["after"]["sha256"] = "0" * 64
        self.assertEqual(bypass_status(altered), "fail")
        altered = copy.deepcopy(report)
        altered["checks"][0]["actual"]["control"] = {}
        self.assertEqual(bypass_status(altered), "blocked")
