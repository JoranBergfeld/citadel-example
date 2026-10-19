import time
import unittest
from tests.acceptance.storage_fixture import storage_inventory
import copy
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from citadel.operations.testing import MemoryLedger


class AdmissionLimitTests(unittest.IsolatedAsyncioTestCase):
    async def test_actual_budget_admissions_reject_overlap_candidate_twenty_one_and_execution_forty_three(self):
        from citadel.acceptance.admission_limits import AdmissionProbes
        ledger = MemoryLedger(clock=time.time)
        for workload, enabled in (("candidate-planner", False), ("release-reviewer", True)):
            with self.assertRaises(ValueError):
                AdmissionProbes(ledger, workload=workload, enabled=enabled, deadline=time.time() + 120)
        observed = await AdmissionProbes(ledger, workload="candidate-planner", enabled=True,
            deadline=time.time() + 120).nonmodel(operation_id="budget")
        self.assertEqual({row["check_id"]: row["response"] for row in observed["checks"]}, {
            "limit.concurrent_runs": "conflict", "limit.candidates": "exhausted",
            "limit.agent_executions": "exhausted"})
        self.assertTrue(all(row["before_sha256"] == row["after_sha256"] for row in observed["checks"]))
        document, _ = await ledger.read()
        self.assertEqual(set(document["budgets"]), {"budget"})
        budget = document["budgets"]["budget"]
        self.assertEqual(len(budget["candidates"]), 20)
        self.assertEqual(len(budget["agents"]), 42)
        self.assertEqual(sum(budget["agents"].values()), 0)
        self.assertTrue(budget["closed"])
        self.assertEqual(budget["remaining"], {"agents": 0, "models": 128, "tokens": 1000000, "reads": 512})
        self.assertEqual(document["operations"], {})
        self.assertEqual(document["drafts"], {})
        self.assertEqual(document["findings"], {})
        from citadel.acceptance.admission_limits import admission_snapshot, evaluate_admission
        from citadel.evidence.manifests import sha256
        now = time.time()
        observed["slot"] = {"scope_sha256": sha256("acceptance/worker"), "steps": [
            {"operation_id": f"budget-slot{index}", "request_id": f"slot-service{index}",
             "target": "1" * 64, "status_code": status, "action": action,
             "started": now - .9 + index * .1, "finished": now - .85 + index * .1}
            for index, (action, status) in enumerate((("renew", 200), ("acquire", 409), ("renew", 200)))]}
        row = {"check_id": "limit.agent_executions", "probe_id": "limit.agent_executions",
            "operation_id": "budget", "run_id": "worker", "caller": "candidate-planner",
            "runtime_identity": "a" * 64, "actual": observed, "request_id": "publication", "status_code": 201,
            "target": "c" * 64, "started": now - 1, "finished": now}
        snapshot = admission_snapshot(document, observed) | {
            "request_id": "observer", "operation_id": "observer", "status_code": 206, "target": "d" * 64,
            "started": now + 1, "finished": now + 2, "sha256": sha256(document)}
        evidence = [
            {"source": "storage", "method": "PutBlob", "request_id": "publication", "status_code": 201,
             "target": "c" * 64, "runtime_identity": "a" * 64, "client_request_id": "budget", "observed": now},
            {"source": "application", "method": "execution", "request_id": "publication", "status_code": 201,
             "target": "c" * 64, "runtime_identity": "a" * 64, "operation_id": "budget", "run_id": "worker",
             "caller": "candidate-planner", "observed": now,
             "facts": {"sha256": sha256(observed), "probe_id": "limit.agent_executions"}},
            {"source": "storage", "method": "GetBlob", "request_id": "observer", "status_code": 206,
             "target": "d" * 64, "runtime_identity": "b" * 64, "client_request_id": "observer", "observed": now + 1}]
        evidence += [step | {"source": "storage", "method": "LeaseBlob", "runtime_identity": "a" * 64,
                            "client_request_id": step["operation_id"], "observed": step["finished"]}
                     for step in observed["slot"]["steps"]]
        for check in ("limit.concurrent_runs", "limit.candidates", "limit.agent_executions"):
            observation = row | {"check_id": check}
            def evaluate(control=snapshot, records=evidence):
                return evaluate_admission(observation, control, records,
                                          runtime_identity="a" * 64, observer_identity="b" * 64)
            self.assertEqual(evaluate()["status"], "pass")
            self.assertEqual(evaluate(records=evidence[:-1])["status"], "blocked")
            for key, wrong in (("agent_executions", 43), ("candidates", 21), ("model_active", True)):
                changed = copy.deepcopy(snapshot)
                changed["budget_state"][key] = wrong
                self.assertEqual(evaluate(control=changed)["status"], "fail")
            from citadel.acceptance.proof_gate import evaluate_check
            from citadel.acceptance.reports import sanitize
            report = {"run_id": "suite", "operation_ids": ["worker", "budget", "observer",
                "budget-slot0", "budget-slot1", "budget-slot2"], "evidence": evidence,
                "runtime_identities": {"candidate-planner": "a" * 64, "evidence-assessor": "c" * 64,
                    "release-reviewer": "d" * 64, "briefing-author": "e" * 64, "reference-data": "f" * 64}}
            exported = {"check_id": check, "expected": "boundary", "status": "pass", "actual": {
                "observation": observation, "control": snapshot | {
                    "suite_id": "suite", "caller": "operator", "action": "read",
                    "container": "planner-operations", "runtime_identity": "b" * 64}}}
            self.assertEqual(evaluate_check(sanitize(exported), sanitize(report))["status"], "pass")
            self.assertEqual(evaluate_check(sanitize(exported), sanitize(report | {
                "operation_ids": ["worker", "budget"]}))["status"], "blocked")
            self.assertEqual(evaluate_check(sanitize(exported), sanitize(report | {
                "operation_ids": [name for name in report["operation_ids"] if name != "budget-slot1"]
            }))["status"], "blocked")

    async def test_disabled_normal_worker_uses_real_sdk_own_identity_and_existing_control_tickets(self):
        from azure.storage.blob.aio import ContainerClient
        from citadel.acceptance.worker import run_gateway_matrix, validate_request
        from tests.runtime.test_storage import FixtureCredential
        runtime_tests = str(Path(__file__).resolve().parents[1] / "runtime")
        sys.path.insert(0, runtime_tests)
        try:
            from test_ticket_storage import TicketWire
        finally:
            sys.path.remove(runtime_tests)
        class Wire(TicketWire):
            async def send(self, request, **options):
                response = await super().send(request, **options)
                response.headers["x-ms-request-id"] = "wire-" + str(len(self.requests))
                return response
        class Credential(FixtureCredential):
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                pass
        wire, credentials = Wire(clock=time.time), []
        wire.blobs["/planner-operations/active-run-slot.json"] = b"{}"
        wire.etags["/planner-operations/active-run-slot.json"] = 1
        config = SimpleNamespace(target="candidate-planner", client_id="11111111-1111-1111-1111-111111111111",
            blob="https://allocated.blob.core.windows.net", operations_container="planner-operations")
        request = {"schema_version": 1, "mode": "admission-limits", "workload": config.target,
            "client_id": config.client_id, "run_id": "admission-worker", "deadline": time.time() + 120}
        for actor, enabled in (("candidate-planner", False), ("briefing-author", True)):
            with self.assertRaises(ValueError):
                validate_request(request | {"workload": actor}, enabled=enabled,
                                 workload=actor, client_id=config.client_id)
        def credential(**options):
            credentials.append(options)
            return Credential()
        with (patch.dict(os.environ, {"CITADEL_ACCEPTANCE_ENABLED": "true", "AZURE_PRINCIPAL_ID": config.client_id}),
              patch("citadel.acceptance.worker.ManagedIdentityCredential", credential),
              patch("citadel.acceptance.worker.ContainerClient",
                    lambda *args, **kw: ContainerClient(*args, transport=wire, **kw)),
              patch("citadel.acceptance.worker.SecretClient",
                    side_effect=AssertionError("Nonmodel admission needs no subscription secret"))):
            rows = await run_gateway_matrix(config, request)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["check_id"], "limit.agent_executions")
        self.assertEqual(rows[0]["status_code"], 201)
        self.assertEqual([step["status_code"] for step in rows[0]["actual"]["slot"]["steps"]], [200, 409, 200])
        self.assertEqual([step["action"] for step in rows[0]["actual"]["slot"]["steps"]], ["renew", "acquire", "renew"])
        from citadel.acceptance.operation_harness import bind_operation_result
        result = {"schema_version": 1, "run_id": request["run_id"], "state": "complete", "observations": rows}
        self.assertEqual(len(bind_operation_result(result, run_id=request["run_id"], mode="admission-limits",
            principal=rows[0]["runtime_identity"], account=config.blob)), 4)
        self.assertEqual(credentials, [{"client_id": config.client_id}])
        document = json.loads(wire.blobs["/planner-operations/acceptance/admission-worker/ledger-v1.json"])
        self.assertEqual(len(document["budgets"][rows[0]["operation_id"]]["agents"]), 42)
        self.assertTrue(all("/planner-operations/" in request.url for request in wire.requests))
        self.assertNotIn("/planner-operations/ledger-v1.json", wire.blobs)
        self.assertNotIn("/planner-operations/active-run-slot.json", wire.leases)
        self.assertLessEqual(len([path for path in wire.blobs if "/read-tickets/" in path]), 512)
        from citadel.acceptance.admission_limits import global_slot
        async with ContainerClient(config.blob, config.operations_container, credential=Credential(), transport=wire,
                api_version="2026-10-06", retry_total=0, retry_connect=0, retry_read=0, retry_status=0) as container:
            unavailable = await global_slot(container, run_id=request["run_id"],
                operation_id="unowned", deadline=time.time() + 120)
        self.assertEqual(len(unavailable["steps"]), 1)
        self.assertEqual(unavailable["steps"][0]["status_code"], 412)
        self.assertNotIn("/planner-operations/active-run-slot.json", wire.leases)


class AdmissionControllerTests(unittest.TestCase):
    def test_same_image_controller_dispatches_then_independently_observes_admission_state_without_replay(self):
        import asyncio
        import base64
        import hashlib
        from citadel.acceptance.admission_limits import AdmissionProbes
        from citadel.acceptance.operation_harness import FaultAcceptance
        from citadel.evidence.manifests import canonical_bytes
        from citadel.operator.state import Blocked
        from tests.acceptance.test_revision import NativeFixture
        from tests.acceptance.test_storage_controls import BlobProvider
        class Native(NativeFixture, BlobProvider):
            def __init__(self):
                NativeFixture.__init__(self)
                BlobProvider.__init__(self)
            def rest(self, method, resource, version, body=None):
                result = super().rest(method, resource, version, body)
                if method != "patch":
                    return result
                env = self.app["properties"]["template"]["containers"][0]["env"]
                encoded = next((row["value"] for row in env if row["name"] == "CITADEL_ACCEPTANCE_REQUEST"), None)
                if encoded is None:
                    return result
                request = json.loads(base64.b64decode(encoded))
                self_case.assertEqual(request["mode"], "admission-limits")
                async def execute():
                    ledger = MemoryLedger(clock=time.time)
                    actual = await AdmissionProbes(ledger, workload=request["workload"], enabled=True,
                        deadline=request["deadline"]).nonmodel(operation_id="budget")
                    return actual, (await ledger.read())[0]
                actual, document = asyncio.run(execute())
                root = request["run_id"]
                from citadel.evidence.manifests import sha256
                actual["slot"] = {"scope_sha256": sha256("acceptance/" + root), "steps": [
                    {"operation_id": f"budget-slot{index}", "target": hashlib.sha256(
                        b"https://planning.blob.core.windows.net/planner-operations/active-run-slot.json").hexdigest()}
                    for index in range(3)]}
                self.objects["planner-operations", f"acceptance/{root}/ledger-v1.json"] = canonical_bytes(document)
                self.summary = canonical_bytes({"schema_version": 1, "run_id": root, "state": "complete",
                    "observations": [{"check_id": "limit.agent_executions", "probe_id": "limit.agent_executions",
                        "run_id": root, "operation_id": "budget", "caller": "candidate-planner", "actual": actual,
                        "runtime_identity": hashlib.sha256(request["client_id"].encode()).hexdigest(),
                        "target": hashlib.sha256(("https://planning.blob.core.windows.net/planner-operations/"
                                                f"acceptance/{root}/observations/budget.json").encode()).hexdigest()}]})
                return result
            def blob_read(self, *args):
                return self.summary
        self_case, native = self, Native()
        original = copy.deepcopy(native.app)
        app = {"app": "/subscriptions/s/resourceGroups/g/providers/Microsoft.App/containerApps/d-candidate-planner",
            "identityClientId": "11111111-1111-1111-1111-111111111111",
            "identityPrincipalId": "11111111-1111-1111-1111-111111111111",
            "image": "registry.example/image@sha256:" + "a" * 64}
        lifecycle = SimpleNamespace(id="d", native=native, state=SimpleNamespace(save=lambda: None), value={
            "inventory": storage_inventory(planning="planning"),
            "outputs": {"appInventory": [app]}})
        report = {"run_id": "suite", "operation_ids": []}
        FaultAcceptance(lifecycle).execute(report, mode="admission-limits")
        self.assertEqual(report["admission_phase"]["state"], "observed")
        self.assertEqual(report["admission_phase"]["snapshots"]["budget"]["budget_state"]["agent_executions"], 42)
        self.assertIn("budget-slot1", report["operation_ids"])
        self.assertEqual(native.app, original)
        self.assertEqual(len(native.patches), 2)
        with self.assertRaises(Blocked):
            FaultAcceptance(lifecycle).execute(report, mode="admission-limits")
        self.assertEqual(len(native.patches), 2)
