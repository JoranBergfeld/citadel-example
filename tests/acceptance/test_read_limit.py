import json
import base64
import copy
import hashlib
import os
import sys
import time
import unittest
from tests.acceptance.storage_fixture import storage_inventory
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


class ReadLimitTests(unittest.IsolatedAsyncioTestCase):
    async def test_actual_worker_spends_512_tickets_on_512_reads_then_refuses_dispatch_without_refill(self):
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
                response.headers["x-ms-request-id"] = "read-wire-" + str(len(self.requests))
                return response

        class Credential(FixtureCredential):
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

        wire = Wire(clock=time.time)
        wire.blobs["/planner-operations/active-run-slot.json"] = b"{}"
        wire.etags["/planner-operations/active-run-slot.json"] = 1
        config = SimpleNamespace(target="candidate-planner", client_id="11111111-1111-1111-1111-111111111111",
            blob="https://allocated.blob.core.windows.net", operations_container="planner-operations")
        request = {"schema_version": 1, "mode": "read-limit", "workload": config.target,
            "client_id": config.client_id, "run_id": "read-worker", "deadline": time.time() + 120}
        for actor, enabled in (("candidate-planner", False), ("briefing-author", True)):
            with self.assertRaises(ValueError):
                validate_request(request | {"workload": actor}, enabled=enabled,
                                 workload=actor, client_id=config.client_id)
        with (patch.dict(os.environ, {"CITADEL_ACCEPTANCE_ENABLED": "true", "AZURE_PRINCIPAL_ID": config.client_id}),
              patch("citadel.acceptance.worker.ManagedIdentityCredential", lambda **kw: Credential()),
              patch("citadel.acceptance.worker.ContainerClient",
                    lambda *args, **kw: ContainerClient(*args, transport=wire, **kw)),
              patch("citadel.acceptance.worker.SecretClient",
                    side_effect=AssertionError("Read boundary needs no allocated subscription"))):
            rows = await run_gateway_matrix(config, request)
        self.assertEqual(len(rows), 1)
        row, = rows
        self.assertEqual(row["check_id"], "limit.read_attempts_run")
        self.assertEqual(row["actual"]["response"], "exhausted")
        self.assertEqual(row["actual"]["read_attempts"], 512)
        self.assertEqual(len(row["actual"]["steps"]), 512)
        self.assertTrue(all(step["status_code"] == 206 for step in row["actual"]["steps"]))
        ledger_path = "/planner-operations/acceptance/read-worker/ledger-v1.json"
        reads = [request for request in wire.requests if request.method == "GET" and ledger_path in request.url]
        self.assertEqual(len(reads), 512)
        self.assertEqual(len({request.headers["x-ms-client-request-id"] for request in reads}), 512)
        self.assertEqual(len([path for path in wire.blobs if "/read-tickets/" in path]), 512)
        self.assertEqual(json.loads(wire.blobs[ledger_path])["operations"], {})
        self.assertNotIn("/planner-operations/ledger-v1.json", wire.blobs)
        self.assertNotIn("/planner-operations/active-run-slot.json", wire.leases)
        from citadel.acceptance.read_limit import evaluate_read_boundary, read_snapshot
        from citadel.evidence.manifests import sha256
        document = json.loads(wire.blobs[ledger_path])
        snapshot = read_snapshot(document) | {
            "status_code": 206, "request_id": "observer-read", "operation_id": "observer-read",
            "target": row["actual"]["steps"][0]["target"], "sha256": sha256(document),
            "started": time.time(), "finished": time.time()}
        evidence = [
            {"source": "storage", "method": "PutBlob", "request_id": row["request_id"], "status_code": 201,
             "target": row["target"], "runtime_identity": row["runtime_identity"],
             "client_request_id": row["operation_id"], "observed": row["finished"]},
            {"source": "application", "method": "execution", "request_id": row["request_id"], "status_code": 201,
             "target": row["target"], "runtime_identity": row["runtime_identity"], "caller": row["caller"],
             "operation_id": row["operation_id"], "run_id": row["run_id"], "observed": row["finished"],
             "facts": {"sha256": sha256(row["actual"]), "probe_id": "limit.read_attempts_run"}},
            {"source": "storage", "method": "GetBlob", "request_id": "observer-read", "status_code": 206,
             "target": snapshot["target"], "runtime_identity": "b" * 64,
             "client_request_id": "observer-read", "observed": snapshot["finished"]},
        ]
        evidence += [step | {"source": "storage", "method": "GetBlob",
            "runtime_identity": row["runtime_identity"], "observed": step["finished"],
            "client_request_id": step["operation_id"]} for step in row["actual"]["steps"]]

        def evaluate(observation=row, control=snapshot, records=evidence):
            return evaluate_read_boundary(observation, control, records,
                runtime_identity=row["runtime_identity"], observer_identity="b" * 64)

        self.assertEqual(evaluate()["status"], "pass")
        self.assertEqual(evaluate(records=evidence[:-1])["status"], "blocked")
        self.assertEqual(evaluate(records=evidence[1:])["status"], "blocked")
        self.assertEqual(evaluate(control=snapshot | {"artifact_count": 1})["status"], "fail")
        self.assertEqual(evaluate(observation=row | {
            "actual": row["actual"] | {"response": "unexpected_success"}})["status"], "blocked")
        extra = evidence[-1] | {"request_id": "unexpected-read", "client_request_id": "unexpected-read"}
        self.assertEqual(evaluate(records=evidence + [extra])["status"], "fail")
        forged = evidence[:-1] + [evidence[-1] | {"runtime_identity": "b" * 64}]
        self.assertEqual(evaluate(records=forged)["status"], "blocked")
        from citadel.acceptance.operation_harness import bind_operation_result
        from citadel.acceptance.proof_gate import evaluate_check
        from citadel.acceptance.reports import sanitize
        bound = {"schema_version": 1, "run_id": request["run_id"], "state": "complete", "observations": rows}
        operations = bind_operation_result(bound, run_id=request["run_id"], mode="read-limit",
            principal=row["runtime_identity"], account=config.blob)
        self.assertEqual(len(operations), 513)
        report = {"run_id": "suite", "operation_ids": [request["run_id"], "observer-read", *operations],
            "runtime_identities": {"candidate-planner": row["runtime_identity"], "evidence-assessor": "c" * 64,
                "release-reviewer": "d" * 64, "briefing-author": "e" * 64, "reference-data": "f" * 64},
            "evidence": evidence}
        exported = {"check_id": "limit.read_attempts_run", "expected": "boundary", "status": "pass", "actual": {
            "observation": row, "control": snapshot | {"suite_id": "suite", "caller": "operator",
                "action": "read", "container": "planner-operations", "runtime_identity": "b" * 64}}}
        self.assertEqual(evaluate_check(sanitize(exported), sanitize(report))["status"], "pass")
        self.assertEqual(evaluate_check(sanitize(exported), sanitize(report | {
            "operation_ids": report["operation_ids"][:-1]}))["status"], "blocked")


class ReadControllerTests(unittest.TestCase):
    def test_same_image_driver_binds_every_read_and_observes_unchanged_ledger_without_replay(self):
        from citadel.acceptance.operation_harness import FaultAcceptance
        from citadel.evidence.manifests import canonical_bytes
        from citadel.operations import empty_ledger
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
                assert request["mode"] == "read-limit"
                root = request["run_id"]
                prefix = f"https://planning.blob.core.windows.net/planner-operations/acceptance/{root}/"
                actual = {"operation_id": "reads", "steps": [
                    {"operation_id": f"reads-read{index:03}",
                     "target": hashlib.sha256((prefix + "ledger-v1.json").encode()).hexdigest()}
                    for index in range(512)]}
                self.objects["planner-operations", f"acceptance/{root}/ledger-v1.json"] = canonical_bytes(empty_ledger())
                self.summary = canonical_bytes({"schema_version": 1, "run_id": root, "state": "complete",
                    "observations": [{"check_id": "limit.read_attempts_run", "probe_id": "limit.read_attempts_run",
                        "run_id": root, "operation_id": "reads", "caller": "candidate-planner", "actual": actual,
                        "runtime_identity": hashlib.sha256(request["client_id"].encode()).hexdigest(),
                        "target": hashlib.sha256((prefix + "observations/reads.json").encode()).hexdigest()}]})
                return result

            def blob_read(self, *args):
                return self.summary

        native = Native()
        original = copy.deepcopy(native.app["properties"]["template"])
        app = {"app": "/subscriptions/s/resourceGroups/g/providers/Microsoft.App/containerApps/d-candidate-planner",
            "identityClientId": "11111111-1111-1111-1111-111111111111",
            "identityPrincipalId": "11111111-1111-1111-1111-111111111111",
            "image": "registry.example/image@sha256:" + "a" * 64}
        lifecycle = SimpleNamespace(id="d", native=native, state=SimpleNamespace(save=lambda: None), value={
            "inventory": storage_inventory(planning="planning"),
            "outputs": {"appInventory": [app]}})
        report = {"run_id": "suite", "operation_ids": [], "operation_phase": {"state": "observed"}}
        FaultAcceptance(lifecycle).execute(report, mode="read-limit")
        self.assertEqual(report["read_phase"]["state"], "observed")
        self.assertEqual(report["read_phase"]["snapshots"]["reads"]["artifact_count"], 0)
        self.assertIn("reads-read511", report["operation_ids"])
        self.assertEqual(native.app["properties"]["template"], original)
        self.assertEqual(len(native.patches), 2)
        self.assertEqual(FaultAcceptance.evaluate(report, [], mode="read-limit")[0]["status"], "blocked")
        with self.assertRaises(Blocked):
            FaultAcceptance(lifecycle).execute(report, mode="read-limit")
        self.assertEqual(len(native.patches), 2)
