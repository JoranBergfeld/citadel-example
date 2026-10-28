import copy
import hashlib
import io
import json
import os
import time
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from citadel.acceptance.operation_harness import bind_operation_result
from citadel.acceptance.worker import validate_request
from citadel.operator.state import Blocked
from citadel.acceptance.proof_gate import evaluate_check
from citadel.acceptance.reports import sanitize
from citadel.evidence.manifests import sha256


def evidence_fixture():
    operation, run = "restart-operation", "restart-control"
    identities = {"candidate-planner": "a" * 64, "reference-data": "b" * 64,
                  "evidence-assessor": "c" * 64, "release-reviewer": "d" * 64, "briefing-author": "e" * 64}
    common = {"caller": "candidate-planner", "runtime_identity": identities["candidate-planner"],
        "run_id": run, "check_id": "fault.restart-no-replay", "probe_id": "fault.restart-no-replay",
        "status_code": 201}
    processes = []
    for index, suffix in enumerate(("-crashed", "-restarted")):
        child = operation + suffix
        actual = {"operation_id": child, "process_id": 1000 + index, "boot_id": str(index + 1) * 32,
            "state": "running", "artifact_count": 0, "before_sha256": "3" * 64, "after_sha256": "3" * 64,
            "deadline": 900, "monotonic_started": 10, "monotonic_finished": 70}
        if index:
            actual.update(replay="conflict", retried="conflict", response="conflict")
        processes.append(common | {"operation_id": child, "target": str(index + 4) * 64,
            "request_id": child, "started": 101 + index * 2, "finished": 102 + index * 63,
            "exit_code": 73 if index == 0 else 0, "actual": actual})
    actual = {"operation_id": operation, "state": "running", "artifact_count": 0,
              "before_sha256": "3" * 64, "after_sha256": "3" * 64, "processes": processes}
    observation = common | {"operation_id": operation, "target": "6" * 64,
        "request_id": operation, "started": 100, "finished": 166, "actual": actual}
    control = {"suite_id": "suite", "caller": "operator", "container": "planner-operations", "action": "read",
        "runtime_identity": "f" * 64, "operation_id": "observer", "target": "7" * 64,
        "request_id": "independent-read", "status_code": 206, "sha256": "3" * 64,
        "ledger_sha256": "3" * 64, "started": 167, "finished": 168,
        "operation_state": {"state": "running", "generation": 1, "deadline": 900,
                            "artifact_count": 0, "product_sha256": None,
                            "input_hash": sha256({"inputs": {"kind": "fixed-process-restart"},
                                "run_id": operation, "deadline": 900})},
        "budget_state": {"run_id": operation, "deadline": 900, "closed": False, "agent_executions": 1,
            "model_active": False, "child_active": False,
            "remaining": {"agents": 41, "models": 128, "tokens": 1000000, "reads": 512}}}
    records = []
    for row in [observation, *processes]:
        records.append(row | {"source": "storage", "method": "PutBlob",
            "client_request_id": row["operation_id"], "observed": row["finished"]})
        records.append(row | {"source": "application", "method": "execution",
            "observed": row["finished"], "facts": {"sha256": sha256(row["actual"]),
                                                  "probe_id": "fault.restart-no-replay"}})
    records.append(control | {"source": "storage", "method": "GetBlob",
                               "client_request_id": "observer", "observed": 168})
    report = {"run_id": "suite", "operation_ids": [run, operation, "observer",
        *[row["operation_id"] for row in processes]], "runtime_identities": identities, "evidence": records}
    check = {"check_id": "fault.restart-no-replay", "expected": "fault",
             "actual": {"observation": observation, "control": control}}
    return check, report


class ProcessRestartContractTests(unittest.TestCase):
    def test_export_requires_two_service_backed_process_receipts_and_original_accounting(self):
        check, report = evidence_fixture()
        self.assertEqual(evaluate_check(sanitize(check), sanitize(report))["status"], "pass")
        for mutation in ("missing", "same-process", "same-boot", "changed", "short", "replenished", "input-conflict"):
            changed, proof = copy.deepcopy(check), copy.deepcopy(report)
            actual = changed["actual"]["observation"]["actual"]
            processes = actual["processes"]
            if mutation == "missing":
                proof["evidence"] = [row for row in proof["evidence"]
                    if row["request_id"] != "restart-operation-crashed"]
            elif mutation == "same-process":
                processes[1]["actual"]["process_id"] = processes[0]["actual"]["process_id"]
            elif mutation == "same-boot":
                processes[1]["actual"]["boot_id"] = processes[0]["actual"]["boot_id"]
            elif mutation == "changed":
                changed["actual"]["control"]["ledger_sha256"] = "9" * 64
            elif mutation == "short":
                processes[1]["actual"]["monotonic_finished"] = 69
            elif mutation == "replenished":
                changed["actual"]["control"]["budget_state"]["remaining"]["agents"] = 42
            else:
                changed["actual"]["control"]["operation_state"]["input_hash"] = "9" * 64
            with self.subTest(mutation=mutation):
                self.assertNotEqual(evaluate_check(sanitize(changed), sanitize(proof))["status"], "pass")

    def test_fixed_restart_mode_requires_the_allocated_planner_and_complete_process_receipts(self):
        request = {"schema_version": 1, "run_id": "restart-control", "mode": "process-restart",
            "workload": "candidate-planner", "client_id": "11111111-1111-1111-1111-111111111111",
            "deadline": time.time() + 900}
        self.assertEqual(validate_request(request, enabled=True, workload=request["workload"],
            client_id=request["client_id"]), request)
        for change in ({"workload": "briefing-author"}, {"mode": "arbitrary-process"},
                       {"command": ["arbitrary"]}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                changed = request | change
                validate_request(changed, enabled=True, workload=changed["workload"],
                                 client_id=request["client_id"])
        observation = {"check_id": "fault.restart-no-replay", "probe_id": "fault.restart-no-replay",
            "run_id": request["run_id"], "operation_id": "restart-operation", "caller": "candidate-planner",
            "runtime_identity": "a" * 64, "target": hashlib.sha256(
                b"https://allocated.blob.core.windows.net/planner-operations/acceptance/"
                b"restart-control/observations/restart-operation.json").hexdigest(),
            "actual": {"operation_id": "restart-operation", "processes": [
                {"operation_id": "restart-operation" + suffix, "target": hashlib.sha256(
                    ("https://allocated.blob.core.windows.net/planner-operations/acceptance/"
                     "restart-control/observations/restart-operation" + suffix + ".json").encode()).hexdigest()}
                for suffix in ("-crashed", "-restarted")]}}
        result = {"schema_version": 1, "run_id": request["run_id"], "state": "complete",
                  "observations": [observation]}

        def bind(value):
            return bind_operation_result(value, run_id=request["run_id"], principal="a" * 64,
                account="https://allocated.blob.core.windows.net", mode="process-restart")

        self.assertEqual(bind(result),
            ["restart-operation", "restart-operation-crashed", "restart-operation-restarted"])
        for mutation in ("missing", "reused", "unrelated"):
            changed = copy.deepcopy(result)
            processes = changed["observations"][0]["actual"]["processes"]
            if mutation == "missing":
                processes.pop()
            elif mutation == "reused":
                processes[1]["operation_id"] = processes[0]["operation_id"]
            else:
                processes[0]["target"] = "unrelated"
            with self.subTest(mutation=mutation), self.assertRaises(Blocked):
                bind(changed)


class ProcessRestartWorkerTests(unittest.IsolatedAsyncioTestCase):
    async def test_public_worker_preserves_crashed_state_and_finite_tickets_across_fresh_interpreters(self):
        from azure.storage.blob.aio import ContainerClient
        from citadel.acceptance.worker import run_gateway_matrix
        from citadel.acceptance.process_restart import child
        from citadel.runtime.configuration import Configuration
        from tests.unit.test_startup import environment
        from tests.runtime.test_storage import FixtureCredential
        from tests.runtime.test_ticket_storage import TicketWire

        class Wire(TicketWire):
            async def send(self, request, **options):
                response = await super().send(request, **options)
                response.headers["x-ms-request-id"] = "service-" + str(len(self.requests))
                return response

        class Credential(FixtureCredential):
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

        class Exporter:
            def emit(self, record):
                pass

            def flush(self, timeout):
                return {"request_id": "export", "status_code": 200, "submitted_records": 0,
                    "acknowledged_records": 0, "failed_records": 0, "dropped_records": 0,
                    "delivery_attempts": 0, "queued_records": 0, "inflight": False,
                    "ingestion_verified": False}

            close = flush

        class Crashed(BaseException):
            pass

        calls = []

        class Process:
            def __init__(self, pid):
                self.pid, self.returncode = pid, None

            async def communicate(self, raw):
                stream = io.StringIO()
                with (patch("citadel.acceptance.process_restart.os.getpid", return_value=self.pid),
                      patch("citadel.acceptance.process_restart.os._exit", side_effect=Crashed),
                      patch("citadel.acceptance.telemetry._exporter", None),
                      redirect_stdout(stream)):
                    try:
                        result = await child(json.loads(raw))
                    except Crashed:
                        self.returncode = 73
                    else:
                        self.returncode = 0
                        print(json.dumps(result))
                return stream.getvalue().encode(), b""

        async def launch(*args, **kwargs):
            calls.append((args, kwargs))
            return Process(1000 + len(calls))

        env = environment() | {"CITADEL_ACCEPTANCE_ENABLED": "true",
            "AZURE_PRINCIPAL_ID": "00000000-0000-0000-0000-000000000002",
            "APPLICATIONINSIGHTS_CONNECTION_STRING": "fixture"}
        config = Configuration.from_environment(env)
        request = {"schema_version": 1, "mode": "process-restart", "workload": config.target,
            "client_id": config.client_id, "run_id": "restart-wire", "deadline": time.time() + 900}
        wire = Wire(clock=time.time)
        wire.blobs["/planner-operations/active-run-slot.json"] = b"{}"
        wire.etags["/planner-operations/active-run-slot.json"] = 1
        container = lambda *args, **kwargs: ContainerClient(*args, transport=wire, **kwargs)
        with (patch.dict(os.environ, env),
              patch("citadel.acceptance.worker.ManagedIdentityCredential", lambda **kwargs: Credential()),
              patch("azure.identity.aio.ManagedIdentityCredential", lambda **kwargs: Credential()),
              patch("citadel.acceptance.worker.ContainerClient", container),
              patch("azure.storage.blob.aio.ContainerClient", container),
              patch("citadel.acceptance.process_restart.asyncio.create_subprocess_exec", launch),
              patch("citadel.acceptance.monitor.MonitorExporter", lambda *args, **kwargs: Exporter()),
              redirect_stdout(io.StringIO())):
            observations = await run_gateway_matrix(config, request)
        summary = json.loads(wire.blobs["/planner-operations/acceptance/restart-wire/observations.json"])
        self.assertEqual(summary["state"], "complete")
        self.assertEqual(len(observations), 1)
        actual = observations[0]["actual"]
        self.assertEqual([row["exit_code"] for row in actual["processes"]], [73, 0])
        self.assertEqual(actual["before_sha256"], actual["after_sha256"])
        self.assertEqual(len(bind_operation_result(summary, run_id=request["run_id"],
            principal=hashlib.sha256(env["AZURE_PRINCIPAL_ID"].encode()).hexdigest(),
            account=config.blob, mode="process-restart")), 3)
        document = json.loads(wire.blobs["/planner-operations/acceptance/restart-wire/ledger-v1.json"])
        self.assertEqual(len(document["budgets"]), 1)
        self.assertEqual(next(iter(document["budgets"].values()))["remaining"],
                         {"agents": 41, "models": 128, "tokens": 1000000, "reads": 512})
        self.assertEqual(next(iter(document["operations"].values()))["state"], "running")
        self.assertNotIn("/planner-operations/active-run-slot.json", wire.leases)
        self.assertLess(len([key for key in wire.blobs if "/read-tickets/" in key]), 512)
        self.assertTrue(all(args[1:] == ("-m", "citadel.acceptance.process_restart") for args, _ in calls))
