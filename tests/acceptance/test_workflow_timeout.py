import asyncio
import io
import json
import time
import unittest
from tests.acceptance.storage_fixture import storage_inventory
from unittest.mock import patch

import httpx

from citadel.acceptance.telemetry import Telemetry
from citadel.evidence.manifests import sha256


def workflow_proof():
    from test_rotation_controls import proof_fixture
    _, report = proof_fixture()
    run, target = "workflow-boundary", "9" * 64
    report["operation_ids"].append(run)
    report["gateway_targets"] = {"candidate-planner": target}
    identity = report["runtime_identities"]["candidate-planner"]
    before, after, evidence = [], [], []
    containers = tuple(report["storage_targets"])
    for side, when, rows in (("before", 105, before), ("after", 1020, after)):
        for container in containers:
            row = {"suite_id": report["run_id"], "operation_id": side + container,
                "caller": "operator", "action": "read", "container": container,
                "target": report["storage_targets"][container], "request_id": side + container,
                "status_code": 206, "started": when, "finished": when + 1,
                "sha256": sha256(side if container == "planner-operations" else container),
                "business_sha256": sha256(container), "count": 1}
            rows.append(row)
            report["operation_ids"].append(row["operation_id"])
            evidence.append(row | {"source": "storage", "method": "GetBlob", "observed": when + 1,
                "runtime_identity": "f" * 64, "client_request_id": row["operation_id"]})
    receipt = {"run_id": run, "operation_id": run, "caller": "operator", "target": target,
        "request_id": "admission", "status_code": 200, "started": 110, "finished": 111,
        "facts": {"accepted_operation_id": run, "business_state": "TASK_STATE_WORKING",
                  "task_sha256": "6" * 64}}
    admitted = {"started": 110, "deadline": 1010, "sha256": "5" * 64}
    timer = {"started": 110.01, "finished": 1010.01, "deadline": 1010,
        "monotonic_started": 50.01, "monotonic_deadline": 950, "monotonic_finished": 950.01}
    budget = {"deadline": 1010, "remaining": {"agents": 41, "models": 128, "tokens": 1000000, "reads": 512},
              "closed": False, "before_sha256": "7" * 64, "after_sha256": "7" * 64}
    evidence.append(receipt | {"source": "gateway", "method": "POST", "observed": 111,
        "credential_sha256": report["subscription_bindings"]["candidate-planner"],
        "facts": {"backend_dispatched": True, "backend_status": 200}})
    report["subscription_bindings"]["operator"] = report["subscription_bindings"]["candidate-planner"]
    evidence.append(receipt | {"source": "application", "method": "SendMessage",
        "runtime_identity": identity, "observed": 111,
        "facts": {"business_state": "running", "accepted_operation_id": run, "deadline": 1010}})
    for method, when, facts in (
        ("workflow.admitted", 110, admitted),
        ("workflow.held", 111, {"sha256": budget["before_sha256"], "deadline": 1010}),
        ("workflow.timeout", 1010.01, timer),
        ("workflow.refused", 1010.02, {"reason": "deadline", "deadline": 1010}),
        ("workflow.fenced", 1010.03, {"business_state": "failed_no_commit", "reason": "deadline",
            "before_sha256": "7" * 64, "after_sha256": "7" * 64, "deadline": 1010, "generation": 2})):
        evidence.append({"source": "application", "method": method, "runtime_identity": identity,
            "run_id": run, "operation_id": run, "caller": "operator" if method == "workflow.admitted"
                else "candidate-planner", "observed": when, "facts": facts,
            "request_id": "", "status_code": 0 if method == "workflow.timeout" else
                409 if method == "workflow.refused" else 200})
    report["evidence"] = evidence
    control = after[0] | {"control_reference": {"operation_id": run, "run_id": run,
        "deadline": 1010, "state": "failed_no_commit", "generation": 2,
        "input_hash": sha256({"inputs": {"operation_id": run, "run_id": run, "fixture": "base-source"},
                             "run_id": run, "deadline": 1010}),
        "business_state": "not_dispatched", "budget_state": budget}}
    allowed = control | {"operation_id": "admitted-read", "request_id": "admitted-read",
                         "started": 112, "finished": 113}
    allowed["control_reference"] = control["control_reference"] | {"state": "running", "generation": 1}
    report["operation_ids"].append(allowed["operation_id"])
    evidence.append(allowed | {"source": "storage", "method": "GetBlob", "observed": 113,
        "runtime_identity": "f" * 64, "client_request_id": allowed["operation_id"]})
    actual = {"run_id": run, "started": 100, "finished": 1030, "deadline": 1240,
        "state": "restored", "before_sha256": "8" * 64, "after_sha256": "8" * 64,
        "before": before, "after": after, "observation": receipt, "control": control,
        "budget_state": budget, "allowed": allowed}
    return {"check_id": "limit.workflow_seconds", "expected": "boundary", "actual": actual}, report


class WorkflowControlTests(unittest.TestCase):
    def test_public_provider_retains_existing_intent_and_never_redispatches(self):
        from types import SimpleNamespace
        from citadel.acceptance.workflow_harness import WorkflowAcceptance
        from citadel.operator.state import Blocked
        report = {"workflow_timeout_phase": {"state": "dispatching"}}
        with self.assertRaises(Blocked):
            WorkflowAcceptance(SimpleNamespace()).execute(report)

    def test_export_requires_production_timer_refusal_restoration_and_independent_unchanged_state(self):
        import copy
        from citadel.acceptance.proof_gate import evaluate_check
        from citadel.acceptance.reports import sanitize
        check, report = workflow_proof()
        self.assertEqual(evaluate_check(sanitize(check), sanitize(report))["status"], "pass")
        for mutation in ("shortened", "no-timer", "no-refusal", "no-storage", "refilled",
                         "business-effect", "no-restoration", "wrong-identity", "extended", "no-admitted-read",
                         "extra-business-dispatch"):
            value, proof = copy.deepcopy(check), copy.deepcopy(report)
            if mutation in ("no-timer", "no-refusal"):
                method = "workflow.timeout" if mutation == "no-timer" else "workflow.refused"
                proof["evidence"] = [row for row in proof["evidence"] if row["method"] != method]
            elif mutation == "no-storage":
                proof["evidence"] = [row for row in proof["evidence"] if row["source"] != "storage"]
            elif mutation == "shortened":
                next(row for row in proof["evidence"] if row["method"] == "workflow.admitted")["facts"]["started"] += 1
            elif mutation == "wrong-identity":
                next(row for row in proof["evidence"] if row["method"] == "workflow.timeout")["runtime_identity"] = "f" * 64
            elif mutation == "refilled":
                value["actual"]["budget_state"]["remaining"]["agents"] = 42
            elif mutation == "business-effect":
                value["actual"]["after"][-1]["sha256"] = "0" * 64
            elif mutation == "extended":
                value["actual"]["budget_state"]["deadline"] += 1
            elif mutation == "no-admitted-read":
                proof["evidence"] = [row for row in proof["evidence"] if row["request_id"] != "admitted-read"]
            elif mutation == "extra-business-dispatch":
                proof["evidence"].append({"source": "gateway", "request_id": "extra-model-call",
                    "observed": 500, "caller": "candidate-planner", "target": "1" * 64, "status_code": 200})
            else:
                value["actual"]["after_sha256"] = "0" * 64
            with self.subTest(mutation=mutation):
                self.assertEqual(evaluate_check(sanitize(value), sanitize(proof))["status"], "blocked")

    def test_workflow_hold_is_disabled_normally_and_has_no_configurable_runtime_duration(self):
        from citadel.acceptance.workflow_timeout import WorkflowHold
        request = {"run_id": "workflow-control", "deadline": time.time() + 1140, "mode": "workflow-timeout"}
        env = {"CITADEL_ACCEPTANCE_ENABLED": "true",
               "CITADEL_ACCEPTANCE_WORKFLOW_HOLD": json.dumps(request)}
        self.assertIsNone(WorkflowHold.from_environment({}, workload="candidate-planner"))
        self.assertEqual(WorkflowHold.from_environment(env, workload="candidate-planner").run_id, "workflow-control")
        for change in ({"seconds": 10}, {"deadline": time.time() + 1141}, {"mode": "arbitrary"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                WorkflowHold.from_environment(env | {"CITADEL_ACCEPTANCE_WORKFLOW_HOLD":
                    json.dumps(request | change)}, workload="candidate-planner")
        with self.assertRaises(ValueError):
            WorkflowHold.from_environment(env, workload="briefing-author")


class WorkflowRuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def test_cancelled_root_waits_for_original_absolute_deadline_before_refusal_even_with_clock_skew(self):
        from citadel.acceptance.workflow_timeout import WorkflowHold
        from citadel.runtime.agents import Runtime
        from tests.unit.test_read_tickets import CountingLedger
        now = [time.time()]
        run = "clock-skew-control"
        ledger = CountingLedger(clock=lambda: now[0])
        hold = WorkflowHold(run, now[0] + 1140)
        runtime = Runtime("candidate-planner", ledger, model=None, peers=None,
            gateway_url="https://gateway.test", clock=lambda: now[0], workflow_hold=hold)
        await runtime.accept("operator", {"operation_id": run, "run_id": run, "fixture": "base-source"})
        await asyncio.sleep(0)
        tasks = list(runtime.tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        now[0] += 899.9
        sleep = asyncio.sleep

        async def clock_catches_up(seconds):
            now[0] += seconds
            await sleep(0)

        with patch("citadel.acceptance.workflow_timeout.asyncio.sleep", clock_catches_up):
            await hold.finish(runtime, {"run_id": run})
        document, _ = await ledger.read()
        self.assertEqual(document["budgets"][run]["remaining"]["agents"], 41)
        self.assertEqual(set(document["budgets"][run]["agents"]), {run})
        self.assertEqual(document["operations"]["operator/invoke/" + run]["state"], "failed_no_commit")

    async def test_authenticated_a2a_root_exhausts_real_900_second_production_timer_without_refill(self):
        from citadel.acceptance.workflow_timeout import WorkflowHold
        from citadel.operator.scenarios import PlannerClient
        from citadel.runtime.agents import Runtime, agent_application
        from test_workflow import FixtureGateway
        from test_reference import trust
        from tests.unit.test_read_tickets import CountingLedger

        run, started, monotonic = "workflow-control", time.time(), time.monotonic()
        ledger, output = CountingLedger(clock=time.time), io.StringIO()
        hold = WorkflowHold.from_environment({"CITADEL_ACCEPTANCE_ENABLED": "true",
            "CITADEL_ACCEPTANCE_WORKFLOW_HOLD": json.dumps({
                "run_id": run, "deadline": started + 1140, "mode": "workflow-timeout"})},
            workload="candidate-planner")
        runtime = Runtime("candidate-planner", ledger, model=None, peers=None,
            gateway_url="https://gateway.test", workflow_hold=hold)
        class Wire(FixtureGateway):
            async def handle_async_request(self, request):
                original = request.url
                response = await super().handle_async_request(request)
                request.url = original
                response.headers["apim-request-id"] = "workflow-gateway"
                return response

        gateway = Wire()
        gateway.apps["candidate-planner"] = agent_application(runtime, trust("candidate-planner"))
        with patch("citadel.acceptance.telemetry._exporter",
                   Telemetry("candidate-planner", "00000000-0000-0000-0000-000000000002", output=output)):
            async with httpx.AsyncClient(transport=gateway, timeout=30) as http:
                client = PlannerClient("https://gateway.test", "operator", http=http)
                await client.invoke(run, "base-source", started + 1140)
                self.assertIsNotNone(client.invocation_receipt)
                tasks = list(runtime.tasks)
                self.assertEqual(len(tasks), 1)
                await asyncio.gather(*tasks)
        self.assertGreaterEqual(time.monotonic() - monotonic, 900)
        self.assertLess(time.monotonic() - monotonic, 1020)
        document, _ = await ledger.read()
        budget = document["budgets"][run]
        self.assertEqual(budget["remaining"], {"agents": 41, "models": 128, "tokens": 1000000, "reads": 512})
        self.assertFalse(budget["closed"])
        operation = document["operations"]["operator/invoke/" + run]
        self.assertEqual(operation["state"], "failed_no_commit")
        self.assertEqual(operation["generation"], 2)
        self.assertIsNone(operation["result"])
        self.assertNotIn("product", operation)
        self.assertEqual(hold.response, "deadline")
        self.assertEqual(hold.before_sha256, hold.after_sha256)
        events = [json.loads(line) for line in output.getvalue().splitlines()]
        admitted = [event for event in events if event["method"] == "workflow.admitted"]
        expired = [event for event in events if event["method"] == "workflow.timeout"]
        self.assertEqual(len(admitted), 1)
        self.assertEqual(len(expired), 1)
        self.assertEqual(len([event for event in events if event["method"] == "workflow.held"]), 1)
        self.assertEqual(len([event for event in events if event["method"] == "workflow.refused"
                              and event["facts"]["reason"] == "deadline"]), 1)
        self.assertEqual(admitted[0]["facts"]["deadline"] - admitted[0]["facts"]["started"], 900)
        self.assertEqual(expired[0]["facts"]["deadline"], admitted[0]["facts"]["deadline"])
        self.assertGreaterEqual(expired[0]["facts"]["monotonic_finished"],
                                expired[0]["facts"]["monotonic_deadline"])
        self.assertEqual(hold.before_sha256, sha256(budget))
        self.assertEqual(gateway.exchanges[0][:3], ("operator", "candidate-planner", "/a2a"))


class WorkflowProviderTests(unittest.TestCase):
    def test_operator_provider_keeps_900_second_business_deadline_and_restores_owned_revision(self):
        import copy
        from types import SimpleNamespace
        from unittest.mock import patch
        from azure.core.credentials import AccessToken
        from azure.core.pipeline.transport import HttpResponse, HttpTransport
        from azure.core.utils import CaseInsensitiveDict
        from azure.storage.blob import BlobClient
        from citadel.acceptance.workflow_harness import WorkflowAcceptance
        from citadel.operator.state import Blocked
        from citadel.operations.testing import MemoryLedger
        from citadel.operator import scenarios

        from contextlib import nullcontext
        now, dispatched, requests, patches, reads, queries = [time.time()], [], [], [], [], []
        started, run = now[0], "workflow-native-wire"
        report = {"run_id": "suite", "operation_ids": [], "evidence": [],
            "checks": [{"check_id": "limit.workflow_seconds", "expected": "boundary", "status": "blocked"}]}
        empty = asyncio.run(MemoryLedger().read())[0]
        budget = {"run_id": run, "deadline": started + 900, "closed": False,
            "remaining": {"agents": 41, "models": 128, "tokens": 1000000, "reads": 512},
            "agents": {run: 0}, "model": None, "child": None, "candidates": [], "grants": [], "history": []}
        root = {"run_id": run, "operation_id": run, "deadline": budget["deadline"],
            "state": "running", "generation": 1, "external": {}, "result": None,
            "input_hash": sha256({"inputs": {"run_id": run, "operation_id": run, "fixture": "base-source"},
                                  "run_id": run, "deadline": budget["deadline"]})}

        class Response(HttpResponse):
            def __init__(self, request, content):
                super().__init__(request, None)
                self.content = content
                self.status_code, self.reason, self.content_type = 206, "Partial Content", "application/json"
                self.headers = CaseInsensitiveDict({"content-length": str(len(content)),
                    "content-range": f"bytes 0-{len(content)-1}/{len(content)}", "x-ms-blob-type": "BlockBlob",
                    "etag": '"wire"', "x-ms-request-id": "read-" + str(len(reads))})

            def body(self):
                return self.content

            def stream_download(self, pipeline, **kwargs):
                response = self

                class Stream:
                    def __init__(self):
                        self.response, self.content_length = response, len(response.content)

                    def __iter__(self):
                        return iter([response.content])

                return Stream()

        class Transport(HttpTransport):
            def open(self):
                pass

            def close(self):
                pass

            def __exit__(self, *args):
                pass

            def send(self, request, **kwargs):
                reads.append(request)
                document = copy.deepcopy(empty)
                if "/planner-operations/" in request.url and dispatched:
                    document["budgets"][run] = budget
                    document["operations"]["operator/invoke/" + run] = root | (
                        {"state": "failed_no_commit", "generation": 2} if now[0] >= budget["deadline"] else {})
                    document["runs"][run] = {"deadline": budget["deadline"]}
                return Response(request, json.dumps(document).encode())

        class Credential:
            def get_token(self, *args, **kwargs):
                return AccessToken("local-wire-fixture", 9999999999)

        class Native:
            template = {"containers": [{"image": "owned@sha256:" + "a" * 64,
                "command": ["python", "-m", "citadel.runtime"], "env": []}]}

            def rest(self, method, resource, api, body=None):
                if "/workspaces/" in resource:
                    self_test.assertEqual(api, "2022-10-01")
                    return {"properties": {"customerId": "00000000-0000-0000-0000-000000000001"}}
                self_test.assertEqual(api, "2025-01-01")
                if method == "patch":
                    patches.append(copy.deepcopy(body))
                    self.template = copy.deepcopy(body["properties"]["template"])
                suffix = self.template.get("revisionSuffix", "normal")
                return {"properties": {"template": copy.deepcopy(self.template),
                    "latestRevisionName": "sample-candidate-planner--" + suffix,
                    "latestReadyRevisionName": "sample-candidate-planner--" + suffix}}

            def blob(self, account, container, name):
                return BlobClient(account, container, name, credential=Credential(), transport=Transport(),
                                  api_version="2026-10-06", retry_total=0)

            def document(self, value):
                queries.append(value)
                return nullcontext("external-wire-query.json")

            def az(self, *args, **kwargs):
                self_test.assertIn("https://api.loganalytics.io", args)
                return {"tables": [{"columns": [{"name": name} for name in (
                    "source", "request_id", "status_code", "runtime_identity", "observed")], "rows": []}]}

        async def send(request):
            requests.append(request)
            dispatched.append(True)
            body = json.loads(request.content)
            return httpx.Response(200, headers={"apim-request-id": "actual-wire-admission"},
                json={"jsonrpc": "2.0", "id": body["id"], "result": {"task": {
                    "id": run, "contextId": run, "status": {"state": "TASK_STATE_SUBMITTED"}}}})

        lifecycle = SimpleNamespace(id="sample", native=Native(), state=SimpleNamespace(save=lambda: None),
            credentials=lambda: {"callerStates": {"operator": "active"},
                                 "callerKeys": {"operator": {"primary": "allocated-operator"}}},
            value={"runs": {}, "inventory": [
                *storage_inventory(planning="owned"),
                "/subscriptions/s/resourceGroups/g/providers/Microsoft.OperationalInsights/workspaces/owned"],
                "outputs": {"gatewayUrl": "https://gateway.test", "appInventory": [{
                    "app": "/owned/sample-candidate-planner", "image": "owned@sha256:" + "a" * 64}]}})
        self_test, client = self, httpx.AsyncClient
        with (patch("citadel.acceptance.workflow_harness.uuid4", lambda: SimpleNamespace(hex=run)),
              patch("citadel.acceptance.workflow_harness.time.time", lambda: now[0]),
              patch("citadel.acceptance.workflow_harness.time.sleep", lambda seconds: now.__setitem__(0, now[0] + seconds)),
              patch("httpx.AsyncClient", lambda **kwargs: client(transport=httpx.MockTransport(send), **kwargs))):
            with self.assertRaises(Blocked):
                WorkflowAcceptance(lifecycle).execute(report)
            with self.assertRaises(Blocked):
                WorkflowAcceptance(lifecycle).execute(report)
        phase = report["workflow_timeout_phase"]
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0].headers["Ocp-Apim-Subscription-Key"], "allocated-operator")
        self.assertEqual(phase["state"], "restored")
        self.assertEqual(lifecycle.value["runs"][run]["deadline"], started + 900)
        self.assertEqual(lifecycle.value["runs"][run]["state"], "control_intent")
        self.assertEqual(len(patches), 2)
        enabled = patches[0]["properties"]["template"]["containers"][0]["env"]
        hold = json.loads(next(item["value"] for item in enabled
                              if item["name"] == "CITADEL_ACCEPTANCE_WORKFLOW_HOLD"))
        self.assertEqual(hold, {"run_id": run, "deadline": started + 1140, "mode": "workflow-timeout"})
        self.assertEqual(lifecycle.native.template["containers"][0]["env"], [])
        self.assertGreaterEqual(now[0] - started, 900)
        self.assertEqual(len(reads), 14)
        self.assertEqual(len(queries), 40)
        from citadel.acceptance.collection import collection_remaining
        self.assertEqual(collection_remaining(report, now[0]), 0)
        self.assertLess(phase["finished"] - started, 1140)
        self.assertEqual(report["checks"][0]["status"], "blocked")
        self.assertNotIn("allocated-operator", str(report))
