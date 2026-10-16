import asyncio
import copy
import json
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import httpx

from citadel.operator.scenarios import PlannerClient
from citadel.operator.state import Blocked
from citadel.acceptance.proof_gate import evaluate_check
from citadel.acceptance.reports import sanitize
from citadel.evidence.manifests import sha256


def fixture():
    from test_poll_limits import fixture as poll_fixture
    check, report = poll_fixture()
    actual = check["actual"]
    report["gateway_targets"] = {"candidate-planner": "7" * 64}
    actual.update(operation_id="http-control", finished=310, deadline=900, response="invocation_ambiguous_reconcile_only",
        before_sha256="2" * 64, after_sha256="2" * 64,
        timer={"started": 120, "finished": 300, "deadline": 900, "monotonic_started": 50,
               "monotonic_deadline": 230, "monotonic_finished": 230.01})
    actual.pop("refusal_started")
    actual.pop("refusal_finished")
    for row, start in zip(actual["observations"], (110, 120)):
        row.update(started=start, finished=start + 1, business_state="TASK_STATE_COMPLETED",
                   accepted_operation_id="scenario1", sha256="1" * 64,
                   input_hash=sha256({"operation_id": "scenario1", "run_id": "scenario1", "fixture": "base-source"}))
    for row in actual["after"]:
        row.update(started=301, finished=302)
    for side in ("before", "after"):
        for row in actual[side]:
            if row["container"] == "planner-operations":
                row["control_reference"] = {"operation_id": "scenario1", "run_id": "scenario1",
                    "deadline": 900, "result_sha256": "3" * 64, "input_hash": sha256({
                        "inputs": {"operation_id": "scenario1", "run_id": "scenario1", "fixture": "base-source"},
                        "run_id": "scenario1", "deadline": 900})}
    report["operation_ids"].append("http-control")
    report["evidence"] = [row for row in report["evidence"] if row["source"] == "storage"]
    for row in report["evidence"]:
        if row["operation_id"].startswith("after"):
            row.update(started=301, finished=302, observed=302)
    for row in actual["observations"]:
        report["evidence"].append(row | {"source": "gateway", "method": "POST", "observed": row["finished"],
            "credential_sha256": "8" * 64, "facts": {"backend_dispatched": True}})
        report["evidence"].append(row | {"source": "application", "method": "SendMessage.cached",
            "runtime_identity": report["runtime_identities"]["candidate-planner"], "observed": row["finished"],
            "facts": {"business_state": "succeeded", "accepted_operation_id": "scenario1",
                      "input_hash": sha256({"inputs": {"operation_id": "scenario1", "run_id": "scenario1",
                          "fixture": "base-source"}, "run_id": "scenario1", "deadline": 900}), "deadline": 900}})
    check.update(check_id="limit.a2a_http_timeout_seconds")
    return check, report


class HttpTimeoutOracleTests(unittest.TestCase):
    def test_export_requires_actual_timer_two_definite_cached_receipts_and_independent_no_effect(self):
        check, report = fixture()
        self.assertEqual(evaluate_check(sanitize(check), sanitize(report))["status"], "pass")
        for source in ("gateway", "application", "storage"):
            changed = report | {"evidence": [row for row in report["evidence"] if row["source"] != source]}
            self.assertEqual(evaluate_check(check, changed)["status"], "blocked", source)
        for mutation in ("short", "early", "changed", "invented", "extra"):
            changed, evidence = copy.deepcopy(check), copy.deepcopy(report)
            if mutation == "short":
                changed["actual"]["timer"]["monotonic_deadline"] -= 1
            elif mutation == "early":
                changed["actual"]["timer"]["monotonic_finished"] = 229
            elif mutation == "changed":
                changed["actual"]["after"][0]["sha256"] = "f" * 64
            elif mutation == "invented":
                changed["actual"]["observations"][1]["request_id"] = "invented"
            else:
                evidence["evidence"].append(evidence["evidence"][-2] | {"request_id": "hidden-replay"})
            self.assertNotEqual(evaluate_check(changed, evidence)["status"], "pass", mutation)

    def test_actual_provider_uses_allocated_operator_key_original_run_and_twelve_sdk_reads(self):
        self._provider()

    def test_acceptance_provider_uses_owned_ready_revision_and_restores_normal_template(self):
        self._provider(acceptance=True)

    def _provider(self, *, acceptance=False):
        from azure.core.credentials import AccessToken
        from azure.core.pipeline.transport import HttpResponse, HttpTransport
        from azure.core.utils import CaseInsensitiveDict
        from azure.storage.blob import BlobClient
        from citadel.acceptance.http_timeout import HttpTimeoutAcceptance
        requests, reads, arm = [], [], []
        deadline = time.time() + 900
        root = {"state": "succeeded", "run_id": "completed", "operation_id": "completed",
                "deadline": deadline, "result": {"sha256": "a" * 64},
                "input_hash": sha256({"inputs": {"operation_id": "completed",
                    "run_id": "completed", "fixture": "base-source"}, "run_id": "completed", "deadline": deadline})}
        content = json.dumps({"operations": {"operator/invoke/completed": root}}).encode()

        class Response(HttpResponse):
            def __init__(self, request):
                super().__init__(request, None)
                self.status_code, self.reason, self.content_type = 206, "Partial Content", "application/json"
                self.headers = CaseInsensitiveDict({"content-length": str(len(content)),
                    "content-range": f"bytes 0-{len(content)-1}/{len(content)}", "x-ms-blob-type": "BlockBlob",
                    "etag": '"wire-root"', "x-ms-request-id": "blob-" + str(len(reads))})

            def body(self):
                return content

            def stream_download(self, pipeline, **kwargs):
                response = self

                class Stream:
                    def __init__(self):
                        self.response, self.content_length = response, len(content)

                    def __iter__(self):
                        return iter([content])
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
                return Response(request)

        class Credential:
            def get_token(self, *args, **kwargs):
                return AccessToken("local-external-wire-fixture", 9999999999)

        class Native:
            template = {"containers": [{"image": "registry/allocated@sha256:" + "a" * 64,
                "command": ["python", "-m", "citadel.runtime"], "env": []}]}

            def rest(self, method, resource, api, body=None):
                arm.append((method, resource, api, body))
                if method == "patch":
                    self.template = copy.deepcopy(body["properties"]["template"])
                suffix = self.template.get("revisionSuffix", "original")
                return {"properties": {"template": copy.deepcopy(self.template),
                    "latestRevisionName": "deployment-candidate-planner--" + suffix,
                    "latestReadyRevisionName": "deployment-candidate-planner--" + suffix}}

            def blob(self, account, container, name):
                return BlobClient(account, container, name, credential=Credential(), transport=Transport(),
                                  api_version="2026-10-06", retry_total=0)

        async def transport(request):
            requests.append(request)
            body = json.loads(request.content)
            if acceptance and len(requests) == 2:
                return httpx.Response(200, headers={"apim-request-id": "cached-2"},
                    json={"jsonrpc": "2.0", "id": body["id"], "result": {"message": {
                        "messageId": "timeout", "role": "ROLE_AGENT",
                        "parts": [{"text": json.dumps({"error": "indeterminate", "complete": False})}]}}})
            return httpx.Response(200, headers={"apim-request-id": "cached-" + str(len(requests))},
                json={"jsonrpc": "2.0", "id": body["id"], "result": {"task": {
                    "id": "completed", "contextId": "completed", "status": {"state": "TASK_STATE_COMPLETED"}}}})

        run = {"state": "succeeded", "fixture": "base-source", "deadline": deadline, "reads": 2}
        lifecycle = SimpleNamespace(id="deployment", value={"inventory": [
            "/subscriptions/s/resourceGroups/g/providers/Microsoft.Storage/storageAccounts/allocated"],
            "runs": {"completed": run}, "outputs": {"gatewayUrl": "https://gateway.example",
                "appInventory": [{"app": "/subscriptions/s/resourceGroups/g/providers/Microsoft.App/containerApps/deployment-candidate-planner",
                                  "image": "registry/allocated@sha256:" + "a" * 64}]}},
            state=SimpleNamespace(save=lambda: None), native=Native(), credentials=lambda: {
                "callerStates": {"operator": "active"}, "callerKeys": {"operator": {"primary": "only-own-key"}}})
        report = {"run_id": "suite", "operation_ids": ["completed"],
                  "scenarios": {"comparison": {"operation_id": "completed"}}}
        client = httpx.AsyncClient
        with patch("citadel.acceptance.http_timeout.httpx.AsyncClient",
                   lambda **kwargs: client(transport=httpx.MockTransport(transport), **kwargs)):
            HttpTimeoutAcceptance(lifecycle, acceptance=acceptance).execute(report)
        phase = report["acceptance_timeout_phase" if acceptance else "http_timeout_phase"]
        self.assertEqual((len(requests), len(reads), phase["read_attempts"]), (2, 12, 16 if acceptance else 12))
        self.assertEqual((phase["state"], run["state"], run["reads"]), ("observed", "succeeded", 2))
        if acceptance:
            self.assertEqual(phase["response"], "indeterminate")
            self.assertEqual(len([row for row in arm if row[0] == "patch"]), 2)
            self.assertEqual(lifecycle.native.template["containers"][0]["env"], [])
            self.assertTrue(all(row[2] == "2025-01-01" for row in arm))
        else:
            self.assertGreaterEqual(phase["timer"]["monotonic_finished"] - phase["timer"]["monotonic_started"], 180)
        self.assertEqual(phase["before_sha256"], phase["after_sha256"])
        self.assertTrue(all(row.method == "GET" for row in reads))
        self.assertTrue(all(row.headers["Ocp-Apim-Subscription-Key"] == "only-own-key" for row in requests))
        self.assertNotIn("only-own-key", str(report))
        with self.assertRaises(Blocked):
            HttpTimeoutAcceptance(lifecycle, acceptance=acceptance).execute(report)
        self.assertEqual((len(requests), len(reads)), (2, 12))


class HttpTimeoutTests(unittest.IsolatedAsyncioTestCase):
    async def test_actual_http_guard_preserves_definite_response_and_never_retries(self):
        requests = []

        async def transport(request):
            requests.append(request)
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": "cached",
                "result": {"task": {"id": "completed", "contextId": "completed",
                    "status": {"state": "TASK_STATE_COMPLETED"}}}},
                headers={"apim-request-id": "actual-received-response"})

        async def hold(response):
            await response.aread()
            await asyncio.sleep(200)

        async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as http:
            client = PlannerClient("https://gateway.example", "own-key", http=http)
            http.event_hooks["response"].append(hold)
            started = time.monotonic()
            with self.assertRaises(Blocked) as caught:
                await client.exchange("/candidate-planner/a2a", time.time() + 900,
                    lambda: http.post("https://gateway.example/candidate-planner/a2a",
                        json={"jsonrpc": "2.0", "id": "cached", "method": "SendMessage"}),
                    invocation=True)
            self.assertEqual(caught.exception.code, "invocation_ambiguous_reconcile_only")
            self.assertEqual(len(requests), 1)
            self.assertGreaterEqual(time.monotonic() - started, 180)
            timer = client.timeout_receipt
            self.assertIsNotNone(timer)
            self.assertEqual(timer["monotonic_deadline"] - timer["monotonic_started"], 180)
            self.assertGreaterEqual(timer["monotonic_finished"], timer["monotonic_deadline"])

    async def test_a_shorter_inherited_deadline_is_not_reported_as_a_full_http_boundary(self):
        async def transport(request):
            await asyncio.sleep(1)

        async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as http:
            client = PlannerClient("https://gateway.example", "own-key", http=http)
            with self.assertRaises(Blocked):
                await client.exchange("/candidate-planner/a2a", time.time() + .02,
                    lambda: http.post("https://gateway.example/candidate-planner/a2a"), invocation=True)
            self.assertLess(client.timeout_receipt["monotonic_deadline"]
                            - client.timeout_receipt["monotonic_started"], 180)
