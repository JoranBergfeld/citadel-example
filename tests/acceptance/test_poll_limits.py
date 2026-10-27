import copy
import unittest
from tests.acceptance.storage_fixture import storage_inventory
import time
from types import SimpleNamespace
from unittest.mock import patch

import httpx

from citadel.acceptance.proof_gate import evaluate_check
from citadel.acceptance.reports import sanitize
from citadel.acceptance.poll_limits import observe_poll
from citadel.acceptance.workflow_routes import observe_invocation
from citadel.evidence.manifests import sha256


def fixture():
    actors = ("candidate-planner", "evidence-assessor", "release-reviewer", "briefing-author", "reference-data")
    identities = dict(zip(actors, (letter * 64 for letter in "acdef")))
    containers = ("planner-operations", "assessor-operations", "reviewer-operations", "author-operations", "drafts", "findings")
    targets = {container: str(index + 1) * 64 for index, container in enumerate(containers)}
    rows, snapshots = [], {}
    for side, start in (("before", 100), ("after", 128)):
        snapshots[side] = []
        for container in containers:
            operation = side + "-" + container
            row = {"operation_id": operation, "request_id": operation, "status_code": 206,
                "target": targets[container], "sha256": "0" * 64, "started": start, "finished": start + 1,
                "caller": "operator", "container": container, "action": "read", "suite_id": "suite"}
            snapshots[side].append(row)
            rows.append(row | {"source": "storage", "method": "GetBlob", "runtime_identity": "b" * 64,
                               "client_request_id": operation, "observed": start + 1})

    def service(receipt, caller, target, operation, *, method="GET", action="status"):
        rows.append(receipt | {"source": "gateway", "method": method, "observed": receipt["finished"],
            "caller": caller, "credential_sha256": ("8" if caller == "operator" else "9") * 64,
            "facts": {"backend_dispatched": True}})
        rows.append(receipt | {"source": "application", "method": action, "observed": receipt["finished"],
            "caller": caller, "runtime_identity": identities[target], "run_id": "scenario1", "operation_id": operation})

    observations = [{"run_id": "scenario1", "operation_id": "scenario1", "caller": "operator",
        "request_id": key, "target": "7" * 64, "status_code": 200, "started": start, "finished": start + 1,
        "sha256": "1" * 64, "business_state": "succeeded"} for key, start in (("o1", 110), ("o2", 126))]
    for row in observations:
        service(row, "operator", "candidate-planner", "scenario1")
    for key, start, state in (("p1", 26, "running"), ("p2", 42, "succeeded")):
        response = httpx.Response(200, headers={"apim-request-id": key},
            request=httpx.Request("GET", "https://gateway.example/evidence-assessor/operations/child"),
            json={"run_id": "scenario1", "operation_id": "child", "state": state})
        record = observe_poll(response, caller="candidate-planner", target="evidence-assessor",
            run_id="scenario1", operation_id="scenario1", started=start, finished=start + 1)
        rows.append(record | {"source": "application", "runtime_identity": identities["candidate-planner"],
                              "observed": start + 1})
        service(record | {"started": start, "finished": start + 1},
                "candidate-planner", "evidence-assessor", "scenario1")
    request = httpx.Request("POST", "https://gateway.example/evidence-assessor/a2a",
        json={"jsonrpc": "2.0", "id": "invoke", "method": "SendMessage"})
    response = httpx.Response(200, request=request, headers={"apim-request-id": "invocation"},
        json={"jsonrpc": "2.0", "id": "invoke", "result": {"task": {
            "id": "child", "contextId": "scenario1", "status": {"state": "TASK_STATE_SUBMITTED"}}}})
    record = observe_invocation(response, caller="candidate-planner", target="evidence-assessor",
        run_id="scenario1", operation_id="scenario1", started=10, finished=11)
    rows.append(record | {"source": "application", "runtime_identity": identities["candidate-planner"], "observed": 11})
    service(record | {"started": 10, "finished": 11}, "candidate-planner", "evidence-assessor", "scenario1",
            method="POST", action="SendMessage")
    report = {"run_id": "suite", "runtime_identities": identities, "storage_targets": targets,
        "subscription_bindings": {"operator": "8" * 64, "candidate-planner": "9" * 64},
        "scenarios": {"comparison": {"operation_id": "scenario1"}},
        "operation_ids": ["scenario1", *[row["operation_id"] for group in snapshots.values() for row in group]],
        "evidence": rows}
    check = {"check_id": "limit.poll_seconds", "expected": "boundary", "actual": {
        "run_id": "scenario1", "started": 99, "finished": 130, "deadline": 900, "observations": observations,
        "before": snapshots["before"], "after": snapshots["after"], "runtime_identity": "b" * 64,
        "response": "poll_interval_15_seconds_required", "refusal_started": 112, "refusal_finished": 113,
        "before_sha256": "2" * 64, "after_sha256": "2" * 64}}
    return check, report


class PollLimitTests(unittest.TestCase):
    def test_actual_provider_uses_twelve_real_sdk_reads_two_real_http_polls_and_real_fifteen_second_wait(self):
        from azure.core.credentials import AccessToken
        from azure.core.pipeline.transport import HttpResponse, HttpTransport
        from azure.core.utils import CaseInsensitiveDict
        from azure.storage.blob import BlobClient
        from citadel.acceptance.poll_limits import PollAcceptance
        # Resolve protocol type annotations before replacing the external HTTP client factory.
        from citadel.operator import scenarios
        from citadel.operator.state import Blocked
        blob_calls, polls = [], []

        class Response(HttpResponse):
            def __init__(self, request):
                super().__init__(request, None)
                self.status_code, self.reason, self.content_type = 206, "Partial Content", "application/json"
                self.headers = CaseInsensitiveDict({"content-length": "2", "content-range": "bytes 0-1/2",
                    "x-ms-blob-type": "BlockBlob", "etag": '"actual-fixture"',
                    "x-ms-request-id": "blob-" + str(len(blob_calls))})

            def body(self):
                return b"{}"

            def stream_download(self, pipeline, **kwargs):
                response = self

                class Stream:
                    def __init__(self):
                        self.response = response
                        self.content_length = 2

                    def __iter__(self):
                        return iter([b"{}"])

                return Stream()

        class Transport(HttpTransport):
            def open(self):
                pass

            def close(self):
                pass

            def __exit__(self, *args):
                pass

            def send(self, request, **kwargs):
                blob_calls.append(request)
                return Response(request)

        class Credential:
            def get_token(self, *args, **kwargs):
                return AccessToken("local-fixture-not-cloud-token", 9999999999)

        class Native:
            def blob(self, account, container, name):
                return BlobClient(account, container, name, credential=Credential(), transport=Transport(),
                                  api_version="2026-10-06", retry_total=0)

        async def transport(request):
            polls.append(request)
            return httpx.Response(200, headers={"apim-request-id": "actual-poll-" + str(len(polls))},
                json={"run_id": "scenario1", "operation_id": "scenario1", "state": "succeeded",
                      "input_hash": "a" * 64, "result": {"sha256": "b" * 64}})

        run = {"state": "succeeded", "deadline": time.time() + 900, "reads": 2}
        lifecycle = SimpleNamespace(value={"inventory": storage_inventory(),
            "runs": {"scenario1": run}, "outputs": {"gatewayUrl": "https://gateway.example"}},
            state=SimpleNamespace(save=lambda: None), native=Native(), credentials=lambda: {
                "callerStates": {"operator": "active"}, "callerKeys": {"operator": {"primary": "own-operator-key"}}})
        report = {"run_id": "suite", "operation_ids": ["scenario1"],
                  "scenarios": {"comparison": {"operation_id": "scenario1"}}}
        client = httpx.AsyncClient
        with patch("citadel.acceptance.poll_limits.httpx.AsyncClient",
                   lambda **kwargs: client(transport=httpx.MockTransport(transport), **kwargs)):
            PollAcceptance(lifecycle).execute(report)
        phase = report["poll_phase"]
        self.assertEqual(phase["state"], "observed")
        self.assertEqual((len(blob_calls), len(polls), phase["read_attempts"]), (12, 2, 12))
        self.assertEqual(phase["response"], "poll_interval_15_seconds_required")
        self.assertEqual(phase["before_sha256"], phase["after_sha256"])
        self.assertGreaterEqual(phase["observations"][1]["started"] - phase["observations"][0]["finished"], 15)
        self.assertEqual(run["reads"], 4)
        self.assertTrue(all(request.method == "GET" for request in blob_calls))
        self.assertTrue(all(request.headers["Ocp-Apim-Subscription-Key"] == "own-operator-key" for request in polls))
        self.assertNotIn("own-operator-key", str(report))
        with self.assertRaises(Blocked):
            PollAcceptance(lifecycle).execute(report)
        self.assertEqual((len(blob_calls), len(polls)), (12, 2))

    def test_provider_persists_intent_before_any_read_and_never_replays_after_failure(self):
        from citadel.acceptance.poll_limits import PollAcceptance
        from citadel.operator.state import Blocked
        calls = []

        def blob(*args):
            calls.append(args)
            raise Blocked("actual_observer_unavailable")

        run = {"state": "succeeded", "deadline": time.time() + 900, "reads": 2}
        lifecycle = SimpleNamespace(value={"inventory": storage_inventory(),
            "runs": {"scenario1": run}, "outputs": {"gatewayUrl": "https://gateway.example"}},
            state=SimpleNamespace(save=lambda: None), native=SimpleNamespace(blob=blob))
        report = {"run_id": "suite", "operation_ids": ["scenario1"],
                  "scenarios": {"comparison": {"operation_id": "scenario1"}}}
        for _ in range(2):
            with self.assertRaises(Blocked):
                PollAcceptance(lifecycle).execute(report)
        self.assertEqual(len(calls), 1)
        self.assertEqual(report["poll_phase"]["state"], "blocked")
        self.assertEqual(report["poll_phase"]["read_attempts"], 0)

    def test_public_poll_gate_needs_real_local_refusal_all_peer_receipts_and_unchanged_business_state(self):
        check, report = fixture()
        self.assertEqual(evaluate_check(sanitize(check), sanitize(report))["status"], "pass")
        for source in ("gateway", "application", "storage"):
            changed = report | {"evidence": [row for row in report["evidence"] if row["source"] != source]}
            self.assertEqual(evaluate_check(check, changed)["status"], "blocked", source)
        changed = copy.deepcopy(check)
        changed["actual"]["response"] = "allowed"
        self.assertEqual(evaluate_check(changed, report)["status"], "fail")
        changed = copy.deepcopy(check)
        changed["actual"]["after"][0]["sha256"] = "f" * 64
        self.assertEqual(evaluate_check(changed, report)["status"], "fail")
        changed = copy.deepcopy(report)
        changed["evidence"] = [row for row in changed["evidence"] if row.get("method") != "poll.observed"]
        self.assertEqual(evaluate_check(check, changed)["status"], "blocked")
        changed = copy.deepcopy(report)
        for row in changed["evidence"]:
            if row.get("request_id") != "p2":
                continue
            row["observed"] = 41
            if row.get("method") == "poll.observed":
                row["facts"].update(started=40, finished=41)
                original = {key: row[key] for key in
                    ("method", "run_id", "operation_id", "caller", "request_id", "status_code", "target")}
                original["facts"] = {key: value for key, value in row["facts"].items() if key != "sha256"}
                row["facts"]["sha256"] = sha256(original)
        self.assertEqual(evaluate_check(check, changed)["status"], "fail")
        changed = copy.deepcopy(report)
        next(row for row in changed["evidence"] if row.get("method") == "poll.observed")["runtime_identity"] = "b" * 64
        self.assertEqual(evaluate_check(check, changed)["status"], "blocked")
