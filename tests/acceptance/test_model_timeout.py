import io
import copy
import json
import time
import unittest
from unittest.mock import patch

import httpx2

from citadel.acceptance.telemetry import Telemetry, correlate
from citadel.evidence.manifests import sha256
from citadel.operations.testing import MemoryLedger
from citadel.runtime.model import GovernedModel


class ModelTimeoutTests(unittest.IsolatedAsyncioTestCase):
    async def test_failed_model_response_cannot_authorize_timeout_completion_or_release_its_admission(self):
        from agent_framework.exceptions import ChatClientException
        from citadel.acceptance.model_timeout import ModelTimeout
        requests, ledger = [], MemoryLedger()

        async def response(request):
            requests.append(request)
            return httpx2.Response(503, headers={"apim-request-id": "failed-model"},
                                   json={"error": {"code": "unavailable"}})

        async with httpx2.AsyncClient(transport=httpx2.MockTransport(response)) as http:
            model = GovernedModel("candidate-planner", "https://gateway.test", "allocated", "approved", http_client=http)
            try:
                with self.assertRaises(ChatClientException):
                    await ModelTimeout(ledger, model=model, enabled=True, deadline=time.time() + 300,
                                       tokens_per_minute=120000).execute(operation_id="unavailable-control")
            finally:
                await model.close()
        document, _ = await ledger.read()
        budget = document["budgets"]["unavailable-control"]
        self.assertEqual(len(requests), 1)
        self.assertFalse(budget["closed"])
        self.assertIsNotNone(budget["model"])
        self.assertEqual(budget["remaining"]["models"], 127)

    async def test_exported_guard_requires_two_service_responses_expired_timer_retained_permit_and_exclusion(self):
        from citadel.acceptance.admission_limits import admission_snapshot, business_hash
        from citadel.acceptance.proof_gate import evaluate_check
        from citadel.acceptance.reports import sanitize
        name, op = "limit.model_timeout_seconds", "timeout-control"
        permit = {"attempt_id": "retained-model", "deadline": 1136, "input_tokens": 16000, "output_tokens": 2000}
        document = {"operations": {}, "drafts": {}, "findings": {}, "budgets": {
            op: {"run_id": op, "closed": False, "deadline": 1900, "agents": {op: 2}, "candidates": [],
                "model": permit, "child": None, "grant": None, "grants": [], "tokens_per_minute": 120000,
                "history": [{"at": 1071, "tokens": 18000}, {"at": 1076, "tokens": 18000}],
                "remaining": {"models": 126, "tokens": 964000, "agents": 41, "reads": 512}}}}
        models = [{"request_id": f"actual-model-{index}", "status_code": 200, "target": "7" * 64,
            "started": started, "finished": started + .1, "input_tokens": 4000, "output_tokens": 1, "tokens": 4001}
            for index, started in enumerate((1070, 1076.1))]
        actual = {"operation_id": op, "deadline": 1900, "state": "timed_out", "models": models,
            "model": permit | {"accepted": 1076}, "before_sha256": business_hash(document),
            "after_sha256": business_hash(document),
            "replay": {"response": "conflict", "before_sha256": sha256(document), "after_sha256": sha256(document)},
            "slot": {side: {"scope_sha256": sha256("acceptance/worker"), "steps": [
                {"operation_id": f"{prefix}-slot{index}", "request_id": f"{side}-slot{index}",
                 "target": "1" * 64, "status_code": status, "action": action,
                 "started": start + index * .1, "finished": start + index * .1 + .01}
                for index, (action, status) in enumerate((("renew", 200), ("acquire", 409), ("renew", 200)))]}
                for side, prefix, start in (("before", op, 1000), ("after", op + "-end", 1195))}}
        observation = {"check_id": name, "probe_id": name, "operation_id": op, "run_id": "worker",
            "caller": "candidate-planner", "runtime_identity": "a" * 64, "actual": actual,
            "request_id": "publication", "status_code": 201, "target": "c" * 64, "started": 999, "finished": 1196}
        snapshot = admission_snapshot(document, actual) | {
            "request_id": "observer", "operation_id": "observer", "status_code": 206, "target": "d" * 64,
            "started": 1197, "finished": 1198, "sha256": sha256(document), "suite_id": "suite",
            "caller": "operator", "container": "planner-operations", "action": "read", "runtime_identity": "b" * 64}
        evidence = [
            observation | {"source": "storage", "method": "PutBlob", "client_request_id": op, "observed": 1196},
            observation | {"source": "application", "method": "execution", "observed": 1196,
                "facts": {"sha256": sha256(actual), "probe_id": name}},
            snapshot | {"source": "storage", "method": "GetBlob", "client_request_id": "observer", "observed": 1197}]
        for model in models:
            evidence.extend([
                model | {"source": "gateway", "method": "POST", "caller": "candidate-planner",
                    "credential_sha256": "9" * 64, "observed": model["finished"], "facts": {"backend_dispatched": True}},
                model | {"source": "application", "method": "chat.completions", "caller": "candidate-planner",
                    "runtime_identity": "a" * 64, "run_id": "worker", "operation_id": op,
                    "observed": model["finished"], "facts": {key: model[key] for key in
                        ("input_tokens", "output_tokens", "tokens", "started", "finished")}}])
        evidence.append({"source": "application", "method": "model.timeout", "run_id": "worker",
            "operation_id": op, "runtime_identity": "a" * 64, "caller": "candidate-planner",
            "observed": 1134, "status_code": 0, "request_id": "", "facts": {
                "model_attempt_id": permit["attempt_id"], "deadline": 1136, "started": 1076.05,
                "finished": 1134, "monotonic_started": 3000, "monotonic_deadline": 3059.95,
                "monotonic_finished": 3060}})
        steps = [step for value in actual["slot"].values() for step in value["steps"]]
        evidence += [step | {"source": "storage", "method": "LeaseBlob", "runtime_identity": "a" * 64,
            "client_request_id": step["operation_id"], "observed": step["finished"]} for step in steps]
        report = {"run_id": "suite", "runtime_identities": {"candidate-planner": "a" * 64,
            "evidence-assessor": "3" * 64, "release-reviewer": "4" * 64,
            "briefing-author": "5" * 64, "reference-data": "6" * 64},
            "gateway_targets": {"model": "7" * 64}, "storage_targets": {"active-run-slot": "1" * 64},
            "subscription_bindings": {"candidate-planner": "9" * 64}, "evidence": evidence,
            "operation_ids": ["worker", op, "observer", *[row["operation_id"] for row in steps]]}
        check = {"check_id": name, "expected": "boundary", "actual": {"observation": observation, "control": snapshot}}
        self.assertEqual(evaluate_check(sanitize(check), sanitize(report))["status"], "pass")
        for index in range(len(evidence)):
            self.assertEqual(evaluate_check(check, report | {"evidence": evidence[:index] + evidence[index + 1:]})["status"],
                             "blocked", index)
        for field, value in (("closed", True), ("model_active", False), ("model", None), ("history_count", 1)):
            changed = copy.deepcopy(check)
            changed["actual"]["control"]["budget_state"][field] = value
            self.assertNotEqual(evaluate_check(changed, report)["status"], "pass", field)
        changed = copy.deepcopy(report)
        next(row for row in changed["evidence"] if row["method"] == "model.timeout")["facts"]["monotonic_deadline"] += 1
        self.assertNotEqual(evaluate_check(check, changed)["status"], "pass")
        changed = copy.deepcopy(check)
        changed["actual"]["control"]["business_sha256"] = "f" * 64
        self.assertEqual(evaluate_check(changed, report)["status"], "fail")

    async def test_actual_sixty_second_guard_retains_admission_after_definite_response_without_replay(self):
        from citadel.acceptance.model_timeout import ModelTimeout
        requests, output, ledger = [], io.StringIO(), MemoryLedger()

        async def response(request):
            requests.append(request)
            return httpx2.Response(200, headers={"apim-request-id": f"received-model-{len(requests)}"},
                json={"id": "fixture", "object": "chat.completion", "created": 0, "model": "approved",
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": "OK"},
                                 "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 4000, "completion_tokens": 1, "total_tokens": 4001}})

        async with httpx2.AsyncClient(transport=httpx2.MockTransport(response)) as http:
            model = GovernedModel("candidate-planner", "https://gateway.test", "allocated", "approved", http_client=http)
            try:
                with (patch("citadel.acceptance.telemetry._exporter",
                            Telemetry("candidate-planner", "11111111-1111-1111-1111-111111111111", output=output)),
                      correlate("timeout-worker", "timeout-control", "candidate-planner")):
                    result = await ModelTimeout(ledger, model=model, enabled=True,
                        deadline=time.time() + 300, tokens_per_minute=120000).execute(operation_id="timeout-control")
            finally:
                await model.close()
        document, _ = await ledger.read()
        budget = document["budgets"]["timeout-control"]
        self.assertEqual(result["state"], "timed_out")
        self.assertEqual(len(requests), 2)
        self.assertEqual(len(result["models"]), 2)
        self.assertEqual(budget["model"], {key: result["model"][key] for key in
            ("attempt_id", "deadline", "input_tokens", "output_tokens")})
        self.assertFalse(budget["closed"])
        self.assertEqual(budget["remaining"], {"models": 126, "tokens": 964000, "agents": 41, "reads": 512})
        self.assertEqual(budget["agents"], {"timeout-control": 2})
        self.assertEqual(result["replay"]["response"], "conflict")
        self.assertEqual(result["replay"]["before_sha256"], result["replay"]["after_sha256"])
        self.assertEqual(result["before_sha256"], result["after_sha256"])
        events = [row for row in map(json.loads, output.getvalue().splitlines()) if row["method"] == "model.timeout"]
        self.assertEqual(len(events), 1)
        timer = events[0]["facts"]
        self.assertEqual(timer["model_attempt_id"], budget["model"]["attempt_id"])
        self.assertEqual(timer["deadline"] - result["model"]["accepted"], 60)
        self.assertGreaterEqual(timer["monotonic_finished"], timer["monotonic_deadline"])
        self.assertAlmostEqual(timer["monotonic_deadline"] - timer["monotonic_started"],
                               timer["deadline"] - timer["started"], places=6)
        self.assertEqual(result["replay"]["after_sha256"], sha256(document))
