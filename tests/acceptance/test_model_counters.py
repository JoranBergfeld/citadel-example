import json
import copy
import hashlib
import time
import unittest

import httpx2

from citadel.operations.testing import MemoryLedger
from citadel.runtime.model import GovernedModel


class ModelCounterTests(unittest.IsolatedAsyncioTestCase):
    def assert_counter_proof(self, result, document):
        from citadel.acceptance.admission_limits import admission_snapshot
        from citadel.acceptance.proof_gate import evaluate_check
        from citadel.acceptance.reports import sanitize
        from citadel.evidence.manifests import sha256
        name = {"execution": "limit.model_attempts_execution", "run": "limit.model_attempts_run",
                "tokens": "limit.tokens_run"}[result["counter_kind"]]
        operation = result["operation_id"]
        start, end = result["models"][0]["started"], result["models"][-1]["finished"]
        result["slot"] = {}
        for side, offset, prefix in (("before", start - 61, operation), ("after", end + 61, operation + "-end")):
            result["slot"][side] = {"scope_sha256": sha256("acceptance/worker"), "steps": [
                {"operation_id": f"{prefix}-slot{index}", "request_id": f"{side}-slot{index}",
                 "target": "1" * 64, "status_code": status, "action": action,
                 "started": offset + index * .1, "finished": offset + index * .1 + .01}
                for index, (action, status) in enumerate((("renew", 200), ("acquire", 409), ("renew", 200)))]}
        observed = {"check_id": name, "probe_id": name, "operation_id": operation, "run_id": "worker",
            "caller": "candidate-planner", "runtime_identity": "a" * 64, "actual": result,
            "request_id": "publication", "status_code": 201, "target": "c" * 64,
            "started": start - 62, "finished": end + 62}
        control = admission_snapshot(document, result) | {
            "request_id": "observer", "operation_id": "observer", "status_code": 206, "target": "d" * 64,
            "started": end + 63, "finished": end + 64, "sha256": sha256(document), "suite_id": "suite1",
            "caller": "operator", "container": "planner-operations", "action": "read", "runtime_identity": "b" * 64}
        rows = [
            observed | {"source": "storage", "method": "PutBlob", "client_request_id": operation,
                        "observed": end + 62},
            observed | {"source": "application", "method": "execution", "observed": end + 62,
                        "facts": {"sha256": sha256(result), "probe_id": name}},
            control | {"source": "storage", "method": "GetBlob", "client_request_id": "observer",
                       "observed": end + 63}]
        for model in result["models"]:
            rows += [
                model | {"source": "gateway", "method": "POST", "observed": model["finished"],
                    "caller": "candidate-planner", "credential_sha256": "9" * 64,
                    "facts": {"backend_dispatched": True}},
                model | {"source": "application", "method": "chat.completions", "observed": model["finished"],
                    "caller": "candidate-planner", "runtime_identity": "a" * 64, "run_id": "worker",
                    "operation_id": operation, "facts": {key: model[key] for key in (
                        "input_tokens", "output_tokens", "tokens", "started", "finished")}}]
        slots = [step for slot in result["slot"].values() for step in slot["steps"]]
        rows += [step | {"source": "storage", "method": "LeaseBlob", "observed": step["finished"],
                        "runtime_identity": "a" * 64, "client_request_id": step["operation_id"]} for step in slots]
        report = {"run_id": "suite1", "runtime_identities": {"candidate-planner": "a" * 64,
            "evidence-assessor": "3" * 64, "release-reviewer": "4" * 64, "briefing-author": "5" * 64,
            "reference-data": "6" * 64}, "gateway_targets": {"model": result["models"][0]["target"]},
            "storage_targets": {"active-run-slot": "1" * 64},
            "subscription_bindings": {"candidate-planner": "9" * 64}, "evidence": rows,
            "operation_ids": ["worker", operation, "observer", *[row["operation_id"] for row in slots]]}
        check = {"check_id": name, "expected": "boundary", "actual": {"observation": observed, "control": control}}
        self.assertEqual(evaluate_check(sanitize(check), sanitize(report))["status"], "pass", name)
        for source in ("application", "gateway", "storage"):
            changed = report | {"evidence": [row for row in rows if row["source"] != source]}
            self.assertEqual(evaluate_check(check, changed)["status"], "blocked")
        changed = copy.deepcopy(check)
        changed["actual"]["control"]["budget_state"]["remaining"]["models"] += 1
        self.assertEqual(evaluate_check(changed, report)["status"], "fail")
        from citadel.acceptance.worker import validate_request
        from citadel.acceptance.operation_harness import bind_operation_result, FaultAcceptance
        mode = {"execution": "model-execution-limit", "run": "model-run-limit",
                "tokens": "model-token-limit"}[result["counter_kind"]]
        request = {"schema_version": 1, "mode": mode, "workload": "candidate-planner",
            "client_id": "11111111-1111-1111-1111-111111111111", "run_id": "worker", "deadline": time.time() + 900}
        validate_request(request, enabled=True, workload="candidate-planner", client_id=request["client_id"])
        published = copy.deepcopy(observed)
        account = "https://allocated.blob.core.windows.net"
        published["target"] = hashlib.sha256(
            f"{account}/planner-operations/acceptance/worker/observations/{operation}.json".encode()).hexdigest()
        for slot in published["actual"]["slot"].values():
            for row in slot["steps"]:
                row["target"] = hashlib.sha256(f"{account}/planner-operations/active-run-slot.json".encode()).hexdigest()
        self.assertEqual(len(bind_operation_result(
            {"schema_version": 1, "run_id": "worker", "state": "complete", "observations": [published]},
            run_id="worker", principal="a" * 64, account=account, mode=mode)), 7)
        report["model_counter_" + result["counter_kind"] + "_phase"] = {
            "observations": [observed], "snapshots": {operation: control}}
        collected = FaultAcceptance.evaluate(report, rows, mode=mode)
        self.assertEqual(len(collected), 1)
        self.assertEqual(collected[0]["status"], "pass")

    async def test_run_attempt_and_aggregate_token_bounds_are_reached_only_by_actual_completed_requests(self):
        from citadel.acceptance.model_counters import ModelCounters
        for kind, count, remaining_models, remaining_tokens, agents in (
                ("run", 128, 0, None, 17), ("tokens", 55, 73, 10000, 7)):
            now, requests = [time.time()], []

            async def sleep(seconds):
                now[0] += seconds

            async def response(request):
                requests.append(request)
                return httpx2.Response(200, headers={"apim-request-id": f"physical-{len(requests)}"},
                    json={"id": "fixture", "object": "chat.completion", "created": 0, "model": "approved",
                        "choices": [{"index": 0, "message": {"role": "assistant", "content": "OK"},
                                     "finish_reason": "stop"}],
                        "usage": {"prompt_tokens": 100, "completion_tokens": 1, "total_tokens": 101}})

            ledger = MemoryLedger(clock=lambda: now[0])
            async with httpx2.AsyncClient(transport=httpx2.MockTransport(response)) as http:
                model = GovernedModel("candidate-planner", "https://gateway.test", "allocated", "approved",
                                      http_client=http, clock=lambda: now[0], sleep=sleep)
                try:
                    result = await ModelCounters(ledger, model=model, enabled=True,
                        deadline=now[0] + 800, tokens_per_minute=120000).execute(kind, operation_id="whole-run")
                finally:
                    await model.close()
            self.assertEqual(len(requests), count)
            self.assertEqual(len(result["models"]), count)
            self.assertEqual(result["response"], "exhausted")
            self.assertEqual(result["before_sha256"], result["after_sha256"])
            document, _ = await ledger.read()
            budget = document["budgets"]["whole-run"]
            self.assertEqual(budget["remaining"]["models"], remaining_models)
            self.assertEqual(budget["remaining"]["agents"], 42 - agents)
            self.assertEqual(sum(budget["agents"].values()), count)
            self.assertLessEqual(max(budget["agents"].values()), 8)
            self.assertTrue(budget["closed"])
            self.assertEqual(budget["remaining"]["tokens"], 1000000 - sum(
                row["input_bound"] + row["output_bound"] for row in result["models"]))
            if remaining_tokens is not None:
                self.assertEqual(budget["remaining"]["tokens"], remaining_tokens)
            else:
                self.assertGreater(budget["remaining"]["tokens"], 0)
            self.assert_counter_proof(result, document)

    async def test_eight_actual_framework_responses_precede_ninth_execution_attempt_refusal(self):
        from citadel.acceptance.model_counters import ModelCounters
        now, calls = [time.time()], []

        async def sleep(seconds):
            now[0] += seconds

        async def response(request):
            calls.append(request)
            return httpx2.Response(200, headers={"apim-request-id": "physical-" + str(len(calls))},
                json={"id": "fixture", "object": "chat.completion", "created": 0, "model": "approved",
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": "OK"},
                                 "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 100, "completion_tokens": 1, "total_tokens": 101}})

        ledger = MemoryLedger(clock=lambda: now[0])
        async with httpx2.AsyncClient(transport=httpx2.MockTransport(response)) as http:
            model = GovernedModel("candidate-planner", "https://gateway.test", "own-test-key", "approved",
                                  http_client=http, clock=lambda: now[0], sleep=sleep)
            try:
                result = await ModelCounters(ledger, model=model, enabled=True,
                    deadline=now[0] + 800, tokens_per_minute=120000).execute(
                        "execution", operation_id="execution-count")
            finally:
                await model.close()
        self.assertEqual(len(calls), 8)
        self.assertEqual(len(result["models"]), 8)
        self.assertEqual(result["response"], "exhausted")
        self.assertEqual(result["before_sha256"], result["after_sha256"])
        document, _ = await ledger.read()
        budget = document["budgets"]["execution-count"]
        self.assertEqual(budget["remaining"]["models"], 120)
        self.assertEqual(budget["agents"], {"execution-count-e00": 8})
        self.assertTrue(budget["closed"])
        self.assertTrue(all(json.loads(call.content)["max_completion_tokens"] == 2000 for call in calls))
        self.assertNotIn("own-test-key", str(result))
        self.assert_counter_proof(result, document)
