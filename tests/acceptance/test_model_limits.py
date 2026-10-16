import json
import copy
import hashlib
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import time
import unittest

import httpx2

from citadel.operations.testing import MemoryLedger
from citadel.runtime.model import GovernedModel


class ModelLimitTests(unittest.IsolatedAsyncioTestCase):
    async def test_invalid_usage_does_not_release_admission_or_escape_as_public_metadata(self):
        from citadel.acceptance.model_limits import ModelLimits
        from agent_framework.exceptions import ChatClientException
        calls = []

        async def response(request):
            calls.append(request)
            return httpx2.Response(200, headers={"apim-request-id": "malformed-usage"},
                json={"id": "fixture", "object": "chat.completion", "created": 0, "model": "approved",
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": "OK"},
                                 "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 4000, "completion_tokens": 2001, "total_tokens": 6001}})

        ledger = MemoryLedger()
        async with httpx2.AsyncClient(transport=httpx2.MockTransport(response)) as http:
            model = GovernedModel("candidate-planner", "https://gateway.test", "allocated", "approved",
                                  http_client=http)
            try:
                with self.assertRaises(ChatClientException):
                    await ModelLimits(ledger, model=model, enabled=True, deadline=time.time() + 900,
                                      tokens_per_minute=120000).boundaries(operation_id="malformed")
            finally:
                await model.close()
        document, _ = await ledger.read()
        self.assertIsNotNone(document["budgets"]["malformed"]["model"])
        self.assertFalse(document["budgets"]["malformed"]["closed"])
        self.assertEqual(len(calls), 1)

    async def test_actual_worker_keeps_own_identity_global_lease_cooldowns_and_real_sdk_result_channel(self):
        await self.exercise_worker("model-limits", 1)

    async def test_actual_execution_counter_worker_uses_eight_real_models_without_extra_grants(self):
        await self.exercise_worker("model-execution-limit", 8)

    async def test_actual_run_counter_worker_fits_physical_read_and_wall_deadline_budgets(self):
        await self.exercise_worker("model-run-limit", 128)

    async def exercise_worker(self, mode, count):
        from azure.storage.blob.aio import ContainerClient
        from azure.keyvault.secrets.aio import SecretClient
        from citadel.acceptance.worker import run_gateway_matrix
        from tests.runtime.test_storage import FixtureCredential, BlobResponse
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))
        try:
            from test_ticket_storage import TicketWire
        finally:
            sys.path.pop(0)
        secrets, models, credentials = [], [], []

        class SecretResponse(BlobResponse):
            def json(self):
                return json.loads(self.content)

        class Wire(TicketWire):
            async def send(self, request, **options):
                if request.url.startswith("https://allocated.vault.azure.net/"):
                    secrets.append(request)
                    response = SecretResponse(request, json.dumps({"value": "allocated-own-key",
                        "id": "https://allocated.vault.azure.net/secrets/subscription-candidate-planner/version1"}).encode())
                    response.status_code, response.reason = 200, "OK"
                    response.headers["content-type"] = "application/json"
                    return response
                response = await super().send(request, **options)
                response.headers["x-ms-request-id"] = "wire-" + str(len(self.requests))
                return response

        class Credential(FixtureCredential):
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

        def credential(**options):
            credentials.append(options)
            return Credential()

        async def response(request):
            models.append(request)
            return httpx2.Response(200, headers={"apim-request-id": f"actual-boundary-model-{len(models)}"},
                json={"id": "fixture", "object": "chat.completion", "created": 0, "model": "approved",
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": "OK"},
                                 "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 4000, "completion_tokens": 1, "total_tokens": 4001}})

        wire = Wire(clock=time.time)
        wire.blobs["/planner-operations/active-run-slot.json"] = b"{}"
        wire.etags["/planner-operations/active-run-slot.json"] = 1
        config = SimpleNamespace(target="candidate-planner", client_id="11111111-1111-1111-1111-111111111111",
            blob="https://allocated.blob.core.windows.net", operations_container="planner-operations",
            vault="https://allocated.vault.azure.net", subscription_secret="subscription-candidate-planner",
            gateway="https://gateway.test", model_deployment="approved", tokens_per_minute=120000)
        request = {"schema_version": 1, "mode": mode, "workload": config.target,
            "client_id": config.client_id, "run_id": "model-boundary-worker",
            "deadline": time.time() + (900 if count == 128 else 300)}
        async with httpx2.AsyncClient(transport=httpx2.MockTransport(response)) as http:
            with (patch.dict(os.environ, {"CITADEL_ACCEPTANCE_ENABLED": "true", "AZURE_PRINCIPAL_ID": config.client_id}),
                  patch("citadel.acceptance.worker.ManagedIdentityCredential", credential),
                  patch("citadel.acceptance.worker.ContainerClient",
                        lambda *args, **kw: ContainerClient(*args, transport=wire, **kw)),
                  patch("citadel.acceptance.worker.SecretClient",
                        lambda *args, **kw: SecretClient(*args, transport=wire, **kw)),
                  patch("citadel.runtime.model.GovernedModel",
                        lambda *args, **kw: GovernedModel(*args, http_client=http, **kw))):
                rows = await run_gateway_matrix(config, request)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status_code"], 201)
        self.assertEqual(credentials, [{"client_id": config.client_id, "retry_total": 0}])
        self.assertEqual(len(secrets), 1)
        self.assertIn("/secrets/subscription-candidate-planner/?api-version=2025-07-01", secrets[0].url)
        self.assertEqual(len(models), count)
        self.assertEqual(models[0].headers["Ocp-Apim-Subscription-Key"], "allocated-own-key")
        actual = rows[0]["actual"]
        receipts = [actual["model"]] if mode == "model-limits" else actual["models"]
        self.assertGreaterEqual(receipts[0]["started"] - actual["slot"]["before"]["steps"][-1]["finished"], 60)
        self.assertGreaterEqual(actual["slot"]["after"]["steps"][0]["started"] - receipts[-1]["finished"], 60)
        self.assertNotIn("/planner-operations/active-run-slot.json", wire.leases)
        self.assertLessEqual(len([path for path in wire.blobs if "/read-tickets/" in path]), 512)
        self.assertNotIn("/planner-operations/ledger-v1.json", wire.blobs)
        self.assertNotIn("allocated-own-key", str(rows))
        with (patch.dict(os.environ, {"CITADEL_ACCEPTANCE_ENABLED": "true", "AZURE_PRINCIPAL_ID": config.client_id}),
              patch("citadel.acceptance.worker.ManagedIdentityCredential", credential),
              patch("citadel.acceptance.worker.ContainerClient",
                    lambda *args, **kw: ContainerClient(*args, transport=wire, **kw))):
            from azure.core.exceptions import ResourceExistsError
            with self.assertRaises(ResourceExistsError):
                await run_gateway_matrix(config, request)
        self.assertEqual(len(models), count)

    async def test_real_framework_request_at_exact_token_bounds_and_concurrent_overflow_never_redispatch(self):
        from citadel.acceptance.model_limits import ModelLimits
        requests = []

        async def respond(request):
            requests.append(json.loads(request.content))
            return httpx2.Response(200, headers={"apim-request-id": "actual-model-boundary"},
                json={"id": "fixture", "object": "chat.completion", "created": 0, "model": "approved",
                      "choices": [{"index": 0, "message": {"role": "assistant", "content": "OK"},
                                   "finish_reason": "stop"}],
                      "usage": {"prompt_tokens": 4000, "completion_tokens": 1, "total_tokens": 4001}})

        ledger = MemoryLedger()
        async with httpx2.AsyncClient(transport=httpx2.MockTransport(respond)) as http:
            model = GovernedModel("candidate-planner", "https://gateway.test", "allocated-test-key",
                                  "approved", http_client=http)
            try:
                result = await ModelLimits(ledger, model=model, enabled=True,
                    deadline=time.time() + 700, tokens_per_minute=120000).boundaries(operation_id="bounds1")
            finally:
                await model.close()
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0]["max_completion_tokens"], 2000)
        self.assertEqual(result["model"]["request_id"], "actual-model-boundary")
        self.assertEqual(result["input_tokens"], 16000)
        self.assertEqual(result["output_tokens"], 2000)
        self.assertEqual({row["check_id"]: row["response"] for row in result["checks"]}, {
            "limit.input_tokens_attempt": "exhausted", "limit.output_tokens_attempt": "exhausted",
            "limit.model_concurrency": "conflict"})
        self.assertTrue(all(row["before_sha256"] == row["after_sha256"] for row in result["checks"]))
        document, _ = await ledger.read()
        budget = document["budgets"]["bounds1"]
        self.assertEqual(budget["remaining"], {"agents": 41, "models": 127, "tokens": 982000, "reads": 512})
        self.assertTrue(budget["closed"])
        self.assertIsNone(budget["model"])
        self.assertEqual(budget["agents"], {"bounds1": 1})
        self.assertNotIn("padding", str(result))
        self.assertNotIn("allocated-test-key", str(result))
        from citadel.acceptance.admission_limits import admission_snapshot
        from citadel.acceptance.proof_gate import evaluate_check
        from citadel.acceptance.reports import sanitize
        from citadel.evidence.manifests import sha256
        start, end = result["model"]["started"], result["model"]["finished"]
        result["slot"] = {}
        for side, offset, prefix in (("before", start - 61, "bounds1"), ("after", end + 61, "bounds1-end")):
            result["slot"][side] = {"scope_sha256": sha256("acceptance/worker"), "steps": [
                {"operation_id": f"{prefix}-slot{index}", "request_id": f"{side}-slot{index}",
                 "target": "1" * 64, "status_code": status, "action": action,
                 "started": offset + index * .1, "finished": offset + index * .1 + .01}
                for index, (action, status) in enumerate((("renew", 200), ("acquire", 409), ("renew", 200)))]}
        observation = {"check_id": "limit.input_tokens_attempt", "probe_id": "limit.input_tokens_attempt",
            "operation_id": "bounds1", "run_id": "worker", "caller": "candidate-planner",
            "runtime_identity": "a" * 64, "actual": result, "request_id": "publication", "status_code": 201,
            "target": "c" * 64, "started": start - 62, "finished": end + 62}
        snapshot = admission_snapshot(document, result) | {
            "request_id": "observer", "operation_id": "observer", "status_code": 206, "target": "d" * 64,
            "started": end + 63, "finished": end + 64, "sha256": sha256(document),
            "suite_id": "suite1", "caller": "operator", "container": "planner-operations",
            "action": "read", "runtime_identity": "b" * 64}
        evidence = [
            observation | {"source": "storage", "method": "PutBlob", "client_request_id": "bounds1",
                           "observed": end + 62},
            observation | {"source": "application", "method": "execution", "observed": end + 62,
                           "facts": {"sha256": sha256(result), "probe_id": "limit.input_tokens_attempt"}},
            snapshot | {"source": "storage", "method": "GetBlob", "client_request_id": "observer",
                        "observed": end + 63},
            result["model"] | {"source": "gateway", "method": "POST", "caller": "candidate-planner",
                "credential_sha256": "9" * 64, "observed": end, "facts": {"backend_dispatched": True}},
            result["model"] | {"source": "application", "method": "chat.completions", "caller": "candidate-planner",
                "runtime_identity": "a" * 64, "run_id": "worker", "operation_id": "bounds1",
                "observed": end, "facts": {key: result["model"][key] for key in (
                    "input_tokens", "output_tokens", "tokens", "started", "finished")}},
        ]
        steps = [step for value in result["slot"].values() for step in value["steps"]]
        evidence += [step | {"source": "storage", "method": "LeaseBlob", "runtime_identity": "a" * 64,
                            "client_request_id": step["operation_id"], "observed": step["finished"]}
                     for step in steps]
        report = {"run_id": "suite1", "runtime_identities": {"candidate-planner": "a" * 64,
            "evidence-assessor": "3" * 64, "release-reviewer": "4" * 64,
            "briefing-author": "5" * 64, "reference-data": "6" * 64},
            "gateway_targets": {"model": result["model"]["target"]},
            "storage_targets": {"active-run-slot": "1" * 64},
            "subscription_bindings": {"candidate-planner": "9" * 64}, "evidence": evidence,
            "operation_ids": ["worker", "bounds1", "observer", *[row["operation_id"] for row in steps]]}
        for name in ("limit.input_tokens_attempt", "limit.output_tokens_attempt", "limit.model_concurrency"):
            check = {"check_id": name, "expected": "boundary", "actual": {
                "observation": observation | {"check_id": name}, "control": snapshot}}
            self.assertEqual(evaluate_check(sanitize(check), sanitize(report))["status"], "pass", name)
            for index in range(len(evidence)):
                changed = report | {"evidence": evidence[:index] + evidence[index + 1:]}
                self.assertEqual(evaluate_check(check, changed)["status"], "blocked", (name, index))
            changed = copy.deepcopy(check)
            changed["actual"]["control"]["budget_state"]["remaining"]["tokens"] = 982001
            self.assertEqual(evaluate_check(changed, report)["status"], "fail")
        from citadel.acceptance.worker import validate_request
        from citadel.acceptance.operation_harness import bind_operation_result
        request = {"schema_version": 1, "run_id": "worker", "workload": "candidate-planner",
            "client_id": "11111111-1111-1111-1111-111111111111",
            "mode": "model-limits", "deadline": time.time() + 900}
        validate_request(request, enabled=True, workload="candidate-planner", client_id=request["client_id"])
        for role in ("evidence-assessor", "release-reviewer", "briefing-author"):
            with self.assertRaises(ValueError):
                validate_request(request | {"workload": role}, enabled=True, workload=role, client_id=request["client_id"])
        account = "https://allocated.blob.core.windows.net"
        observation["target"] = hashlib.sha256(
            (account + "/planner-operations/acceptance/worker/observations/bounds1.json").encode()).hexdigest()
        for step in steps:
            step["target"] = hashlib.sha256((account + "/planner-operations/active-run-slot.json").encode()).hexdigest()
        bound = bind_operation_result({"schema_version": 1, "run_id": "worker", "state": "complete",
            "observations": [observation]}, run_id="worker", principal="a" * 64, account=account, mode="model-limits")
        self.assertEqual(len(bound), 7)
