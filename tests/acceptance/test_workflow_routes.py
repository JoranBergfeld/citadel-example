import copy
import json
import unittest

import httpx

from citadel.acceptance.route_context import build_route_context
from tests.acceptance.test_route_context import ledgers


class WorkflowRouteTests(unittest.TestCase):
    def test_unusable_wall_clock_receipt_is_not_evidence_and_does_not_abort_valid_work(self):
        from citadel.acceptance.workflow_routes import observe_status, status_controls
        documents = ledgers()
        context = build_route_context(documents, run_ids=["real-run"])
        body = documents["evidence-assessor"]["operations"]["candidate-planner/invoke/assess2"]
        response = httpx.Response(200,
            request=httpx.Request("GET", "https://gateway.example/evidence-assessor/operations/assess2"),
            headers={"apim-request-id": "actual-service"}, json=body)
        for finished in (99, 131, float("nan"), float("inf")):
            with self.subTest(finished=finished):
                record = observe_status(response, caller="candidate-planner", target="evidence-assessor",
                    run_id="real-run", operation_id="parent1", started=100, finished=finished)
                self.assertIsNone(record)
                self.assertEqual(status_controls([], context), [])

    def test_invocation_receipt_requires_real_task_identity_and_matching_completed_source(self):
        from a2a.types import SendMessageResponse, Task, TaskStatus, TaskState
        from google.protobuf.json_format import MessageToDict
        from citadel.acceptance.workflow_routes import observe_invocation, invocation_controls
        from citadel.evidence.manifests import sha256
        context = build_route_context(ledgers(), run_ids=["real-run"])
        request = httpx.Request("POST", "https://gateway.example/evidence-assessor/a2a",
            json={"jsonrpc": "2.0", "method": "SendMessage", "id": "wire"})
        result = MessageToDict(SendMessageResponse(task=Task(id="assess2", context_id="real-run",
            status=TaskStatus(state=TaskState.TASK_STATE_SUBMITTED))))
        response = httpx.Response(200, request=request, headers={"apim-request-id": "accepted-service"},
            json={"jsonrpc": "2.0", "id": "wire", "result": result})
        record = observe_invocation(response, caller="candidate-planner", target="evidence-assessor",
            run_id="real-run", operation_id="parent1", started=100, finished=101)
        self.assertEqual(record["method"], "invocation.observed")
        evidence = [record | {"source": "application", "runtime_identity": "a" * 64, "observed": 101}]
        observed = invocation_controls(evidence, context)
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0]["accepted_operation_id"], "assess2")
        self.assertEqual(record["facts"]["sha256"], sha256(observed[0]))
        for changes in ({"facts": record["facts"] | {"accepted_operation_id": "other"}},
                        {"source": "console"}, {"request_id": None}):
            self.assertEqual(invocation_controls([evidence[0] | changes], context), [])
        for body in ({"jsonrpc": "2.0", "id": "wrong", "result": result},
                     {"jsonrpc": "2.0", "id": "wire", "result": {"task": {}}}):
            self.assertIsNone(observe_invocation(httpx.Response(200, request=request,
                headers={"apim-request-id": "accepted-service"}, json=body),
                caller="candidate-planner", target="evidence-assessor", run_id="real-run",
                operation_id="parent1", started=100, finished=101))

    def test_actual_completed_status_observation_reconstructs_only_matching_genuine_context(self):
        from citadel.acceptance.workflow_routes import observe_status, status_controls
        from citadel.evidence.manifests import sha256
        documents = ledgers()
        context = build_route_context(documents, run_ids=["real-run"])
        body = documents["evidence-assessor"]["operations"]["candidate-planner/invoke/assess2"]
        request = httpx.Request("GET", "https://gateway.example/evidence-assessor/operations/assess2")
        response = httpx.Response(200, request=request, headers={"apim-request-id": "actual-service"}, json=body)
        record = observe_status(response, caller="candidate-planner", target="evidence-assessor",
            run_id="real-run", operation_id="parent1", started=100, finished=101)
        self.assertEqual(record["method"], "status.observed")
        self.assertNotIn("private test prose", json.dumps(record))
        records = [record | {"source": "application", "runtime_identity": "a" * 64, "observed": 101}]
        observed = status_controls(records, context)
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0]["control_reference"], context["operations"]["evidence-assessor"])
        self.assertEqual(observed[0]["observation_kind"], "workflow")
        self.assertEqual(record["facts"]["sha256"], sha256(observed[0]))
        changed = copy.deepcopy(records)
        changed[0]["facts"]["result_sha256"] = "9" * 64
        self.assertEqual(status_controls(changed, context), [])
        changed = copy.deepcopy(records)
        changed[0]["source"] = "console"
        self.assertEqual(status_controls(changed, context), [])
        response = httpx.Response(200, request=request, json=body | {"state": "pending"})
        self.assertIsNone(observe_status(response, caller="candidate-planner", target="evidence-assessor",
            run_id="real-run", operation_id="parent1", started=100, finished=101))
