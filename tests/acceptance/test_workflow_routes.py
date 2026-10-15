import copy
import json
import unittest

import httpx

from citadel.acceptance.route_context import build_route_context
from tests.acceptance.test_route_context import ledgers


class WorkflowRouteTests(unittest.TestCase):
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
