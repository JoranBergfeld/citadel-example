import hashlib
import time
import unittest
from types import SimpleNamespace

import httpx

from citadel.acceptance.origin_harness import BoundaryAcceptance, bind_origin_result, operator_discovery
from citadel.operator.state import Blocked
from citadel.operations import OperationError


class OriginHarnessTests(unittest.IsolatedAsyncioTestCase):
    def test_collection_uses_correlated_workflow_status_without_dispatching_an_extra_read(self):
        from tests.acceptance.test_route_oracle import owner_route_proof
        from citadel.evidence.manifests import sha256
        args, context, reads = owner_route_proof("status")
        observed, control, snapshots, records, identities, _ = args
        control.update(observation_kind="workflow", run_id="real-run", started=80, finished=81,
                       sources=["gateway"], reason="observed")
        records[2]["observed"] = 80.5
        reference = control["control_reference"]
        records[3].update(control, observed=80.5, method="status.observed", facts={
            "probe_id": control["check_id"], "sha256": sha256(control),
            "read_operation_id": reference["operation_id"], "input_hash": reference["input_hash"],
            "result_sha256": reference["result_sha256"], "started": 80, "finished": 81})
        records[4].update(control, observed=80.5)
        subscriptions = [
            "/subscriptions/s/resourceGroups/g/providers/Microsoft.ApiManagement/service/a/subscriptions/" + caller
            for caller in ("candidate-planner", "briefing-author")]
        for row in records:
            if row["source"] == "gateway":
                resource = next(value for value in subscriptions if value.endswith("/" + row["caller"]))
                row["credential_sha256"] = hashlib.sha256(resource.lower().encode()).hexdigest()
        lifecycle = SimpleNamespace(value={"outputs": {"inventory": {"gateway": {"subscriptions": subscriptions}}}})
        report = {"run_id": "suite1", "operation_ids": ["real-run"], "boundary_phase": {
            "origins": [], "gateway": [observed], "identities": identities, "route_context": context,
            "context_reads": reads, "snapshots": {observed["run_id"]: snapshots}}}
        evaluated = BoundaryAcceptance(lifecycle).evaluate(report, records)
        self.assertEqual({row["check_id"]: row["status"] for row in evaluated},
                         {observed["check_id"]: "pass", control["check_id"]: "pass"})
        self.assertIn(control["operation_id"], report["operation_ids"])

    def test_boundary_driver_persists_comparison_derived_targets_before_fixed_operator_dispatch(self):
        from tests.acceptance.test_storage_controls import BlobProvider
        from tests.acceptance.test_route_context import ledgers
        from citadel.runtime.configuration import OPERATIONS
        from unittest.mock import patch
        import json
        native, documents, saves, requests = BlobProvider(), ledgers(), [], []
        for actor, container in {**OPERATIONS, "findings": "findings"}.items():
            native.objects[container, "ledger-v1.json"] = json.dumps(
                documents[actor] | {"schema_version": 1}).encode()
        report = {"run_id": "suite1", "operation_ids": ["real-run"],
                  "scenarios": {"comparison": {"operation_id": "real-run"}}}
        lifecycle = SimpleNamespace(native=native, value={
            "inventory": ["/subscriptions/s/resourceGroups/g/providers/Microsoft.Storage/storageAccounts/allocated"],
            "outputs": {"appInventory": [], "gatewayUrl": "https://gateway.example"}},
            state=SimpleNamespace(save=lambda: saves.append(len(native.requests))),
            credentials=lambda: {"callerStates": {"operator": "active"},
                                 "callerKeys": {"operator": {"primary": "operator-only"}}})
        def provider(request):
            requests.append(request)
            self.assertIn("route_context", report["boundary_phase"])
            self.assertGreaterEqual(saves[-1], 5)
            return httpx.Response(403, headers={
                "apim-request-id": "wire-" + str(len(requests)), "x-citadel-denial": "route_denied"})
        client_type = httpx.AsyncClient
        with patch("httpx.AsyncClient", lambda **kw: client_type(transport=httpx.MockTransport(provider), **kw)):
            rows = BoundaryAcceptance(lifecycle).execute(report)
        self.assertEqual(len(rows), 20)
        self.assertEqual(len(report["boundary_phase"]["context_reads"]), 5)
        self.assertIn("review1", report["operation_ids"])
        self.assertIn("review2", report["operation_ids"])
        self.assertEqual(len(set(report["operation_ids"])), len(report["operation_ids"]))
        self.assertEqual(report["boundary_phase"]["state"], "observed")
        self.assertTrue(all(row["status_code"] == 403 for row in rows))
        self.assertTrue(all(method == "GET" for method, _, _ in native.requests))

    async def test_operator_matrix_reads_only_own_key_and_actual_owner_task_without_workload_impersonation(self):
        from citadel.acceptance.origin_harness import operator_routes
        from citadel.acceptance.route_context import build_route_context
        from tests.acceptance.test_route_context import ledgers
        from a2a.types import Task, TaskStatus, TaskState, Artifact, Part
        from google.protobuf.json_format import MessageToDict
        import json
        documents = ledgers()
        context = build_route_context(documents, run_ids=["real-run"])
        row = documents["candidate-planner"]["operations"]["operator/invoke/real-run"]
        requests, reads = [], []

        class OwnKey(dict):
            def __getitem__(self, key):
                self_case.assertEqual(key, "operator")
                return super().__getitem__(key)
        self_case = self
        lifecycle = SimpleNamespace(value={"outputs": {"gatewayUrl": "https://gateway.example"}},
            credentials=lambda: {"callerStates": OwnKey(operator="active"),
                                 "callerKeys": OwnKey(operator={"primary": "only-operator-key"})})

        def provider(request):
            requests.append(request)
            self.assertEqual(request.headers["Ocp-Apim-Subscription-Key"], "only-operator-key")
            headers = {"apim-request-id": "actual-" + str(len(requests))}
            if request.url.path == "/candidate-planner/operations/real-run":
                return httpx.Response(200, headers=headers, json=row)
            if request.url.path == "/candidate-planner/a2a":
                self.assertEqual(request.headers["a2a-version"], "1.0")
                payload = json.loads(request.content)
                self.assertEqual(payload["method"], "GetTask")
                task = Task(id="real-run", context_id="real-run",
                    status=TaskStatus(state=TaskState.TASK_STATE_COMPLETED),
                    artifacts=[Artifact(artifact_id="real-run", parts=[Part(text=json.dumps(row["product"]))])])
                return httpx.Response(200, headers=headers,
                    json={"jsonrpc": "2.0", "id": payload["id"], "result": MessageToDict(task)})
            if request.url.path == "/candidate-planner/.well-known/agent-card.json":
                return httpx.Response(200, headers=headers, json={"supportedInterfaces": [{
                    "url": "https://gateway.example/candidate-planner/a2a",
                    "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}]})
            return httpx.Response(403, headers=headers | {"x-citadel-denial": "route_denied"})

        async with httpx.AsyncClient(transport=httpx.MockTransport(provider)) as client:
            observed = await operator_routes(lifecycle, run_id="suite1", deadline=time.time() + 120,
                admit=lambda: reads.append(1), client=client, route_context=context)
        self.assertEqual(len(requests), 20)
        self.assertEqual(len(reads), 20)
        self.assertEqual({item.get("actual") for item in observed if item["status_code"] == 200},
                         {"gateway_card", "owned_status", "owned_task"})
        self.assertTrue(all(row["caller"] == "operator" and "runtime_identity" not in row for row in observed))
        self.assertNotIn("only-operator-key", str(observed))
        self.assertNotIn("private test prose", str(observed))

    def test_collected_gateway_controls_are_evaluated_individually_with_observer_evidence(self):
        from tests.acceptance.test_route_oracle import route_proof
        observed, control, snapshots, records, identities, _ = route_proof()
        subscriptions = [
            "/subscriptions/s/resourceGroups/g/providers/Microsoft.ApiManagement/service/a/subscriptions/" + caller
            for caller in ("candidate-planner", "briefing-author")]
        for row in records:
            if row["source"] == "gateway":
                resource = next(value for value in subscriptions if value.endswith("/" + row["caller"]))
                row["credential_sha256"] = hashlib.sha256(resource.lower().encode()).hexdigest()
        lifecycle = SimpleNamespace(value={"outputs": {"inventory": {"gateway": {"subscriptions": subscriptions}}}})
        report = {"run_id": "suite1", "boundary_phase": {
            "origins": [], "gateway": [observed, control], "identities": identities,
            "snapshots": {observed["run_id"]: snapshots, control["run_id"]: snapshots}}}
        evaluated = BoundaryAcceptance(lifecycle).evaluate(report, records)
        self.assertEqual({row["check_id"]: row["status"] for row in evaluated},
                         {observed["check_id"]: "pass", control["check_id"]: "pass"})
        self.assertTrue(all("before" in row["actual"] and "after" in row["actual"] for row in evaluated))

    async def test_expired_operator_control_refuses_even_private_credential_access(self):
        lifecycle = SimpleNamespace(credentials=lambda: self.fail("Expired control accessed credentials"))
        with self.assertRaises(OperationError):
            await operator_discovery(lifecycle, run_id="origin1", deadline=time.time() - 1,
                                     admit=lambda: self.fail("Expired control admitted"), client=None)

    def test_collection_before_origin_dispatch_does_not_invent_results_or_require_unused_inventory(self):
        self.assertEqual(BoundaryAcceptance(SimpleNamespace(value={})).evaluate({}, []), [])

    async def test_operator_positive_control_uses_only_its_own_allocated_credential(self):
        requests = []

        async def provider(request):
            requests.append(request)
            self.assertEqual(request.headers["Ocp-Apim-Subscription-Key"], "allocated-operator-test-key")
            return httpx.Response(200, headers={"apim-request-id": "actual-gateway-id"},
                json={"supportedInterfaces": [{"url": "https://gateway.example/candidate-planner/a2a",
                      "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}]})

        lifecycle = SimpleNamespace(value={"outputs": {"gatewayUrl": "https://gateway.example"}},
            credentials=lambda: {"callerStates": {"operator": "active"},
                                "callerKeys": {"operator": {"primary": "allocated-operator-test-key"}}})
        reads = []
        async with httpx.AsyncClient(transport=httpx.MockTransport(provider)) as client:
            result = await operator_discovery(lifecycle, run_id="origin1", deadline=time.time() + 120,
                                             admit=lambda: reads.append(1), client=client)
        self.assertEqual(len(requests), 1)
        self.assertEqual(reads, [1])
        self.assertEqual(result["actual"], "gateway_card")
        self.assertEqual(result["caller"], "operator")
        self.assertNotIn("runtime_identity", result)
        self.assertEqual(result["request_id"], "actual-gateway-id")
        self.assertEqual(requests[0].headers["x-citadel-operation-id"], result["operation_id"])
        self.assertEqual(str(requests[0].url),
                         "https://gateway.example/candidate-planner/.well-known/agent-card.json")

    def test_origin_worker_result_requires_all_exact_modes_and_bound_destination_identity(self):
        origin = "https://actual.example.azurecontainerapps.io"
        rows = [{"run_id": "r1", "operation_id": f"op{index}",
                 "caller": "evidence-assessor", "runtime_identity": "a" * 64,
                 "check_id": "origin.evidence-assessor." + mode,
                 "target": hashlib.sha256((origin + "/.well-known/agent-card.json").encode()).hexdigest()}
                for index, mode in enumerate(("missing-certificate", "unrelated-certificate", "forged-context"))]
        result = {"schema_version": 1, "run_id": "r1", "state": "complete", "observations": rows}

        def bind(value):
            return bind_origin_result(value, actor="evidence-assessor", run_id="r1",
                                      principal="a" * 64, origin=origin)

        self.assertEqual(bind(result), ["op0", "op1", "op2"])
        for altered in (result | {"observations": rows[:1]},
                        result | {"observations": [rows[0], rows[0], rows[2]]},
                        result | {"observations": [rows[0] | {"runtime_identity": "b" * 64}, *rows[1:]]}):
            with self.assertRaises(Blocked):
                bind(altered)
