import hashlib
import time
import unittest
from types import SimpleNamespace

import httpx

from citadel.acceptance.origin_harness import BoundaryAcceptance, bind_origin_result, operator_discovery
from citadel.operator.state import Blocked
from citadel.operations import OperationError


class OriginHarnessTests(unittest.IsolatedAsyncioTestCase):
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
