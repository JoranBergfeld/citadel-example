import asyncio
import json
import io
import sys
import time
import unittest
from contextlib import AsyncExitStack, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import httpx
import httpx2

from citadel.acceptance.probes import GatewayProbe, OperatorProbe
from citadel.acceptance.route_context import build_route_context
from citadel.operator.scenarios import PlannerClient
from citadel.runtime.agents import Runtime, agent_application
from citadel.runtime.model import GovernedModel
from citadel.runtime.network import GatewayPeers
from citadel.runtime.reference import reference_application


class OwnerRouteRuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_completed_workflow_funds_owner_and_finding_controls_without_new_grants_or_refills(self):
        runtime_tests = str(Path(__file__).resolve().parents[1] / "runtime")
        sys.path.insert(0, runtime_tests)
        try:
            from test_reference import reference, trust
            from test_read_tickets import CountingLedger
            from test_workflow import FixtureGateway
        finally:
            sys.path.remove(runtime_tests)
        class Wire(FixtureGateway):
            async def handle_async_request(self, request):
                copy = httpx.Request(request.method, request.url, headers=request.headers, content=request.content)
                response = await super().handle_async_request(copy)
                response.headers["apim-request-id"] = "test-request"
                return response
        gateway, now, records = Wire(), [time.time()], []
        drafts = CountingLedger(clock=lambda: now[0])
        findings = CountingLedger(clock=lambda: now[0])
        ledgers = {role: CountingLedger(clock=lambda: now[0]) for role in (
            "candidate-planner", "evidence-assessor", "release-reviewer", "briefing-author")}
        mcp = reference_application(reference(4), trust("reference-data"))
        gateway.apps["reference-data"] = mcp

        async def model_response(request):
            return httpx2.Response(200, json={
                "id": "external-model-fixture", "object": "chat.completion", "created": 0,
                "model": "approved-deployment",
                "choices": [{"index": 0, "message": {"role": "assistant", "content":
                    "Fictional reference-data comparison; source accuracy unverified."}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120}})

        async def rate_sleep(seconds):
            now[0] += seconds
            await asyncio.sleep(.001)

        async def poll_sleep(seconds):
            self.assertEqual(seconds, 15)
            await asyncio.sleep(.1)

        async with AsyncExitStack() as stack:
            stack.enter_context(patch("citadel.acceptance.monitor.MonitorExporter",
                lambda *args, **kw: SimpleNamespace(emit=records.append)))
            stack.enter_context(patch("citadel.acceptance.telemetry._exporter", None))
            stack.enter_context(redirect_stdout(io.StringIO()))
            from citadel.acceptance.telemetry import configure
            configure("candidate-planner", "11111111-1111-1111-1111-111111111111",
                client_id="11111111-1111-1111-1111-111111111111", connection_string="external-fixture")
            await stack.enter_async_context(mcp.app.router.lifespan_context(mcp.app))
            for role, ledger in ledgers.items():
                http = await stack.enter_async_context(httpx.AsyncClient(transport=gateway))
                model_http = await stack.enter_async_context(httpx2.AsyncClient(
                    transport=httpx2.MockTransport(model_response)))
                model = GovernedModel(role, "https://gateway.test", role, "approved-deployment",
                    http_client=model_http, clock=lambda: now[0], sleep=rate_sleep)
                stack.push_async_callback(model.close)
                peers = GatewayPeers(role, "https://gateway.test", role, http_client=http,
                                     clock=lambda: now[0], sleep=poll_sleep)
                runtime = Runtime(role, ledger, model=model, peers=peers, gateway_url="https://gateway.test",
                    clock=lambda: now[0], artifacts=drafts if role == "evidence-assessor" else findings, drafts=drafts)
                stack.push_async_callback(runtime.shutdown)
                gateway.apps[role] = agent_application(runtime, trust(role))
            http = await stack.enter_async_context(httpx.AsyncClient(transport=gateway))
            planner = PlannerClient("https://gateway.test", "operator", http=http)
            await planner.invoke("actual-comparison", "base-source", time.time() + 120)
            async with asyncio.timeout(15):
                while True:
                    await asyncio.sleep(.1)
                    status = await planner.status("actual-comparison", time.time() + 30)
                    if status["state"] not in ("pending", "running"):
                        break
            self.assertEqual(status["state"], "succeeded")
            product = await planner.product("actual-comparison", time.time() + 30)
            self.assertEqual(product["status"], "complete")
            documents = {role: (await ledger.read())[0] for role, ledger in ledgers.items()}
            documents["findings"] = (await findings.read())[0]
            before_drafts = (await drafts.read())[0]
            pools_before = {role: set(ledger.ticket_store.pools) for role, ledger in ledgers.items()}
            context = build_route_context(documents, run_ids=["actual-comparison"])
            from citadel.acceptance.workflow_routes import status_controls
            controls = status_controls([row | {"source": "application"} for row in records], context)
            self.assertEqual({row["check_id"] for row in controls}, {
                "route.candidate-planner.evidence-assessor.status",
                "route.evidence-assessor.release-reviewer.status"})
            from citadel.acceptance.workflow_routes import invocation_controls
            invocations = invocation_controls([row | {"source": "application"} for row in records],
                                               context, operator=planner.invocation_receipt)
            self.assertEqual({row["check_id"] for row in invocations}, {
                "route.operator.candidate-planner.invoke",
                "route.candidate-planner.evidence-assessor.invoke",
                "route.evidence-assessor.release-reviewer.invoke",
                "route.candidate-planner.briefing-author.invoke"})
            self.assertTrue(all(row["accepted_operation_id"] ==
                context["operations"][row["check_id"].split(".")[2]]["operation_id"] for row in invocations))
            for row in invocations:
                reference = context["operations"][row["check_id"].split(".")[2]]
                self.assertTrue(any(record["method"] == "SendMessage"
                    and record.get("facts", {}).get("accepted_operation_id") == row["accepted_operation_id"]
                    and record["facts"].get("input_hash") == reference["input_hash"]
                    and record.get("operation_id") == row["accepted_operation_id"]
                    and all(record.get(key) == row[key] for key in ("run_id", "caller"))
                    for record in records), row)
            for row in controls:
                self.assertTrue(any(record["method"] == "status"
                    and all(record.get(key) == row[key] for key in ("run_id", "operation_id", "caller"))
                    for record in records), row)
            self.assertNotEqual(context["operations"]["release-reviewer"]["operation_id"],
                                context["read_scope"]["operation_id"])
            lifecycle = SimpleNamespace(value={"outputs": {"gatewayUrl": "https://gateway.test"}},
                credentials=lambda: {"callerStates": {"operator": "active"},
                                     "callerKeys": {"operator": {"primary": "operator"}}})
            observations = []
            for caller, targets in (("operator", ("candidate-planner",)),
                    ("candidate-planner", ("evidence-assessor", "briefing-author")),
                    ("evidence-assessor", ("release-reviewer",)), ("briefing-author", ())):
                http = await stack.enter_async_context(httpx.AsyncClient(transport=gateway))
                options = {"client": http, "enabled": True, "run_id": "probe-" + caller,
                           "deadline": time.time() + 120, "route_context": context}
                probe = (OperatorProbe(lifecycle, admit=lambda: None, **options) if caller == "operator"
                         else GatewayProbe(caller, "https://gateway.test", caller, **options))
                for target in targets:
                    operation = context["operations"][target]["operation_id"]
                    if target not in ("evidence-assessor", "release-reviewer"):
                        observations.append(await probe.status(target, operation))
                    observations.append(await probe.task(target, operation))
                if caller in ("candidate-planner", "briefing-author"):
                    selected = context["finding_controls"][caller]
                    observations.append(await probe.finding(selected["finding"], selected["read_scope"]))
            self.assertEqual(len(observations), 8)
            self.assertTrue(all(row.get("status_code") == 200 and row.get("status") != "blocked"
                                for row in observations), observations)
            self.assertEqual({row["actual"] for row in observations}, {"owned_status", "owned_task", "exact_finding"})
            http = await stack.enter_async_context(httpx.AsyncClient(transport=gateway))
            probe = GatewayProbe("candidate-planner", "https://gateway.test", "candidate-planner",
                                 client=http, enabled=True, run_id="reference-controls")
            initialized = await probe.mcp_initialize()
            self.assertEqual(initialized.get("actual"), "mcp_initialized", initialized)
            for tool in ("search_airports", "lookup_airport", "list_runways"):
                row = await probe.reference_tool(tool, ident=None if tool == "search_airports" else "EB01")
                self.assertEqual(row.get("actual"), "reference_data", row)
            self.assertEqual((await findings.read())[0], documents["findings"])
            self.assertEqual((await drafts.read())[0], before_drafts)
            self.assertEqual({role: set(ledger.ticket_store.pools) for role, ledger in ledgers.items()}, pools_before)
            self.assertLessEqual(gateway.read_attempts + sum(
                ledger.read_attempts for ledger in [drafts, findings, *ledgers.values()]), 512)
