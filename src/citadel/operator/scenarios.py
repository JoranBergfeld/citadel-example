"""Operator -> Candidate Planner only. Durable runtime tickets remain authoritative."""

import asyncio
import importlib
import json
import re
import time

import httpx
from a2a.client.errors import A2AClientTimeoutError
from a2a.types import AgentCapabilities, AgentCard, AgentInterface, GetTaskRequest
from agent_framework_a2a import A2AAgent

from citadel.evidence.manifests import sha256
from citadel.runtime.configuration import endpoint
from .state import Blocked, write_private, public_output


FIXTURES = {"comparison": "base-source", "replacement": "missing-width-replacement",
            "exhaustion": "no-alternative", "denied-bypass": "base-source"}


def acceptance_hook(lifecycle, check_id, run_id):
    lifecycle.require_plan_observation()
    if lifecycle.value["phase"] != "deployed_unverified":
        raise Blocked("runtime_deployment_required")
    try:
        hook = importlib.import_module("citadel.acceptance.operator_hooks")
    except ModuleNotFoundError:
        raise Blocked("task20_acceptance_harness_required") from None
    result = hook.run(lifecycle=lifecycle, check_id=check_id, run_id=run_id)
    statuses = ({"pass", "blocked", "fail", "pending_human", "pending_second_pass"}
                if check_id in ("full-acceptance", "collect-evidence") else {"pass"})
    if (not isinstance(result, dict) or result.get("status") not in statuses
            or result.get("run_id") != run_id
            or not re.fullmatch(r"[a-f0-9]{64}", str(result.get("evidence_sha256", "")))):
        raise Blocked("required_live_control_evidence_incomplete")
    return result


class PlannerClient:
    def __init__(self, gateway, key, *, http):
        self.gateway, self.key, self.http = endpoint(gateway), key, http
        self.mode, self.sent = None, False
        http.event_hooks.setdefault("request", []).insert(0, self.guard)
        self.card = AgentCard(
            name="candidate-planner", description="Configured gateway interface; not live discovery proof",
            version="1.0.0", supported_interfaces=[AgentInterface(
                url=self.gateway + "/candidate-planner/a2a", protocol_binding="JSONRPC", protocol_version="1.0")],
            capabilities=AgentCapabilities(streaming=False),
            default_input_modes=["text/plain"], default_output_modes=["text/plain"])

    async def guard(self, request):
        if self.sent or self.mode is None or str(request.url) != self.mode:
            raise Blocked("hidden_retry_or_gateway_redirect")
        self.sent = True
        request.headers["Ocp-Apim-Subscription-Key"] = self.key

    async def exchange(self, path, deadline, callback, *, invocation=False):
        self.mode, self.sent = self.gateway + path, False
        try:
            async with asyncio.timeout(max(0, min(180 if invocation else 30, deadline - time.time()))):
                return await callback()
        except (httpx.RequestError, TimeoutError, A2AClientTimeoutError):
            raise Blocked("invocation_ambiguous_reconcile_only" if invocation else "status_unavailable") from None
        finally:
            self.mode = None

    async def invoke(self, run_id, fixture, deadline):
        async with A2AAgent(agent_card=self.card, http_client=self.http) as agent:
            result = await self.exchange("/candidate-planner/a2a", deadline,
                lambda: agent.run(json.dumps({"operation_id": run_id, "run_id": run_id, "fixture": fixture}),
                                  background=True), invocation=True)
            return result.continuation_token

    async def status(self, run_id, deadline):
        async def request():
            response = await self.http.get(self.gateway + "/candidate-planner/operations/" + run_id)
            if response.status_code == 429:
                raise Blocked("run_read_tickets_exhausted")
            if response.status_code != 200:
                raise Blocked("authorized_status_not_established")
            result = response.json()
            if result.get("state") == "missing":
                raise Blocked("missing_state_is_not_nonexecution")
            if result.get("run_id") != run_id or result.get("operation_id") != run_id:
                raise Blocked("operation_ownership_binding_conflict")
            return result
        return await self.exchange("/candidate-planner/operations/" + run_id, deadline, request)

    async def product(self, run_id, deadline):
        async with A2AAgent(agent_card=self.card, http_client=self.http) as agent:
            task = await self.exchange("/candidate-planner/a2a", deadline,
                                      lambda: agent.client.get_task(GetTaskRequest(id=run_id)))
            if task.id != run_id or task.context_id != run_id or not task.artifacts:
                raise Blocked("completed_task_binding_missing")
            return json.loads(task.artifacts[0].parts[0].text)


def scenario_command(lifecycle, args):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", args.run_id):
        raise Blocked("invalid_run_identity")
    if lifecycle.value["phase"] != "deployed_unverified":
        raise Blocked("runtime_deployment_required")
    credentials = lifecycle.credentials()
    if credentials["callerStates"]["operator"] != "active":
        raise Blocked("operator_credential_suspended")
    runs = lifecycle.value["runs"]
    existing = runs.get(args.run_id)
    if args.command == "demo":
        fixture = FIXTURES[args.scenario]
        if existing and (existing["fixture"] != fixture or existing["scenario"] != args.scenario):
            raise Blocked("immutable_run_input_conflict")
        if not existing:
            if any(r["state"] not in ("succeeded", "failed_no_commit") for r in runs.values()):
                raise Blocked("existing_run_requires_reconciliation")
            if args.scenario == "denied-bypass":
                acceptance_hook(lifecycle, "denied-bypass-controls", args.run_id)
            existing = {"fixture": fixture, "scenario": args.scenario, "deadline": time.time() + 900,
                        "state": "dispatch_intent", "reads": 0}
            runs[args.run_id] = existing
            lifecycle.state.save()
            invoke = True
        else:
            invoke = False
    else:
        if existing is None:
            raise Blocked("unknown_local_run_no_replay")
        invoke = False
    if existing["reads"] >= 64:
        raise Blocked("operator_poll_bound_exhausted")

    async def run():
        async with httpx.AsyncClient(follow_redirects=False, timeout=30) as http:
            client = PlannerClient(lifecycle.value["outputs"]["gatewayUrl"],
                                   credentials["callerKeys"]["operator"]["primary"], http=http)
            if invoke:
                try:
                    await client.invoke(args.run_id, existing["fixture"], existing["deadline"])
                    existing["state"] = "accepted"
                    lifecycle.state.save()
                except Blocked as exc:
                    if exc.code != "invocation_ambiguous_reconcile_only":
                        raise
                    existing["state"] = "indeterminate"
                    lifecycle.state.save()
            while time.time() < existing["deadline"]:
                if args.command == "demo":
                    await asyncio.sleep(15)
                elif existing.get("lastRead") and time.time() - existing["lastRead"] < 15:
                    raise Blocked("poll_interval_15_seconds_required")
                if existing["reads"] >= 64:
                    raise Blocked("operator_poll_bound_exhausted")
                existing["reads"] += 1
                existing["lastRead"] = time.time()
                lifecycle.state.save()
                status = await client.status(args.run_id, existing["deadline"])
                existing["state"] = status["state"]
                lifecycle.state.save()
                if status["state"] == "succeeded":
                    existing["reads"] += 1
                    lifecycle.state.save()
                    product = await client.product(args.run_id, existing["deadline"])
                    if sha256(product) != status["result"]["sha256"]:
                        raise Blocked("completed_product_hash_conflict")
                    if public_output(product, lifecycle.config, credentials) != product:
                        raise Blocked("sensitive_product_content_rejected")
                    write_private(lifecycle.state.directory / (args.run_id + "-product.json"), product)
                    existing["productSha256"] = sha256(product)
                    lifecycle.state.save()
                    return {"status": "succeeded", "run_id": args.run_id, "product": product,
                            "acceptance": "unverified", "proseSignoff": "required"}
                if status["state"] in ("failed_no_commit", "indeterminate"):
                    raise Blocked("run_" + status["state"] + "_no_automatic_replay")
                if args.command == "status":
                    return {"status": status["state"], "run_id": args.run_id}
            raise Blocked("run_absolute_deadline_expired")
    return asyncio.run(run())
