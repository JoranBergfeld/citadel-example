"""Durable nonblocking A2A hosting; only freshly admitted work is scheduled."""

import asyncio
import json
import logging
import time
from contextlib import asynccontextmanager
from uuid import uuid4

from a2a.server.context import ServerCallContext
from a2a.server.request_handlers import RequestHandler
from a2a.server.routes import add_a2a_routes_to_fastapi, create_jsonrpc_routes
from a2a.server.routes.common import ServerCallContextBuilder
from a2a.types import (
    AgentCapabilities, AgentCard, AgentInterface, Artifact, Message, Part, Task, TaskState, TaskStatus,
)
from a2a.utils.errors import InvalidParamsError, TaskNotFoundError, UnsupportedOperationError
from fastapi import FastAPI, Request
from google.protobuf.json_format import MessageToDict
from starlette.responses import JSONResponse

from citadel.evidence import CAVEATS, EvidenceError
from citadel.evidence.manifests import sha256
from citadel.operations import DraftReader, OperationError, Operations, identity
from citadel.operations.limits import Accounting, ReadAllowance
from citadel.gateway import GatewayTrust
from .model import INSTRUCTIONS
from .state import ScopedLedger, control_reads, read_scope


class Runtime:
    def __init__(self, workload, ledger, *, model, peers, gateway_url,
                 artifacts=None, drafts=None, tokens_per_minute=120000, clock=time.time):
        self.workload, self.model, self.peers, self.clock = workload, model, peers, clock
        self.ledger = ScopedLedger(ledger)
        self.ops = Operations(self.ledger, workload=workload, clock=clock)
        self.accounting = Accounting(self.ledger, workload=workload, clock=clock,
                                     tokens_per_minute=tokens_per_minute)
        self.artifacts, self.drafts = artifacts, drafts
        self.artifact_ops = (Operations(ScopedLedger(artifacts), workload=workload, clock=clock)
                             if artifacts is not None else None)
        self.draft_reader = DraftReader(ScopedLedger(drafts)) if drafts is not None else None
        self.tasks = set()
        self.renew_at = {}
        self.gateway_url = gateway_url.rstrip("/")
        self.card = AgentCard(
            name=workload, description=INSTRUCTIONS[workload], version="1.0.0",
            supported_interfaces=[AgentInterface(
                url=f"{self.gateway_url}/{workload}/a2a", protocol_binding="JSONRPC",
                protocol_version="1.0")],
            capabilities=AgentCapabilities(streaming=False),
            default_input_modes=["text/plain"], default_output_modes=["text/plain"],
        )

    async def accept(self, caller, payload):
        if not isinstance(payload, dict):
            raise OperationError("invalid_input", "Expected a bounded operation object")
        operation_id, run_id = identity(payload.get("operation_id")), identity(payload.get("run_id"))
        if self.workload == "candidate-planner":
            if (caller != "operator" or payload.keys() != {"operation_id", "run_id", "fixture"}
                    or operation_id != run_id or payload["fixture"] not in (
                        "base-source", "missing-width-replacement", "no-alternative")):
                raise OperationError("invalid_input", "Root run requires exact identity and fixture")
        elif "grant" not in payload or payload["grant"]["grant_id"] != operation_id:
            raise OperationError("invalid_input", "Child operation must be its authenticated grant")
        async with asyncio.timeout(10):
            with control_reads(3, clock=self.clock):
                current = await self.ops.status(caller, "invoke", operation_id)
                if current["state"] != "missing":
                    return await self.ops.accept(caller, "invoke", operation_id, payload,
                                                 run_id=run_id, deadline=current["deadline"])
                if self.workload == "candidate-planner":
                    budget = await self.accounting.start_run(run_id)
                    deadline = budget["deadline"]
                    reservation = 96
                else:
                    grant = payload["grant"]
                    if grant["run_id"] != run_id:
                        raise OperationError("invalid_input", "Run differs from inherited grant")
                    await self.accounting.adopt(grant, authenticated_issuer=caller)
                    deadline = grant["deadline"]
                    reservation = 40 if self.workload == "evidence-assessor" else grant["allowance"]["reads"]
                allowance = await self.accounting.reserve_reads(operation_id, reservation)
            for _ in range(3):
                allowance.take()
            allowance.take()
            failure_allowance = ReadAllowance(1, deadline, self.clock)
            with read_scope(allowance):
                accepted = await self.ops.accept(caller, "invoke", operation_id, payload,
                                                 run_id=run_id, deadline=deadline)
                ownership = await self.ops.claim(caller, "invoke", operation_id,
                                                 worker=uuid4().hex, lease_seconds=180)
                self.renew_at[ownership.key] = self.clock() + 90
                task = asyncio.create_task(self._execute(caller, payload, ownership, deadline, failure_allowance))
                self.tasks.add(task)
                task.add_done_callback(self.tasks.discard)
            return accepted

    async def _execute(self, caller, payload, ownership, deadline, failure_allowance):
        try:
            async with asyncio.timeout(max(0, deadline - self.clock())):
                await self.accounting.start_agent(payload["operation_id"], payload["operation_id"])
                if self.workload == "candidate-planner":
                    product = await self._plan(payload, ownership, deadline)
                    finding, rejection = None, None
                elif self.workload == "briefing-author":
                    product = await self._author(payload, deadline)
                    finding, rejection = None, None
                else:
                    result = (await self._assess(payload, ownership, deadline)
                              if self.workload == "evidence-assessor"
                              else await self._review(payload, ownership, deadline))
                    product = None
                    finding, rejection = result.get("finding"), result.get("reason")
                await self.renew_if_needed(ownership)
                receipt = await self.accounting.close(payload["operation_id"])
                await self.ops.complete(ownership, product=product, finding=finding,
                                        rejection=rejection, receipt=receipt)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            code = exc.code if isinstance(exc, (OperationError, EvidenceError)) else "unavailable"
            logging.getLogger(__name__).warning("execution_incomplete workload=%s code=%s",
                                                self.workload, code)
            try:
                with read_scope(failure_allowance):
                    await self.ops.mark_incomplete(ownership, code)
            except OperationError:
                # Expired/fenced/unavailable state remains incomplete, never success.
                pass
        finally:
            self.renew_at.pop(ownership.key, None)

    async def renew_if_needed(self, ownership):
        if self.clock() >= self.renew_at.get(ownership.key, 0):
            await self.ops.renew(ownership, lease_seconds=180)
            self.renew_at[ownership.key] = self.clock() + 90

    async def _explain(self, payload, evidence):
        return await self.model.explain(self.accounting, payload["operation_id"],
                                        payload["operation_id"], evidence)

    async def _plan(self, payload, owner, deadline):
        commentary = await self._explain(payload, {"fixture": payload["fixture"], "target": 3, "pool_limit": 20})
        pool = await self.peers.reference(payload["fixture"], deadline)
        selected, assessed, references = [], [], []
        for airport in pool["airports"]:
            ident = airport["ident"]["parsed"]
            await self.renew_if_needed(owner)
            await self.accounting.candidate(payload["operation_id"], ident)
            result = await self.peers.child(self, owner, payload, "evidence-assessor", {"airport_ident": ident},
                {"agents": 2, "models": 2, "tokens": 36000, "reads": 72})
            if result["kind"] == "rejected":
                assessed.append({"airport_ident": ident, "classification": "release_rejected"})
                continue
            ref = result["finding"]
            finding = await self.peers.finding(ref, deadline)
            if finding["airport_ident"] != ident or finding["provenance"] != pool["provenance"]:
                raise OperationError("conflict", "Finding does not belong to this candidate/source/fixture")
            assessed.append(finding)
            if finding["classification"] == "complete":
                selected.append(ident)
                references.append(ref)
            if len(selected) == 3:
                break
        product = {
            "status": "complete" if len(selected) == 3 else "bounded_pool_exhausted",
            "selected_identifiers": selected, "pool_count": len(pool["airports"]), "assessed": assessed,
            "provenance": pool["provenance"], "caveats": list(CAVEATS), "planner_commentary": commentary,
        }
        if len(selected) == 3:
            product["brief"] = await self.peers.child(self, owner, payload, "briefing-author",
                {"findings": references}, {"agents": 1, "models": 1, "tokens": 18000, "reads": 24})
        return product

    async def _assess(self, payload, owner, deadline):
        ident = identity(payload["airport_ident"])
        reference = await self.peers.reference(payload["fixture"], deadline, ident)
        assessment = reference.assess_airport(ident)
        notes = await self._explain(payload, self._summary(ident, assessment))
        operation_id = uuid4().hex
        draft = {
            "artifact_id": sha256({"run": payload["run_id"], "airport": ident}), "version": 1,
            "schema_version": 1, "run_id": payload["run_id"], "operation_id": operation_id,
            "airport_ident": ident, **assessment, "private_notes": notes,
        }
        inputs = {"draft": draft, "expected_version": 0}
        await self.ops.begin_external(owner, operation_id,
            sha256({"inputs": inputs, "run_id": payload["run_id"], "deadline": deadline}))
        await self.artifact_ops.accept("evidence-assessor", "submit-draft", operation_id, inputs,
                                       run_id=payload["run_id"], deadline=deadline)
        draft_owner = await self.artifact_ops.claim("evidence-assessor", "submit-draft", operation_id,
                                                    worker=uuid4().hex, lease_seconds=180)
        status = await self.artifact_ops.submit_draft(draft_owner, draft, expected_version=0, reference=reference)
        await self.ops.reconcile_external(owner, operation_id, status)
        ref = {key: status["result"][key] for key in ("artifact_id", "version", "sha256")}
        return await self.peers.child(self, owner, payload, "release-reviewer", {"draft": ref},
                                      {"agents": 1, "models": 1, "tokens": 18000, "reads": 32})

    async def _review(self, payload, owner, deadline):
        ref = payload["draft"]
        draft = await self.draft_reader.get_draft(ref["artifact_id"], ref["version"], ref["sha256"])
        reference = await self.peers.reference(payload["fixture"], deadline, draft["airport_ident"])
        try:
            projection = reference.shareable_projection(draft)
        except EvidenceError as exc:
            if exc.code != "data_integrity":
                raise
            await self._explain(payload, {"decision": "rejected", "reason": "draft_evidence_mismatch"})
            return {"reason": "draft_evidence_mismatch"}
        await self._explain(payload, self._summary(draft["airport_ident"], projection))
        operation_id = uuid4().hex
        inputs = {"draft": ref}
        await self.ops.begin_external(owner, operation_id,
            sha256({"inputs": inputs, "run_id": payload["run_id"], "deadline": deadline}))
        await self.artifact_ops.accept("evidence-assessor", "release", operation_id, inputs,
                                       run_id=payload["run_id"], deadline=deadline)
        release_owner = await self.artifact_ops.claim("evidence-assessor", "release", operation_id,
                                                      worker=uuid4().hex, lease_seconds=180)
        status = await self.artifact_ops.release(release_owner, ref, drafts=self.draft_reader, reference=reference)
        await self.ops.reconcile_external(owner, operation_id, status)
        return {"finding": {key: status["result"][key] for key in ("artifact_id", "version", "sha256")}}

    @staticmethod
    def _summary(ident, assessment):
        return {
            "airport_ident": ident, "classification": assessment["classification"],
            "gap_reasons": assessment["gap_reasons"], "caveats": assessment["caveats"],
            "provenance": assessment["provenance"],
        }

    async def _author(self, payload, deadline):
        refs = payload["findings"]
        if (not isinstance(refs, list) or len(refs) != 3
                or len({ref["artifact_id"] for ref in refs}) != 3):
            raise OperationError("invalid_input", "Brief requires three distinct exact released findings")
        findings = [await self.peers.finding(ref, deadline) for ref in refs]
        provenance = findings[0]["provenance"]
        if any(item["classification"] != "complete" or item["provenance"] != provenance
               or item["provenance"]["fixture"]["id"] != payload["fixture"] for item in findings):
            raise OperationError("conflict", "A complete brief requires matching complete released evidence")
        narrative = await self._explain(payload, [self._summary(item["airport_ident"], item) for item in findings])
        return {
            "status": "complete", "fictional": True, "narrative": narrative, "citations": refs,
            "findings": findings, "provenance": provenance,
            "caveats": list(dict.fromkeys(caveat for item in findings for caveat in item["caveats"])),
        }

    async def status(self, caller, operation_id):
        async with asyncio.timeout(10):
            with control_reads(1, clock=self.clock):
                return await self.ops.status(caller, "invoke", identity(operation_id))

    async def task_status(self, caller, operation_id):
        status = await self.status(caller, operation_id)
        if status["state"] == "missing":
            raise TaskNotFoundError()
        state = {
            "pending": TaskState.TASK_STATE_SUBMITTED,
            "running": TaskState.TASK_STATE_WORKING,
            "succeeded": TaskState.TASK_STATE_COMPLETED,
            "failed_no_commit": TaskState.TASK_STATE_FAILED,
            "indeterminate": TaskState.TASK_STATE_FAILED,
        }[status["state"]]
        artifacts = []
        if status["state"] == "succeeded":
            result = status["result"]
            if self.workload in ("candidate-planner", "briefing-author"):
                with control_reads(1, clock=self.clock):
                    result = await self.ops.completed_result(caller, "invoke", operation_id)
            artifacts = [Artifact(artifact_id=operation_id, parts=[Part(text=json.dumps(result))])]
        return Task(id=operation_id, context_id=status["run_id"], status=TaskStatus(state=state),
                    artifacts=artifacts)

    async def shutdown(self):
        for task in tuple(self.tasks):
            task.cancel()
        await asyncio.gather(*tuple(self.tasks), return_exceptions=True)


class TrustedContext(ServerCallContextBuilder):
    def build(self, request):
        return ServerCallContext(state={"caller": request.scope["citadel.caller"],
                                        "action": request.scope["citadel.action"],
                                        "headers": {"a2a-version": request.headers.get("a2a-version", "")}})


class DurableHandler(RequestHandler):
    def __init__(self, runtime):
        self.runtime = runtime

    async def on_message_send(self, params, context):
        if not params.configuration.return_immediately:
            raise InvalidParamsError("Only bounded nonblocking task acceptance is supported")
        try:
            async with asyncio.timeout(10):
                parts = params.message.parts
                if len(parts) != 1 or not parts[0].text:
                    raise OperationError("invalid_input", "One structured text message is required")
                payload = json.loads(parts[0].text)
                status = await self.runtime.accept(context.state["caller"], payload)
                if status["state"] != "pending":
                    return await self.runtime.task_status(context.state["caller"], status["operation_id"])
                return Task(id=status["operation_id"], context_id=status["run_id"],
                            status=TaskStatus(state=TaskState.TASK_STATE_SUBMITTED))
        except (ValueError, KeyError, TypeError, OperationError, TimeoutError) as exc:
            code = (exc.code if isinstance(exc, OperationError) else
                    "indeterminate" if isinstance(exc, TimeoutError) else "invalid_input")
            return Message(message_id=uuid4().hex, role="ROLE_AGENT",
                           parts=[Part(text=json.dumps({"error": code, "complete": False}))])

    async def on_get_task(self, params, context):
        return await self.runtime.task_status(context.state["caller"], params.id)

    async def unsupported(self, *args, **kwargs):
        raise UnsupportedOperationError()

    on_list_tasks = on_cancel_task = on_message_send_stream = unsupported
    on_subscribe_to_task = on_create_task_push_notification_config = unsupported
    on_get_task_push_notification_config = on_list_task_push_notification_configs = unsupported
    on_delete_task_push_notification_config = on_get_extended_agent_card = unsupported


def agent_application(runtime, trust):
    @asynccontextmanager
    async def lifespan(app):
        yield
        await runtime.shutdown()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    add_a2a_routes_to_fastapi(app, jsonrpc_routes=create_jsonrpc_routes(
        DurableHandler(runtime), "/a2a", context_builder=TrustedContext(), enable_v0_3_compat=False))

    @app.get("/.well-known/agent-card.json")
    async def card():
        return MessageToDict(runtime.card)

    @app.get("/operations/{operation_id}")
    async def status(operation_id: str, request: Request):
        try:
            return await runtime.status(request.scope["citadel.caller"], operation_id)
        except OperationError as exc:
            return JSONResponse({"error": exc.code}, status_code=409)

    if runtime.workload == "release-reviewer":
        @app.get("/findings/{finding_id}/versions/{version}")
        async def finding(finding_id: str, version: str):
            try:
                if not version.isdecimal():
                    raise OperationError("invalid_input", "Exact numeric finding version required")
                with control_reads(1, clock=runtime.clock):
                    return await runtime.artifact_ops.get_finding(finding_id, int(version))
            except OperationError as exc:
                return JSONResponse({"error": exc.code}, status_code=404 if exc.code == "not_found" else 409)

    return GatewayTrust(app, trust)
