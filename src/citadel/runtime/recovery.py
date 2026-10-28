"""Explicit owner-side reconciliation. Never accepts or schedules workflow work."""

from copy import deepcopy
import re

from starlette.responses import JSONResponse

from citadel.evidence.manifests import sha256
from citadel.operations import OperationError, Operations, identity, operation_key
from .state import read_deadline, snapshots


class ProofLedger:
    """Existing fence writes may not extend the enclosing control deadline."""
    def __init__(self, ledger):
        self.ledger = ledger

    async def read(self):
        return await self.ledger.read()

    async def commit(self, document, etag, *, deadline):
        return await self.ledger.commit(document, etag, deadline=min(deadline, read_deadline.get()))


class Recovery:
    def __init__(self, runtime):
        self.runtime = runtime
        self.ledger = runtime.ledger
        self.clock = runtime.clock
        self.ops = Operations(ProofLedger(self.ledger), workload=runtime.workload, clock=self.clock)

    async def check_run(self, run_id, request_id):
        binding = await self.runtime.run_index.resolve_in_scope(identity(run_id))
        if (binding["caller"] != "operator" or binding["inputs"].keys() != {
                "run_id", "operation_id", "fixture"}
                or binding["input_hash"] != sha256(binding["inputs"])
                or binding["run_id"] != run_id or binding["operation_id"] != run_id
                or binding["inputs"]["run_id"] != run_id
                or binding["inputs"]["operation_id"] != binding["operation_id"]):
            raise OperationError("conflict", "Original retained ownership or inputs are unavailable")
        outcome = await self.check(binding["caller"], binding["operation_id"], run_id,
                                   request_id, inputs=binding["inputs"])
        await self.runtime.run_index.recovered_in_scope(binding, outcome)
        return outcome

    async def check(self, caller, operation_id, run_id, request_id, *, inputs=None,
                    input_hash=None, grant_hash=None):
        identity(request_id)
        key = operation_key(caller, "invoke", operation_id)
        document, etag = await self.ledger.read()
        record = document["operations"].get(key)
        if record is not None and (record["run_id"] != run_id or inputs is not None and record["input_hash"] != sha256(
                {"inputs": inputs, "run_id": run_id, "deadline": record["deadline"]})
                or input_hash is not None and input_hash != record["input_hash"]):
            raise OperationError("conflict", "Original operation differs from retained inputs")
        controls = document.setdefault("operator_controls", {})
        binding = {"run_id": run_id, "operation": key,
                   "input_hash": sha256(inputs) if inputs is not None else input_hash,
                   "grant_hash": grant_hash}
        control = controls.get(request_id)
        if control is not None:
            if control["binding"] != binding:
                raise OperationError("conflict", "Control request is bound to another run")
            if control.get("outcome") is not None and control["outcome"]["state"] != "unknown":
                return deepcopy(control["outcome"])
        else:
            if len(controls) >= 1024:
                raise OperationError("exhausted", "Retained control audit is full")
            control = {"binding": binding, "action": "check-and-recover",
                       "requested_by": "operator-web" if self.runtime.workload == "candidate-planner" else caller,
                       "requested_at": self.clock(), "outcome": None}
            controls[request_id] = control
            await self.ledger.commit(document, etag, deadline=read_deadline.get())
        try:
            if record is None:
                raise OperationError("missing", "Missing operation is not proof of no execution")
            original_budget = document["budgets"].get(operation_id)
            if grant_hash is not None and (original_budget is None
                    or grant_hash != sha256(original_budget["grant"])):
                raise OperationError("conflict", "Child grant differs from its original parent")
            state = await self.ops.fence(caller, "invoke", operation_id)
            document, _ = await self.ledger.read()
            record = document["operations"][key]
            budget = document["budgets"].get(operation_id)
            if budget is None or budget["run_id"] != run_id or budget["deadline"] != record["deadline"]:
                raise OperationError("missing", "Original accounting binding unavailable; no release")
            if budget["model"] is not None:
                raise OperationError("blocked", "Outstanding model effect; infrastructure diagnostics required")
            if state["state"] == "succeeded" and (not budget["closed"] or budget.get("receipt") is None
                    or (record.get("result") or {}).get("receipt") != budget["receipt"]):
                raise OperationError("blocked", "Completed child has no exact closed-budget receipt")
            statuses, child_proof = await self.dependencies(record, budget, request_id)
            if state["state"] == "indeterminate":
                state = await self.ops.recover_external(caller, "invoke", operation_id, statuses)
            partial = state["state"] == "indeterminate" or child_proof is not None
            if budget["child"] is not None and child_proof is None:
                raise OperationError("blocked", "Outstanding child effect has no bound proof")
            proof_ledgers = [self.ledger]
            if self.runtime.artifact_ops is not None:
                proof_ledgers.append(self.runtime.artifact_ops.ledger)
            if partial:
                if self.clock() < record["deadline"] + 16:
                    raise OperationError("conflict", "Partial work requires original deadline plus storage-lease expiry")
                first = await self.snapshot(proof_ledgers)
                for ledger in proof_ledgers:
                    snapshots.get().pop(ledger, None)
                if first != await self.snapshot(proof_ledgers):
                    raise OperationError("conflict", "Recovery snapshots changed; check explicitly later")
            elif state["state"] not in ("failed_no_commit", "succeeded"):
                raise OperationError("conflict", "Completed work needs no recovery")
            document, etag = await self.ledger.read()
            proof = {
                "input_hash": record["input_hash"], "generation": state["generation"],
                "run_id": run_id, "operation_id": operation_id, "deadline": record["deadline"],
                "admission_generation": state.get("admission_generation", 0),
                "state": state["state"], "verified_at": self.clock(),
                "partial_effects_retained": True, "replayed": False,
                "grant_hash": sha256(budget["grant"]),
                "child_proof": sha256(child_proof) if child_proof else None}
            if partial:
                proof["snapshots"] = [first, first]
            document["operator_controls"][request_id]["proof"] = proof
            await self.ledger.commit(document, etag, deadline=read_deadline.get())
            if self.runtime.workload == "candidate-planner":
                await self.runtime.ticket_store.release_run(
                    self.runtime.pool(caller, operation_id).scope,
                    generation=state.get("admission_generation", 0))
            label = ("released_quiescent_partial" if partial else
                     "already_complete" if state["state"] == "succeeded" else "released_no_commit")
            child = self.runtime.workload != "candidate-planner"
            if child:
                label = ("quiescent_partial" if partial else
                         "already_complete" if state["state"] == "succeeded" else "quiescent_no_commit")
            outcome = self.outcome(run_id, request_id, label, state["state"],
                "Child is fenced/quiescent; no global admission was changed." if child else
                "Quiescent partial effects retained; execution remains incomplete. Start a new run separately."
                if partial else "Already completed; no work replayed."
                if state["state"] == "succeeded" else "Definite no-commit; exact owned admission released.")
            if child:
                outcome["proof"] = proof
        except OperationError as exc:
            outcome = self.outcome(run_id, request_id,
                "unknown" if exc.code in ("indeterminate", "unavailable") else "blocked",
                "unknown", str(exc))
        document, etag = await self.ledger.read()
        document["operator_controls"][request_id]["outcome"] = outcome
        await self.ledger.commit(document, etag, deadline=read_deadline.get())
        return outcome

    async def snapshot(self, ledgers):
        return sha256([document for document, _ in [await ledger.read() for ledger in ledgers]])

    async def dependencies(self, record, budget, request_id):
        statuses, child_proof = {}, None
        grant = budget["child"]
        if grant is not None:
            external = record["external"].get(grant["grant_id"])
            if (external is None or grant["parent_id"] != record["operation_id"]
                    or grant["issuer"] != self.runtime.workload
                    or grant["run_id"] != record["run_id"] or grant["deadline"] != record["deadline"]):
                raise OperationError("blocked", "Unresolved child admission lacks its exact dispatch binding")
            if self.runtime.peers is None:
                raise OperationError("unavailable", "Child owner proof unavailable")
            result = await self.runtime.peers.recover_child(grant["recipient"], grant["grant_id"],
                sha256({"request": request_id, "child": grant["grant_id"]}),
                {"run_id": record["run_id"], "input_hash": external["input_hash"],
                 "grant_hash": sha256(grant)}, read_deadline.get())
            proof = result.get("proof", {})
            if (result.get("run_id") != record["run_id"]
                    or result.get("state") not in ("quiescent_no_commit", "quiescent_partial", "already_complete")
                    or proof.get("input_hash") != external["input_hash"]
                    or proof.get("grant_hash") != sha256(grant)
                    or proof.get("deadline") != grant["deadline"]
                    or proof.get("operation_id") != grant["grant_id"]
                    or proof.get("run_id") != record["run_id"]
                    or proof.get("state") != result.get("execution")
                    or proof.get("replayed") is not False
                    or proof.get("partial_effects_retained") is not True):
                raise OperationError("blocked", "Child effects unresolved or proof does not match the grant")
            child_proof = proof
            if result["execution"] in ("succeeded", "failed_no_commit"):
                statuses[grant["grant_id"]] = {"state": result["execution"],
                                               "input_hash": proof["input_hash"]}
        artifacts = self.runtime.artifact_ops
        for operation_id, external in record["external"].items():
            if operation_id in statuses or grant is not None and operation_id == grant["grant_id"]:
                continue
            if external["state"] in ("succeeded", "failed_no_commit"):
                continue
            if artifacts is None:
                raise OperationError("blocked", "Downstream dispatch has no authoritative receipt")
            document, _ = await artifacts.ledger.read()
            matches = [(key, value) for key, value in document["operations"].items()
                       if value["operation_id"] == operation_id and value["run_id"] == record["run_id"]
                       and value["input_hash"] == external["input_hash"]]
            if len(matches) != 1:
                raise OperationError("blocked", "Private commit is missing or not exactly bound")
            key, _ = matches[0]
            local_ops = Operations(ProofLedger(artifacts.ledger), workload=self.runtime.workload, clock=self.clock)
            status = await local_ops.fence(*key.split("/"))
            if status["state"] not in ("succeeded", "failed_no_commit"):
                raise OperationError("blocked", "Private commit remains unresolved")
            statuses[operation_id] = status
        return statuses, child_proof

    def outcome(self, run_id, request_id, state, execution, reason):
        return {"run_id": run_id, "request_id": request_id, "state": state,
                "execution": execution, "reason": reason, "recorded_at": self.clock(),
                "retryable": False}


def install_recovery_routes(app, runtime):
    async def control(run_id, request_id, request):
        try:
            if runtime.recovery_admission is None:
                raise OperationError("unavailable", "Recovery proof admission unavailable")
            body = await request.json()
            if run_id is not None and body != {}:
                raise OperationError("invalid_input", "Only opaque run and request identities are accepted")
            end = float(request.headers.get("x-citadel-recovery-deadline", runtime.clock() + 30))
            async with runtime.recovery_admission.request("recovery-proof", deadline=end):
                if run_id is not None:
                    result = await Recovery(runtime).check_run(identity(run_id), identity(request_id))
                else:
                    if not isinstance(body, dict) or body.keys() != {"run_id", "input_hash", "grant_hash"}:
                        raise OperationError("invalid_input", "Exact parent-owned child binding required")
                    if any(not isinstance(body[key], str) or not re.fullmatch(r"[a-f0-9]{64}", body[key])
                           for key in ("input_hash", "grant_hash")):
                        raise OperationError("invalid_input", "Exact original hashes are required")
                    result = await Recovery(runtime).check(request.scope["citadel.caller"],
                        identity(request.path_params["operation_id"]), identity(body["run_id"]),
                        identity(request_id), input_hash=body["input_hash"], grant_hash=body["grant_hash"])
            return JSONResponse(result)
        except OperationError as exc:
            return JSONResponse({"state": "unknown", "execution": "unknown", "reason": str(exc)},
                status_code=429 if exc.code == "exhausted" else 503)
        except (TimeoutError, ValueError, TypeError, KeyError):
            return JSONResponse({"state": "unknown", "execution": "unknown",
                                 "reason": "Recovery outcome unavailable; check explicitly later."}, status_code=503)

    if runtime.workload == "candidate-planner":
        from fastapi import Request

        @app.post("/operator/runs/{run_id}/recover/{request_id}")
        async def recover_run(run_id: str, request_id: str, request: Request):
            return await control(run_id, request_id, request)
    else:
        from fastapi import Request

        @app.post("/operator/recovery/{operation_id}/{request_id}")
        async def recover_child(operation_id: str, request_id: str, request: Request):
            return await control(None, request_id, request)
