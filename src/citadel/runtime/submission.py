"""Planner-owned hosted submission intent. Existing intents never authorize replay."""

from copy import deepcopy
import asyncio

from citadel.evidence.manifests import sha256
from citadel.operations import OperationError, identity
from .state import read_deadline


SCENARIOS = {"comparison": "base-source", "replacement": "missing-width-replacement",
             "exhaustion": "no-alternative"}


def submission_run(request_id):
    return "ui-" + sha256({"request_id": identity(request_id)})[:61]


class ScenarioSubmission:
    def __init__(self, index, accept):
        self.index, self.accept = index, accept

    async def submit(self, request_id, scenario):
        if not isinstance(scenario, str) or scenario not in SCENARIOS:
            raise OperationError("invalid_input", "Choose comparison, replacement or exhaustion")
        # Bounded identifiers remain compatible with retained-run URLs (64 chars).
        run_id = submission_run(request_id)
        payload = {"run_id": run_id, "operation_id": run_id, "fixture": SCENARIOS[scenario]}
        binding = {"caller": "operator", "run_id": run_id, "operation_id": run_id,
                   "fixture": payload["fixture"], "input_hash": sha256(payload), "inputs": payload}
        async with self.index.admission.request():
            document, etag = await self.index._read()
            entries = document["retained_runs"]
            if run_id in entries:
                entry = entries[run_id]
                if entry["binding"] != binding or entry.get("submission", {}).get("request_id") != request_id:
                    raise OperationError("conflict", "Submission identity has immutable scenario inputs")
                return self.result(entry)
            self.index.require_resolved_dispatch(entries)
            if len(entries) >= self.index.capacity:
                raise OperationError("exhausted", "Retained run index is full")
            entry = {"binding": deepcopy(binding), "execution": "unknown",
                     "retained_at": self.index.clock(), "provenance": None,
                     "assessed": [], "assessed_complete": False,
                     "submission": {"request_id": request_id, "dispatch": "intent", "reason": "unknown"}}
            entries[run_id] = entry
            # Only a confirmed conditional write authorizes this one dispatch.
            await self.index.ledger.commit(document, etag, deadline=read_deadline.get())
        try:
            accepted = await self.accept("operator", payload)
            execution, reason = accepted["state"], "accepted"
        except OperationError as exc:
            execution = "unknown"
            reason = ("active_run_blocker" if exc.code == "conflict" else
                      "allowance_exhausted" if exc.code == "exhausted" else "ambiguous_dispatch")
        except TimeoutError:
            execution, reason = "unknown", "ambiguous_dispatch"
        async with self.index.admission.request():
            document, etag = await self.index._read()
            entry = document["retained_runs"][run_id]
            entry["submission"].update(dispatch="recorded", reason=reason)
            # Execution can finish before this response is persisted.
            if entry["execution"] == "unknown":
                entry["execution"] = execution
            await self.index.ledger.commit(document, etag, deadline=read_deadline.get())
            return self.result(entry)

    @staticmethod
    def result(entry):
        return {"run_id": entry["binding"]["run_id"], "state": "ok",
                "execution": entry["execution"],
                "reason": entry["submission"]["reason"]}


def attach_submission(app, runtime):
    from fastapi import Request
    from starlette.responses import JSONResponse

    @app.post("/operator/scenarios")
    async def submit(request: Request):
        try:
            if runtime.run_index is None:
                raise OperationError("unavailable", "Retained submission state unavailable")
            payload = await request.json()
            if not isinstance(payload, dict) or payload.keys() != {"request_id", "scenario"}:
                raise OperationError("invalid_input", "Only scenario and request identity are accepted")
            async with asyncio.timeout(30):
                result = await ScenarioSubmission(runtime.run_index, runtime.accept).submit(**payload)
            return JSONResponse(result)
        except OperationError as exc:
            state = exc.code if exc.code in ("invalid_input", "conflict", "exhausted") else "unknown"
            return JSONResponse({"state": state, "execution": "unknown"}, status_code={
                "invalid_input": 400, "conflict": 409, "exhausted": 429}.get(state, 503))
        except (ValueError, TypeError, KeyError, TimeoutError):
            return JSONResponse({"state": "unknown", "execution": "unknown"}, status_code=503)
