"""Planning-owned saved decisions and briefs; no private Evidence Review reads."""

import math

from fastapi import Request
from starlette.responses import JSONResponse

from citadel.evidence import CAVEATS
from citadel.evidence.manifests import sha256
from citadel.operations import OperationError, identity, operation_key
from .evidence_observation import assessment, exact, strings
from .observation import provenance_projection
from .state import read_deadline


MAX_RESPONSE_BYTES = 262144


def candidate_decision(item, finding=None, *, replacement=False):
    ident = identity(item["airport_ident"])
    if item["classification"] == "release_rejected":
        return {"airport_ident": ident, "classification": "unknown", "gap_reasons": [],
                "release": "rejected", "selection": "skipped", "reason": "release_rejected",
                "caveats": list(CAVEATS), "finding": None}
    complete = item["classification"] == "complete"
    return {**assessment(item), "release": "approved",
            "selection": "selected" if complete else "skipped",
            "reason": ("replacement_after_skipped_candidate" if replacement else
                       "complete_approved_finding") if complete else "insufficient_evidence",
            "finding": exact(finding) if finding else None}


def saved_product(record, key):
    product, result = record.get("product"), record.get("result") or {}
    if product is None:
        return None, None
    binding = exact(result)
    if (record["state"] != "succeeded" or result.get("kind") != "work-product"
            or binding["artifact_id"] != sha256(key) or binding["version"] != 1
            or binding["sha256"] != sha256(product)):
        raise OperationError("conflict", "Saved planning product binding differs")
    return product, binding


class PlanningObservations:
    def __init__(self, runtime):
        self.runtime = runtime

    async def document(self):
        try:
            document, _ = await self.runtime.ledger.read()
            return document
        except OperationError as exc:
            if exc.code == "missing":
                raise OperationError("unavailable", "Owner source unavailable") from None
            raise

    async def decisions(self, run_id):
        if self.runtime.run_index is None:
            raise OperationError("unavailable", "Retained context unavailable")
        entry = await self.runtime.run_index.context_in_scope(run_id)
        binding = entry["binding"]
        document = await self.document()
        key = operation_key(binding["caller"], "invoke", binding["operation_id"])
        record = document["operations"].get(key)
        execution, product, product_ref = "unknown", None, None
        if record:
            expected = sha256({"inputs": binding["inputs"], "run_id": run_id,
                               "deadline": record["deadline"]})
            if record["run_id"] != run_id or record["input_hash"] != expected:
                raise OperationError("conflict", "Retained run differs from admitted operation")
            execution = record["state"]
            product, product_ref = saved_product(record, key)
        decisions = entry.get("decisions", [])
        assessed = entry.get("assessed", [])
        provenance = entry.get("provenance")
        assessed_complete = entry.get("assessed_complete", False)
        if not isinstance(decisions, list) or not isinstance(assessed, list) or max(len(decisions), len(assessed)) > 20:
            raise OperationError("unavailable", "Invalid saved candidate bound")
        if product:
            saved = product["assessed"]
            if not isinstance(saved, list) or len(saved) > 20:
                raise OperationError("unavailable", "Invalid saved candidate bound")
            selected = product["selected_identifiers"]
            if (not isinstance(selected, list) or len(selected) > 3 or len(set(selected)) != len(selected)
                    or not set(selected).issubset(item["airport_ident"] for item in saved)):
                raise OperationError("unavailable", "Invalid saved selection")
            retained = {item["airport_ident"]: item for item in decisions}
            assessed, decisions = [], []
            skipped = False
            for number, item in enumerate(saved):
                previous = retained.get(item["airport_ident"], {})
                ref = ({"artifact_id": item["artifact_id"], "version": item["version"], "sha256": sha256(item)}
                       if "artifact_id" in item and "version" in item else previous.get("finding"))
                if previous.get("finding") is not None and previous["finding"] != ref:
                    raise OperationError("conflict", "Saved finding differs from retained decision")
                decision = candidate_decision(item, ref, replacement=number >= 3 and skipped)
                if decision["selection"] == "selected" and item["airport_ident"] not in selected:
                    decision.update(selection="skipped", reason="not_selected_in_saved_plan")
                skipped |= decision["selection"] == "skipped"
                decisions.append(decision)
                assessed.append(decision["airport_ident"])
            if provenance is not None and provenance != product["provenance"]:
                raise OperationError("conflict", "Saved source differs from retained run")
            provenance, assessed_complete = product["provenance"], True
        candidates = []
        for ident in assessed:
            decision = next((item for item in decisions if item["airport_ident"] == ident), None)
            if decision is None:
                candidates.append({"airport_ident": identity(ident), "classification": "unknown",
                    "release": "unknown", "selection": "unknown", "gap_reasons": [],
                    "reason": "unavailable_historical_decision", "finding": None, "caveats": list(CAVEATS)})
                continue
            rejected = decision["release"] == "rejected"
            safe = candidate_decision(
                {**decision, "classification": "release_rejected" if rejected else decision["classification"]},
                decision.get("finding"), replacement=decision["reason"] == "replacement_after_skipped_candidate")
            if decision["selection"] not in ("selected", "skipped") or decision["reason"] not in (
                    "complete_approved_finding", "replacement_after_skipped_candidate",
                    "insufficient_evidence", "release_rejected", "not_selected_in_saved_plan"):
                raise OperationError("unavailable", "Invalid saved selection")
            safe.update(selection=decision["selection"], reason=decision["reason"])
            if safe.get("provenance") and safe["provenance"] != provenance_projection(provenance):
                raise OperationError("conflict", "Candidate source differs from retained run")
            candidates.append(safe)
        complete = (assessed_complete and
                    all(item["selection"] != "unknown" for item in candidates))
        exact_findings = all(item["release"] != "approved" or item["finding"] for item in candidates)
        outcome = product["status"] if product else "incomplete" if execution in (
            "indeterminate", "failed_no_commit") else "unknown"
        if outcome not in ("complete", "bounded_pool_exhausted", "incomplete", "unknown"):
            raise OperationError("unavailable", "Unknown saved planning outcome")
        pool_count = product["pool_count"] if product else None
        if pool_count is not None and (type(pool_count) is not int or not len(candidates) <= pool_count <= 20):
            raise OperationError("unavailable", "Invalid saved pool bound")
        return {"state": "ok" if complete and product and provenance and exact_findings else "partial",
                "run_id": run_id, "execution": execution, "outcome": outcome,
                "pool_count": pool_count,
                "candidates": candidates, "assessed_complete": complete,
                "provenance": provenance_projection(provenance) if provenance else None,
                "caveats": strings(product["caveats"]) if product else list(CAVEATS),
                "reason": ("unavailable_historical_decisions" if not complete else
                           "unavailable_historical_finding_binding" if not exact_findings else
                           "no_saved_plan" if product is None else None),
                "bindings": {"inputs": binding["input_hash"], "product": product_ref, "decisions": sha256(candidates)}}

    async def brief(self, run_id):
        document = await self.document()
        matches = [(key, record) for key, record in document["operations"].items()
                   if key.startswith("candidate-planner/invoke/") and record["run_id"] == run_id]
        result = {"state": "partial", "run_id": run_id, "brief": None,
                  "execution": "unknown", "reason": "unavailable_historical_brief_binding",
                  "bindings": {}}
        # A run ID is not a "latest" selector. Ambiguous history cannot choose
        # another product, even if one invocation happens to have succeeded.
        if len(matches) != 1:
            return result
        key, record = matches[0]
        if key != operation_key("candidate-planner", "invoke", record["operation_id"]):
            raise OperationError("conflict", "Author operation identity differs")
        result["execution"] = record["state"]
        product, ref = saved_product(record, key)
        if product is None:
            result["reason"] = "no_saved_brief"
            return result
        citations = [exact(item) for item in product["citations"]]
        if (len(citations) != 3 or len({item["artifact_id"] for item in citations}) != 3
                or product["status"] != "complete" or product["fictional"] is not True
                or not isinstance(product["narrative"], str)):
            raise OperationError("unavailable", "Invalid saved brief")
        if "findings" in product:
            findings = product["findings"]
            if len(findings) != 3 or any(
                    sha256(item) != citation["sha256"] or item.get("run_id", run_id) != run_id
                    for item, citation in zip(findings, citations)):
                raise OperationError("conflict", "Saved citation differs from original finding")
        brief = {"narrative": product["narrative"], "citations": citations,
                 "provenance": provenance_projection(product["provenance"]),
                 "caveats": strings(product["caveats"]), "fictional": True}
        result.update(state="ok", reason=None, brief=brief,
                      bindings={"brief": ref, "citations": citations})
        return result


def install(app, runtime):
    owner = PlanningObservations(runtime)

    async def respond(request, function, run_id):
        try:
            if runtime.observation_reads is None:
                raise OperationError("unavailable", "Deployment observation admission unavailable")
            end = float(request.headers.get("x-citadel-observation-deadline", runtime.clock() + 30))
            if not math.isfinite(end):
                raise ValueError("Invalid deadline")
            async with runtime.observation_reads.request(deadline=end):
                response = JSONResponse(await function(identity(run_id)))
                if runtime.clock() >= read_deadline.get():
                    raise OperationError("deadline", "Observation deadline expired")
                if len(response.body) > MAX_RESPONSE_BYTES:
                    raise OperationError("result_limit", "Saved projection exceeds response bound")
                return response
        except OperationError as exc:
            state = {"forbidden": "denied", "not_found": "missing", "missing": "missing",
                     "exhausted": "exhausted"}.get(exc.code, "unavailable")
            return JSONResponse({"state": state}, status_code={
                "denied": 403, "missing": 404, "exhausted": 429}.get(state, 503))
        except (TimeoutError, KeyError, TypeError, ValueError, OverflowError):
            return JSONResponse({"state": "unavailable"}, status_code=503)

    if runtime.workload == "candidate-planner":
        @app.get("/operator/runs/{run_id}/decisions")
        async def decisions(run_id: str, request: Request):
            return await respond(request, owner.decisions, run_id)
    else:
        @app.get("/operator/runs/{run_id}/brief")
        async def brief(run_id: str, request: Request):
            return await respond(request, owner.brief, run_id)
