"""Reference Data's bounded, source-exact Operator projection.

The only supporting Blob authority is Planner's retained index, not its operation
ledger. Browser input selects a run; it supplies no ownership or source binding.
"""

from copy import deepcopy
import math

from starlette.responses import JSONResponse
from starlette.routing import Route

from citadel.evidence import EvidenceError
from citadel.evidence.manifests import profile_manifest, sha256
from citadel.operations import OperationError, identity
from .observation import RunIndex, provenance_projection
from .state import ScopedLedger, read_deadline


class ReferenceObservation:
    def __init__(self, ledger, admission, references):
        self.ledger, self.admission = ScopedLedger(ledger), admission
        self.references = references

    async def observe(self, run_id, *, deadline=None):
        run_id = identity(run_id)
        async with self.admission.request(deadline=deadline):
            result = await self._observe(run_id)
            if self.admission.clock() >= read_deadline.get():
                raise OperationError("deadline", "Observation deadline expired")
            return result

    async def _observe(self, run_id):
        try:
            document, _ = await self.ledger.read()
        except OperationError as exc:
            if exc.code == "missing":
                raise OperationError("unavailable", "Retained context unavailable") from None
            raise
        entries = document.get("retained_runs")
        if (type(document.get("schema_version")) is not int or document["schema_version"] != 1
                or not isinstance(entries, dict) or len(entries) > RunIndex.capacity):
            raise OperationError("unavailable", "Retained context unavailable")
        entry = entries.get(run_id)
        if entry is None:
            raise OperationError("missing", "No retained run")
        binding, provenance = entry["binding"], entry.get("provenance")
        if (binding.get("run_id") != run_id or binding["inputs"].get("run_id") != run_id
                or binding["inputs"].get("fixture") != binding["fixture"]
                or sha256(binding["inputs"]) != binding["input_hash"]):
            raise OperationError("conflict", "Retained inputs differ")
        candidates = entry.get("assessed")
        result = {"state": "partial", "run_id": run_id, "candidates": [],
                  "bindings": {"inputs": binding["input_hash"], "source": None},
                  "reason": "unavailable_assessed_bindings"}
        # Older retained runs are deliberately not reconstructed from a pool.
        if candidates is None:
            return result
        if (not isinstance(candidates, list) or len(candidates) > 20
                or any(not isinstance(ident, str) for ident in candidates)
                or len(candidates) != len(set(candidates))):
            raise OperationError("unavailable", "Invalid assessed context")
        for ident in candidates:
            identity(ident)
        result["bindings"]["assessed"] = list(candidates)
        if not candidates:
            result.update(state="empty", reason="no_saved_assessments")
            return result
        if provenance is not None:
            result["bindings"]["source"] = provenance_projection(provenance)
        selected = self.references.get(binding["fixture"])
        base = self.references.get("base-source")
        if (provenance is None or selected is None or base is None
                or selected.provenance != provenance
                or base.provenance["source"] != provenance["source"]
                or base.provenance["profile"] != provenance["profile"]
                or provenance["fixture"]["id"] != binding["fixture"]):
            result["reason"] = "unavailable_source"
            return result
        result["profile"] = profile_manifest()
        result["source_provenance"] = selected.source_manifest
        result["overlay"] = selected.fixture_manifest
        result["overlay"]["mutations"] = [change for change in result["overlay"]["mutations"]
                                         if change["airport_ident"] in candidates]
        try:
            for ident in candidates:
                assessment = selected.assess_airport(ident)
                original = base.assess_airport(ident)["evidence"]
                differences = []
                original_rows = {row["id"]["parsed"]: row for row in original["runways"]}
                for row in assessment["evidence"]["runways"]:
                    source = original_rows[row["id"]["parsed"]]
                    for field, value in row.items():
                        if value != source[field]:
                            differences.append({"label": "synthetic-overlay", "runway_id": row["id"]["parsed"],
                                                "field": field, "original": source[field], "overlay": value})
                result["candidates"].append({"airport_ident": ident, "assessment": assessment,
                                            "original_source": original, "overlay_differences": differences})
        except (EvidenceError, KeyError):
            # Never return a guessed subset as a successful exact-source read.
            result.update(candidates=[], reason="unavailable_source")
            return result
        result.update(state="ok" if entry.get("assessed_complete") is True else "partial",
                      reason="saved_assessed_candidates" if entry.get("assessed_complete") is True
                      else "incomplete_assessed_context")
        return deepcopy(result)

    def routes(self):
        async def handler(request):
            try:
                if request.url.query or await request.body():
                    raise OperationError("invalid_input", "Only opaque run selection is accepted")
                value = request.headers.get("x-citadel-observation-deadline")
                end = float(value) if value is not None else None
                if end is not None and not math.isfinite(end):
                    raise ValueError
                result = await self.observe(request.path_params["run_id"], deadline=end)
                return JSONResponse(result, headers={"Cache-Control": "no-store"})
            except OperationError as exc:
                code = {"forbidden": 403, "missing": 404, "exhausted": 429,
                        "invalid_input": 400}.get(exc.code, 503)
                return JSONResponse({"state": {403: "denied", 404: "missing", 429: "exhausted",
                                              400: "denied"}.get(code, "unavailable")}, status_code=code)
            except (TimeoutError, ValueError, KeyError, TypeError):
                return JSONResponse({"state": "unavailable"}, status_code=503)
        return [Route("/operator/reference/runs/{run_id}", handler, methods=["GET"])]
