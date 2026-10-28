"""Evidence Review's read-only Operator projections, never workload draft authority."""

import math

from fastapi import Request
from starlette.responses import JSONResponse

from citadel.evidence.manifests import sha256
from citadel.operations import OperationError, identity, operation_key
from .observation import provenance_projection


PAGE_SIZE = 20


def exact(value):
    artifact = identity(value["artifact_id"])
    version, digest = value["version"], value["sha256"]
    if (type(version) is not int or version < 1 or not isinstance(digest, str)
            or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest)):
        raise OperationError("unavailable", "Invalid saved exact binding")
    return {"artifact_id": artifact, "version": version, "sha256": digest}


def strings(value):
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise OperationError("unavailable", "Invalid saved public text")
    return list(value)


def assessment(value):
    classification = value["classification"]
    if classification not in ("complete", "insufficient_evidence"):
        raise OperationError("unavailable", "Invalid saved completeness")
    return {"airport_ident": identity(value["airport_ident"]), "classification": classification,
            "gap_reasons": strings(value["gap_reasons"]), "caveats": strings(value["caveats"]),
            "provenance": provenance_projection(value["provenance"])}


def page(items, cursor):
    if cursor:
        identity(cursor)
        positions = [i for i, item in enumerate(items) if sha256(item["binding"]) == cursor]
        if not positions:
            raise OperationError("invalid_input", "Unknown observation cursor")
        items = items[positions[0] + 1:]
    selected = items[:PAGE_SIZE]
    return selected, sha256(selected[-1]["binding"]) if len(items) > PAGE_SIZE else None


class EvidenceObservations:
    def __init__(self, runtime):
        self.runtime = runtime

    async def draft_items(self, run_id):
        identity(run_id)
        document, _ = await self.runtime.artifact_ops.ledger.read()
        operations, _ = await self.runtime.ledger.read()
        items, partial, unbound = [], False, set()
        for artifact_id, versions in sorted(document["drafts"].items()):
            for version, draft in sorted(versions.items(), key=lambda pair: int(pair[0])):
                if draft.get("run_id") != run_id:
                    continue
                ref = exact({"artifact_id": artifact_id, "version": int(version), "sha256": sha256(draft)})
                record = document["operations"].get(operation_key(
                    "evidence-assessor", "submit-draft", draft["operation_id"]))
                if (draft["artifact_id"] != artifact_id or draft["version"] != ref["version"]
                        or record is None or record["run_id"] != run_id
                        or record["state"] != "succeeded"
                        or record["result"] != {"kind": "draft", **ref}):
                    partial = True
                    unbound.add((artifact_id, int(version)))
                    continue
                prose = draft.get("assessment_prose")
                if prose is not None and not isinstance(prose, str):
                    raise OperationError("unavailable", "Invalid saved prose")
                items.append({"binding": ref, "draft": ref, **assessment(draft),
                              "assessment_prose": prose,
                              "prose_state": "saved" if prose is not None else "unavailable_history"})
                partial |= prose is None
        known = run_id in document["runs"] or run_id in operations["runs"]
        return items, partial, known, unbound

    async def drafts(self, run_id, cursor=None):
        items, partial, known, _ = await self.draft_items(run_id)
        selected, next_cursor = page(items, cursor)
        return {"state": "partial" if partial or not known else "ok" if items else "empty",
                "run_id": run_id, "visibility": "private_operator_inspection",
                "drafts": selected, "next_cursor": next_cursor,
                "reason": "unavailable_history" if not known else None,
                "bindings": {"drafts": [item["draft"] for item in selected]}}

    async def draft(self, run_id, artifact_id, version):
        identity(artifact_id)
        if not version.isdecimal() or len(version) > 9 or int(version) < 1:
            raise OperationError("invalid_input", "An exact positive version is required")
        items, _, known, unbound = await self.draft_items(run_id)
        if not known:
            return {"state": "partial", "reason": "unavailable_history", "run_id": run_id}
        if (artifact_id, int(version)) in unbound:
            return {"state": "partial", "reason": "unavailable_historical_draft_binding", "run_id": run_id}
        item = next((item for item in items if item["draft"]["artifact_id"] == artifact_id
                     and item["draft"]["version"] == int(version)), None)
        if item is None:
            raise OperationError("not_found", "Exact run-bound draft is not retained")
        return {"state": "ok" if item["prose_state"] == "saved" else "partial",
                "run_id": run_id, "visibility": "private_operator_inspection",
                "draft": item, "bindings": {"draft": item["draft"]}}

    @staticmethod
    def finding_path(run_id, ref):
        return f'/operator/runs/{run_id}/findings/{ref["artifact_id"]}/versions/{ref["version"]}'

    @staticmethod
    def released(document, run_id, only=None):
        items = []
        for artifact_id, versions in sorted(document["findings"].items()):
            for version, finding in sorted(versions.items(), key=lambda pair: int(pair[0])):
                if only is not None and (artifact_id, int(version)) != only:
                    continue
                if finding.get("run_id") != run_id:
                    continue
                ref = exact({"artifact_id": artifact_id, "version": int(version), "sha256": sha256(finding)})
                draft = exact(finding["draft"])
                record = document["operations"].get(operation_key(
                    "evidence-assessor", "release", finding["operation_id"]))
                if (finding["artifact_id"] != artifact_id or finding["version"] != ref["version"]
                        or record is None or record["run_id"] != run_id or record["state"] != "succeeded"
                        or record["result"] != {"kind": "finding", **ref}
                        or record["input_hash"] != sha256({"inputs": {"draft": draft},
                            "run_id": run_id, "deadline": record["deadline"]})):
                    items.append({"binding": {"artifact_id": artifact_id, "version": int(version),
                                              "linkage": "unavailable"},
                                  "artifact_id": artifact_id, "version": int(version),
                                  "outcome": "unknown", "reason": "unavailable_historical_finding_binding"})
                    continue
                items.append({"binding": ref, "draft": draft, "finding": ref,
                    "release_id": identity(finding["operation_id"]), "outcome": "approved",
                    "finding_path": EvidenceObservations.finding_path(run_id, ref)})
        return items

    async def releases(self, run_id, cursor=None):
        identity(run_id)
        document, _ = await self.runtime.artifact_ops.ledger.read()
        operations, _ = await self.runtime.ledger.read()
        items = self.released(document, run_id)
        partial = any(item["outcome"] == "unknown" for item in items)
        for key, record in sorted(operations["operations"].items()):
            if not key.startswith("evidence-assessor/invoke/") or record["run_id"] != run_id:
                continue
            binding = record.get("retained_bindings", {}).get("draft")
            draft = exact(binding) if binding else None
            result = record.get("result") or {}
            approved = next((item for item in items
                             if item.get("finding") and (
                                 (result.get("finding") == item["finding"]
                                  and (draft is None or item["draft"] == draft))
                                 or (item["draft"] == draft and record["state"] != "succeeded"))), None)
            if approved is not None:
                approved["review_operation_id"] = identity(record["operation_id"])
                approved["execution"] = record["state"]
                continue
            item = {"binding": {"operation_id": identity(record["operation_id"]),
                                "input_hash": record["input_hash"]},
                    "review_operation_id": identity(record["operation_id"]),
                    "execution": record["state"], "outcome": "unknown"}
            if draft:
                item["draft"] = draft
            else:
                partial = True
                item["reason"] = "unavailable_historical_draft_binding"
            if result.get("kind") == "rejected" and result.get("reason") == "draft_evidence_mismatch":
                item.update(outcome="rejected", reason="draft_evidence_mismatch")
            elif result.get("kind") == "collaboration":
                # The invocation's success never regenerates a deleted finding.
                item["reason"] = "unavailable_historical_finding"
                partial = True
            elif record["state"] == "succeeded":
                partial = True
            items.append(item)
        selected, next_cursor = page(items, cursor)
        known = run_id in document["runs"] or run_id in operations["runs"]
        return {"state": "partial" if partial or not known else "ok" if items else "empty",
                "run_id": run_id, "releases": selected, "next_cursor": next_cursor,
                "reason": "unavailable_history" if not known else None,
                "bindings": {"releases": [item["binding"] for item in selected]}}

    async def finding(self, run_id, artifact_id, version):
        identity(run_id)
        identity(artifact_id)
        if not version.isdecimal() or len(version) > 9 or int(version) < 1:
            raise OperationError("invalid_input", "An exact positive version is required")
        document, _ = await self.runtime.artifact_ops.ledger.read()
        operations, _ = await self.runtime.ledger.read()
        if run_id not in document["runs"] and run_id not in operations["runs"]:
            return {"state": "partial", "reason": "unavailable_history", "run_id": run_id}
        released = self.released(document, run_id, only=(artifact_id, int(version)))
        item = next((item for item in released if item.get("finding", {}).get("artifact_id") == artifact_id
                     and item["finding"]["version"] == int(version)), None)
        if item is None:
            if any(item.get("artifact_id") == artifact_id and item.get("version") == int(version)
                   for item in released):
                return {"state": "partial", "reason": "unavailable_historical_finding_binding", "run_id": run_id}
            raise OperationError("not_found", "Exact run-bound finding is not retained")
        saved = document["findings"][artifact_id][str(int(version))]
        # This is an allowlisted projection of the hash-bound artifact, not a
        # rewritten artifact or a claim that the projection has the same hash.
        return {"state": "ok", "run_id": run_id, "bindings": {"finding": item["finding"]},
                "finding": {**assessment(saved), **item["finding"], "draft": item["draft"],
                            "reviewer": "release-reviewer", "run_id": run_id,
                            "operation_id": item["release_id"]}}


def install(app, runtime):
    owner = EvidenceObservations(runtime)

    async def respond(request, function, *args):
        try:
            if runtime.observation_reads is None:
                raise OperationError("unavailable", "Deployment observation admission unavailable")
            end = float(request.headers.get("x-citadel-observation-deadline", runtime.clock() + 30))
            if not math.isfinite(end):
                raise ValueError("Invalid deadline")
            async with runtime.observation_reads.request(deadline=end):
                result = await function(*args)
                result["activity"] = runtime.activity.observe(args[0])
                return JSONResponse(result)
        except OperationError as exc:
            state = {"forbidden": "denied", "not_found": "missing", "missing": "unavailable",
                     "exhausted": "exhausted"}.get(exc.code, "unavailable")
            return JSONResponse({"state": state}, status_code={
                "denied": 403, "missing": 404, "exhausted": 429}.get(state, 503))
        except (TimeoutError, KeyError, TypeError, ValueError, OverflowError):
            return JSONResponse({"state": "unavailable"}, status_code=503)

    if runtime.workload == "evidence-assessor":
        @app.get("/operator/runs/{run_id}/drafts")
        async def drafts(run_id: str, request: Request):
            return await respond(request, owner.drafts, run_id)

        @app.get("/operator/runs/{run_id}/drafts/page/{cursor}")
        async def draft_page(run_id: str, cursor: str, request: Request):
            return await respond(request, owner.drafts, run_id, cursor)

        @app.get("/operator/runs/{run_id}/drafts/{artifact_id}/versions/{version}")
        async def draft(run_id: str, artifact_id: str, version: str, request: Request):
            return await respond(request, owner.draft, run_id, artifact_id, version)
    else:
        @app.get("/operator/runs/{run_id}/releases")
        async def releases(run_id: str, request: Request):
            return await respond(request, owner.releases, run_id)

        @app.get("/operator/runs/{run_id}/releases/page/{cursor}")
        async def release_page(run_id: str, cursor: str, request: Request):
            return await respond(request, owner.releases, run_id, cursor)

        @app.get("/operator/runs/{run_id}/findings/{artifact_id}/versions/{version}")
        async def finding(run_id: str, artifact_id: str, version: str, request: Request):
            return await respond(request, owner.finding, run_id, artifact_id, version)
