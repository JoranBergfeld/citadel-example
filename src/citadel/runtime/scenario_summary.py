"""Allowlisted summary of an exact saved Planner product, not workflow playback."""

from citadel.evidence import CAVEATS
from citadel.operations import OperationError


def scenario_summary(product):
    assessed = product.get("assessed", [])
    if not isinstance(assessed, list) or len(assessed) > 20:
        raise OperationError("unavailable", "Saved candidates exceed the bounded pool")
    selected = product.get("selected_identifiers", [])
    if not isinstance(selected, list) or len(selected) > 3:
        raise OperationError("unavailable", "Saved selection is invalid")
    summary = {"outcome": product.get("status", "unknown"), "selected_identifiers": selected,
               "pool_count": product.get("pool_count"), "caveats": list(CAVEATS),
               "candidates": [], "brief": None}
    for position, candidate in enumerate(assessed):
        classification = candidate["classification"]
        summary["candidates"].append({
            "airport_ident": candidate["airport_ident"], "classification": classification,
            "gap_reasons": candidate.get("gap_reasons", []),
            "decision": ("replacement selected" if candidate["airport_ident"] in selected and position >= 3 else
                         "selected" if candidate["airport_ident"] in selected else
                         "Release rejected; skipped" if classification == "release_rejected" else
                         "Insufficient evidence; skipped"),
        })
    brief = product.get("brief")
    if brief:
        citations = brief.get("citations", [])
        if not isinstance(citations, list) or len(citations) > 3:
            raise OperationError("unavailable", "Saved citations exceed the selection bound")
        # A parent product embeds the hash-verified completed Author product.
        # Never pass findings, read scopes, private draft content or model exchanges.
        summary["brief"] = {
            "narrative": brief.get("narrative"),
            "citations": [{key: ref[key] for key in ("artifact_id", "version", "sha256")} for ref in citations],
            "caveats": list(dict.fromkeys([*CAVEATS, *brief.get("caveats", [])])),
        }
    return summary
