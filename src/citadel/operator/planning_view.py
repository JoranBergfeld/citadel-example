"""Escaped Exercise Planning views of public decisions and actual saved briefs."""

import asyncio
from html import escape

from citadel.evidence import CAVEATS
from citadel.operations import OperationError, identity
from .evidence_view import assessment_content, finding_link, ref_text, status
from .observation import Observed


def observation_path(run_id, projection):
    identity(run_id)
    if projection not in ("decisions", "brief"):
        raise OperationError("invalid_input", "Unknown Exercise Planning projection")
    owner = "candidate-planner" if projection == "decisions" else "briefing-author"
    return f"/{owner}/operator/runs/{run_id}/{projection}"


def citation(run_id, ref):
    return (f'<a href="{finding_link(run_id, ref)}">'
            f'Exact approved finding: {ref_text(ref)}</a>')


def provenance_content(provenance, caveats):
    source, profile, fixture = (provenance[key] for key in ("source", "profile", "fixture"))
    label = "Labelled synthetic overlay" if provenance["evidence_origin"] == "synthetic-overlay" else "Fixture"
    content = f"""<details><summary>Exact saved source, profile and overlay</summary>
<p>Source: {escape(str(source["kind"]))} · snapshot {escape(str(source["snapshot"]))}
· SHA256 {escape(source["sha256"])}</p>
<p>Profile: {escape(profile["id"])} · version {escape(str(profile["version"]))}
· SHA256 {escape(profile["sha256"])}</p>
<p>{label}: {escape(fixture["id"])} · version {escape(str(fixture["version"]))}
· SHA256 {escape(fixture["sha256"])}</p>
<p>Evidence origin: {escape(provenance["evidence_origin"])}. Original source values are not rewritten.</p>
</details><h4>Original caveats</h4><ul>"""
    return content + "".join(f"<li>{escape(value)}</li>" for value in caveats) + "</ul>"


async def render(request, observer, run_id, csrf):
    if any(key in request.path_params for key in ("projection", "artifact_id", "collection")):
        raise OperationError("invalid_input", "Select an Exercise Planning run")
    kinds = ("decisions", "brief")
    observations = (await asyncio.gather(*(
        observer.planning(run_id, kind, refresh=request.method == "POST") for kind in kinds))
        if observer and hasattr(observer, "planning") else [Observed(state="unavailable") for _ in kinds])
    content = f"""<main><h2>Exercise Planning · {escape(run_id)}</h2>
<p>Planning uses approved findings only, never private draft previews.
Approval permits sharing, not completeness, airport safety or operational suitability.</p>
<p><a href="/teams/evidence/runs/{escape(run_id)}">Operator-only Evidence Review</a>
is a separate authority: unpublished drafts are not planning evidence.</p>
<p><a href="/teams/reference/runs/{escape(run_id)}">Original assessed Reference Data</a></p>
<ul>""" + "".join(f"<li>{escape(value)}</li>" for value in CAVEATS) + "</ul>"
    for kind, observed in zip(kinds, observations):
        content += status(observed, "Candidate decisions" if kind == "decisions" else "Saved brief")
        data = observed.data or {}
        if data.get("reason"):
            content += f'<p>{escape(data["reason"])}. Missing history is not reconstructed or replaced with current data.</p>'
        if kind == "decisions":
            content += f'<p>Planner execution: {escape(data.get("execution", "unknown"))}.</p>'
            outcome = data.get("outcome", "unknown")
            if outcome == "bounded_pool_exhausted":
                content += (f'<p>Saved bounded candidate pool: {data["pool_count"]}.</p>'
                            "<aside>Expected bounded-pool exhaustion: insufficient approved complete evidence "
                            "for three candidates. No brief was requested; not a technical failure or an airport-safety judgment.</aside>")
            elif outcome == "incomplete":
                content += "<aside>Incomplete execution with unknown effects; a technical interruption is not insufficient evidence or expected exhaustion.</aside>"
            elif outcome == "complete":
                content += "<p>Completed saved comparison. The Author projection below independently confirms any saved brief.</p>"
            if not data.get("assessed_complete"):
                content += "<aside>Partial assessment history; unassessed candidates and missing decisions are not inferred.</aside>"
            for item in data.get("candidates", []):
                content += (f'<article><h4>{escape(item["airport_ident"])}</h4>'
                            f'<p>Release: {escape(item["release"])} · {escape(item["selection"])}'
                            f' · {escape(item["reason"])}</p><details><summary>Saved evidence summary</summary>')
                if item.get("provenance"):
                    content += assessment_content(item)
                else:
                    content += f'<p>Completeness: {escape(item["classification"])}. Historical evidence details unavailable.</p>'
                if item.get("finding"):
                    content += citation(run_id, item["finding"])
                content += "</details></article>"
            if data.get("provenance"):
                content += provenance_content(data["provenance"], data["caveats"])
        elif data.get("brief"):
            brief = data["brief"]
            content += f'<article><h4>Actual saved fictional brief</h4><p>{escape(brief["narrative"])}</p>'
            content += "<h4>Exact saved approved-finding citations</h4><ul>"
            content += "".join(f"<li>{citation(run_id, ref)}</li>" for ref in brief["citations"]) + "</ul>"
            content += provenance_content(brief["provenance"], brief["caveats"]) + "</article>"
        else:
            content += "<aside>No saved brief available in this observation. No brief is generated, reconstructed or substituted.</aside>"
    target = f"/teams/planning/runs/{run_id}"
    return content + f"""<form method="post" action="{escape(target)}/refresh">
<input type="hidden" name="csrf" value="{escape(csrf)}"><button>Refresh Exercise Planning</button></form>
<p>Inspection never executes models, releases, retries or regenerates products.</p></main>"""
