"""Operator-only Evidence Review navigation and escaped saved-product presentation."""

import asyncio
from datetime import datetime, timezone
from html import escape

from citadel.operations import OperationError, identity
from .observation import Observed


def finding_link(run_id, ref):
    """Stable same-origin citation interface; never points to workload draft APIs."""
    identity(run_id)
    identity(ref["artifact_id"])
    if type(ref["version"]) is not int or ref["version"] < 1:
        raise OperationError("invalid_input", "An exact finding version is required")
    return f'/teams/evidence/runs/{run_id}/findings/{ref["artifact_id"]}/versions/{ref["version"]}'


def observation_path(run_id, projection, cursor=None, artifact_id=None, version=None):
    identity(run_id)
    if cursor:
        identity(cursor)
    if projection in ("drafts", "releases") and artifact_id is None and version is None:
        owner = "evidence-assessor" if projection == "drafts" else "release-reviewer"
        return f"/{owner}/operator/runs/{run_id}/{projection}" + ("/page/" + cursor if cursor else "")
    if projection in ("finding", "draft") and cursor is None:
        identity(artifact_id)
        if type(version) is not int or not 1 <= version <= 999999999:
            raise OperationError("invalid_input", "An exact finding version is required")
        owner, collection = (("release-reviewer", "findings") if projection == "finding"
                             else ("evidence-assessor", "drafts"))
        return f"/{owner}/operator/runs/{run_id}/{collection}/{artifact_id}/versions/{version}"
    raise OperationError("invalid_input", "Unknown Evidence Review projection")


def status(observed, title):
    messages = {
        "denied": "Observation denied; no execution outcome established.",
        "missing": "Confirmed exact artifact missing; it is not regenerated or replaced with a newer version.",
        "empty": "Confirmed empty saved projection, not proof of no execution.",
        "partial": "Partial history: saved products remain inspectable; missing records/bindings are not reconstructed.",
        "unavailable": "Observation unavailable, not an execution failure.",
        "exhausted": "Deployment observation allowance exhausted; no fallback or refill.",
        "unknown": "Unknown observation; absence does not prove no work.",
        "ok": "Saved service observation, not live activity.",
    }
    timestamp = (datetime.fromtimestamp(observed.last_success, timezone.utc).isoformat()
                 if observed.last_success is not None else "none")
    content = f"<h3>{title}</h3><p>{escape(observed.state)} — {messages.get(observed.state, messages['unknown'])}</p>"
    content += f"<p>Last successful observation (UTC): {timestamp}. Not an atomic cross-team snapshot.</p>"
    if observed.stale:
        content += "<aside>stale — refresh failed; retained data is last known, not current activity.</aside>"
    return content


def ref_text(ref):
    return (f'{escape(ref["artifact_id"])} · version {ref["version"]}'
            f' · SHA256 {escape(ref["sha256"])}')


def assessment_content(item):
    content = f'<p>Completeness: {escape(item["classification"])}. Not airport safety or operational suitability.</p>'
    content += "<ul>" + "".join(f"<li>{escape(reason)}</li>" for reason in item["gap_reasons"]) + "</ul>"
    content += "<h4>Original caveats</h4><ul>" + "".join(
        f"<li>{escape(caveat)}</li>" for caveat in item["caveats"]) + "</ul>"
    provenance = item["provenance"]
    content += "<details><summary>Exact saved provenance</summary>"
    for kind in ("source", "profile", "fixture"):
        value = provenance[kind]
        content += (f'<p>{kind}: {escape(str(value.get("id", value.get("snapshot", ""))))}'
                    f' · {escape(value["sha256"])}</p>')
    return content + f'<p>Evidence origin: {escape(provenance["evidence_origin"])}</p></details>'


async def render(request, observer, run_id, csrf):
    params = request.path_params
    artifact_id, version = params.get("artifact_id"), params.get("version")
    projection, cursor = params.get("projection"), params.get("detail_cursor")
    refresh = request.method == "POST"
    automatic = request.headers.get("x-citadel-refresh") == "automatic"
    if artifact_id:
        if (params.get("collection") not in (None, "drafts")
                or not version.isdecimal() or len(version) > 9):
            raise OperationError("invalid_input", "An exact numeric finding version is required")
        kind = "draft" if params.get("collection") == "drafts" else "finding"
        queries = [(kind, {"artifact_id": artifact_id, "version": int(version)})]
    elif projection:
        if projection not in ("drafts", "releases"):
            raise OperationError("invalid_input", "Unknown Evidence Review page")
        queries = [(projection, {"cursor": cursor})]
    else:
        queries = [("drafts", {}), ("releases", {})]
    observations = (await asyncio.gather(*(
        observer.evidence(run_id, kind, refresh=refresh, **({"automatic": True} if automatic else {}),
                          **options) for kind, options in queries))
        if observer and hasattr(observer, "evidence") else [Observed(state="unavailable") for _ in queries])
    content = f"""<main><h2>Evidence Review · {escape(run_id)}</h2>
<p>Private Operator inspection. Assessment drafts are unpublished and private to Evidence Review.
Exercise Planning workloads have no draft read authority or previews.</p>
<p>Release Reviewer remains the approving agent. This view adds no human release gate.
Approval permits sharing, not completeness. Approved findings may report insufficient evidence.</p>
<p>Indeterminate reviewer execution is incomplete with unknown effects; technical failure is not insufficient evidence.</p>
<a href="/teams/evidence/runs/{escape(run_id)}">Drafts and release outcomes for this run</a>"""
    for (kind, _), observed in zip(queries, observations):
        content += status(observed, {"drafts": "Private saved assessment drafts",
                                    "releases": "Release outcomes", "finding": "Exact approved finding",
                                    "draft": "Exact private draft"}[kind])
        data = observed.data or {}
        if kind in ("drafts", "draft"):
            drafts = data.get("drafts", []) if kind == "drafts" else ([data["draft"]] if data.get("draft") else [])
            for item in drafts:
                ref = item["draft"]
                content += (f'<article id="draft-{ref["artifact_id"]}-v{ref["version"]}">'
                            f'<h4>Private draft · {escape(item["airport_ident"])}</h4><p>{ref_text(ref)}</p>')
                content += ("<p>" + escape(item["assessment_prose"]) + "</p>" if item.get("assessment_prose") is not None
                            else "<aside>Saved assessment prose unavailable in this history. Private notes are never substituted.</aside>")
                content += assessment_content(item) + "</article>"
        elif kind == "releases":
            for item in data.get("releases", []):
                content += f'<article><h4>Release outcome: {escape(item["outcome"])}</h4>'
                if item.get("draft"):
                    ref = item["draft"]
                    link = f'/teams/evidence/runs/{run_id}/drafts/{ref["artifact_id"]}/versions/{ref["version"]}'
                    content += f'<p><a href="{escape(link)}">Exact private draft: {ref_text(ref)}</a></p>'
                else:
                    content += "<p>Exact historical draft binding unavailable.</p>"
                if item.get("execution"):
                    content += f'<p>Reviewer execution: {escape(item["execution"])}; not the run outcome.</p>'
                if item.get("reason"):
                    content += f'<p>{escape(item["reason"])}</p>'
                if item.get("finding"):
                    content += (f'<a href="{finding_link(run_id, item["finding"])}">'
                                f'Open exact approved finding: {ref_text(item["finding"])}</a>')
                content += "</article>"
        elif data.get("finding"):
            item = data["finding"]
            ref = item["draft"]
            link = f'/teams/evidence/runs/{run_id}/drafts/{ref["artifact_id"]}/versions/{ref["version"]}'
            content += f'<article><p>{ref_text(item)}</p><p>Released from <a href="{escape(link)}">exact private draft: {ref_text(ref)}</a></p>'
            content += assessment_content(item) + "</article>"
        if data.get("next_cursor"):
            target = f'/teams/evidence/runs/{run_id}/{kind}/page/{data["next_cursor"]}'
            content += f'<a href="{escape(target)}">Next 20 {kind}</a>'
    target = request.url.path.removesuffix("/refresh")
    return content + f"""<form method="post" action="{escape(target)}/refresh">
<input type="hidden" name="csrf" value="{escape(csrf)}"><button>Refresh Evidence Review</button></form>
<p>History refresh is manual. Inspection never executes models, releases, retries or regenerates products.</p></main>"""
