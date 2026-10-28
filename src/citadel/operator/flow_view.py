"""Authored topology and independently observed owner calls for one selected run."""

import asyncio
from datetime import datetime, timezone
from html import escape
import math
import textwrap

from .observation import Observed


OWNERS = {
    "candidate-planner": "Candidate Planner",
    "evidence-assessor": "Evidence Assessor",
    "release-reviewer": "Release Reviewer",
    "briefing-author": "Briefing Author",
}
TARGETS = {
    "model": "Requesting a model explanation through the model route",
    "reference": "Awaiting Reference Data through the gateway",
    "evidence-assessor": "Awaiting Evidence Assessor through the gateway",
    "release-reviewer": "Awaiting Release Reviewer through the gateway",
    "briefing-author": "Awaiting Briefing Author through the gateway",
    "findings": "Reading exact approved findings through the gateway",
}
ROUTES = {
    "candidate-planner": ("model", "reference", "evidence-assessor", "findings", "briefing-author"),
    "evidence-assessor": ("model", "reference", "release-reviewer"),
    "release-reviewer": ("model", "reference"),
    "briefing-author": ("model", "findings"),
}
TEAMS = {
    "reference": "reference", "candidate-planner": "planning", "briefing-author": "planning",
    "records": "planning", "evidence-assessor": "evidence", "release-reviewer": "evidence",
    "drafts": "evidence", "findings": "evidence",
}


async def observations(observer, run_id, *, refresh=False, automatic=False):
    if not observer or not hasattr(observer, "evidence") or not hasattr(observer, "planning"):
        return {owner: Observed(state="unavailable") for owner in list(OWNERS)[1:]}
    results = await asyncio.gather(
        observer.evidence(run_id, "drafts", refresh=refresh, automatic=automatic),
        observer.evidence(run_id, "releases", refresh=refresh, automatic=automatic),
        observer.planning(run_id, "brief", refresh=refresh, automatic=automatic))
    return dict(zip(list(OWNERS)[1:], results))


def link(run_id, node):
    return f"/teams/{TEAMS[node]}/runs/{run_id}" if node in TEAMS else f"#architecture-{node}"


def owner_content(run_id, projections, now):
    run = escape(run_id)
    content = """<section class="owner-observations"><h4>Observed owner activity</h4>
<p>Independent projections; last-success times are not an atomic snapshot. Unknown does not mean idle.
Calls between observations may not be visible. A saved running label never lights a node.</p><ul>"""
    for owner, title in OWNERS.items():
        observed = projections.get(owner) or Observed()
        activity = (observed.data or {}).get("activity") or {}
        target = activity.get("target")
        # Do not let another run/owner or arbitrary service nominate a route.
        bound = (activity.get("owner") == owner and activity.get("run_id") == run_id
                 and activity.get("kind") == "inflight" and target in ROUTES[owner])
        started, end = activity.get("observed_at"), activity.get("expires_at")
        valid_time = (type(started) in (int, float) and type(end) in (int, float)
                      and math.isfinite(started) and math.isfinite(end) and started < end <= started + 15)
        fresh = (bound and valid_time and started <= now < end and not observed.stale
                 and observed.state in ("ok", "partial", "empty"))
        action = TARGETS[target] if bound else ""
        label = action if fresh else "Current activity unknown. Last observed: " + (action or "no in-flight call evidenced")
        timestamp = (datetime.fromtimestamp(observed.last_success, timezone.utc).isoformat()
                     if observed.last_success is not None else "none")
        attrs = (f' data-run="{run}" data-kind="inflight" data-target="{target}"'
                 f' data-observed-at="{started}" data-expires-at="{end}"' if bound and valid_time else "")
        content += (f'<li data-owner-activity="{owner}" data-state="{escape(observed.state)}" '
                    f'data-stale="{str(observed.stale).lower()}"{attrs} data-action="{escape(action)}">'
                    f'<strong>{title}</strong> · <span data-activity-label>{escape(label)}</span>'
                    f'<small>{escape(observed.state)} · last successful observation (UTC): {timestamp}'
                    f'{" · stale / last known" if observed.stale else ""}</small></li>')
    return content + "</ul></section>"


def render(run_id, projections, *, now):
    run = escape(run_id)
    content = f"""<section class="flow-panel" data-flow-run="{run}" aria-labelledby="flow-heading">
<div class="flow-heading"><div><h3 id="flow-heading">Follow the cross-team flow</h3>
<p>Authored architecture / possible routes — not an execution trace.</p></div>
<button type="button" data-animation-toggle aria-pressed="false">Pause animation</button></div>
<p>Observed owner activity below is separate from the architecture. A pulse means a fresh
owning service reports an in-flight call, not proof that the destination is executing.
Animation controls change presentation only, never execution.</p>"""
    content += owner_content(run_id, projections, now)
    content += """
<div class="flow-entry">"""
    for node, label in (("ui", "Operator UI"), ("backend", "UI backend"),
                        ("apim", "APIM entry"), ("gateway", "Gateway-mediated calls")):
        content += f'<a data-inspect-node="{node}" href="{link(run_id, node)}">{label}</a>'
        if node != "gateway":
            content += '<span aria-hidden="true"> → </span>'
    content += """</div><div class="team-map"><svg viewBox="0 0 960 650" role="group"
aria-labelledby="architecture-title architecture-description">
<title id="architecture-title">Cross-team architecture — selectable nodes</title>
<desc id="architecture-description">Authored possible calls, not observed stages. Reference Data,
Evidence Review and Exercise Planning have distinct scoped storage and authority.
Select a node for run-bound inspection or architecture detail. All service calls use the gateway.</desc>
<defs><marker id="route-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6"
orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z"/></marker></defs>"""
    lanes = (
        ("Reference Data", "Read-only source capability", (
            ("reference", "Reference Data", "Assessed airports / runways only"),
            ("reference-storage", "Reference storage", "Scoped read-only dataset access"))),
        ("Evidence Review", "Private drafts → approved sharing", (
            ("evidence-assessor", "Evidence Assessor", "Check completeness / explain gaps"),
            ("drafts", "Assessment drafts", "Private · exact versions · Operator inspection"),
            ("release-reviewer", "Release Reviewer", "Approves sharing, not completeness"),
            ("findings", "Approved findings", "Shared · exact released versions"),
            ("evidence-storage", "Evidence storage", "Scoped private drafts / released findings"))),
        ("Exercise Planning", "Approved findings only; no draft previews", (
            ("candidate-planner", "Candidate Planner", "Select / skip within bounded pool"),
            ("briefing-author", "Briefing Author", "Write from exact approved citations"),
            ("records", "Planning records", "Decisions / saved fictional brief"),
            ("planning-storage", "Planning storage", "Scoped owner operation / product records"))),
    )
    for column, (team, subtitle, _) in enumerate(lanes):
        x = 10 + column * 320
        content += (f'<rect class="team-lane" x="{x}" y="10" width="300" height="630" rx="8"/>'
                    f'<text class="lane-title" x="{x + 20}" y="42">{team}</text>'
                    f'<text class="lane-subtitle" x="{x + 20}" y="64">{escape(subtitle)}</text>')
    paths = (
        ("candidate-planner:evidence-assessor", "M670 134 H610"),
        ("candidate-planner:briefing-author", "M800 168 V320"),
        ("candidate-planner:reference", "M800 100 V82 H160 V245"),
        ("candidate-planner:findings", "M670 145 H635 V458 H610"),
        ("evidence-assessor:reference", "M350 134 H315 V263 H290"),
        ("evidence-assessor:release-reviewer", "M350 150 H335 V354 H350"),
        ("release-reviewer:reference", "M350 354 H315 V288 H290"),
        ("briefing-author:findings", "M670 354 H645 V480 H610"),
    )
    for route, path in paths:
        content += f'<path class="route-wire" data-route="{route}" d="{path}"/>'
    for path in ("M480 168 V210", "M500 320 V278", "M480 388 V430", "M480 498 V540",
                 "M160 313 V500", "M800 388 V430", "M800 498 V540"):
        content += f'<path class="storage-wire" d="{path}"/>'
    for column, (_, _, nodes) in enumerate(lanes):
        x = 30 + column * 320
        positions = ((245, 500) if column == 0 else
                     (100, 210, 320, 430, 540) if column == 1 else (100, 320, 430, 540))
        for (node, title, description), y in zip(nodes, positions):
            content += (f'<a class="flow-node" data-node="{node}" data-inspect-node="{node}" '
                        f'href="{escape(link(run_id, node))}" aria-label="{escape(title + ": " + description)}">'
                        f'<rect x="{x}" y="{y}" width="260" height="68" rx="6"/>'
                        f'<text class="node-title" x="{x + 12}" y="{y + 23}">{title}</text>')
            for number, line in enumerate(textwrap.wrap(description, 40)):
                content += f'<text class="node-description" x="{x + 12}" y="{y + 42 + number * 13}">{escape(line)}</text>'
            content += "</a>"
    content += """<text class="wire-label" x="735" y="235">gateway / A2A</text>
<text class="wire-label" x="320" y="625">Service arrows use gateway routes; thin links are scoped storage access.</text>
</svg></div><p class="model-route"><a data-inspect-node="model" href="#architecture-model">
Scoped model route</a> · agents → gateway → model deployment. The UI has no model permission.</p>
<details class="possible-routes"><summary>Possible service routes and authority (authored, not observed)</summary>
<ul>"""
    for owner, targets in ROUTES.items():
        for target in targets:
            label = {"model": "Model route", "reference": "Reference Data", "findings": "Approved findings"}.get(
                target, OWNERS.get(target, target))
            protocol = "MCP" if target == "reference" else "exact finding read" if target == "findings" else (
                "model request" if target == "model" else "A2A request / wait")
            content += (f'<li data-route="{owner}:{target}">{OWNERS[owner]} → gateway → {label}'
                        f' · {protocol}</li>')
    content += """</ul><p>Evidence Assessor saves private drafts; Release Reviewer reads exact drafts,
rechecks Reference Data and publishes approved findings. Planning agents never read drafts.
Each service uses its own scoped storage identity; storage access is not a generic gateway proxy.</p></details>
<details class="architecture-detail"><summary>Architecture node detail</summary>
<section id="architecture-ui"><h4>Operator UI</h4><p>One authenticated Operator, three perspectives,
one selected run. Browser access stays on this origin; inspection never submits work.</p></section>
<section id="architecture-backend"><h4>UI backend</h4><p>Distinct server-side Operator caller,
authorized projections and explicit controls only. No team-data, model or generic proxy authority.</p></section>
<section id="architecture-apim"><h4>APIM entry</h4><p>Separate narrow observation / control actions;
deny-by-default caller, action and path checks. Credentials stay server-side.</p></section>
<section id="architecture-gateway"><h4>Gateway-mediated calls</h4><p>Authorized MCP, A2A, finding and model routes.
Workload origins retain certificate / signed-context protection and ordinary ownership checks.</p></section>
<section id="architecture-model"><h4>Scoped model routing</h4><p>Each agent's bounded model request uses
the gateway and its own authority. Models explain and write, not approve access or select candidates.
No prompts, hidden reasoning or model streams are exposed.</p></section>
<section id="architecture-reference-storage"><h4>Reference storage</h4><p>Reference Data owns read-only
source access. Inspection resolves exact run-bound source/profile/overlay bindings for assessed candidates;
original values remain distinct from labelled overlays. No UI Blob role.</p></section>
<section id="architecture-evidence-storage"><h4>Evidence storage</h4><p>Evidence Review owns private
versioned drafts and exact approved findings. Operator draft inspection does not grant Planning
draft access. Approval permits sharing, not completeness or safety.</p></section>
<section id="architecture-planning-storage"><h4>Planning storage</h4><p>Exercise Planning owns bounded
candidate decisions, operation records and saved briefs. Exact approved citations reopen their historical
versions, never newer substitutes. Missing history remains unavailable.</p></section></details>
</section>"""
    return content


STYLE = """
.flow-panel{border:1px solid #536478;border-radius:.8rem;padding:1.2rem;margin:1.2rem 0;background:#142437}
.flow-heading{display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap}
.flow-heading h3{margin:0}.flow-heading p{margin:.25rem 0}.flow-panel>p{font-size:.9rem}
.flow-entry,.model-route{text-align:center;border:1px solid #536478;border-radius:.5rem;padding:.8rem}
.team-map{overflow-x:auto}.team-map svg{display:block;min-width:800px;width:100%;height:auto}
.team-lane{fill:#101b28;stroke:#536478}.lane-title{fill:#e5edf5;font-size:18px;font-weight:bold}
.lane-subtitle,.wire-label{fill:#c1cedc;font-size:11px}
.flow-node rect{fill:#1a3046;stroke:#8497ac;stroke-width:1.5}
.flow-node text{fill:#e5edf5;pointer-events:none}.node-title{font-size:16px;font-weight:bold}
.node-description{font-size:11px}.flow-node:hover rect{fill:#284663}
.flow-node[data-live] rect{stroke:#8ed8eb;stroke-width:3}
.route-wire{fill:none;stroke:#8497ac;stroke-width:1.6;marker-end:url(#route-arrow)}
#route-arrow path{fill:#8497ac}.storage-wire{fill:none;stroke:#536478;stroke-width:1;marker-end:url(#route-arrow)}
.route-wire[data-live]{stroke:#8ed8eb;stroke-width:3}
.possible-routes li[data-live]{color:#8ed8eb;font-weight:bold}
.owner-observations li{margin:.8rem 0}.owner-observations small{display:block;color:#c1cedc}
.architecture-detail:has(:target){content-visibility:visible}
@keyframes owner-pulse{50%{stroke-opacity:.35}}
@keyframes route-pulse{50%{opacity:.55}}
[data-motion=animated] .flow-node[data-pulse] rect{animation:owner-pulse 1.4s ease-in-out infinite}
[data-motion=animated] .route-wire[data-pulse]{animation:owner-pulse 1.4s ease-in-out infinite}
[data-motion=animated] li[data-pulse]{animation:route-pulse 1.4s ease-in-out infinite}
@media(prefers-reduced-motion:reduce){[data-pulse],[data-pulse] rect{animation:none!important}}
@media(max-width:760px){.flow-panel{padding:.75rem}}
"""
