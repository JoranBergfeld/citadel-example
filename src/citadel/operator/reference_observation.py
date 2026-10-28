"""Server-only Reference Data client and escaped, read-only team presentation."""

from datetime import datetime, timezone
from html import escape
import json

from citadel.operations import OperationError, identity
from .observation import ObservationClient


class ReferenceObservationClient(ObservationClient):
    def key(self, run_id, cursor):
        if cursor is not None:
            raise OperationError("invalid_input", "Reference Data has no browse cursor")
        return (self.admission.deployment, identity(run_id), "reference-assessed", None)

    def path(self, run_id, cursor):
        return "/reference-data/operator/reference/runs/" + identity(run_id)


def _value(value):
    return escape(json.dumps(value, ensure_ascii=False))


def _records(evidence):
    content = ""
    for kind in ("airport", "country", "region", "runways"):
        rows = evidence.get(kind, [])
        if isinstance(rows, dict):
            rows = [rows]
        content += f"<details><summary>{kind}</summary>"
        for row in rows:
            content += "<table><thead><tr><th>Field</th><th>Raw</th><th>Parsed</th><th>Quality reasons</th></tr></thead><tbody>"
            for field, cell in row.items():
                content += (f"<tr><th>{escape(field)}</th><td>{_value(cell['raw'])}</td>"
                            f"<td>{_value(cell['parsed'])}</td><td>{_value(cell['quality_reasons'])}</td></tr>")
            content += "</tbody></table>"
        content += "</details>"
    return content


def reference_content(observed, csrf, run_id):
    state = observed.state if observed else "unavailable"
    data = observed.data if observed and observed.data else {}
    timestamp = (datetime.fromtimestamp(observed.last_success, timezone.utc).isoformat()
                 if observed and observed.last_success is not None else "none")
    descriptions = {
        "ok": "Exact saved assessed-candidate bindings; no live activity is implied.",
        "partial": "Historical source or assessed bindings unavailable. Current data is never substituted.",
        "empty": "No saved assessments in this retained context; this does not prove no work occurred.",
        "missing": "Confirmed missing retained run; no backfill or proof of non-execution.",
        "denied": "Observation denied; this establishes no execution outcome.",
        "exhausted": "Deployment observation allowance exhausted; no fallback or refill.",
        "unavailable": "Observation unavailable; this is not an execution failure.",
        "unknown": "Observation unknown; missing evidence is not proof of no work.",
    }
    content = (f"<main><h2>Reference Data · {escape(run_id)}</h2>"
               f"<p>Reference Data projection: {escape(state)}. {descriptions.get(state, descriptions['unknown'])}</p>"
               f"<p>Last successful observation (UTC): {timestamp}. Not an atomic cross-team snapshot.</p>")
    if observed and observed.stale:
        content += "<aside>stale — refresh failed; last successfully observed exact evidence is retained.</aside>"
    content += "<p>Only saved assessed candidates are shown. Original source values are unchanged. No browsing, export or editing.</p>"
    for item in data.get("candidates", []):
        assessment = item["assessment"]
        content += (f"<details><summary>{escape(item['airport_ident'])} · {escape(assessment['classification'])}</summary>"
                    "<p>Completeness is not release approval, accuracy, airport safety or operational suitability.</p>"
                    "<h3>Completeness quality reasons</h3><ul>" +
                    "".join(f"<li>{escape(reason)}</li>" for reason in assessment["gap_reasons"]) + "</ul>"
                    "<details><summary>Original source · raw and parsed values</summary>" +
                    _records(item["original_source"]) + "</details>"
                    "<details><summary>Assessment values · labelled overlay, not source edits</summary>" +
                    _records(assessment["evidence"]) + "</details>"
                    "<h3>Labelled overlay differences</h3>")
        for difference in item["overlay_differences"]:
            content += (f"<p>synthetic-overlay · runway {difference['runway_id']} · {escape(difference['field'])}: "
                        f"Original source {_value(difference['original'])} → Overlay {_value(difference['overlay'])}</p>")
        if not item["overlay_differences"]:
            content += "<p>No overlay differences for this assessed candidate.</p>"
        content += "<ul>" + "".join(f"<li>{escape(caveat)}</li>" for caveat in assessment["caveats"]) + "</ul></details>"
    for key, title in (("profile", "Comparison profile"), ("source_provenance", "Source provenance"),
                       ("overlay", "Labelled overlay provenance"), ("bindings", "Exact saved bindings")):
        if key in data:
            content += f"<details><summary>{title}</summary><pre>{_value(data[key])}</pre></details>"
    target = "/teams/reference/runs/" + escape(run_id)
    return content + (f'<form method="post" action="{target}/refresh"><input type="hidden" name="csrf" '
                      f'value="{escape(csrf)}"><button>Refresh Reference Data</button></form>'
                      "<p>History refresh is manual. Observation never executes or recovers work.</p></main>")
