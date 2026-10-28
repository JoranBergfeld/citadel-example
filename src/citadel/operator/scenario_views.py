"""Current-run prose from saved service projections only."""

from html import escape


def scenario_content(data):
    reason = data.get("submission_reason")
    content = ""
    if reason:
        content += "<aside>" + {
            "active_run_blocker": "Global admission is blocked or operation state conflicts. An unresolved UI or CLI run may still own admission. Check the retained runs explicitly; no reset or automatic replay is available.",
            "ambiguous_dispatch": "Submission response was lost or ambiguous. Execution is unknown; inspect this run or explicitly check recovery. Do not resubmit it.",
            "allowance_exhausted": "Submission allowance exhausted; no fallback or refill.",
            "unknown": "Dispatch intent is retained but its outcome is unknown. Reopening never replays it.",
            "accepted": "Submission accepted. A persisted running label alone is not evidence of live activity.",
        }.get(reason, "Submission outcome unknown; never blindly replay.") + "</aside>"
    summary = data.get("summary")
    if not summary:
        return content + "<p>No saved scenario summary or brief is available. Execution may be incomplete or unknown.</p>"
    outcome = summary.get("outcome")
    title = {"complete": "Saved comparison result",
             "bounded_pool_exhausted": "Expected bounded-pool exhaustion: insufficient evidence, not technical failure"}.get(
                 outcome, "Incomplete or unknown saved result")
    content += f"<h3>{title}</h3>"
    if data.get("fixture") != "base-source":
        content += "<aside>Labelled synthetic overlay, separate from original source values. Original source data is unchanged.</aside>"
    content += f'<p>Bounded candidate pool: {escape(str(summary.get("pool_count", "unknown")))}.</p><ul>'
    for candidate in summary["candidates"]:
        content += (f'<li>{escape(candidate["airport_ident"])} · {escape(candidate["classification"])} · '
                    f'{escape(candidate["decision"])}')
        gaps = candidate.get("gap_reasons", [])
        if gaps:
            content += "<details><summary>Evidence gaps</summary><ul>" + "".join(
                f"<li>{escape(gap)}</li>" for gap in gaps) + "</ul></details>"
        content += "</li>"
    content += "</ul>"
    brief = summary.get("brief")
    if not brief:
        content += "<p>No saved brief. Missing products are not regenerated or presented as success.</p>"
    else:
        content += "<h3>Actual saved fictional brief</h3>"
        content += (f'<p>{escape(brief["narrative"])}</p>' if brief.get("narrative") else
                    "<p>Saved brief prose unavailable; not reconstructed.</p>")
        content += "<ul>" + "".join(
            f'<li>Approved finding {escape(ref["artifact_id"])} · version {escape(str(ref["version"]))} · '
            f'{escape(ref["sha256"])}</li>' for ref in brief["citations"]) + "</ul>"
        content += "<p>Exact saved approved-finding references; never substitute a newer version.</p>"
        content += "".join(f'<p>{escape(caveat)}</p>' for caveat in brief.get("caveats", []))
    return content + "".join(f'<p>{escape(caveat)}</p>' for caveat in summary.get("caveats", []))
