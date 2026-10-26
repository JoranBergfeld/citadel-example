"""Read actual retention and sampling configuration; pair it with queried exporter counts."""

import math

from citadel.evidence.manifests import sha256
from citadel.operator.state import Blocked
from .collection import TABLES
from .oracle import hash_value
from .telemetry_proof import _application


def workspace_resource(lifecycle):
    marker = "/providers/Microsoft.OperationalInsights/workspaces/"
    rows = [rid for rid in lifecycle.value["inventory"]
            if marker in rid and "/" not in rid.split(marker, 1)[1]]
    if len(rows) != 1:
        raise Blocked("exact_acceptance_workspace_required")
    return rows[0]


def _resources(lifecycle):
    inventory = lifecycle.value["inventory"]
    selected = {"workspace": workspace_resource(lifecycle)}
    for name, marker in (
        ("insights", "/providers/Microsoft.Insights/components/"),
    ):
        rows = [rid for rid in inventory if marker in rid and "/" not in rid.split(marker, 1)[1]]
        if len(rows) != 1:
            raise Blocked("exact_telemetry_resource_inventory_required")
        selected[name] = rows[0]
    rows = [rid for rid in inventory if "/providers/Microsoft.ApiManagement/service/" in rid
            and rid.endswith("/diagnostics/applicationinsights")]
    if len(rows) != 1:
        raise Blocked("exact_gateway_diagnostic_inventory_required")
    return selected | {"gateway": rows[0]}


def telemetry_inputs(lifecycle):
    return {name: sha256(resource.lower()) for name, resource in _resources(lifecycle).items()}


def _number(value):
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError("Actual numeric diagnostic setting required")
    return float(value)


def _privacy(properties):
    return {side: {direction: {"headers": properties[side][direction]["headers"],
        "body": {"bytes": properties[side][direction]["body"]["bytes"]}}
        for direction in ("request", "response")} for side in ("frontend", "backend")}


def observe_retention(lifecycle, workspace, tables):
    targets = _resources(lifecycle)
    insights = lifecycle.native.rest("get", targets["insights"], "2020-02-02")
    gateway = lifecycle.native.rest("get", targets["gateway"], "2024-05-01")
    try:
        wp, ip, gp = workspace["properties"], insights["properties"], gateway["properties"]
        selected = [{"name": row["name"], "plan": row["properties"]["plan"],
            "retentionInDays": _number(row["properties"]["retentionInDays"]),
            "totalRetentionInDays": _number(row["properties"]["totalRetentionInDays"])}
            for row in tables if row["name"] in TABLES]
        return {"source": "actual-arm-retention-and-sampling",
            "targets": {name: sha256(document["id"].lower())
                        for name, document in (("workspace", workspace), ("insights", insights), ("gateway", gateway))},
            "workspace_sha256": sha256({"retentionInDays": _number(wp["retentionInDays"]),
                "dailyQuotaGb": _number(wp["workspaceCapping"]["dailyQuotaGb"])}),
            "tables_sha256": sha256(sorted(selected, key=lambda row: row["name"])),
            "insights_sha256": sha256({"workspace": sha256(ip["WorkspaceResourceId"].lower()),
                "sampling": _number(ip["SamplingPercentage"]), "local_auth_disabled": ip["DisableLocalAuth"]}),
            "gateway_sha256": sha256({"sampling": {"samplingType": gp["sampling"]["samplingType"],
                "percentage": _number(gp["sampling"]["percentage"])},
                **{key: gp[key] for key in ("alwaysLog", "httpCorrelationProtocol", "logClientIp", "verbosity")},
                **_privacy(gp)})}
    except (KeyError, ValueError, TypeError, AttributeError):
        return {"state": "blocked", "reason": "actual_retention_sampling_metadata_missing"}


def evaluate_retention(check, report):
    result = {"check_id": "telemetry.retention-and-unsampled", "status": "blocked",
              "reason": "actual_settings_and_complete_ingested_prefixes_required"}
    try:
        expected, actual = report["telemetry_inputs"], check["actual"]
        if (set(expected) != {"workspace", "insights", "gateway"}
                or not all(hash_value(value) for value in expected.values())
                or sha256(expected) != report["inputs"]["telemetry"]
                or actual.get("source") != "actual-arm-retention-and-sampling"):
            return result
        if actual["targets"] != expected:
            return result | {"status": "fail", "reason": "actual_telemetry_resource_binding_mismatch"}
        privacy = {"request": {"headers": [], "body": {"bytes": 0}},
                   "response": {"headers": [], "body": {"bytes": 0}}}
        hashes = {
            "workspace_sha256": sha256({"retentionInDays": 30.0, "dailyQuotaGb": -1.0}),
            "tables_sha256": sha256([{"name": name, "plan": "Analytics", "retentionInDays": 30.0,
                                     "totalRetentionInDays": 30.0} for name in sorted(TABLES)]),
            "insights_sha256": sha256({"workspace": expected["workspace"], "sampling": 100.0,
                                      "local_auth_disabled": True}),
            "gateway_sha256": sha256({"sampling": {"samplingType": "fixed", "percentage": 100.0},
                "alwaysLog": "allErrors", "httpCorrelationProtocol": "W3C", "logClientIp": False,
                "verbosity": "information", "frontend": privacy, "backend": privacy}),
        }
        if any(not hash_value(actual.get(key)) for key in hashes):
            return result
        if any(actual[key] != value for key, value in hashes.items()):
            return result | {"status": "fail", "reason": "actual_retention_sampling_or_payload_privacy_mismatch"}
        application = _application(report)
        if application["status"] != "pass":
            return result | {"status": application["status"]}
        return result | {"status": "pass", "reason": "actual_thirty_day_unsampled_settings_and_lossless_ingestion_verified"}
    except (KeyError, ValueError, TypeError, AttributeError):
        return result
