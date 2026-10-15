"""Required obligations, not results. A missing driver/proof remains blocked."""

from citadel.gateway.trust import INVOCATION_CALLERS, FINDING_CALLERS
from citadel.runtime.configuration import LIMITS
from .probes import AGENTS


CONTAINERS = ("reference", "drafts", "findings", "assessor-operations", "reviewer-operations",
              "candidate-lists", "briefs", "planner-operations", "author-operations")
STORAGE = {
    "reference-data": {"reference": "read"},
    "evidence-assessor": {"drafts": "write", "assessor-operations": "write"},
    "release-reviewer": {"drafts": "read", "findings": "write", "reviewer-operations": "write"},
    "candidate-planner": {"candidate-lists": "write", "planner-operations": "write"},
    "briefing-author": {"briefs": "write", "author-operations": "write"},
}
FAULTS = (
    "safe-read-recovery", "safe-read-exhaustion", "dropped-committed-write",
    "dropped-committed-release", "pending-incomplete", "running-incomplete",
    "indeterminate-incomplete", "missing-incomplete", "fenced-explicit-retry",
    "stale-generation-denied", "identical-input-reuse", "changed-input-conflict",
    "concurrent-exact-draft-release", "concurrent-different-operation-release",
    "concurrent-version-conflict", "deadline-no-late-effect", "restart-no-replay",
    "draft-hash-binding", "immutable-versions", "partial-not-completed",
)


def required_checks():
    checks = {f"scenario.{name}": "semantic" for name in
              ("comparison", "replacement", "exhaustion", "denied-bypass")}
    for caller in ("operator", *AGENTS):
        for target in AGENTS:
            for capability in ("invoke", "discovery", "status", "task"):
                checks[f"route.{caller}.{target}.{capability}"] = (
                    "allow" if caller in INVOCATION_CALLERS[target] else "deny")
        for capability in ("initialize", "search_airports", "lookup_airport", "list_runways"):
            checks[f"route.{caller}.reference-data.{capability}"] = (
                "allow" if caller in INVOCATION_CALLERS["reference-data"] else "deny")
        checks[f"route.{caller}.release-reviewer.findings"] = "allow" if caller in FINDING_CALLERS else "deny"
        checks[f"route.{caller}.model.inference"] = "deny" if caller == "operator" else "allow"
    for caller, grants in STORAGE.items():
        for container in CONTAINERS:
            for action in ("read", "write"):
                checks[f"storage.{caller}.{container}.{action}"] = (
                    "allow" if grants.get(container) == "write" or
                    action == "read" and container in grants else "deny")
        checks[f"model.{caller}.direct-denied"] = "deny"
        for fault in ("missing-certificate", "unrelated-certificate", "forged-context"):
            checks[f"origin.{caller}.{fault}"] = "deny"
    checks.update({f"fault.{fault}": "fault" for fault in FAULTS})
    checks.update({f"limit.{limit}": "boundary" for limit in LIMITS
                   if limit not in ("cost_warning_hours", "evidence_collection_seconds")})
    checks.update({name: "evidence" for name in (
        "inventory.five-environments-and-rest", "inventory.actual-free-plan",
        "telemetry.application-ingestion", "telemetry.gateway-correlation",
        "telemetry.storage-correlation", "telemetry.retention-and-unsampled",
        "rotation.subscription-allowed-and-revoked", "rotation.certificate-allowed-and-revoked",
        "rotation.context-allowed-and-revoked", "projection.private-fields-absent",
        "protocol.a2a-1.0", "protocol.mcp-2025-11-25", "protocol.model-v1",
        "authority.executing-identities", "authority.status-owner-scope",
    )})
    return checks
