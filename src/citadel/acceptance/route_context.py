"""Bounded read targets derived from actual completed, caller-owned operations."""

from citadel.evidence.manifests import sha256
from citadel.gateway.trust import INVOCATION_CALLERS
from citadel.operations import identity, OperationError
from .oracle import hash_value
from .probes import AGENTS


def validate_route_context(context):
    try:
        if (not isinstance(context, dict) or set(context) != {"operations", "finding", "read_scope", "finding_controls"}
                or not isinstance(context["operations"], dict) or set(context["operations"]) != set(AGENTS)
                or not isinstance(context["finding"], dict)
                or set(context["finding"]) != {"artifact_id", "version", "sha256"}
                or type(context["finding"]["version"]) is not int or context["finding"]["version"] < 1
                or not hash_value(context["finding"]["sha256"])
                or not isinstance(context["read_scope"], dict)
                or set(context["read_scope"]) != {"operation_id", "run_id"}):
            raise ValueError("Exact bounded route context required")
        controls = context["finding_controls"]
        if not isinstance(controls, dict) or set(controls) != {"candidate-planner", "briefing-author"}:
            raise ValueError("Separate funded finding-read controls required")
        identity(context["finding"]["artifact_id"])
        run_id = identity(context["read_scope"]["run_id"])
        scope = identity(context["read_scope"]["operation_id"])
        scopes = set()
        for control in controls.values():
            if (not isinstance(control, dict) or set(control) != {"finding", "read_scope"}
                    or not isinstance(control["finding"], dict)
                    or set(control["finding"]) != {"artifact_id", "version", "sha256"}
                    or type(control["finding"]["version"]) is not int or control["finding"]["version"] < 1
                    or not hash_value(control["finding"]["sha256"])
                    or not isinstance(control["read_scope"], dict)
                    or set(control["read_scope"]) != {"operation_id", "run_id"}
                    or control["read_scope"]["run_id"] != run_id):
                raise ValueError("Exact separately funded finding control required")
            identity(control["finding"]["artifact_id"])
            scopes.add(identity(control["read_scope"]["operation_id"]))
        if len(scopes) != 2 or controls["candidate-planner"] != {
                "finding": context["finding"], "read_scope": context["read_scope"]}:
            raise ValueError("Finding controls must not compete for one finite reviewer pool")
        for actor, row in context["operations"].items():
            if (not isinstance(row, dict)
                    or set(row) != {"operation_id", "run_id", "input_hash", "result_sha256", "task_sha256"}
                    or row["run_id"] != run_id
                    or any(not hash_value(row[key]) for key in ("input_hash", "result_sha256", "task_sha256"))):
                raise ValueError("A completed same-run operation binding is required")
            identity(row["operation_id"])
            if actor == "release-reviewer" and row["operation_id"] in scopes:
                raise ValueError("Finding and status controls must not compete for one reviewer pool")
    except OperationError:
        raise ValueError("Invalid bounded route identity") from None


def build_route_context(documents, *, run_ids, available=None):
    if (not isinstance(documents, dict) or set(documents) != {*AGENTS, "findings"}
            or not isinstance(run_ids, list) or not 0 < len(run_ids) <= 4
            or not isinstance(documents.get("findings"), dict)
            or not isinstance(documents["findings"].get("findings"), dict)):
        raise ValueError("Observed ledgers and approved scenario runs are required")
    for run_id in run_ids:
        identity(run_id)
    completed = {}
    for actor in AGENTS:
        document = documents[actor]
        if not isinstance(document, dict) or not isinstance(document.get("operations"), dict):
            raise ValueError("Missing actual operation ledger")
        owner = next(iter(INVOCATION_CALLERS[actor]))
        completed[actor] = [row for key, row in sorted(document["operations"].items())
            if isinstance(row, dict) and row.get("state") == "succeeded" and row.get("run_id") in run_ids
            and isinstance(row.get("operation_id"), str) and key == owner + "/invoke/" + row["operation_id"]]
    for author in completed["briefing-author"]:
        product = author.get("product")
        if (not isinstance(product, dict) or product.get("status") != "complete"
                or not isinstance(product.get("citations"), list) or len(product["citations"]) != 3
                or not isinstance(product.get("read_scopes"), list)
                or len(product["citations"]) != len(product["read_scopes"])):
            continue
        released = []
        for reference, scope in zip(product["citations"], product["read_scopes"]):
            if (not isinstance(reference, dict) or not isinstance(scope, dict)
                    or not isinstance(reference.get("artifact_id"), str)
                    or type(reference.get("version")) is not int
                    or scope.get("run_id") != author["run_id"]):
                raise ValueError("Released reference has no same-run funded pool")
            versions = documents["findings"]["findings"].get(reference["artifact_id"], {})
            if not isinstance(versions, dict):
                raise ValueError("Released finding versions are malformed")
            finding = versions.get(str(reference["version"]))
            if finding is None or sha256(finding) != reference.get("sha256"):
                raise ValueError("Exact genuine released finding is required")
            if not any(row["run_id"] == author["run_id"] and row["operation_id"] == scope.get("operation_id")
                       and isinstance(row.get("result"), dict) and row["result"].get("finding") == reference
                       and row["result"].get("read_scope") == scope for row in completed["release-reviewer"]):
                raise ValueError("Finding read scope is not the genuine completed reviewer's funded scope")
            if available is not None and scope["operation_id"] not in available.get("release-reviewer", set()):
                raise ValueError("Existing reviewer pool has no remaining control read")
            released.append({"finding": dict(reference), "read_scope": dict(scope)})
        selected = {}
        for actor in AGENTS:
            candidates = [row for row in completed[actor] if row["run_id"] == author["run_id"]]
            if actor == "release-reviewer":
                candidates = [row for row in candidates if row["operation_id"] == released[2]["read_scope"]["operation_id"]]
            if actor == "evidence-assessor":
                candidates.sort(key=lambda row: row.get("result", {}).get("finding") != released[1]["finding"])
                if available is not None:
                    candidates = [row for row in candidates if row["operation_id"] in available.get(actor, set())]
            if actor == "briefing-author":
                candidates = [author]
            if not candidates:
                raise ValueError("No completed owner control with a separate funded reviewer pool")
            row = candidates[0]
            result = row.get("result")
            if not isinstance(result, dict):
                raise ValueError("Completed operation has no committed result")
            task = row.get("product") if actor in ("candidate-planner", "briefing-author") else result
            if (not isinstance(task, dict) or actor in ("candidate-planner", "briefing-author")
                    and result.get("sha256") != sha256(task)):
                raise ValueError("Committed task hash differs from its observed product")
            selected[actor] = {"operation_id": row["operation_id"], "run_id": row["run_id"],
                "input_hash": row.get("input_hash"), "result_sha256": sha256(result), "task_sha256": sha256(task)}
        context = {"operations": selected, **released[0],
                   "finding_controls": dict(zip(("candidate-planner", "briefing-author"), released[:2]))}
        validate_route_context(context)
        return context
    raise ValueError("A genuine completed comparison with released findings is required")


def finding_control(context, caller):
    return context["finding_controls"].get(caller, {"finding": context["finding"], "read_scope": context["read_scope"]})
