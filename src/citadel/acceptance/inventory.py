"""Actual ARM metadata and existing private human-plan evidence, never an inferred SKU."""

import hashlib
import math
import time
from uuid import UUID

from citadel.evidence.manifests import sha256
from citadel.operator.plan import BINDING_FIELDS, timestamp
from citadel.operator.state import Blocked
from .coverage import STORAGE
from .oracle import hash_value


CHECKS = ("inventory.five-environments-and-rest", "inventory.actual-free-plan")
TEAMS = {"reference-data": "Reference Data", "evidence-assessor": "Evidence Review",
         "release-reviewer": "Evidence Review", "candidate-planner": "Exercise Planning",
         "briefing-author": "Exercise Planning"}


def _principal(value):
    return hashlib.sha256(str(UUID(value)).encode()).hexdigest()


def _app(name, identities, container, ingress):
    environment = {item["name"]: item.get("value") for item in container["env"]}
    if len(environment) != len(container["env"]):
        raise ValueError("Duplicate actual environment fields")
    return {"name": name, "runtime_identity": _principal(environment["AZURE_PRINCIPAL_ID"]),
            "sha256": sha256({"identity": sorted(rid.lower() for rid in identities), "image": container["image"],
                "ingress": {"clientCertificateMode": ingress["clientCertificateMode"].lower(),
                            "allowInsecure": ingress["allowInsecure"]},
                "command": container["command"], "args": container["args"],
                "target": environment["CITADEL_TARGET"], "principal": environment["AZURE_PRINCIPAL_ID"],
                "client": environment["AZURE_CLIENT_ID"], "quota": environment["CITADEL_MODEL_TOKENS_PER_MINUTE"]})}


def _environment(name, properties):
    return {"name": name, "sha256": sha256({"customProperties": properties["customProperties"],
            "kind": properties["kind"], "server": {"type": properties["server"]["type"]}})}


def inventory_inputs(lifecycle):
    value, environments, applications = lifecycle.value, [], []
    gateway, request = value["outputs"]["gatewayUrl"], value["planRequest"]
    for app in value["outputs"]["appInventory"]:
        name = app["app"].rsplit("/", 1)[-1].removeprefix(lifecycle.id + "-")
        reference = name == "reference-data"
        environments.append(_environment(name, {"kind": "testing", "server": {"type": "Azure compute service"},
            "customProperties": {"workload": app["app"], "identity-resource-id": app["identity"],
                "identity-kind": "Azure user-assigned managed identity; not Entra Agent ID", "team": TEAMS[name],
                "protocol": "MCP" if reference else "A2A", "protocol-version": "2025-11-25" if reference else "1.0.0",
                "gateway-address": gateway + "/" + name + ("/mcp" if reference else "/a2a")}}))
        applications.append(_app(name, [app["identity"]], {"image": app["image"],
            "command": ["python", "-m", "citadel.runtime"], "args": [], "env": [
                {"name": key, "value": item} for key, item in {
                    "CITADEL_TARGET": name, "AZURE_PRINCIPAL_ID": app["identityPrincipalId"],
                    "AZURE_CLIENT_ID": app["identityClientId"],
                    "CITADEL_MODEL_TOKENS_PER_MINUTE": str(lifecycle.config["modelTokensPerMinute"])}.items()]},
            {"clientCertificateMode": "accept", "allowInsecure": False}))
    return {"target": sha256(value["outputs"]["inventory"]["capabilities"]["service"].lower()),
        "created": timestamp(request["resourceCreatedAt"]).timestamp(),
        "environments": sorted(environments, key=lambda row: row["name"]),
        "applications": sorted(applications, key=lambda row: row["name"]),
        "rest_sha256": sha256({"kind": "rest", "environmentId": "/workspaces/default/environments/release-reviewer",
                              "definitionId": "/workspaces/default/apis/released-findings/versions/v1-0-0/definitions/declared-rest",
                              "runtimeUri": [gateway + "/release-reviewer"]}),
        "plan": {"sha256": value["planProof"], "scope_sha256": sha256({key: request[key] for key in BINDING_FIELDS}),
                 "started": timestamp(request["requestedAt"]).timestamp()}}


def observe_inventory(lifecycle, documents):
    """Only receives the real responses returned by Lifecycle.verify_inventory."""
    try:
        center, applications = documents["center"], []
        for name, document in documents["applications"].items():
            containers = document["properties"]["template"]["containers"]
            if document["properties"]["provisioningState"] != "Succeeded" or len(containers) != 1:
                raise ValueError("Actual application is not provisioned")
            applications.append(_app(name, document["identity"]["userAssignedIdentities"], containers[0],
                                     document["properties"]["configuration"]["ingress"]))
        if center["properties"]["provisioningState"] != "Succeeded":
            raise ValueError("Actual inventory service is not provisioned")
        plan = documents["plan"]
        observation = plan["observation"]
        return {"source": "arm-and-private-human-portal-evidence", "finished": time.time(),
            "target": sha256(center["id"].lower()), "created": timestamp(center["systemData"]["createdAt"]).timestamp(),
            "environments": sorted([_environment(row["name"], row["properties"])
                                    for row in documents["environments"]], key=lambda row: row["name"]),
            "applications": sorted(applications, key=lambda row: row["name"]),
            "rest_sha256": sha256({"kind": documents["finding"]["properties"]["kind"],
                "environmentId": documents["deployment"]["properties"]["environmentId"],
                "definitionId": documents["deployment"]["properties"]["definitionId"],
                "runtimeUri": documents["deployment"]["properties"]["server"]["runtimeUri"]}),
            "plan": {"sha256": sha256(plan), "source": plan["source"], "name": observation["observedPlan"],
                "scope_sha256": sha256({key: observation[key] for key in BINDING_FIELDS}),
                "observed": timestamp(observation["observedAt"]).timestamp(),
                "evidence_sha256": observation["evidenceSha256"]}}
    except (KeyError, TypeError, ValueError, Blocked):
        return {"state": "blocked", "reason": "actual_inventory_or_private_observation_missing"}


def evaluate_inventory(check, report):
    result = {"check_id": check.get("check_id"), "status": "blocked",
              "reason": "actual_inventory_and_bound_human_observation_required"}
    try:
        expected, actual = report["inventory_inputs"], check["actual"]
        if (sha256(expected) != report["inputs"]["inventory"]
                or actual.get("source") != "arm-and-private-human-portal-evidence"):
            return result
        if actual["target"] != expected["target"] or actual["created"] != expected["created"]:
            return result | {"status": "fail", "reason": "actual_resource_incarnation_changed"}
        if check["check_id"] == CHECKS[0]:
            for field in ("applications", "environments"):
                rows = actual[field]
                if (len(rows) != 5 or {row["name"] for row in rows} != set(STORAGE)
                        or rows != expected[field]):
                    return result | {"status": "fail", "reason": "actual_five_workload_metadata_mismatch"}
            if (any(row["runtime_identity"] != report["runtime_identities"][row["name"]]
                    for row in actual["applications"]) or actual["rest_sha256"] != expected["rest_sha256"]):
                return result | {"status": "fail", "reason": "executing_identity_or_real_rest_inventory_mismatch"}
        elif check["check_id"] == CHECKS[1]:
            plan, bound = actual["plan"], expected["plan"]
            if (plan["sha256"] != bound["sha256"] or plan["scope_sha256"] != bound["scope_sha256"]
                    or not all(hash_value(plan[key]) for key in ("sha256", "scope_sha256", "evidence_sha256"))
                    or type(plan["observed"]) not in (int, float)
                    or not math.isfinite(plan["observed"])
                    or type(actual["finished"]) not in (int, float) or not math.isfinite(actual["finished"])
                    or not max(expected["created"], bound["started"]) <= plan["observed"] <= actual["finished"]):
                return result
            if plan["source"] != "human-azure-portal" or plan["name"] != "Free":
                return result | {"status": "fail", "reason": "actual_human_observed_free_plan_required"}
        else:
            return result
        return result | {"status": "pass", "reason": "actual_bound_inventory_observation_verified"}
    except (KeyError, TypeError, ValueError, AttributeError):
        return result
