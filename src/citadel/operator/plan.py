"""Human portal observation bound to the actual API Center resource incarnation."""

from datetime import datetime, timezone
import hashlib
from uuid import uuid4

from .state import Blocked, digest, private, read_private, write_private, write_private_bytes


BINDING_FIELDS = ("requestId", "deploymentId", "resourceId", "resourceCreatedAt")
OBSERVATION_FIELDS = {*BINDING_FIELDS, "observedAt", "observedPlan", "evidenceSha256"}


def timestamp(value):
    try:
        result = datetime.fromisoformat(value)
        if result.utcoffset() is None:
            raise ValueError
        return result.astimezone(timezone.utc)
    except (TypeError, ValueError):
        raise Blocked("api_center_observation_timestamp_invalid") from None


def current_request(lifecycle):
    value, state = lifecycle.value, lifecycle.state
    if not value.get("foundation_started") or not value.get("outputs"):
        raise Blocked("api_center_foundation_required")
    group = lifecycle.subscription + "/resourceGroups/" + lifecycle.groups["platform"]
    prefix = group + "/providers/Microsoft.ApiCenter/services/"
    resources = value["outputs"]["inventory"]["platform"]["resources"]
    centers = [r for r in resources if r.lower().startswith(prefix.lower())
               and r[len(prefix):] and "/" not in r[len(prefix):]]
    if len(centers) != 1 or not any(g["id"].lower() == group.lower() for g in lifecycle.owned_groups()):
        raise Blocked("api_center_owned_resource_required")
    resource = lifecycle.native.rest("get", centers[0], "2024-03-01")
    if (resource.get("id", "").lower() != centers[0].lower()
            or resource.get("tags", {}).get("citadel-deployment") != lifecycle.id
            or resource.get("location") != lifecycle.config["location"]):
        raise Blocked("api_center_resource_identity_conflict")
    if resource.get("properties", {}).get("provisioningState") != "Succeeded":
        raise Blocked("api_center_provider_not_succeeded")
    created = resource.get("systemData", {}).get("createdAt")
    if not created:
        raise Blocked("api_center_creation_identity_unavailable")
    binding = {"deploymentId": lifecycle.id, "resourceId": resource["id"],
               "resourceCreatedAt": timestamp(created).isoformat()}
    previous = value.get("planRequest", {})
    if any(previous.get(k) != v for k, v in binding.items()):
        value["planRequest"] = {
            **binding, "requestId": uuid4().hex,
            "requestedAt": datetime.now(timezone.utc).isoformat(),
            "portalUrl": "https://portal.azure.com/#@" + lifecycle.config["tenantId"]
                         + "/resource" + resource["id"] + "/overview",
        }
        value.pop("planProof", None)
        state.save()
    request = value["planRequest"]
    write_private(state.directory / "api-center-plan-request.json", request)
    return request


def require_observation(lifecycle):
    request = current_request(lifecycle)
    expected = lifecycle.value.get("planProof")
    if not expected:
        raise Blocked("api_center_portal_observation_required")
    try:
        proof = read_private(lifecycle.state.directory / "api-center-plan-proof.json")
        evidence = evidence_bytes(lifecycle.state.directory / "api-center-plan-evidence.bin")
    except FileNotFoundError:
        raise Blocked("api_center_portal_observation_required") from None
    if digest(proof) != expected or proof.get("source") != "human-azure-portal":
        raise Blocked("api_center_observation_integrity_conflict")
    validate_observation(proof["observation"], request, evidence)
    return proof


def evidence_bytes(path):
    path = private(path)
    with path.open("rb") as stream:
        content = stream.read(10 * 1024 * 1024 + 1)
    if not content or len(content) > 10 * 1024 * 1024:
        raise Blocked("api_center_observation_evidence_required_max_10mib")
    return content


def validate_observation(observation, request, evidence):
    if not isinstance(observation, dict) or set(observation) != OBSERVATION_FIELDS:
        raise Blocked("api_center_observation_fields")
    if any(observation[k] != request[k] for k in BINDING_FIELDS):
        raise Blocked("api_center_observation_resource_mismatch")
    if observation["observedPlan"] != "Free":
        raise Blocked("api_center_observed_plan_not_free")
    observed = timestamp(observation["observedAt"])
    if (observed < max(timestamp(request["requestedAt"]), timestamp(request["resourceCreatedAt"]))
            or observed > datetime.now(timezone.utc)):
        raise Blocked("api_center_observation_time_outside_resource_request")
    if observation["evidenceSha256"] != hashlib.sha256(evidence).hexdigest():
        raise Blocked("api_center_observation_evidence_hash_mismatch")


def record_observation(lifecycle, observation_path, evidence_path):
    # A rejected new observation must never leave an older Free assertion usable.
    lifecycle.value.pop("planProof", None)
    lifecycle.state.save()
    request = current_request(lifecycle)
    observation = read_private(observation_path)
    evidence = evidence_bytes(evidence_path)
    validate_observation(observation, request, evidence)
    proof = {"source": "human-azure-portal", "observation": observation,
             "recordedAt": datetime.now(timezone.utc).isoformat()}
    write_private_bytes(lifecycle.state.directory / "api-center-plan-evidence.bin", evidence)
    write_private(lifecycle.state.directory / "api-center-plan-proof.json", proof)
    lifecycle.value["planProof"] = digest(proof)
    lifecycle.state.event("record-plan-observation", "human_observed_free")
    return {"status": "api_center_free_observation_recorded", "runtimeActivated": False,
            "resume": "deploy with the same state directory and explicit paid confirmation"}


def observation_summary(lifecycle):
    try:
        proof = require_observation(lifecycle)
    except Blocked as exc:
        return {"status": "blocked", "code": exc.code}
    except (OSError, ValueError, TypeError, KeyError):
        return {"status": "blocked", "code": "api_center_observation_unavailable"}
    observation = proof["observation"]
    return {"status": "human_observed_free", "source": proof["source"],
            "proofSha256": digest(proof), "evidenceSha256": observation["evidenceSha256"],
            "resourceBindingSha256": digest({k: observation[k] for k in BINDING_FIELDS}),
            "observedAt": observation["observedAt"]}
