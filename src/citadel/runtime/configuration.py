"""Fail-closed environment contract shared by the five standalone processes."""

import json
import re
from dataclasses import dataclass
from urllib.parse import urlsplit
from uuid import UUID

from citadel.gateway import TrustConfiguration
from .model import INSTRUCTIONS


OPERATIONS = {
    "candidate-planner": "planner-operations", "evidence-assessor": "assessor-operations",
    "release-reviewer": "reviewer-operations", "briefing-author": "author-operations",
}
LIMITS = {
    "concurrent_runs": 1, "workflow_seconds": 900, "candidates": 20, "agent_executions": 42,
    "model_attempts_run": 128, "model_attempts_execution": 8, "input_tokens_attempt": 16000,
    "output_tokens_attempt": 2000, "tokens_run": 1000000, "model_concurrency": 1,
    "model_requests_minute": 12, "model_tokens_minute_target": 120000, "model_timeout_seconds": 60,
    "safe_read_timeout_seconds": 30, "a2a_http_timeout_seconds": 180, "read_attempts_run": 512,
    "safe_read_retries": 2, "acceptance_seconds": 10, "poll_seconds": 15,
    "evidence_collection_seconds": 600, "cost_warning_hours": 24,
}


def endpoint(value, suffix=None):
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.path not in ("", "/") or parsed.port is not None or parsed.query or parsed.fragment
            or (suffix is not None and not parsed.hostname.endswith(suffix))):
        raise ValueError("Expected the explicit allocated HTTPS service origin")
    return value.rstrip("/")


@dataclass(frozen=True)
class Configuration:
    target: str
    client_id: str
    gateway: str
    blob: str
    vault: str
    trust: TrustConfiguration
    operations_container: str | None
    subscription_secret: str | None
    model_deployment: str | None
    tokens_per_minute: int | None
    deployment_id: str | None
    observation_blob: str | None
    reference_context_blob: str | None = None

    @classmethod
    def from_environment(cls, env):
        try:
            target = env["CITADEL_TARGET"]
            if target not in (*INSTRUCTIONS, "reference-data"):
                raise ValueError("Unknown workload")
            client_id = str(UUID(env["AZURE_CLIENT_ID"]))
            if (env["CITADEL_BLOB_API_VERSION"] != "2026-10-06"
                    or env["CITADEL_VAULT_API_VERSION"] != "2025-07-01"):
                raise ValueError("Data-plane API pin differs")
            limits = json.loads(env["CITADEL_LIMITS"])
            if limits != LIMITS or any(type(value) is not int for value in limits.values()):
                raise ValueError("Runtime limits differ from approved ceilings")
            trust = TrustConfiguration.from_json(target, env["CITADEL_GATEWAY_CERTIFICATES"],
                                                   env["CITADEL_CONTEXT_KEYS"])
            container = secret = model = quota = None
            deployment = observation_blob = None
            reference_context_blob = None
            if target in ("candidate-planner", "evidence-assessor", "release-reviewer", "reference-data"):
                deployment = env["CITADEL_DEPLOYMENT_ID"]
                if not re.fullmatch(r"[a-z0-9]{3,12}", deployment):
                    raise ValueError("Trusted deployment identity required")
                observation_blob = endpoint(env["CITADEL_OBSERVATION_BLOB_URL"], ".blob.core.windows.net")
            if target == "reference-data":
                if env["CITADEL_REFERENCE_CONTAINER"] != "reference":
                    raise ValueError("Reference Data may read only its allocated container")
                reference_context_blob = endpoint(
                    env["CITADEL_REFERENCE_CONTEXT_BLOB_URL"], ".blob.core.windows.net")
            else:
                container = env["CITADEL_OPERATIONS_CONTAINER"]
                secret = env["CITADEL_SUBSCRIPTION_SECRET_NAME"]
                if container != OPERATIONS[target] or secret != "subscription-" + target:
                    raise ValueError("Storage or secret capability differs from workload allocation")
                model = env["CITADEL_MODEL_DEPLOYMENT"]
                quota = int(env["CITADEL_MODEL_TOKENS_PER_MINUTE"])
                if not model or not 1 <= quota <= 120000:
                    raise ValueError("Actual independently verified model TPM quota is required")
            return cls(target, client_id, endpoint(env["CITADEL_GATEWAY_URL"]),
                       endpoint(env["CITADEL_BLOB_URL"], ".blob.core.windows.net"),
                       endpoint(env["CITADEL_VAULT_URL"], ".vault.azure.net"), trust,
                       container, secret, model, quota, deployment, observation_blob, reference_context_blob)
        except (KeyError, TypeError, OverflowError) as exc:
            raise ValueError("Required allocated runtime configuration is missing or invalid") from exc
