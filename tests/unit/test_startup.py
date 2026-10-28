import json
import unittest
from datetime import datetime, timedelta, timezone

from citadel.runtime.configuration import Configuration


def environment(role="candidate-planner"):
    now = datetime.now(timezone.utc)
    return {
        "CITADEL_TARGET": role, "AZURE_CLIENT_ID": "00000000-0000-0000-0000-000000000001",
        "CITADEL_DEPLOYMENT_ID": "citadeltest",
        "CITADEL_OBSERVATION_BLOB_URL": "https://observe.blob.core.windows.net",
        "CITADEL_GATEWAY_URL": "https://gateway.test",
        "CITADEL_BLOB_URL": "https://team.blob.core.windows.net",
        "CITADEL_VAULT_URL": "https://team.vault.azure.net",
        "CITADEL_BLOB_API_VERSION": "2026-10-06", "CITADEL_VAULT_API_VERSION": "2025-07-01",
        "CITADEL_GATEWAY_CERTIFICATES": json.dumps([{
            "sha256": "a" * 64, "not_before": (now - timedelta(days=1)).isoformat(),
            "not_after": (now + timedelta(days=89)).isoformat(),
        }]),
        "CITADEL_CONTEXT_KEYS": json.dumps({"test": "test-only-context-key-at-least-32-bytes"}),
        "CITADEL_MODEL_DEPLOYMENT": "approved-deployment",
        "CITADEL_MODEL_TOKENS_PER_MINUTE": "60000",
        "CITADEL_OPERATIONS_CONTAINER": "planner-operations",
        "CITADEL_SUBSCRIPTION_SECRET_NAME": "subscription-" + role,
        "CITADEL_REFERENCE_CONTAINER": "reference",
        "CITADEL_LIMITS": json.dumps({
            "concurrent_runs": 1, "workflow_seconds": 900, "candidates": 20, "agent_executions": 42,
            "model_attempts_run": 128, "model_attempts_execution": 8, "input_tokens_attempt": 16000,
            "output_tokens_attempt": 2000, "tokens_run": 1000000, "model_concurrency": 1,
            "model_requests_minute": 12, "model_tokens_minute_target": 120000,
            "model_timeout_seconds": 60, "safe_read_timeout_seconds": 30, "a2a_http_timeout_seconds": 180,
            "read_attempts_run": 512, "safe_read_retries": 2, "acceptance_seconds": 10, "poll_seconds": 15,
            "evidence_collection_seconds": 600, "cost_warning_hours": 24,
        }),
    }


class StartupTests(unittest.TestCase):
    def test_exact_workload_identity_limits_and_allocated_capabilities_are_required(self):
        config = Configuration.from_environment(environment())
        self.assertEqual(config.target, "candidate-planner")
        self.assertEqual(config.tokens_per_minute, 60000)
        for altered in [
            {"AZURE_CLIENT_ID": ""}, {"CITADEL_OPERATIONS_CONTAINER": "assessor-operations"},
            {"CITADEL_SUBSCRIPTION_SECRET_NAME": "subscription-operator"},
            {"CITADEL_GATEWAY_URL": "http://gateway.test"},
            {"CITADEL_MODEL_TOKENS_PER_MINUTE": "0"},
            {"CITADEL_BLOB_API_VERSION": "latest"},
            {"CITADEL_CONTEXT_KEYS": "{}"},
            {"CITADEL_OBSERVATION_BLOB_URL": "https://team.example.test"},
            {"CITADEL_DEPLOYMENT_ID": ""},
            {"CITADEL_LIMITS": '{"workflow_seconds":901}'},
        ]:
            with self.subTest(altered=tuple(altered)):
                with self.assertRaises(ValueError):
                    Configuration.from_environment(environment() | altered)

    def test_reference_data_needs_no_model_or_subscription_secret(self):
        values = environment("reference-data")
        for name in ("CITADEL_MODEL_TOKENS_PER_MINUTE", "CITADEL_MODEL_DEPLOYMENT",
                     "CITADEL_SUBSCRIPTION_SECRET_NAME", "CITADEL_OPERATIONS_CONTAINER"):
            del values[name]
        config = Configuration.from_environment(values)
        self.assertEqual(config.target, "reference-data")
        self.assertIsNone(config.subscription_secret)
