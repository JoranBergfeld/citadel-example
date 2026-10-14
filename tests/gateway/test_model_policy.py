import json
from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET

import httpx2
from agent_framework import Message
from agent_framework_openai import OpenAIChatCompletionClient
from openai import AsyncOpenAI


ROOT = Path(__file__).resolve().parents[2]


class ModelPolicyTests(unittest.IsolatedAsyncioTestCase):
    async def test_policy_token_field_matches_actual_pinned_adapter_request(self):
        requests = []

        def respond(request):
            requests.append(json.loads(request.content))
            return httpx2.Response(200, json={
                "id": "fixture", "object": "chat.completion", "created": 0,
                "model": "gpt-4.1-mini",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "fixture"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            })

        async with httpx2.AsyncClient(transport=httpx2.MockTransport(respond)) as transport:
            async with AsyncOpenAI(
                api_key="test-only", http_client=transport, max_retries=0,
                base_url="https://gateway.invalid/openai/v1/",
            ) as client:
                adapter = OpenAIChatCompletionClient(model="citadel-gpt-41-mini", async_client=client)
                await adapter.get_response([Message("user", ["fixture"])], options={"max_tokens": 2000})
        policy = ET.parse(ROOT / "infra/policies/model.xml")
        expression = policy.find("./inbound/set-variable[@name='validModelRequest']").get("value")
        field = re.search(r'var tokens = \(int\?\)body\["([^"]+)"\]', expression).group(1)
        self.assertEqual(requests[0].get(field), 2000, "Policy must inspect the actual SDK wire field")
        self.assertEqual(requests[0]["model"], "citadel-gpt-41-mini")

    def test_model_gateway_policy_preserves_tls_auth_timeout_and_global_admission_contract(self):
        policy = ET.parse(ROOT / "infra/policies/model.xml")
        self.assertEqual(policy.find("./inbound/authentication-managed-identity").get("resource"), "https://cognitiveservices.azure.com")
        self.assertEqual(policy.find("./inbound/rate-limit-by-key").attrib, {
            "calls": "12", "renewal-period": "60", "counter-key": "citadel-model",
        })
        self.assertEqual(policy.find("./inbound/azure-openai-token-limit").get("tokens-per-minute"), "120000")
        self.assertEqual(policy.find("./backend/limit-concurrency").get("max-count"), "1")
        self.assertEqual(policy.find("./backend/limit-concurrency/forward-request").get("timeout"), "60")
        self.assertEqual(policy.find("./inbound/rewrite-uri").get("template"), "/openai/v1/chat/completions")
