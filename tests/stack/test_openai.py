"""Exercise the real adapter and client; intercept only external model HTTP."""

import asyncio
import json
import unittest

import httpx2
from agent_framework import Message
from agent_framework_openai import OpenAIChatCompletionClient
from openai import AsyncOpenAI


class OpenAIStackTests(unittest.IsolatedAsyncioTestCase):
    async def test_adapter_uses_explicit_gateway_v1_url_and_subscription_header(self):
        requests = []

        def respond(request):
            requests.append(request)
            return httpx2.Response(
                200,
                json={
                    "id": "stack-fixture",
                    "object": "chat.completion",
                    "created": 0,
                    "model": "gpt-4.1-mini",
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": "fixture"},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {
                        "prompt_tokens": 1,
                        "completion_tokens": 1,
                        "total_tokens": 2,
                    },
                },
            )

        async with httpx2.AsyncClient(
            transport=httpx2.MockTransport(respond)
        ) as http_client:
            async with AsyncOpenAI(
                api_key="nonsecret-local-fixture",
                base_url="https://gateway.invalid/openai/v1/",
                default_headers={"Ocp-Apim-Subscription-Key": "nonsecret-fixture"},
                http_client=http_client,
                max_retries=0,
                timeout=60,
            ) as client:
                adapter = OpenAIChatCompletionClient(
                    model="approved-deployment", async_client=client
                )
                async with asyncio.timeout(5):
                    result = await adapter.get_response(
                        [Message("user", ["fixture"])], options={"max_tokens": 2000}
                    )

        self.assertEqual(result.text, "fixture")
        self.assertEqual(len(requests), 1)
        self.assertEqual(
            str(requests[0].url),
            "https://gateway.invalid/openai/v1/chat/completions",
        )
        self.assertEqual(
            requests[0].headers["Ocp-Apim-Subscription-Key"], "nonsecret-fixture"
        )
        self.assertEqual(json.loads(requests[0].content)["model"], "approved-deployment")
        self.assertNotIn("api-version", requests[0].url.params)


if __name__ == "__main__":
    unittest.main()
