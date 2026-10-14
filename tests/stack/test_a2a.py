"""Real local JSON-RPC transport; the fixture agent never invokes a model."""

import asyncio
import json
import unittest

import httpx
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import add_a2a_routes_to_fastapi, create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import AgentCapabilities, AgentCard, AgentInterface, TaskState
from agent_framework import AgentResponse, BaseAgent, Message
from agent_framework_a2a import A2AAgent, A2AExecutor
from fastapi import FastAPI


class HeldFixtureAgent(BaseAgent):
    def __init__(self, release):
        super().__init__(name="stack-fixture")
        self.release = release

    async def run(self, messages=None, **kwargs):
        await self.release.wait()
        return AgentResponse(messages=[Message("assistant", ["fixture complete"])])


class A2AStackTests(unittest.IsolatedAsyncioTestCase):
    async def test_nonblocking_acceptance_and_single_request_polling_use_a2a_1(self):
        release = asyncio.Event()
        card = AgentCard(
            name="stack-fixture",
            description="Local interface smoke test, not a Citadel agent",
            version="0.1.0",
            supported_interfaces=[
                AgentInterface(
                    url="http://stack.test/a2a",
                    protocol_binding="JSONRPC",
                    protocol_version="1.0",
                )
            ],
            capabilities=AgentCapabilities(streaming=True),
            default_input_modes=["text/plain"],
            default_output_modes=["text/plain"],
        )
        handler = DefaultRequestHandler(
            agent_executor=A2AExecutor(HeldFixtureAgent(release)),
            task_store=InMemoryTaskStore(),
            agent_card=card,
        )
        app = FastAPI()
        add_a2a_routes_to_fastapi(
            app,
            jsonrpc_routes=create_jsonrpc_routes(
                handler, rpc_url="/a2a", enable_v0_3_compat=False
            ),
        )
        exchanges = []

        async def record(request):
            exchanges.append(json.loads(request.content))

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            event_hooks={"request": [record]},
            timeout=180,
        ) as http_client:
            async with A2AAgent(agent_card=card, http_client=http_client) as agent:
                try:
                    async with asyncio.timeout(10):
                        accepted = await agent.run("fixture", background=True)
                    self.assertIsNotNone(accepted.continuation_token)
                    self.assertFalse(release.is_set())
                    self.assertEqual(len(exchanges), 1)
                    self.assertTrue(
                        exchanges[0]["params"]["configuration"]["returnImmediately"]
                    )

                    async with asyncio.timeout(2):
                        working = await agent.poll_task(accepted.continuation_token)
                    self.assertIsNotNone(working.continuation_token)
                    self.assertEqual(len(exchanges), 2)
                    self.assertEqual(exchanges[1]["method"], "GetTask")

                    release.set()
                    async with asyncio.timeout(2):
                        while True:
                            result = await agent.poll_task(working.continuation_token)
                            if result.continuation_token is None:
                                break
                            await asyncio.sleep(0.01)
                    self.assertEqual(
                        result.raw_representation[-1].status.state,
                        TaskState.TASK_STATE_COMPLETED,
                    )
                    self.assertIn("fixture complete", result.text)
                    self.assertTrue(
                        all(
                            exchange["method"] == "GetTask"
                            for exchange in exchanges[1:]
                        )
                    )
                finally:
                    release.set()


if __name__ == "__main__":
    unittest.main()
