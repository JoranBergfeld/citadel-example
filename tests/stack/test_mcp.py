"""Real MCP initialization and tool calls over an in-process HTTP boundary."""

import asyncio
import unittest

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.fastmcp import FastMCP


class MCPStackTests(unittest.IsolatedAsyncioTestCase):
    async def test_streamable_http_negotiates_approved_protocol_and_calls_a_tool(self):
        server = FastMCP(
            "stack-fixture", stateless_http=True, json_response=True
        )

        @server.tool()
        def echo(value: str) -> str:
            """Return an inert test value, without data or model access."""
            return value

        app = server.streamable_http_app()
        async with asyncio.timeout(5):
            async with server.session_manager.run():
                async with httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=app),
                    timeout=30,
                ) as http_client:
                    async with streamable_http_client(
                        "http://localhost:8000/mcp", http_client=http_client
                    ) as (read, write, _):
                        async with ClientSession(read, write) as session:
                            initialized = await session.initialize()
                            self.assertEqual(
                                initialized.protocolVersion, "2025-11-25"
                            )
                            tools = await session.list_tools()
                            self.assertEqual([tool.name for tool in tools.tools], ["echo"])
                            result = await session.call_tool("echo", {"value": "fixture"})
                            self.assertFalse(result.isError)
                            self.assertEqual(result.content[0].text, "fixture")


if __name__ == "__main__":
    unittest.main()
