"""Smoke tests at the approved installed-runtime and public SDK seams."""

import importlib
import importlib.metadata
import platform
import sys
import unittest


class RuntimeTests(unittest.TestCase):
    def test_runtime_is_the_approved_cpython_release(self):
        self.assertEqual(sys.implementation.name, "cpython")
        self.assertEqual(sys.version_info[:3], (3, 12, 15))
        self.assertEqual(sys.platform, "linux")
        self.assertEqual(platform.machine(), "x86_64")

    def test_installed_application_and_selected_sdks_import(self):
        importlib.import_module("citadel")
        for distribution, version, module in (
            ("agent-framework-core", "1.21.0", "agent_framework"),
            ("agent-framework-openai", "1.16.0", "agent_framework_openai"),
            ("agent-framework-a2a", "1.0.0b261002", "agent_framework_a2a"),
            ("a2a-sdk", "1.2.1", "a2a"),
            ("mcp", "1.30.0", "mcp"),
            ("openai", "3.23.0", "openai"),
            ("fastapi", "0.141.1", "fastapi"),
            ("starlette", "1.7.0", "starlette"),
            ("uvicorn", "0.54.0", "uvicorn"),
            ("pydantic", "2.13.5", "pydantic"),
            ("anyio", "4.15.1", "anyio"),
            ("sse-starlette", "3.5.0", "sse_starlette"),
            ("httpx", "0.28.1", "httpx"),
            ("httpx2", "2.13.1", "httpx2"),
            ("azure-identity", "1.26.0", "azure.identity"),
            ("azure-core", "1.41.0", "azure.core"),
            ("azure-storage-blob", "12.31.0", "azure.storage.blob"),
            ("aiohttp", "3.14.3", "aiohttp"),
            ("azure-keyvault-secrets", "4.11.3", "azure.keyvault.secrets"),
        ):
            with self.subTest(distribution=distribution):
                self.assertEqual(importlib.metadata.version(distribution), version)
                importlib.import_module(module)


if __name__ == "__main__":
    unittest.main()
