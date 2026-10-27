import json
from pathlib import Path
import shutil
import subprocess
import time
import unittest
from uuid import uuid4

from citadel.operator.native import Native
from citadel.operator.state import Blocked


class NativeTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(__file__).parent / ("scratch-" + uuid4().hex)
        self.directory.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree, self.directory)

    def test_native_cli_sends_sensitive_arguments_only_on_stdin_and_redacts_child_errors(self):
        calls = []

        def process(args, **kwargs):
            calls.append((args, kwargs))
            return subprocess.CompletedProcess(args, 1, b"secret-key subscription-id", b"private-key")

        native = Native({"tools": {"azurePython": "/locked/azure/bin/python"}},
                        self.directory, process=process)
        with self.assertRaises(Blocked) as caught:
            native.az("account", "show", "--subscription", "subscription-id")
        self.assertEqual(str(caught.exception.code), "azure_command_failed")
        self.assertNotIn("subscription-id", str(calls[0][0]))
        self.assertIn("subscription-id", calls[0][1]["input"].decode())
        self.assertNotIn("secret", str(caught.exception))

    def test_parameter_file_is_private_and_removed_even_on_failure(self):
        native = Native({"tools": {"azurePython": "/locked/azure/bin/python"}}, self.directory)
        filename = None
        with self.assertRaisesRegex(RuntimeError, "fixture"):
            with native.document({"private": "never-argv"}) as filename:
                self.assertEqual(Path(filename).stat().st_mode & 0o777, 0o600)
                self.assertEqual(json.loads(Path(filename).read_text()), {"private": "never-argv"})
                raise RuntimeError("fixture")
        self.assertFalse(Path(filename).exists())

    def test_service_get_uses_pinned_api_and_never_synthesizes_plan_metadata(self):
        calls = []
        resource = "/subscriptions/private-target/resourceGroups/owned/providers/Microsoft.ApiCenter/services/actual"
        response = {"id": resource, "systemData": {"createdAt": "2026-01-01T00:00:00Z"},
                    "properties": {"provisioningState": "Succeeded"}}
        def process(args, **kwargs):
            calls.append((args, json.loads(kwargs["input"])))
            return subprocess.CompletedProcess(args, 0, json.dumps(response).encode(), b"")
        native = Native({"tools": {"azurePython": "/locked/azure/bin/python"}},
                        self.directory, process=process)
        self.assertEqual(native.rest("get", resource, "2024-03-01"), response)
        self.assertNotIn(resource, str(calls[0][0]))
        self.assertIn("https://management.azure.com" + resource + "?api-version=2024-03-01", calls[0][1])

    def test_cloud_driver_uses_private_local_context_and_never_changes_host_config(self):
        calls = []
        def process(args, **kwargs):
            calls.append(kwargs)
            return subprocess.CompletedProcess(args, 0, b"{}", b"")
        native = Native({"tools": {"azurePython": "/locked/azure/bin/python"}}, self.directory, process=process)
        native.az("version")
        self.assertEqual(calls[0]["env"]["AZURE_CONFIG_DIR"], str((self.directory / "azure").absolute()))
        self.assertEqual(calls[0]["umask"], 0o077)

    def test_collection_deadline_bounds_each_native_child_including_inventory(self):
        calls = []
        def process(args, **kwargs):
            calls.append(kwargs)
            return subprocess.CompletedProcess(args, 0, b"{}", b"")
        native = Native({"tools": {"azurePython": "/locked/azure/bin/python"}}, self.directory, process=process)
        native.deadline = time.monotonic() + 1
        native.az("version", timeout=120)
        self.assertLessEqual(calls[0]["timeout"], 1)
