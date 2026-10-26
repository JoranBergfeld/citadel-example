import base64
import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from citadel.acceptance.console import ConsoleProbe, PtyConsole, decode_result
from citadel.acceptance.reference_worker import PREFIX
from citadel.evidence.manifests import canonical_bytes, sha256
from citadel.operator.native import Native
from citadel.operator.state import Blocked


class ConsoleTests(unittest.TestCase):
    def test_revision_default_equivalence_keeps_nondefaults_strict_and_inputs_unchanged(self):
        from citadel.acceptance.console import reference_revision_template
        original = {"containers": [{"image": "pinned", "args": [],
                    "resources": {"cpu": .5, "ephemeralStorage": "2Gi"}}],
                    "scale": {"minReplicas": 1, "cooldownPeriod": 300, "pollingInterval": 30}}
        before = copy.deepcopy(original)
        omitted = {"containers": [{"image": "pinned", "resources": {"cpu": .5}}],
                   "scale": {"minReplicas": 1}}
        self.assertEqual(reference_revision_template(original), omitted)
        self.assertEqual(original, before)
        null_defaults = copy.deepcopy(omitted)
        null_defaults["scale"].update(cooldownPeriod=None, pollingInterval=None)
        self.assertEqual(reference_revision_template(null_defaults), omitted)
        for path, value in (
                (("scale", "cooldownPeriod"), 600), (("scale", "pollingInterval"), 60),
                (("containers", 0, "args"), ["--different"]),
                (("containers", 0, "resources", "ephemeralStorage"), "4Gi"),
                (("containers", 0, "resources", "cpu"), 1),
                (("containers", 0, "image"), "different")):
            changed = copy.deepcopy(original)
            target = changed
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            with self.subTest(path=path):
                self.assertNotEqual(reference_revision_template(changed), omitted)

    def test_reference_console_binds_actual_revision_identity_and_durable_intent_without_grants(self):
        identity = "/subscriptions/s/resourceGroups/g/providers/Microsoft.ManagedIdentity/userAssignedIdentities/d-reference-data"
        app = {"app": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/g/providers/Microsoft.App/containerApps/d-reference-data",
            "identity": identity, "identityClientId": "22222222-2222-2222-2222-222222222222",
            "identityPrincipalId": "33333333-3333-3333-3333-333333333333",
            "image": "registry.example/image@sha256:" + "a" * 64}
        template = {"containers": [{"name": "reference-data", "image": app["image"],
            "command": ["python", "-m", "citadel.runtime"], "args": [],
            "resources": {"cpu": .5, "memory": "1Gi", "ephemeralStorage": "2Gi"}, "env": [
                {"name": "AZURE_CLIENT_ID", "value": app["identityClientId"]},
                {"name": "AZURE_PRINCIPAL_ID", "value": app["identityPrincipalId"]},
                {"name": "CITADEL_BLOB_URL", "value": "https://referencefixture.blob.core.windows.net"},
                {"name": "CITADEL_TARGET", "value": "reference-data"}]}],
            "scale": {"minReplicas": 1, "maxReplicas": 1, "cooldownPeriod": 300, "pollingInterval": 30}}
        revision_template = copy.deepcopy(template)
        del revision_template["containers"][0]["args"]
        del revision_template["containers"][0]["resources"]["ephemeralStorage"]
        revision_template["scale"]["cooldownPeriod"] = None
        revision_template["scale"]["pollingInterval"] = None
        deployed = {"identity": {"type": "UserAssigned", "userAssignedIdentities": {identity.lower(): {
            "clientId": app["identityClientId"], "principalId": app["identityPrincipalId"]}}},
            "properties": {"latestRevisionName": "d-reference-data--ready",
                "latestReadyRevisionName": "d-reference-data--ready", "template": template,
                "configuration": {"activeRevisionsMode": "Single",
                    "ingress": {"fqdn": "d-reference-data.example.azurecontainerapps.io"}}}}
        calls, admissions, saved = [], [], []

        def rest(method, resource, api):
            calls.append((method, resource, api))
            if resource == app["app"]:
                return deployed
            if resource.endswith("/replicas"):
                return {"value": [{"name": "replica1", "properties": {"containers": [
                    {"name": "reference-data", "ready": True}]}}]}
            return {"properties": {"active": True, "template": revision_template}}

        lifecycle = SimpleNamespace(id="d", value={},
            native=SimpleNamespace(rest=rest),
            state=SimpleNamespace(save=lambda: saved.append(True)))

        class Console:
            corrupt = False
            calls = 0

            def run(self, arguments, *, deadline):
                self.calls += 1
                self.arguments = arguments
                intent = list(lifecycle.value["probe_intents"].values())[-1]
                self.manifest = intent["manifest"]
                assert intent["state"] == "dispatching" and saved
                return {"schema_version": 1, "run_id": "wrong-run" if self.corrupt else self.manifest["run_id"], "state": "complete",
                    "runtime_identity": hashlib.sha256(app["identityPrincipalId"].encode()).hexdigest(),
                    "manifest_sha256": sha256(self.manifest), "observations": [], "read_attempts": 3}

        console = Console()
        try:
            result = ConsoleProbe(lifecycle, console=console, admit=lambda count=1: admissions.append(count)).execute(
                app, "reference-data", "reference1", mode="origin-boundary", deadline=time.time() + 120)
        except Blocked as error:
            self.fail("Actual revision-API default omissions must not block the identical app: " + error.code)
        self.assertEqual(result["run_id"], "reference1")
        self.assertEqual(lifecycle.value["probe_intents"]["reference1"]["state"], "observed")
        self.assertTrue(all(method == "get" for method, _, _ in calls))
        self.assertTrue(all(api == "2025-07-01" if "/revisions/" in resource else api == "2025-01-01"
                            for _, resource, api in calls))
        self.assertIn("--revision", console.arguments)
        self.assertIn("--replica", console.arguments)
        self.assertIn("--container", console.arguments)
        self.assertNotIn("secret", str(console.manifest))
        with self.assertRaises(Blocked):
            ConsoleProbe(lifecycle, console=console, admit=lambda count=1: None).execute(
                app, "reference-data", "reference1", mode="origin-boundary")
        self.assertEqual(sum(admissions), 190)
        from tests.acceptance.storage_fixture import storage_accounts
        accounts = storage_accounts()
        storage = {"suite_id": "suite1", "accounts": accounts,
                   "targets": {key: {"sha256": "a" * 64, "etag": '"known"'} for key in accounts}}
        try:
            result = ConsoleProbe(lifecycle, console=console, admit=lambda count=1: admissions.append(count)).execute(
                app, "reference-data", "reference3", mode="storage-boundaries",
                storage=storage, deadline=time.time() + 120)
        except (Blocked, AttributeError) as error:
            self.fail("Storage validation must bind the actual deployed Blob endpoint: " + type(error).__name__)
        self.assertEqual(result["run_id"], "reference3")
        self.assertEqual(console.manifest["storage"], storage)
        changed = copy.deepcopy(storage)
        changed["accounts"]["reference"] = "https://referenceother.blob.core.windows.net"
        with self.assertRaises(Blocked):
            ConsoleProbe(lifecycle, console=console, admit=lambda count=1: admissions.append(count)).execute(
                app, "reference-data", "reference4", mode="storage-boundaries",
                storage=changed, deadline=time.time() + 120)
        self.assertEqual(console.calls, 2, "A foreign allocation must fail before console dispatch")
        console.corrupt = True
        with self.assertRaises(Blocked):
            ConsoleProbe(lifecycle, console=console, admit=lambda count=1: None).execute(
                app, "reference-data", "reference2", mode="origin-boundary")
        self.assertEqual(lifecycle.value["probe_intents"]["reference2"]["state"], "indeterminate")
        attempted = len(calls)
        with self.assertRaises(Blocked):
            ConsoleProbe(lifecycle, console=console, admit=lambda count=1: None).execute(
                app, "reference-data", "reference2", mode="origin-boundary")
        self.assertEqual(len(calls), attempted)

    def test_real_pty_keeps_cli_inputs_private_and_discards_nonresult_output(self):
        root = Path(".build") / ("console-" + uuid4().hex)
        root.mkdir(mode=0o700, parents=True)
        result = {"schema_version": 1, "run_id": "r1", "state": "complete", "observations": []}
        raw = canonical_bytes(result)
        line = PREFIX + base64.b64encode(raw).decode() + ":" + hashlib.sha256(raw).hexdigest()
        seen = []

        def process(args, **options):
            seen.append((args, options))
            script = (
                "import json,os,sys;"
                "request=json.load(os.fdopen(int(os.environ['CITADEL_CONSOLE_REQUEST_FD'])));"
                "assert request[:2]==['containerapp','exec'];"
                "assert os.isatty(0) and os.isatty(1);"
                "print('private-provider-output',flush=True);"
                f"print({line!r},flush=True)"
            )
            return subprocess.Popen([sys.executable, "-c", script], **options)

        native = Native({"tools": {"azurePython": "/explicit/pinned/python"}}, root)
        args = ["containerapp", "exec", "--name", "d-reference-data", "--resource-group", "d-reference",
            "--subscription", "11111111-1111-1111-1111-111111111111",
            "--revision", "d-reference-data--ready", "--replica", "replica1",
            "--container", "reference-data", "--command",
            "python -m citadel.acceptance.reference_worker --enabled --manifest e30="]
        try:
            observed = PtyConsole(native, process=process).run(args, deadline=time.time() + 10)
            self.assertEqual(observed, result)
            self.assertEqual(len(seen), 1)
            self.assertEqual(seen[0][0][0], "/explicit/pinned/python")
            self.assertNotIn("d-reference-data", str(seen[0][0]))
            self.assertNotIn("private-provider-output", str(observed))
            self.assertEqual(list(root.glob("request-*.json")), [])
        finally:
            shutil.rmtree(root)

    def test_results_require_exact_hash_framing_and_never_parse_arbitrary_cli_json(self):
        raw = canonical_bytes({"run_id": "r1"})
        valid = (PREFIX + base64.b64encode(raw).decode() + ":" + hashlib.sha256(raw).hexdigest()).encode()
        self.assertEqual(decode_result(valid), {"run_id": "r1"})
        for value in (b'{"status":"pass"}', valid[:-1] + b"x", (PREFIX + "!!!:bad").encode()):
            with self.subTest(value=value[:25]), self.assertRaises(Blocked):
                decode_result(value)

    def test_arbitrary_shell_other_workload_and_expired_console_refuse_before_process_access(self):
        arguments = ["containerapp", "exec", "--name", "d-reference-data", "--resource-group", "g",
            "--subscription", "11111111-1111-1111-1111-111111111111",
            "--revision", "revision1", "--replica", "replica1", "--container", "reference-data",
            "--command", "python -m citadel.acceptance.reference_worker --enabled --manifest e30="]
        console = PtyConsole(SimpleNamespace())
        for key, value in (("--command", "sh"), ("--container", "candidate-planner"),
                           ("--name", "other-app")):
            changed = list(arguments)
            changed[changed.index(key) + 1] = value
            with self.subTest(key=key), self.assertRaises(Blocked):
                console.run(changed, deadline=time.time() + 10)
        with self.assertRaises(Blocked):
            console.run(arguments, deadline=time.time() - 1)
