import io
import json
import os
from pathlib import Path
import shutil
import unittest
from uuid import uuid4

from citadel.operator import main


class CliCase(unittest.TestCase):
    def setUp(self):
        self.directory = Path(__file__).parent / ("scratch-" + uuid4().hex)
        self.directory.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree, self.directory)
        self.config = self.directory / "config.json"
        self.state = self.directory / "state"
        self.values = {
            "deploymentId": "test19",
            "subscriptionId": "11111111-1111-4111-8111-111111111111",
            "tenantId": "22222222-2222-4222-8222-222222222222",
            "publisherEmail": "operator@example.test",
            "collectorPrincipalIds": ["33333333-3333-4333-8333-333333333333"],
            "location": "westeurope", "modelCapacity": 1, "modelTokensPerMinute": 1000,
            "createResourceGroups": True,
            "bundleDir": str(self.directory / "bundle"),
            "tools": {"azurePython": "/explicit/azure-cli/bin/python"},
        }
        self.write_config()

    def write_config(self):
        self.config.write_text(json.dumps(self.values))
        self.config.chmod(0o600)

    def cli(self, *args, **kwargs):
        output = io.StringIO()
        code = main(list(args), stdout=output, **kwargs)
        return code, json.loads(output.getvalue())


class CliTests(CliCase):
    def test_initialize_is_private_immutable_and_never_prints_target_or_credentials(self):
        args = ("init", "--config", str(self.config), "--state-dir", str(self.state))
        code, result = self.cli(*args)
        self.assertEqual(code, 0, result)
        original = (self.state / "state.json").read_bytes()
        self.assertEqual(self.cli(*args)[0], 0)
        self.assertEqual((self.state / "state.json").read_bytes(), original)
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.state / "state.json").stat().st_mode & 0o777, 0o600)
        self.assertNotIn(self.values["subscriptionId"], json.dumps(result))
        self.values["modelTokensPerMinute"] = 2000
        self.write_config()
        self.assertEqual(self.cli(*args)[0], 2)
        self.assertEqual((self.state / "state.json").read_bytes(), original)

    def test_invalid_boundaries_and_public_config_fail_before_any_adapter(self):
        for key, value in (("deploymentId", "../bad"), ("location", "eastus"),
                           ("modelCapacity", True), ("modelTokensPerMinute", 0),
                           ("modelTokensPerMinute", 120001)):
            with self.subTest(key=key, value=value):
                old = self.values[key]
                self.values[key] = value
                self.write_config()
                self.assertEqual(self.cli("init", "--config", str(self.config),
                                         "--state-dir", str(self.state))[0], 2)
                self.values[key] = old
        self.write_config()
        self.config.chmod(0o644)
        self.assertEqual(self.cli("init", "--config", str(self.config),
                                 "--state-dir", str(self.state))[0], 2)

    @unittest.skipUnless(os.environ.get("CITADEL_EVIDENCE_DATA"), "retained exact source required")
    def test_prepare_verifies_all_eight_objects_and_detects_changed_bytes(self):
        bundle = self.directory / "bundle"
        args = ("prepare", "--source-dir", os.environ["CITADEL_EVIDENCE_DATA"],
                "--bundle-dir", str(bundle))
        code, report = self.cli(*args)
        self.assertEqual(code, 0, report)
        self.assertEqual(report["complete"], 16)
        self.assertEqual(len(list(bundle.iterdir())), 8)
        self.assertEqual(self.cli(*args)[0], 0)
        (bundle / "reference-data.json").write_text("{}")
        self.assertNotEqual(self.cli(*args)[0], 0)
