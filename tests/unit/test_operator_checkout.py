"""Operator CLI checkout resources are independent of package installation layout."""

import json
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from uuid import uuid4

import citadel
from citadel.operator.state import write_private


ROOT = Path(__file__).resolve().parents[2]


class CheckoutTests(unittest.TestCase):
    def test_relocated_operator_uses_checkout_resources_before_any_paid_action(self):
        directory = ROOT / "tests/unit" / ("scratch-checkout-" + uuid4().hex)
        directory.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree, directory)
        packages = directory / "site-packages"
        shutil.copytree(Path(citadel.__file__).parent, packages / "citadel",
                        ignore=shutil.ignore_patterns("__pycache__"))
        config = directory / "config.json"
        write_private(config, {
            "deploymentId": "checkout", "subscriptionId": "11111111-1111-4111-8111-111111111111",
            "tenantId": "22222222-2222-4222-8222-222222222222",
            "publisherEmail": "test@example.test",
            "collectorPrincipalIds": ["33333333-3333-4333-8333-333333333333"],
            "location": "westeurope", "modelCapacity": 1, "modelTokensPerMinute": 1000,
            "createResourceGroups": True, "bundleDir": str(directory / "bundle"),
            "tools": {"azurePython": "/not-used"},
        })

        def cli(*args):
            return subprocess.run([
                sys.executable, "-I", "-c",
                "import sys; sys.path.insert(0, sys.argv.pop(1)); "
                "from citadel.operator import main; raise SystemExit(main())",
                str(packages), *args, "--state-dir", str(directory / "state"),
            ], cwd=ROOT, capture_output=True, text=True, timeout=30)

        initialized = cli("init", "--config", str(config))
        self.assertEqual(initialized.returncode, 0, initialized.stdout + initialized.stderr)
        denied = cli("deploy")
        self.assertEqual(denied.returncode, 2, denied.stdout + denied.stderr)
        self.assertEqual(json.loads(denied.stdout), {
            "status": "blocked", "code": "explicit_paid_provisioning_confirmation_required",
        })
