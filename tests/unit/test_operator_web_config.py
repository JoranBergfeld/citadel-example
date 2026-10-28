"""Private setup/configuration and single-process deployment boundary."""

import base64
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from citadel.operator.web import AuthConfig, hash_passphrase


ROOT = Path(__file__).resolve().parents[2]


class ConfigurationTests(unittest.TestCase):
    def test_hashes_accept_unicode_spaces_and_have_independent_salts(self):
        phrase = "  test café words ☃  "
        first, second = hash_passphrase(phrase), hash_passphrase(phrase)
        self.assertNotEqual(first, second)
        self.assertIn("$argon2id$v=19$m=65536,t=3,p=1$", first)
        self.assertEqual(len(base64.b64decode(first.split("$")[-2] + "==")), 16)
        AuthConfig("test-user", first, "https://operator.test")
        for invalid in ("short", "a" * 129):
            with self.assertRaises(ValueError):
                hash_passphrase(invalid)

    def test_bad_or_missing_private_configuration_refuses_startup(self):
        with patch.dict("os.environ", {}, clear=True), self.assertRaises(ValueError):
            AuthConfig.from_environment()
        hashed = hash_passphrase("labelled test passphrase")
        for username, encoded, origin in (
            ("", hashed, "https://operator.test"),
            ("test", hashed.replace("65536", "1024"), "https://operator.test"),
            ("test", hashed, "http://operator.test"),
            ("test", hashed, "https://operator.test/path"),
        ):
            with self.assertRaises(ValueError):
                AuthConfig(username, encoded, origin)

    def test_operator_is_separate_from_five_team_workloads_and_has_no_team_authority(self):
        self.assertEqual(len(json.loads((ROOT / "infra/workloads.json").read_text())), 5)
        operator = (ROOT / "infra/modules/operator-app.bicep").read_text()
        self.assertIn("minReplicas: 1, maxReplicas: 1", operator)
        self.assertIn("activeRevisionsMode: 'Single'", operator)
        self.assertIn("allowInsecure: false", operator)
        self.assertIn("'citadel.operator.web'", operator)
        self.assertNotIn("CITADEL_BLOB", operator)
        self.assertNotIn("CITADEL_MODEL", operator)
        self.assertNotIn("context-keys", operator)
        self.assertNotIn("subscription-operator", operator)
        main = (ROOT / "infra/main.bicep").read_text()
        self.assertIn("output operatorInventory object", main)
