"""Offline APIM contract; not evidence of deployed enforcement."""

from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[2]


class RetryPolicyTests(unittest.TestCase):
    def test_retry_is_a_separate_planner_only_web_action_with_exact_origin_path(self):
        source = (ROOT / "infra/modules/workload-api.bicep").read_text()
        retry = re.search(r"name: 'operator-retry'(.*?)\n\s*}", source, re.S)
        self.assertIsNotNone(retry, "APIM must publish the separately authorized retry operation")
        self.assertIn("method: 'POST'", retry[1])
        self.assertIn("path: '/operator/runs/{runId}/retry/{requestId}'", retry[1])
        self.assertIn("target == 'candidate-planner' ? retryOperations : []", source)
        policy = ET.parse(ROOT / "infra/policies/workload.xml")
        authorization = policy.find("./inbound/set-variable[@name='authorized']").get("value")
        branch = re.search(r'if \(op == "operator-retry"\) \{([^}]+)}', authorization)
        self.assertIsNotNone(branch)
        self.assertIn('"__TARGET__" == "candidate-planner" && caller == "operator-web"', branch[1])
        origin = policy.find("./inbound/set-variable[@name='originPath']").get("value")
        branch = re.search(r'if \(op == "operator-retry"\) \{([^}]+)}', origin)
        self.assertIsNotNone(branch)
        self.assertIn('"/operator/runs/"', branch[1])
        self.assertIn('MatchedParameters["runId"] + "/retry/"', branch[1])
        self.assertIn('MatchedParameters["requestId"]', branch[1])
