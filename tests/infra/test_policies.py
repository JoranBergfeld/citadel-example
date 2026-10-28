import json
from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[2]


class PolicyTests(unittest.TestCase):
    def test_workload_policy_contains_only_exact_caller_graph_and_separate_read_authority(self):
        source = (ROOT / "infra/policies/workload.xml").read_text()
        callers = {
            "candidate-planner": ["operator"],
            "evidence-assessor": ["candidate-planner"],
            "release-reviewer": ["evidence-assessor"],
            "briefing-author": ["candidate-planner"],
            "reference-data": ["candidate-planner", "evidence-assessor", "release-reviewer"],
        }
        configured = {w["name"]: w["callers"] for w in json.loads((ROOT / "infra/workloads.json").read_text())}
        self.assertEqual(configured, callers)
        for target, allowed in configured.items():
            policy = ET.fromstring(source.replace("__TARGET__", target).replace(
                "__CALLERS__", ", ".join(f"&quot;{caller}&quot;" for caller in allowed),
            ).replace("__KEY_ID__", "current"))
            expression = policy.find("./inbound/set-variable[@name='authorized']").get("value")
            declaration = re.search(r"var invocation = new \[\] \{ ([^}]+) \}", expression).group(1)
            self.assertEqual(re.findall(r'"([^"]+)"', declaration), allowed)
            self.assertEqual(policy.find("./inbound/set-backend-service").get("backend-id"), target)
            self.assertEqual(policy.find("./inbound/authentication-certificate").get("certificate-id"), "gateway-client")
            signed = policy.find("./inbound/set-header[@name='X-Citadel-Signature']")
            self.assertEqual(signed.get("exists-action"), "override")
            self.assertIsNotNone(policy.find("./inbound/base"))
            self.assertEqual(policy.find("./inbound/rewrite-uri").get("copy-unmatched-params"), "false")
        # The deterministic read branch is not part of the invocation caller list.
        expression = ET.fromstring(source).find("./inbound/set-variable[@name='authorized']").get("value")
        branch = re.search(r'if \(op == "findings-read"\) \{(.*?)\}', expression).group(1)
        self.assertEqual(re.findall(r'caller == "([^"]+)"', branch), ["candidate-planner", "briefing-author"])

    def test_unknown_credentials_are_denied_and_forwarding_context_is_replaced(self):
        policy = ET.parse(ROOT / "infra/policies/global.xml")
        caller_expression = policy.find("./inbound/set-variable[@name='caller']").get("value")
        declaration = re.search(r"var known = new \[\] \{ ([^}]+) \}", caller_expression).group(1)
        self.assertEqual(set(re.findall(r'"([^"]+)"', declaration)), {
            "operator", "operator-web", "candidate-planner", "evidence-assessor", "release-reviewer", "briefing-author",
        })
        self.assertEqual(policy.find("./inbound/choose/when/return-response/set-status").get("code"), "403")
        self.assertEqual(policy.find("./inbound/set-header[@name='X-Citadel-Caller']").get("exists-action"), "override")
        for name in ("Authorization", "Ocp-Apim-Subscription-Key", "X-Forwarded-Client-Cert", "X-Client-Cert", "X-Client-Certificate"):
            self.assertEqual(policy.find(f"./inbound/set-header[@name='{name}']").get("exists-action"), "delete")

    def test_all_policy_files_are_xml_and_never_log_payloads_or_credentials(self):
        for path in (ROOT / "infra/policies").glob("*.xml"):
            policy = ET.parse(path)
            self.assertEqual(policy.getroot().tag, "policies")
            self.assertEqual({node.tag for node in policy.getroot()}, {"inbound", "backend", "outbound", "on-error"})
            for forbidden in ("trace", "log-to-eventhub", "send-request"):
                self.assertEqual(policy.findall(f".//{forbidden}"), [])

    def test_upstream_faults_are_not_relabelled_as_authorization_denials(self):
        for path in (ROOT / "infra/policies").glob("*.xml"):
            policy = ET.parse(path)
            for status in policy.findall("./on-error//set-status"):
                self.assertNotIn(status.get("code"), {"401", "403"})

    def test_authorization_branches_expose_only_fixed_denial_codes_and_real_gateway_ids(self):
        reasons = {"Route denied": "route_denied", "Method denied": "method_denied",
                   "Unknown caller": "unknown_caller", "Model caller denied": "model_caller_denied"}
        for path in (ROOT / "infra/policies").glob("*.xml"):
            policy = ET.parse(path)
            for response in policy.findall(".//return-response"):
                status = response.find("set-status")
                if status.get("code") != "403":
                    continue
                denial = response.find("./set-header[@name='X-Citadel-Denial']")
                self.assertIsNotNone(denial, path.name)
                self.assertEqual(denial.find("value").text, reasons[status.get("reason")])
                request_id = response.find("./set-header[@name='X-Citadel-Gateway-Request-Id']/value")
                self.assertEqual(request_id.text, '@(context.RequestId.ToString("N"))')
        global_policy = ET.parse(ROOT / "infra/policies/global.xml")
        self.assertEqual(global_policy.find(
            "./outbound/set-header[@name='X-Citadel-Denial']").get("exists-action"), "delete")
        self.assertEqual(global_policy.find(
            "./outbound/set-header[@name='X-Citadel-Gateway-Request-Id']/value").text,
            '@(context.RequestId.ToString("N"))')
