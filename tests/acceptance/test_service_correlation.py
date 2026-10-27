import copy
import unittest

from citadel.acceptance.proof_gate import evaluate_check
from citadel.acceptance.reports import sanitize
from citadel.acceptance.coverage import required_checks
from citadel.evidence.manifests import sha256
from tests.acceptance.test_authority_aggregate import authority_report


def gateway_report():
    from tests.acceptance.test_protocol_oracle import (
        a2a_protocol_report, mcp_protocol_report, model_protocol_report)
    from tests.acceptance.test_model_oracle import ModelOracleTests
    _, report = authority_report("status-owner-scope")
    identities = report["runtime_identities"]
    subscriptions = report["subscription_bindings"]

    def append(prefix, incoming):
        incoming = copy.deepcopy(incoming)
        principal_map = {value: identities[key] for key, value in incoming["runtime_identities"].items()}
        visited = set()

        def rewrite(value):
            if isinstance(value, (dict, list)):
                if id(value) in visited:
                    return
                visited.add(id(value))
            if isinstance(value, dict):
                if isinstance(value.get("request_id"), str):
                    value["request_id"] = prefix + value["request_id"]
                if value.get("runtime_identity") in principal_map:
                    value["runtime_identity"] = principal_map[value["runtime_identity"]]
                if value.get("source") == "gateway":
                    value["credential_sha256"] = subscriptions[value["caller"]]
                for child in value.values():
                    rewrite(child)
            elif isinstance(value, list):
                for child in value:
                    rewrite(child)

        rewrite(incoming)
        for check in incoming["checks"]:
            for key in ("observation", "control"):
                row = check["actual"][key]
                for event in incoming["evidence"]:
                    if event.get("request_id") == row.get("request_id") and event.get("method") in (
                            "probe", "invocation.observed", "status.observed"):
                        event["facts"]["sha256"] = sha256(row)
            if check["check_id"].startswith("route.") and not any(
                    existing["check_id"] == check["check_id"] for existing in report["checks"]):
                report["checks"].append(check)
        report["evidence"].extend(incoming["evidence"])
        report["operation_ids"].extend(incoming["operation_ids"])

    for prefix, provider in (("a2a-", a2a_protocol_report), ("mcp-", mcp_protocol_report),
                             ("model-", model_protocol_report)):
        append(prefix, provider()[1])
    observation, control, snapshots, evidence = ModelOracleTests().fixture()
    observation.pop("runtime_identity")
    observation.update(check_id="route.operator.model.inference", caller="operator",
                       reason="model_caller_denied", target=control["allowed"]["target"])
    evidence[0] = observation | {"source": "gateway", "method": "POST", "observed": 100.5,
        "credential_sha256": subscriptions["operator"], "facts": {"backend_dispatched": False}}
    for rows in snapshots.values():
        for row in rows.values():
            row["caller"] = "operator"
    append("operator-model-", {"runtime_identities": {"evidence-assessor": "a" * 64},
        "evidence": evidence, "operation_ids": ["phase1", "direct1", "comparison1", "assess1",
            "acquire1", "release1", "beforedrafts", "beforefindings", "afterdrafts", "afterfindings"],
        "checks": [{"check_id": observation["check_id"], "expected": "deny", "status": "pass",
            "actual": {"observation": observation, "control": control | {"runtime_identity": "f" * 64},
                **{side: list(rows.values()) for side, rows in snapshots.items()}}}]})
    existing = {row["check_id"] for row in report["checks"]}
    for identifier, expected in required_checks().items():
        if not identifier.startswith("route.") or identifier in existing:
            continue
        assert expected == "deny", identifier
        _, caller, target, capability = identifier.split(".")
        template = next(row for row in report["checks"] if row["expected"] == "allow"
                        and row["check_id"].split(".")[2:] == [target, capability])
        control = template["actual"]["observation"]
        observed = {key: value for key, value in control.items() if key not in (
            "observation_kind", "actual", "business_state", "accepted_operation_id")}
        observed.update(check_id=identifier, caller=caller, operation_id=identifier,
                        request_id=identifier, run_id="denial-run", started=100, finished=101,
                        status_code=403, reason="route_denied")
        report["operation_ids"].extend([identifier, "denial-run"])
        report["evidence"].append(observed | {"source": "gateway", "observed": 100.5,
            "method": "GET" if capability == "discovery" else "POST",
            "credential_sha256": subscriptions[caller], "facts": {"backend_dispatched": False}})
        if caller != "operator":
            report["evidence"].append(observed | {"source": "application", "observed": 100.5,
                "method": "probe", "runtime_identity": identities[caller],
                "facts": {"probe_id": identifier, "sha256": sha256(observed)}})
        report["checks"].append({"check_id": identifier, "expected": "deny", "status": "pass",
            "actual": template["actual"] | {"observation": observed, "control": control}})
    return report


class ServiceCorrelationTests(unittest.TestCase):
    def test_gateway_census_requires_all_routes_models_mcp_and_owner_status_controls(self):
        from citadel.acceptance.service_correlation import collect_correlations
        report = gateway_report()
        for child in report["checks"]:
            self.assertEqual(evaluate_check(child, report)["status"], "pass", child["check_id"])
        check = next(row for row in collect_correlations(report)
                     if row["check_id"] == "telemetry.gateway-correlation")
        self.assertEqual(check["status"], "pass")
        self.assertEqual(len(check["actual"]["required_checks"]), 110)
        self.assertEqual(check["actual"]["count"], 156)
        self.assertEqual(evaluate_check(sanitize(check), sanitize(report))["status"], "pass")
        for source in ("application", "gateway", "storage"):
            changed = report | {"evidence": [row for row in report["evidence"] if row["source"] != source]}
            self.assertEqual(evaluate_check(check, changed)["status"], "blocked")
        changed = copy.deepcopy(report)
        service = next(row for row in changed["evidence"] if row["source"] == "gateway")
        changed["evidence"].append(service | {"credential_sha256": "9" * 64})
        self.assertNotEqual(evaluate_check(check, changed)["status"], "pass")
        altered = copy.deepcopy(check)
        altered["actual"]["count"] -= 1
        self.assertEqual(evaluate_check(altered, report)["status"], "blocked")

    def test_every_storage_matrix_receipt_and_observer_read_is_counted_and_independently_reverified(self):
        from citadel.acceptance.service_correlation import collect_correlations
        _, report = authority_report("executing-identities")
        check = next(row for row in collect_correlations(report)
                     if row["check_id"] == "telemetry.storage-correlation")
        self.assertEqual(check["status"], "pass")
        self.assertEqual(check["actual"]["count"], 360)
        self.assertEqual(evaluate_check(sanitize(check), sanitize(report))["status"], "pass")
        for source in ("application", "storage"):
            changed = copy.deepcopy(report)
            changed["evidence"].remove(next(row for row in changed["evidence"] if row["source"] == source))
            self.assertEqual(evaluate_check(check, changed)["status"], "blocked")
        changed = copy.deepcopy(report)
        changed["checks"][0]["actual"] = {}
        self.assertEqual(evaluate_check(check, changed)["status"], "blocked")
        altered = copy.deepcopy(check)
        altered["actual"]["count"] = 359
        self.assertEqual(evaluate_check(altered, report)["status"], "blocked")
        changed = copy.deepcopy(report)
        service = next(row for row in changed["evidence"] if row["source"] == "storage")
        changed["evidence"].append(service | {"status_code": 200})
        self.assertNotEqual(evaluate_check(check, changed)["status"], "pass")
