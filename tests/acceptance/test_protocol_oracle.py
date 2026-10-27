import copy
import hashlib
import unittest

from citadel.acceptance.proof_gate import evaluate_check
from citadel.acceptance.reports import sanitize
from citadel.evidence.manifests import sha256
from tests.acceptance.test_route_oracle import route_proof


def mcp_protocol_report():
    _, control, snapshots, source, identities, _ = route_proof()
    protocols = {"mcp": "2025-11-25", "mcp_transport": "Streamable HTTP"}
    report = {"run_id": "suite1", "runtime_identities": identities, "protocols": protocols,
              "subscription_bindings": {}, "checks": [], "evidence": source[5:],
              "operation_ids": ["control-run"]}
    for caller in ("candidate-planner", "evidence-assessor", "release-reviewer"):
        report["subscription_bindings"][caller] = sha256(caller)
        for method in ("initialize", "search_airports", "lookup_airport", "list_runways"):
            key = f"route.{caller}.reference-data.{method}"
            row = control | {"caller": caller, "check_id": key, "protocols": dict(protocols),
                "request_id": caller + "-" + method, "operation_id": caller + "-" + method,
                "actual": "mcp_initialized" if method == "initialize" else "reference_data",
                "sha256": "9" * 64}
            report["operation_ids"].append(row["operation_id"])
            report["evidence"].extend([
                row | {"source": "gateway", "observed": 102.5, "method": "POST",
                    "credential_sha256": report["subscription_bindings"][caller],
                    "facts": {"backend_dispatched": True}},
                row | {"source": "application", "observed": 102.5, "method": "probe",
                    "runtime_identity": identities[caller],
                    "facts": {"sha256": sha256(row), "probe_id": key}},
                row | {"source": "application", "observed": 102.5, "method": method,
                    "runtime_identity": identities["reference-data"]}])
            report["checks"].append({"check_id": key, "expected": "allow", "status": "pass",
                "actual": {"observation": row, "control": row,
                    **{side: list(values.values()) for side, values in snapshots.items()}}})
    check = {"check_id": "protocol.mcp-2025-11-25", "expected": "evidence", "status": "pass",
             "actual": {"required_checks": sorted(row["check_id"] for row in report["checks"])}}
    return check, report


def a2a_protocol_report():
    from tests.acceptance.test_authority_aggregate import authority_report
    _, report = authority_report("status-owner-scope")
    report["protocols"] = {"a2a": "1.0.0", "a2a_binding": "JSONRPC"}
    report["checks"] = [row for row in report["checks"]
                        if row["expected"] == "allow" and row["check_id"].endswith(".task")]
    wire = {"a2a": "1.0", "a2a_binding": "JSONRPC"}
    for child in list(report["checks"]):
        _, caller, target, _ = child["check_id"].split(".")
        endpoint = hashlib.sha256(f"https://gateway.example/{target}/a2a".encode()).hexdigest()
        for row in (child["actual"]["observation"], child["actual"]["control"]):
            row.update(protocols=dict(wire), target=endpoint)
            for record in report["evidence"]:
                if record["request_id"] == row["request_id"]:
                    record.update(target=endpoint)
                    if record.get("method") == "probe":
                        record["facts"]["sha256"] = sha256(row)
        for capability in ("discovery", "invoke"):
            row = dict(child["actual"]["observation"])
            row.pop("control_reference")
            row.update(check_id=f"route.{caller}.{target}.{capability}",
                       request_id=target + "-" + capability, operation_id=target + "-" + capability)
            if capability == "discovery":
                row.update(actual="gateway_card", target=hashlib.sha256(
                    f"https://gateway.example/{target}/.well-known/agent-card.json".encode()).hexdigest())
            else:
                row.pop("protocols")
                reference = child["actual"]["route_context"]["operations"][target]
                row.update(actual="accepted_invocation", observation_kind="workflow",
                           run_id="real-run", started=80, finished=81,
                           business_state="TASK_STATE_SUBMITTED", accepted_operation_id=reference["operation_id"])
            report["operation_ids"].append(row["operation_id"])
            report["evidence"].append(row | {"source": "gateway", "observed": row["finished"],
                "method": "GET" if capability == "discovery" else "POST",
                "credential_sha256": report["subscription_bindings"][caller],
                "facts": {"backend_dispatched": True}})
            if caller != "operator":
                report["evidence"].append(row | {"source": "application", "observed": row["finished"],
                    "method": "probe" if capability == "discovery" else "invocation.observed",
                    "runtime_identity": report["runtime_identities"][caller],
                    "facts": {"probe_id": row["check_id"], "sha256": sha256(row)}})
            backend = row | {"source": "application", "observed": row["finished"],
                "method": "discovery" if capability == "discovery" else "SendMessage",
                "runtime_identity": report["runtime_identities"][target]}
            report["evidence"].append(backend)
            if capability == "invoke":
                report["evidence"].append(backend | {"operation_id": reference["operation_id"], "facts": {
                    "accepted_operation_id": reference["operation_id"], "input_hash": reference["input_hash"]}})
            report["checks"].append({"check_id": row["check_id"], "expected": "allow", "status": "pass",
                "actual": child["actual"] | {"observation": row, "control": row}})
    check = {"check_id": "protocol.a2a-1.0", "expected": "evidence", "status": "pass",
             "actual": {"required_checks": sorted(row["check_id"] for row in report["checks"])}}
    return check, report


def model_protocol_report():
    from citadel.acceptance.coverage import STORAGE
    from tests.acceptance.test_model_oracle import ModelOracleTests
    identities = {actor: str(index + 1) * 64 for index, actor in enumerate(STORAGE)}
    report = {"run_id": "suite1", "runtime_identities": identities,
        "protocols": {"model_path": "/openai/v1/chat/completions"},
        "subscription_bindings": {}, "checks": [], "evidence": [], "operation_ids": ["phase1", "comparison1"]}
    for actor in STORAGE:
        observed, control, snapshots, evidence = ModelOracleTests().fixture()
        caller = actor if actor != "reference-data" else "evidence-assessor"
        observed.update(caller=actor, check_id=f"model.{actor}.direct-denied",
            runtime_identity=identities[actor], operation_id="direct-" + actor, request_id="denied-" + actor)
        allowed = control["allowed"]
        allowed.update(caller=caller, runtime_identity=identities[caller],
                       operation_id="model-" + caller, request_id="allowed-" + caller)
        control["runtime_identity"] = "f" * 64
        report["subscription_bindings"][caller] = sha256(caller)
        evidence[0].update(observed)
        evidence[1].update(allowed)
        evidence[2].update(allowed, credential_sha256=sha256(caller),
            facts={"backend_dispatched": True, "backend_target": observed["target"],
                   "backend_method": "POST", "backend_status": 200})
        for rows in snapshots.values():
            for row in rows.values():
                row["caller"] = "operator"
        report["checks"].append({"check_id": observed["check_id"], "expected": "deny", "status": "pass",
            "actual": {"observation": observed, "control": control,
                **{side: list(rows.values()) for side, rows in snapshots.items()}}})
        if actor != "reference-data":
            row = allowed | {"check_id": f"route.{actor}.model.inference"}
            report["checks"].append({"check_id": row["check_id"], "expected": "allow", "status": "pass",
                                    "actual": {"observation": row, "control": {}}})
        report["evidence"].extend(evidence)
        report["operation_ids"].extend(row["operation_id"] for row in evidence)
    report["operation_ids"] = sorted(set(report["operation_ids"]))
    check = {"check_id": "protocol.model-v1", "expected": "evidence", "status": "pass",
             "actual": {"required_checks": sorted(row["check_id"] for row in report["checks"])}}
    return check, report


class ProtocolOracleTests(unittest.TestCase):
    def test_collection_emits_only_protocols_with_complete_observed_wire_proofs(self):
        from citadel.acceptance.protocol_oracle import collect_protocols
        _, report = mcp_protocol_report()
        before = copy.deepcopy(report)
        results = {row["check_id"]: row for row in collect_protocols(report)}
        self.assertEqual(results["protocol.mcp-2025-11-25"]["status"], "pass")
        self.assertEqual(results["protocol.a2a-1.0"]["status"], "blocked")
        self.assertEqual(results["protocol.model-v1"]["status"], "blocked")
        self.assertEqual(report, before)

    def test_model_v1_requires_queried_backend_route_and_real_framework_usage_for_all_agents(self):
        check, report = model_protocol_report()
        for child in report["checks"]:
            self.assertEqual(evaluate_check(child, report)["status"], "pass", child["check_id"])
        self.assertEqual(evaluate_check(sanitize(check), sanitize(report))["status"], "pass")
        for key in ("backend_target", "backend_method", "backend_status"):
            changed = copy.deepcopy(report)
            for row in changed["evidence"]:
                if row["source"] == "gateway":
                    row["facts"].pop(key)
            self.assertEqual(evaluate_check(check, changed)["status"], "blocked", key)
        changed = copy.deepcopy(report)
        for row in changed["evidence"]:
            if row["source"] == "gateway":
                row["facts"]["backend_target"] = "9" * 64
        self.assertEqual(evaluate_check(check, changed)["status"], "fail")
        for source in ("application", "gateway", "storage"):
            self.assertEqual(evaluate_check(check, report | {"evidence": [
                row for row in report["evidence"] if row["source"] != source]})["status"], "blocked")

    def test_a2a_requires_all_four_actual_cards_invocations_and_exact_completed_tasks(self):
        check, report = a2a_protocol_report()
        for child in report["checks"]:
            self.assertEqual(evaluate_check(child, report)["status"], "pass", child["check_id"])
        self.assertEqual(evaluate_check(sanitize(check), sanitize(report))["status"], "pass")
        for source in ("application", "gateway", "storage"):
            changed = report | {"evidence": [row for row in report["evidence"] if row["source"] != source]}
            self.assertEqual(evaluate_check(check, changed)["status"], "blocked")
        for child in report["checks"]:
            changed = report | {"checks": [row for row in report["checks"] if row is not child]}
            self.assertEqual(evaluate_check(check, changed)["status"], "blocked", child["check_id"])
        self.assertEqual(evaluate_check(check, report | {
            "protocols": {"a2a": "0.3.0", "a2a_binding": "JSONRPC"}})["status"], "blocked")

    def test_mcp_negotiation_and_each_real_tool_receipt_survive_export_and_require_all_sources(self):
        check, report = mcp_protocol_report()
        for child in report["checks"]:
            self.assertEqual(evaluate_check(child, report)["status"], "pass", child["check_id"])
        self.assertEqual(evaluate_check(sanitize(check), sanitize(report))["status"], "pass")
        for source in ("application", "gateway", "storage"):
            changed = report | {"evidence": [row for row in report["evidence"] if row["source"] != source]}
            self.assertEqual(evaluate_check(check, changed)["status"], "blocked")
        for change in ({"checks": report["checks"][1:]},
                       {"checks": report["checks"] + [report["checks"][0]]},
                       {"protocols": report["protocols"] | {"mcp": "2024-11-05"}}):
            self.assertEqual(evaluate_check(check, report | change)["status"], "blocked")
        changed = copy.deepcopy(report)
        changed["checks"][0]["actual"] = {}
        self.assertEqual(evaluate_check(check, changed)["status"], "blocked")

    def test_protocol_must_be_observed_not_just_pinned_or_annotated_as_passing(self):
        check, report = mcp_protocol_report()
        changed = copy.deepcopy(report)
        row = changed["checks"][0]["actual"]["observation"]
        row.pop("protocols")
        for record in changed["evidence"]:
            if record.get("method") == "probe" and record["request_id"] == row["request_id"]:
                record["facts"]["sha256"] = sha256(row)
        self.assertEqual(evaluate_check(check, changed)["status"], "blocked")
        changed["checks"][0]["status"] = "fail"
        self.assertEqual(evaluate_check(check, changed)["status"], "fail")
