"""Private, append-only attempts and explicit per-product human confirmation."""

import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from citadel.evidence.manifests import sha256
from citadel.operator.state import Blocked, private, write_private, write_private_bytes
from .oracle import hash_value


FIELDS = frozenset("""
schema_version run_id operation_id operation_ids check_id status mode fingerprint scope
required_checks checks scenarios human_reviews product_sha256 semantics_sha256
supported gaps_visible fictional confirmed_at expected actual business_state reason
source sources request_id control_request_id caller runtime_identity gateway_identity
control_identity
observation control before after target container action etag suite_id client_request_id
method event_id facts certificate_sha256 generation read_attempts agent_executions upstream_attempts backend_dispatched
model_attempts input_tokens output_tokens tokens deadline retry artifact_count probe_id
started finished observed status_code control_status before_sha256 after_sha256
before_count after_count evidence evidence_sha256 artifacts sha256 count version
software configuration image manifest protocols model inputs limits lifecycle_refs
acceptance automated_status human_status coverage optional_not_exercised
collection_deadline
collection_windows collection_attempts last_collection
state states completed_states remaining_reads identical_input response replay fenced stale retried
completed missing_operation_id operation_state input_hash missing_state budget_state closed
business_sha256 steps
route_context context_reads control_reference finding read_scope artifact_id operations result_sha256 task_sha256
finding_controls observation_kind read_operation_id ticket_reads
accepted_operation_id
release_source draft draft_sha256 projection_sha256 reference_reads
input_hashes run_ids deadlines result_hashes simultaneous_commits conditional_conflicts
rejected_state rejected_operation_id rejected_draft_sha256 rejected_count rejected_sha256
drafts attempts responses draft_read content_sha256 source_sha256 expected_input_hashes result_kinds
version_proof versions draft_before draft_after findings source_run fields_sha256 reviewer
runtime_identities subscription_bindings credential_sha256
name region sku version_upgrade_option verification a2a a2a_binding mcp mcp_transport
model_path blob_data_api key_vault_data_api
""".split())
DYNAMIC = {"scenarios", "human_reviews", "limits", "protocols", "inputs", "lifecycle_refs",
           "runtime_identities", "subscription_bindings", "collection_windows", "operations", "finding_controls"}


def sanitize(value, *, dynamic=False):
    """Unknown payloads are not exported even under innocuous-looking keys."""
    if isinstance(value, dict):
        return {key: sanitize(item, dynamic=key in DYNAMIC) for key, item in value.items()
                if isinstance(key, str) and (key in FIELDS or dynamic and re.fullmatch("[A-Za-z0-9_.-]{1,80}", key))}
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    if isinstance(value, str):
        if (len(value) > 512 or re.search(
                r"(?i)bearer\s|-----BEGIN|[?&](?:sig|token|key)=|subscription-key|/subscriptions/", value)):
            return "[redacted]"
        return value
    if value is None or type(value) in (bool, int, float):
        return value
    raise ValueError("Evidence must be JSON data")


def confirm_narrative(report, scenario, product_sha256, *, supported, gaps_visible, fictional):
    if (scenario not in report["scenarios"] or not hash_value(product_sha256)
            or report["scenarios"][scenario]["product_sha256"] != product_sha256
            or any(type(v) is not bool for v in (supported, gaps_visible, fictional))):
        raise ValueError("Review must bind one exact observed narrative and explicit decisions")
    report["human_reviews"][scenario] = {
        "product_sha256": product_sha256, "supported": supported, "gaps_visible": gaps_visible,
        "fictional": fictional, "confirmed_at": datetime.now(timezone.utc).isoformat(),
    }


def automated_status(report):
    from .coverage import required_checks
    from .proof_gate import evaluate_check
    if not isinstance(report, dict):
        return "blocked"
    required, checks = report.get("required_checks", []), report.get("checks", [])
    records = report.get("evidence", [])
    operations = report.get("operation_ids", [])
    if (type(report.get("schema_version")) is not int or report["schema_version"] != 1
            or not isinstance(report.get("run_id"), str)
            or not re.fullmatch("[A-Za-z0-9_-]{1,64}", report["run_id"])
            or not isinstance(operations, list) or not operations
            or not all(isinstance(key, str) and re.fullmatch("[A-Za-z0-9_-]{1,128}", key)
                       for key in operations) or len(set(operations)) != len(operations)
            or not isinstance(required, list) or not all(isinstance(key, str) for key in required)
            or not isinstance(checks, list)
            or not all(isinstance(check, dict) and isinstance(check.get("check_id"), str)
                       and isinstance(check.get("status"), str) for check in checks)
            or set(required) != set(required_checks()) or len(set(required)) != len(required)
            or len({c.get("check_id") for c in checks}) != len(checks)
            or {c.get("check_id") for c in checks} != set(required)
            or report.get("mode") != "cloud" or not hash_value(report.get("fingerprint"))):
        return "blocked"
    states = {check.get("status") for check in checks}
    if "fail" in states:
        return "fail"
    if (not isinstance(records, list) or not all(isinstance(record, dict) for record in records)
            or not {"application", "gateway", "storage"} <= {
                record.get("source") for record in records
                if isinstance(record.get("source"), str) and isinstance(record.get("request_id"), str)
                and record["request_id"] and type(record.get("status_code")) is int
                and 100 <= record["status_code"] <= 599}):
        return "blocked"
    verified = {evaluate_check(check, report)["status"] for check in checks if check["status"] == "pass"}
    if "fail" in verified:
        return "fail"
    return "pass" if states == {"pass"} and verified == {"pass"} else "blocked"


def reviewed_status(report):
    status = automated_status(report)
    if status != "pass":
        return status
    return narrative_status(report)


def narrative_status(report):
    """Human decisions do not certify automation or a pair of cloud attempts."""
    from .scenarios import FIXTURES
    scenarios, reviews = report.get("scenarios", {}), report.get("human_reviews", {})
    if (not isinstance(scenarios, dict) or set(scenarios) != set(FIXTURES)
            or not isinstance(reviews, dict)
            or not all(isinstance(product, dict) and hash_value(product.get("product_sha256"))
                       and hash_value(product.get("semantics_sha256")) for product in scenarios.values())):
        return "blocked"
    for name, product in scenarios.items():
        review = reviews.get(name)
        if review is not None and not isinstance(review, dict):
            return "blocked"
        if not review or review.get("product_sha256") != product.get("product_sha256"):
            return "pending_human"
        if not all(review.get(key) is True for key in ("supported", "gaps_visible", "fictional")):
            return "fail"
    return "pass"


def acceptance_status(attempts):
    if not attempts:
        return "blocked"
    last = attempts[-1]
    status = reviewed_status(last)
    if status != "pass":
        return status
    if len(attempts) < 2:
        return "pending_second_pass"
    previous = attempts[-2]
    if (reviewed_status(previous) != "pass" or previous["fingerprint"] != last["fingerprint"]
            or previous["run_id"] == last["run_id"]
            or not last.get("operation_ids") or not previous.get("operation_ids")
            or set(previous["operation_ids"]) & set(last["operation_ids"])
            or previous["required_checks"] != last["required_checks"]
            or {k: v["semantics_sha256"] for k, v in previous["scenarios"].items()} !=
               {k: v["semantics_sha256"] for k, v in last["scenarios"].items()}):
        return "pending_second_pass"
    return "pass"


def report_directory(directory):
    directory = Path(directory).absolute()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    private(directory, directory=True)
    # An ignored path inside a checkout is still not outside version control.
    result = subprocess.run(["git", "-C", str(directory), "rev-parse", "--show-toplevel"],
                            capture_output=True, check=False)
    if result.returncode == 0:
        raise Blocked("evidence_directory_must_be_outside_vcs")
    return directory


def export_report(directory, report):
    directory = report_directory(directory)
    clean = sanitize(report)
    identifier = clean.get("run_id", "")
    if not re.fullmatch("[A-Za-z0-9_-]{1,64}", identifier):
        raise ValueError("Invalid evidence run identity")
    fingerprint = sha256(clean)
    stem = identifier + "-" + fingerprint
    path = directory / (stem + ".json")
    if not path.exists():
        write_private(path, clean)
    elif private(path).read_bytes() != json.dumps(clean, sort_keys=True, separators=(",", ":")).encode():
        # canonical_bytes also preserves Unicode; compare decoded content instead.
        if json.loads(path.read_text()) != clean:
            raise Blocked("immutable_evidence_conflict")
    lines = [f"# Citadel acceptance — {identifier}", "",
             f"Status: **{clean.get('acceptance', 'blocked')}**.",
             "Local contract checks are not deployed proof.", "",
             "| Check | Status | Reason |", "|---|---|---|"]
    for check in clean.get("checks", []):
        lines.append(f"| {check['check_id']} | {check['status']} | {check.get('reason', '')} |")
    lines += ["", "Human review is per exact scenario product. Failed attempts are retained.",
              "Fresh deployment, repair, manual teardown and residue proof remain separate gates.",
              "Ordinary managed identities are not Entra Agent IDs; optional enterprise integrations unexercised."]
    write_private_bytes(directory / (stem + ".md"), ("\n".join(lines) + "\n").encode())
    return {"status": clean.get("acceptance", "blocked"), "run_id": identifier,
            "schema_version": 1, "evidence_sha256": fingerprint}
