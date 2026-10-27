"""Aggregate already-executed identity and owner controls, never their labels."""

from .coverage import required_checks


DEPENDENCIES = {
    "authority.executing-identities": tuple(sorted(
        key for key in required_checks() if key.startswith("storage."))),
    "authority.status-owner-scope": tuple(sorted(
        key for key in required_checks() if key.startswith("route.")
        and key.split(".")[-1] in ("status", "task", "findings"))),
}


def evaluate_authority(check, report):
    from .proof_gate import evaluate_check
    result = {"check_id": check.get("check_id"), "status": "blocked",
              "reason": "complete_independent_authority_proofs_required"}
    required = DEPENDENCIES.get(check.get("check_id"))
    children = report.get("checks")
    if (required is None or check.get("actual") != {"required_checks": list(required)}
            or not isinstance(children, list) or any(not isinstance(child, dict) for child in children)):
        return result
    states = set()
    for identifier in required:
        matches = [child for child in children if child.get("check_id") == identifier]
        if len(matches) != 1:
            states.add("blocked")
            continue
        child = matches[0]
        states.add(evaluate_check(child, report)["status"] if child.get("status") == "pass"
                   else "fail" if child.get("status") == "fail" else "blocked")
    if "fail" in states:
        return result | {"status": "fail", "reason": "observed_authority_control_failed"}
    if states != {"pass"}:
        return result
    return result | {"status": "pass", "reason": "all_exact_authority_service_proofs_reverified"}


def collect_authority(report):
    for identifier, required in DEPENDENCIES.items():
        check = {"check_id": identifier, "expected": "evidence",
                 "actual": {"required_checks": list(required)}}
        yield check | evaluate_authority(check, report)
