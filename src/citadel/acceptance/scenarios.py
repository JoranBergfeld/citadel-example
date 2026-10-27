"""Independent semantic oracle using the public immutable evidence contract."""

from citadel.evidence import CAVEATS
from citadel.evidence.manifests import sha256
from .oracle import hash_value


FIXTURES = {"comparison": "base-source", "replacement": "missing-width-replacement",
            "exhaustion": "no-alternative", "denied-bypass": "base-source"}


def expected_scenario(source, scenario):
    fixture = FIXTURES[scenario]
    data = source if fixture == "base-source" else source.with_overlay(source.fixture_manifests()[fixture])
    pool = data.search_airports()
    selected, assessed = [], []
    for airport in pool["airports"]:
        ident = airport["ident"]["parsed"]
        assessment = data.assess_airport(ident)
        assessed.append({"airport_ident": ident, **assessment})
        if assessment["classification"] == "complete":
            selected.append(ident)
        if len(selected) == 3:
            break
    return {"status": "complete" if len(selected) == 3 else "bounded_pool_exhausted",
            "selected_identifiers": selected, "pool_count": len(pool["airports"]),
            "assessed": assessed, "provenance": data.provenance, "caveats": list(CAVEATS)}


def evaluate_scenario(source, scenario, product):
    result = {"check_id": scenario, "status": "blocked", "reason": "scenario_product_missing"}
    if not isinstance(product, dict):
        return result
    expected = expected_scenario(source, scenario)
    for key in ("status", "selected_identifiers", "pool_count", "provenance", "caveats"):
        if product.get(key) != expected[key]:
            return result | {"status": "fail", "reason": "deterministic_semantic_mismatch"}
    assessed = product.get("assessed")
    if not isinstance(assessed, list) or len(assessed) != len(expected["assessed"]):
        return result | {"status": "fail", "reason": "assessed_pool_mismatch"}
    released_missing = False
    for actual, wanted in zip(assessed, expected["assessed"]):
        if not isinstance(actual, dict) or any(actual.get(k) != v for k, v in wanted.items()):
            return result | {"status": "fail", "reason": "assessment_or_provenance_mismatch"}
        if {"private_notes", "reviewer_deliberation", "prompts", "credentials"} & actual.keys():
            return result | {"status": "fail", "reason": "private_projection_leaked"}
        draft = actual.get("draft")
        if draft is None:
            released_missing = True
        elif (not isinstance(draft, dict) or set(draft) != {"artifact_id", "version", "sha256"}
              or not hash_value(draft.get("sha256")) or not isinstance(draft.get("artifact_id"), str)
              or not draft["artifact_id"] or type(draft.get("version")) is not int or draft["version"] < 1
              or actual.get("version") != draft["version"] or actual.get("reviewer") != "release-reviewer"):
            return result | {"status": "fail", "reason": "draft_hash_or_release_binding_malformed"}
    if expected["status"] == "bounded_pool_exhausted":
        if "brief" in product:
            return result | {"status": "fail", "reason": "exhaustion_is_not_a_complete_brief"}
    else:
        brief = product.get("brief", {})
        if (brief.get("status") != "complete" or brief.get("fictional") is not True
                or brief.get("provenance") != expected["provenance"]
                or brief.get("caveats") != expected["caveats"]
                or not isinstance(brief.get("narrative"), str) or not brief["narrative"]):
            return result | {"reason": "exact_released_brief_missing"}
        findings, citations, scopes = (brief.get(key, []) for key in ("findings", "citations", "read_scopes"))
        if not len(findings) == len(citations) == len(scopes) == 3:
            return result | {"reason": "exact_released_versions_missing"}
        if [finding.get("airport_ident") for finding in findings] != expected["selected_identifiers"]:
            return result | {"status": "fail", "reason": "brief_candidates_mismatch"}
        for finding, citation in zip(findings, citations):
            if (set(citation) != {"artifact_id", "version", "sha256"}
                    or not hash_value(citation["sha256"]) or type(citation["version"]) is not int
                    or citation["version"] < 1 or sha256(finding) != citation["sha256"]
                    or finding.get("artifact_id") != citation["artifact_id"]
                    or finding.get("version") != citation["version"]
                    or finding not in assessed):
                return result | {"status": "fail", "reason": "exact_finding_binding_mismatch"}
    if released_missing:
        return result | {"reason": "exact_released_versions_missing"}
    return result | {"status": "pass", "reason": "deterministic_facts_verified",
                     "product_sha256": sha256(product), "semantics_sha256": sha256(expected)}
