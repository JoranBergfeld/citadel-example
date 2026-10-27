"""A preserved partial commit can be quiescent without becoming a successful run."""

import math
import re
import time

from .state import Blocked, digest, read_private


def runs_quiescent(lifecycle, *, exclude=None):
    for run_id, run in lifecycle.value["runs"].items():
        if run_id == exclude or run["state"] in ("succeeded", "failed_no_commit"):
            continue
        if run["state"] != "indeterminate" or not run.get("quiescenceProof"):
            return False
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", run_id):
            raise Blocked("invalid_partial_run_quiescence_proof")
        proof = read_private(lifecycle.state.directory / (run_id + "-quiescence.json"))
        original = {key: value for key, value in run.items() if key != "quiescenceProof"}
        verified = proof.get("verified_at")
        snapshots = proof.get("snapshots", [])
        admission = proof.get("admission", {})
        if (digest(proof) != run["quiescenceProof"] or proof.get("schema_version") != 1
                or proof.get("state") != "verified_quiescent_partial_commit"
                or proof.get("deployment_id") != lifecycle.id
                or proof.get("configuration") != digest(lifecycle.config)
                or proof.get("run_id") != run_id or proof.get("original_run") != original
                or type(verified) not in (int, float) or not math.isfinite(verified)
                or not run["deadline"] + 16 <= verified <= time.time()
                or not isinstance(proof.get("approval"), str) or not proof["approval"]
                or len(snapshots) != 2
                or any(not isinstance(row, dict) or not re.fullmatch(r"[a-f0-9]{64}", row.get("sha256", ""))
                       for row in snapshots)
                or snapshots[0]["sha256"] != snapshots[1]["sha256"]
                or admission.get("state") != "released_verified"
                or admission.get("scope") != "operator/invoke/" + run_id
                or proof.get("partial_effects_retained") is not True
                or proof.get("replayed") is not False):
            raise Blocked("invalid_partial_run_quiescence_proof")
    return True
