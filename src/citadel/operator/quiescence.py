"""A preserved partial commit can be quiescent without becoming a successful run."""

import math
import re
import time
from contextlib import contextmanager
from uuid import uuid4

from .state import Blocked, digest, read_private


@contextmanager
def maintenance(lifecycle, *, exclude=None, owner=None):
    """Own the same nonexpiring slot as UI/CLI execution, for the entire change."""
    from azure.core.exceptions import AzureError, HttpResponseError
    from azure.storage.blob import BlobLeaseClient

    if not runs_quiescent(lifecycle, exclude=exclude):
        raise Blocked("credential_change_requires_quiescent_runs")
    held = getattr(lifecycle, "_maintenance_record", None)
    if held is not None and held is lifecycle.value.get("maintenance") and held["state"] == "held":
        yield held
        return
    lifecycle.inventory()
    inventory = lifecycle.value["inventory"]
    suffix = "/blobServices/default/containers/planner-operations"
    accounts = [item.removesuffix(suffix) for item in inventory
                if "/providers/Microsoft.Storage/storageAccounts/" in item and item.endswith(suffix)]
    if len(accounts) != 1 or accounts[0] not in inventory:
        raise Blocked("exact_owned_planner_admission_required")
    previous = lifecycle.value.get("maintenance", {})
    resuming = previous.get("state") in ("intent", "held", "unknown")
    if resuming and (owner is None or previous.get("owner") != owner):
        raise Blocked("maintenance_ownership_requires_reconciliation")
    record = previous if resuming else {
        "lease_id": str(uuid4()), "state": "intent", "owner": owner, "changed": False}
    lifecycle.value["maintenance"] = record
    lifecycle.state.save()
    account = "https://" + accounts[0].rsplit("/", 1)[-1] + ".blob.core.windows.net"
    with lifecycle.native.blob(account, "planner-operations", "active-run-slot.json") as client:
        lease = BlobLeaseClient(client, lease_id=record["lease_id"])
        try:
            if resuming:
                # Renew only the persisted exact lease; never break/reacquire an
                # ambiguous lease, or replace another run's ownership.
                lease.renew(timeout=5)
            else:
                lease.acquire(lease_duration=-1, timeout=5)
        except HttpResponseError as exc:
            record["state"] = "blocked" if exc.status_code == 409 and not resuming else "unknown"
            lifecycle.state.save()
            raise Blocked("deployment_admission_not_quiescent_or_unavailable") from None
        except AzureError:
            record["state"] = "unknown"
            lifecycle.state.save()
            raise Blocked("deployment_admission_not_quiescent_or_unavailable") from None
        record["state"] = "held"
        lifecycle.state.save()
        lifecycle._maintenance_record = record
        succeeded = False
        try:
            yield record
            succeeded = True
        finally:
            lifecycle._maintenance_record = None
            if succeeded or not record["changed"]:
                try:
                    lease.release(timeout=5)
                except AzureError:
                    record["state"] = "unknown"
                    lifecycle.state.save()
                    raise Blocked("maintenance_release_requires_reconciliation") from None
                record["state"] = "released"
                lifecycle.state.save()


def runs_quiescent(lifecycle, *, exclude=None, clock=time.time):
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
                or not run["deadline"] + 16 <= verified <= clock()
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
