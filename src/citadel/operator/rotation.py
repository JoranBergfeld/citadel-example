"""Explicit staged rotation. Retirement requires actual target-identity controls."""

import base64
import copy
from datetime import datetime, timedelta, timezone
import secrets
from urllib.parse import urlsplit
from uuid import uuid4

from .scenarios import acceptance_hook
from .state import Blocked, read_private, write_private


def certificate(deployment_id):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs12
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "citadel-" + deployment_id)])
    # Backdate within the existing 30-second trust clock tolerance; the signed
    # interval is still exactly 90 days, never 90 days plus a grace period.
    start = (datetime.now(timezone.utc) - timedelta(seconds=30)).replace(microsecond=0)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(start).not_valid_after(start + timedelta(days=90))
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), False)
            .sign(key, hashes.SHA256()))
    return {
        "gatewayCertificatePfx": base64.b64encode(pkcs12.serialize_key_and_certificates(
            b"citadel", key, cert, None, serialization.NoEncryption())).decode(),
        "gatewayCertificates": [{"sha256": cert.fingerprint(hashes.SHA256()).hex(),
                                 "not_before": start.isoformat(),
                                 "not_after": (start + timedelta(days=90)).isoformat()}],
    }


def restart(lifecycle, target=None):
    for app in lifecycle.value["outputs"]["appInventory"]:
        name = app["app"].split("/")[-1]
        if target and name != lifecycle.id + "-" + target:
            continue
        group = app["app"].split("/")[4]
        revisions = lifecycle.native.az("containerapp", "revision", "list", "--name", name,
                        "--resource-group", group, "--subscription", lifecycle.config["subscriptionId"])
        active = [r for r in revisions if r["properties"].get("active")]
        if not active:
            raise Blocked("active_workload_revision_missing")
        for revision in active:
            lifecycle.native.az("containerapp", "revision", "restart", "--revision", revision["name"],
                "--resource-group", group, "--subscription", lifecycle.config["subscriptionId"])


def reconcile(lifecycle, credentials):
    write_private(lifecycle.state.directory / "credentials.json", credentials)
    lifecycle.arm("validate", runtime=True)
    lifecycle.capture_outputs(lifecycle.arm("create", runtime=True))


def rotate_command(lifecycle, args):
    if lifecycle.value["phase"] != "deployed_unverified":
        raise Blocked("runtime_deployment_required")
    path = lifecycle.state.directory / "rotation.json"
    pending = read_private(path) if path.exists() else {}
    control = lifecycle.value.get("rotation_controls", {}).get(pending.get("run_id"), {})
    collectible = (args.command == "rotate" and args.stage == "finalize"
        and (args.kind, args.target) == (pending.get("kind"), pending.get("target"))
        and bool(control) and all(control.get(stage, {}).get("state") in (None, "observed", "verified")
        for stage in ("new", "old"))
        and pending.get("selector_intent", {}).get("state") in (None, "restored"))
    if any(r["state"] not in ("succeeded", "failed_no_commit")
           and not (collectible and key == pending.get("run_id"))
           for key, r in lifecycle.value["runs"].items()):
        raise Blocked("credential_change_requires_quiescent_runs")
    lifecycle.inventory()
    credentials = lifecycle.credentials()
    if args.command == "revoke":
        if args.caller not in credentials["callerStates"]:
            raise Blocked("unknown_allocated_caller")
        identifier = next((r for r in lifecycle.value["outputs"]["inventory"]["gateway"]["subscriptions"]
                           if r.endswith("/" + args.caller)), None)
        if not identifier:
            raise Blocked("owned_subscription_inventory_missing")
        credentials["callerStates"][args.caller] = "suspended"
        write_private(lifecycle.state.directory / "credentials.json", credentials)
        lifecycle.native.rest("patch", identifier, "2024-05-01", {"properties": {"state": "suspended"}})
        actual = lifecycle.native.rest("get", identifier, "2024-05-01")
        if actual["properties"]["state"] != "suspended":
            raise Blocked("subscription_suspension_not_verified")
        lifecycle.state.event("revoke", "suspended_live_denial_unverified")
        return {"status": "suspended", "caller": args.caller, "liveDenialProof": "required"}
    target = args.target
    if args.kind == "subscription" and target not in credentials["callerKeys"]:
        raise Blocked("allocated_caller_required")
    if args.kind == "context" and target not in credentials["contextKeys"]:
        raise Blocked("allocated_backend_required")
    if args.stage == "prepare":
        if path.exists():
            pending = read_private(path)
            owner = getattr(args, "acceptance_run_id", None)
            if owner is not None and owner != pending.get("acceptance_run_id"):
                raise Blocked("rotation_collection_owner_conflict")
            if (pending["kind"], pending["target"]) != (args.kind, target):
                raise Blocked("another_rotation_requires_reconciliation")
        else:
            pending = {"kind": args.kind, "target": target, "run_id": uuid4().hex,
                       "phase": "prepared", "old": copy.deepcopy(credentials),
                       "new": certificate(lifecycle.id) if args.kind == "certificate" else secrets.token_urlsafe(32)}
            acceptance_run_id = getattr(args, "acceptance_run_id", None)
            if acceptance_run_id is not None:
                if acceptance_run_id not in lifecycle.value.get("acceptance_attempts", {}):
                    raise Blocked("matching_acceptance_collection_owner_required")
                pending["acceptance_run_id"] = acceptance_run_id
            from citadel.acceptance.rotation_harness import capture_retired_secret
            pending["old_secret_id"] = capture_retired_secret(lifecycle, args.kind, target, credentials)
            write_private(path, pending)
        if pending["phase"] != "prepared":
            return {"status": "rotation_staged", "liveProof": "required_before_retirement"}
        credentials = copy.deepcopy(pending["old"])
        if args.kind == "certificate":
            # Install dual trust with the old gateway certificate still selected.
            credentials["gatewayCertificates"] += pending["new"]["gatewayCertificates"]
            reconcile(lifecycle, credentials)
            restart(lifecycle)
            credentials["gatewayCertificatePfx"] = pending["new"]["gatewayCertificatePfx"]
            reconcile(lifecycle, credentials)
            certificate_id = next(r for r in lifecycle.value["outputs"]["inventory"]["gateway"]["resources"]
                                  if r.endswith("/certificates/gateway-client"))
            lifecycle.native.rest("post", certificate_id + "/refreshSecret", "2024-05-01")
        elif args.kind == "subscription":
            old = credentials["callerKeys"][target]["primary"]
            credentials["callerKeys"][target] = {"primary": pending["new"], "secondary": old}
            reconcile(lifecycle, credentials)
            if target != "operator":
                restart(lifecycle, target)
        else:
            key_id = "k" + pending["run_id"][:16]
            credentials["contextKeys"][target]["keys"][key_id] = pending["new"]
            reconcile(lifecycle, credentials)
            restart(lifecycle, target)
            credentials["contextKeys"][target]["activeId"] = key_id
            reconcile(lifecycle, credentials)
        pending["phase"] = "staged"
        write_private(path, pending)
        lifecycle.state.event("rotate", "staged_live_proof_required")
        return {"status": "rotation_staged", "liveProof": "required_before_retirement"}
    pending = read_private(path)
    if (pending["kind"], pending["target"]) != (args.kind, target) or pending["phase"] not in ("staged", "retired"):
        raise Blocked("matching_staged_rotation_required")
    acceptance_hook(lifecycle, "rotation-new-material-allowed", pending["run_id"])
    if pending["phase"] == "staged":
        if args.kind == "certificate":
            credentials["gatewayCertificates"] = pending["new"]["gatewayCertificates"]
        elif args.kind == "subscription":
            credentials["callerKeys"][target]["secondary"] = secrets.token_urlsafe(32)
        else:
            key_id = credentials["contextKeys"][target]["activeId"]
            credentials["contextKeys"][target]["keys"] = {key_id: pending["new"]}
        reconcile(lifecycle, credentials)
        if args.kind == "certificate":
            restart(lifecycle)
        elif target != "operator":
            restart(lifecycle, target)
        pending["phase"] = "retired"
        write_private(path, pending)
    acceptance_hook(lifecycle, "rotation-old-material-denied", pending["run_id"])
    if args.kind == "certificate":
        vault_id = next(r for r in lifecycle.value["outputs"]["inventory"]["platform"]["resources"]
                        if "/Microsoft.KeyVault/vaults/" in r and "/secrets/" not in r)
        versions = lifecycle.native.az("keyvault", "secret", "list-versions", "--vault-name", vault_id.split("/")[-1],
                                        "--name", "gateway-certificate")
        enabled = [v for v in versions if v.get("attributes", {}).get("enabled")]
        if not enabled:
            raise Blocked("certificate_secret_versions_missing")
        newest = max(enabled, key=lambda v: v["attributes"]["created"])
        for version in enabled:
            if version["id"] != newest["id"]:
                parsed = urlsplit(version["id"])
                if (parsed.scheme != "https" or parsed.hostname != vault_id.split("/")[-1] + ".vault.azure.net"
                        or parsed.query or parsed.fragment or parsed.username
                        or not parsed.path.startswith("/secrets/gateway-certificate/")
                        or len(parsed.path.split("/")) != 4):
                    raise Blocked("unrelated_secret_version_protection")
                lifecycle.inventory()
                lifecycle.native.az("keyvault", "secret", "set-attributes", "--id", version["id"], "--enabled", "false")
    # Preserve private diagnostics and old material until explicit operator disposal.
    archived = lifecycle.state.directory / ("rotation-" + pending["run_id"] + ".json")
    path.rename(archived)
    lifecycle.state.event("rotate", "verified_by_live_hook")
    return {"status": "rotated", "liveProof": "verified_by_hook"}
