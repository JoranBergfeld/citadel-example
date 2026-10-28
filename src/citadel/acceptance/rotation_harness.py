"""Staged lifecycle rotation with allocated callers and independent queried evidence."""

import asyncio
import hashlib
import re
import time
from types import SimpleNamespace
from uuid import UUID, uuid4
from urllib.parse import urlsplit

import httpx

from citadel.evidence.manifests import sha256
from citadel.gateway.trust import INVOCATION_CALLERS
from citadel.operator.state import Blocked, read_private, write_private
from .collection import AzureQuery, Collector, collection_remaining
from .oracle import hash_value
from .reports import export_report
from .revision import RevisionProbe
from .rotation_controls import LEDGERS, TARGETS, evaluate_rotation, rotation_read, rotation_path, rotation_method
from .rotation_selector import RetiredSigner
from .storage_probes import StorageControls
from .storage_accounts import storage_accounts


def capture_retired_secret(lifecycle, kind, target, credentials):
    if kind == "context" or kind == "subscription" and target == "operator":
        return None
    if kind == "certificate":
        vaults = [r for r in lifecycle.value["outputs"]["inventory"]["platform"]["resources"]
                  if "/Microsoft.KeyVault/vaults/" in r and "/secrets/" not in r]
        if len(vaults) != 1:
            raise Blocked("exact_platform_certificate_vault_required")
        vault, name = vaults[0].rsplit("/", 1)[-1], "gateway-certificate"
        versions = lifecycle.native.az("keyvault", "secret", "list-versions", "--vault-name", vault, "--name", name)
        enabled = [version for version in versions if version.get("attributes", {}).get("enabled")]
        if not enabled:
            raise Blocked("owned_retired_certificate_version_required")
        newest = max(enabled, key=lambda version: version["attributes"]["created"])
        prefix = "https://" + vault + ".vault.azure.net/secrets/" + name + "/"
        if (not newest.get("id", "").startswith(prefix)
                or len(newest["id"].removeprefix(prefix)) != 32):
            raise Blocked("owned_retired_certificate_version_binding_conflict")
        return newest["id"]
    elif target == "operator-web":
        from citadel.operator.web_admin import app_id
        resource = app_id(lifecycle)
        if not resource:
            raise Blocked("operator_web_inventory_required")
        deployed = lifecycle.native.rest("get", resource, "2025-01-01")
        secrets = deployed["properties"]["configuration"]["secrets"]
        matches = [item["keyVaultUrl"] for item in secrets if item["name"] == "operator-subscription"]
        if len(matches) != 1:
            raise Blocked("exact_allocated_rotation_caller_required")
        parsed = urlsplit(matches[0])
        parts = parsed.path.split("/")
        if (parsed.scheme != "https" or not parsed.hostname or parsed.query or parsed.fragment
                or parsed.username or parsed.port or len(parts) != 4 or parts[1] != "secrets"
                or parts[2] != "subscription-operator-web" or re.fullmatch("[a-f0-9]{32}", parts[3]) is None):
            raise Blocked("owned_retired_secret_version_binding_conflict")
        allocations = lifecycle.value["outputs"]["operatorInventory"]["foundation"]["secrets"]
        allocated = [item for item in allocations if item.endswith("/secrets/" + parts[2])
                     and item in lifecycle.value["inventory"]]
        if (len(allocated) != 1
                or parsed.hostname != allocated[0].split("/vaults/")[1].split("/")[0] + ".vault.azure.net"):
            raise Blocked("owned_retired_secret_version_binding_conflict")
        vault, name = parsed.hostname.removesuffix(".vault.azure.net"), parts[2]
        secret = lifecycle.native.az("keyvault", "secret", "show", "--vault-name", vault,
                                    "--name", name, "--version", parts[3])
        if secret.get("id") != matches[0] or secret.get("value") != credentials["callerKeys"][target]["primary"]:
            raise Blocked("owned_retired_secret_version_binding_conflict")
        return secret["id"]
    else:
        apps = [app for app in lifecycle.value["outputs"]["appInventory"]
                if app["app"].endswith("/" + lifecycle.id + "-" + target)]
        if len(apps) != 1:
            raise Blocked("exact_allocated_rotation_caller_required")
        deployed = lifecycle.native.rest("get", apps[0]["app"], "2025-01-01")
        env = {item["name"]: item.get("value")
               for item in deployed["properties"]["template"]["containers"][0]["env"]}
        vault = urlsplit(env["CITADEL_VAULT_URL"]).hostname.removesuffix(".vault.azure.net")
        name, expected = env["CITADEL_SUBSCRIPTION_SECRET_NAME"], credentials["callerKeys"][target]["primary"]
    secret = lifecycle.native.az("keyvault", "secret", "show", "--vault-name", vault, "--name", name)
    prefix = "https://" + vault + ".vault.azure.net/secrets/" + name + "/"
    if secret.get("value") != expected or not secret.get("id", "").startswith(prefix):
        raise Blocked("owned_retired_secret_version_binding_conflict")
    return secret["id"]


def allowed_control(row, report, backend):
    actor, evidence = row["caller"], report["evidence"]
    method = rotation_method(actor, backend)
    gateway = [e for e in evidence if e.get("source") == "gateway"
        and e.get("request_id") == row.get("request_id") and e.get("target") == row["target"]
        and e.get("status_code") == 200 and e.get("caller") == actor
        and e.get("credential_sha256") == report["subscription_bindings"].get(actor)
        and e.get("facts", {}).get("backend_dispatched") is True
        and row["started"] - 5 <= e.get("observed", -1) <= row["finished"] + 5]
    backend_rows = [e for e in evidence if e.get("source") == "application"
        and e.get("request_id") == row.get("request_id") and e.get("status_code") == 200
        and e.get("method") == method and e.get("caller") == actor
        and e.get("runtime_identity") == report["runtime_identities"][backend]
        and row["started"] - 5 <= e.get("observed", -1) <= row["finished"] + 5]
    probes = [e for e in evidence if e.get("source") == "application"
        and e.get("method") == "rotation.probe" and e.get("request_id") == row.get("request_id")
        and e.get("runtime_identity") == report["runtime_identities"].get(actor)
        and e.get("run_id") == row["run_id"] and e.get("operation_id") == row["operation_id"]
        and e.get("facts", {}).get("sha256") == sha256(row)]
    return (row.get("status_code") == 200 and row.get("actual") == "read_only_control"
            and len(gateway) == len(backend_rows) == 1
            and (actor in ("operator", "operator-web") or len(probes) == 1))


class RotationAcceptance:
    def __init__(self, lifecycle):
        self.lifecycle = lifecycle

    def control(self, stage, run_id, *, fingerprints, directory):
        lifecycle = self.lifecycle
        path = lifecycle.state.directory / "rotation.json"
        pending = read_private(path)
        expected_phase = "staged" if stage == "new" else "retired"
        verified_current = (stage == "new" and pending["phase"] == "retired"
            and lifecycle.value.get("rotation_controls", {}).get(run_id, {}).get("new", {}).get("state") == "verified")
        if pending["run_id"] != run_id or pending["phase"] != expected_phase and not verified_current:
            raise Blocked("matching_owned_rotation_stage_required")
        from citadel.operator.quiescence import runs_quiescent
        if not runs_quiescent(lifecycle, exclude=run_id):
            raise Blocked("rotation_controls_require_quiescent_runs")
        from citadel.operator.quiescence import maintenance
        with maintenance(lifecycle, exclude=run_id, owner={
                "command": "rotation-control", "run_id": run_id, "stage": stage}) as held:
            return self._control(stage, run_id, pending, held, fingerprints=fingerprints, directory=directory)

    def _control(self, stage, run_id, pending, held, *, fingerprints, directory):
        lifecycle = self.lifecycle
        path = lifecycle.state.directory / "rotation.json"
        kind, target = pending["kind"], pending["target"]
        backend = TARGETS.get(target) if kind == "subscription" else target if kind == "context" else "evidence-assessor"
        actor = target if kind == "subscription" else next(iter(sorted(INVOCATION_CALLERS.get(backend, ()))))
        if not backend or not actor:
            raise Blocked("allocated_rotation_read_capability_required")
        records = lifecycle.value.setdefault("rotation_controls", {})
        if run_id not in records:
            if stage != "new":
                raise Blocked("current_rotation_control_required_before_retirement")
            records[run_id] = {"schema_version": 1, "mode": "cloud", "run_id": run_id,
                **fingerprints, "operation_ids": [run_id], "evidence": [], "checks": [],
                "started": time.time(), "finished": time.time(), "deadline": time.time() + 900,
                "read_attempts": 0, "observations": [], "caller": actor, "name": backend,
                "acceptance_run_id": pending.get("acceptance_run_id"),
                "required_checks": ["rotation." + kind + "-allowed-and-revoked"]}
        record = records[run_id]
        if record.get("acceptance_run_id") != pending.get("acceptance_run_id"):
            raise Blocked("rotation_collection_owner_conflict")
        if record["fingerprint"] != fingerprints["fingerprint"]:
            raise Blocked("rotation_control_inputs_changed")
        if record.get(stage, {}).get("state") != "verified":
            lifecycle.value["runs"][run_id] = {"state": "control_intent", "fixture": "base-source",
                "scenario": "rotation", "deadline": record["deadline"]}
            lifecycle.state.save()

        def admit():
            if record["read_attempts"] >= 512 or time.time() >= record["deadline"]:
                raise Blocked("rotation_control_original_envelope_exhausted")
            record["read_attempts"] += 1
            lifecycle.state.save()

        def save_selector():
            write_private(path, pending)

        native, previous = lifecycle.native, getattr(lifecycle.native, "deadline", None)
        native.deadline = min(previous or float("inf"), time.monotonic() + max(0, record["deadline"] - time.time()))
        try:
            if stage not in record:
                previous_change = held["changed"]
                held["changed"] = True
                record[stage] = {"state": "dispatching"}
                lifecycle.state.save()
                if stage == "new":
                    if actor == "briefing-author":
                        controls = StorageControls(native, account=storage_accounts(lifecycle),
                            suite_id=run_id, admit=admit)
                        runs = [key for key, row in lifecycle.value["runs"].items()
                                if row["state"] == "succeeded" and row.get("fixture") == "base-source"][-4:]
                        source = controls.route_context(runs, minimum_finding_reads=2)
                        record["finding_control"] = source["context"]["finding_controls"]["briefing-author"]
                        record["source_reads"] = source["observations"] + source["ticket_reads"]
                        record["operation_ids"].extend(row["operation_id"] for row in record["source_reads"])
                        lifecycle.state.save()
                    record["observations"].append(self._read(record, kind, actor, backend, admit))
                    record[stage]["state"] = "observed"
                else:
                    if record.get("new", {}).get("state") != "verified":
                        raise Blocked("verified_current_rotation_control_required")
                    accounts = storage_accounts(lifecycle)
                    controls = StorageControls(native,
                        account=accounts,
                        suite_id=run_id, admit=admit)
                    record["before"] = [controls._read(container, "ledger-v1.json")[0] for container in LEDGERS]
                    record["operation_ids"].extend(row["operation_id"] for row in record["before"])
                    selector = RetiredSigner(lifecycle, pending, save=save_selector, admit=admit)
                    if kind == "subscription":
                        record["before_sha256"] = sha256(lifecycle.credentials()["callerKeys"][actor])
                    else:
                        record["before_sha256"] = selector.switch()
                    record["observations"].append(self._read(record, kind, actor, backend, admit, retired=True,
                                                               pending=pending))
                    record["after_sha256"] = (sha256(lifecycle.credentials()["callerKeys"][actor])
                        if kind == "subscription" else selector.restore())
                    record["observations"].append(self._read(record, kind, actor, backend, admit))
                    record["after"] = [controls._read(container, "ledger-v1.json")[0] for container in LEDGERS]
                    record["operation_ids"].extend(row["operation_id"] for row in record["after"])
                    record["state"] = "restored"
                    record[stage]["state"] = "observed"
                held["changed"] = previous_change
                lifecycle.state.save()
            elif record[stage]["state"] not in ("observed", "verified"):
                raise Blocked("rotation_control_intent_requires_reconciliation")
            record["finished"] = time.time()
            lifecycle.state.save()
            self._collect(record, admit)
            if stage == "new":
                status = "pass" if allowed_control(record["observations"][0], record, backend) else "blocked"
            else:
                check = {"check_id": record["required_checks"][0], "expected": "evidence",
                    "actual": {key: record[key] for key in ("run_id", "caller", "name", "observations",
                        "before", "after", "before_sha256", "after_sha256", "state")}}
                result = evaluate_rotation(check, record)
                record["checks"] = [check | result]
                status = result["status"]
            if status == "pass":
                record[stage]["state"] = "verified"
                if stage == "old" or "old" not in record:
                    lifecycle.value["runs"][run_id]["state"] = "failed_no_commit"
            record["acceptance"] = status
            lifecycle.state.save()
            return export_report(directory, record)
        finally:
            native.deadline = previous
            lifecycle.state.save()

    def _read(self, record, kind, actor, backend, admit, *, retired=False, pending=None):
        lifecycle, operation = self.lifecycle, uuid4().hex
        credentials = lifecycle.credentials()
        key = (pending["old"]["callerKeys"][actor]["primary"]
               if retired and kind == "subscription" else credentials["callerKeys"][actor]["primary"])
        control = {"kind": kind, "target": backend, "credential_sha256": hashlib.sha256(key.encode()).hexdigest(),
            "secret_version": pending["old_secret_id"].rsplit("/", 1)[-1]
                if retired and kind == "subscription" and actor != "operator" else None}
        if actor == "operator-web":
            control["projection"] = "run-list"
            if not retired:
                capture_retired_secret(lifecycle, kind, actor, credentials)
        if actor == "briefing-author":
            control.update(record["finding_control"])
        record["operation_ids"].append(operation)
        lifecycle.state.save()
        if actor in ("operator", "operator-web"):
            async def execute():
                async def admitted():
                    admit()
                async with httpx.AsyncClient(timeout=30, follow_redirects=False, trust_env=False) as client:
                    return await rotation_read(workload=actor, gateway=lifecycle.value["outputs"]["gatewayUrl"],
                        key=key, request={"rotation": control, "deadline": record["deadline"], "run_id": operation},
                        client=client, admit=admitted)
            row = asyncio.run(execute())
        else:
            apps = [app for app in lifecycle.value["outputs"]["appInventory"]
                    if app["app"].endswith("/" + lifecycle.id + "-" + actor)]
            if len(apps) != 1:
                raise Blocked("exact_rotation_caller_application_required")
            result = RevisionProbe(lifecycle, admit=admit).execute(apps[0], actor, operation,
                mode="rotation", rotation=control, deadline=record["deadline"])
            if result.get("state") != "complete" or len(result["observations"]) != 1:
                raise Blocked("rotation_worker_control_incomplete")
            row = result["observations"][0]
            principal = hashlib.sha256(str(UUID(apps[0]["identityPrincipalId"])).encode()).hexdigest()
            if row.get("runtime_identity") != principal:
                raise Blocked("rotation_executing_identity_conflict")
        suffix = rotation_path(control)
        if (row.get("caller") != actor or row.get("run_id") != operation
                or row.get("check_id") != record["required_checks"][0]
                or row.get("credential_sha256") != control["credential_sha256"]
                or row.get("target") != hashlib.sha256(
                    (lifecycle.value["outputs"]["gatewayUrl"] + "/" + backend + suffix).encode()).hexdigest()
                or row.get("operation_id") in record["operation_ids"]):
            raise Blocked("rotation_worker_immutable_binding_conflict")
        from citadel.operations import identity
        record["operation_ids"].append(identity(row["operation_id"]))
        lifecycle.state.save()
        return row

    def _collect(self, record, admit):
        owner_id = record.get("acceptance_run_id")
        owner = record if owner_id is None else self.lifecycle.value.get("acceptance_attempts", {}).get(owner_id)
        if owner is None:
            raise Blocked("matching_acceptance_collection_owner_required")
        remaining = min(collection_remaining(owner, time.time()), record["deadline"] - time.time())
        if remaining <= 0:
            raise Blocked("rotation_original_collection_allowance_exhausted")
        windows = owner.setdefault("collection_windows", {})
        key = "rotation-" + record.get("run_id", "") + "-" + str(len(windows))
        windows[key] = {"started": time.time(), "finished": None}
        self.lifecycle.state.save()
        try:
            from .retention import workspace_resource
            try:
                workspace_id = workspace_resource(self.lifecycle)
            except Blocked:
                raise Blocked("exact_rotation_workspace_required") from None
            admit()
            workspace = self.lifecycle.native.rest("get", workspace_id, "2022-10-01")
            record["evidence"] = Collector(AzureQuery(self.lifecycle.native, workspace["properties"]["customerId"]),
                started=record["started"], finished=record["finished"], budget_seconds=remaining,
                prior=record["evidence"]).poll()
        finally:
            windows[key]["finished"] = time.time()
            self.lifecycle.state.save()

    def execute(self, report):
        from citadel.operator.rotation import rotate_command
        for kind, target in (("subscription", "candidate-planner"), ("certificate", None),
                             ("context", "evidence-assessor")):
            if collection_remaining(report, time.time()) <= 0:
                raise Blocked("rotation_original_collection_allowance_exhausted")
            args = SimpleNamespace(command="rotate", kind=kind, target=target, stage="prepare",
                                   acceptance_run_id=report["run_id"])
            rotate_command(self.lifecycle, args)
            pending = read_private(self.lifecycle.state.directory / "rotation.json")
            args.stage = "finalize"
            rotate_command(self.lifecycle, args)
            result = self.lifecycle.value["rotation_controls"][pending["run_id"]]
            report["operation_ids"].extend(result["operation_ids"])
            report["evidence"].extend(result["evidence"])
            check = result["checks"][0]
            actual = check["actual"]
            for side in ("before", "after"):
                for row in actual[side]:
                    row["suite_id"] = report["run_id"]
            from .operator_hooks import Harness
            Harness._replace(report, check)
            self.lifecycle.state.save()
