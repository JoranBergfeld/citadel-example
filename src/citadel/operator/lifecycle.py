"""Deployment inventory lifecycle. All cloud effects go through the native boundary."""

from datetime import datetime, timezone
import fnmatch
import hashlib
import json
import platform
from pathlib import Path
import secrets
import sys
import time
import tomllib

from citadel.evidence import ReferenceData
from citadel.evidence.manifests import canonical_bytes
from citadel.evidence.preparation import ARTIFACT_NAMES
from citadel.gateway.configuration import validate_deployment_inputs
from citadel.operations import empty_ledger
from .native import Native
from .model_metadata import regional_standard_sku
from .state import Blocked, ROOT, digest, read_private, source_fingerprint, write_private, write_private_bytes, public_output


TEAMS = ("platform", "reference", "evidence", "planning")
WORKLOADS = json.loads((ROOT / "infra/workloads.json").read_text())
PROVIDERS = ("Microsoft.Resources", "Microsoft.Authorization", "Microsoft.App",
             "Microsoft.ManagedIdentity", "Microsoft.ContainerRegistry", "Microsoft.Storage",
             "Microsoft.KeyVault", "Microsoft.ApiManagement", "Microsoft.CognitiveServices",
             "Microsoft.ApiCenter", "Microsoft.Insights", "Microsoft.OperationalInsights")
DATA_ACTIONS = ("Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
                "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write")


def now():
    return datetime.now(timezone.utc)


def resource_ids(value):
    if isinstance(value, str):
        return {value} if value.startswith("/subscriptions/") else set()
    if isinstance(value, dict):
        return set().union(*(resource_ids(v) for v in value.values())) if value else set()
    if isinstance(value, list):
        return set().union(*(resource_ids(v) for v in value)) if value else set()
    return set()


def permits(entries, action, *, data=False):
    allowed, denied = ("dataActions", "notDataActions") if data else ("actions", "notActions")
    return any(any(fnmatch.fnmatchcase(action.lower(), p.lower()) for p in e.get(allowed, []))
               and not any(fnmatch.fnmatchcase(action.lower(), p.lower()) for p in e.get(denied, []))
               for e in entries)


class Lifecycle:
    def __init__(self, state, adapter=None):
        self.state = state
        self.value = state.load()
        self.config = self.value["config"]
        self.native = adapter or Native(self.config, state.directory)
        self.id = self.config["deploymentId"]
        self.subscription = "/subscriptions/" + self.config["subscriptionId"]
        self.groups = {team: f"citadel-{self.id}-{team}" for team in TEAMS}

    def command(self, args):
        if args.command == "record-plan-observation":
            from .plan import record_observation
            return record_observation(self, args.observation, args.evidence)
        if args.command == "acceptance":
            from .scenarios import acceptance_hook
            return acceptance_hook(self, "collect-evidence" if args.collect_only else "full-acceptance", args.run_id)
        if args.command == "review-acceptance":
            from citadel.acceptance.operator_hooks import review
            return review(lifecycle=self, run_id=args.run_id, confirmation=read_private(args.review))
        if args.command == "deploy" and not args.confirm_paid:
            raise Blocked("explicit_paid_provisioning_confirmation_required")
        if args.command == "check":
            return self.check()
        if args.command == "preflight":
            return self.preflight()
        if args.command == "deploy":
            return self.deploy(args.wheelhouse)
        if args.command == "inventory":
            return self.inventory()
        if args.command == "collect":
            return self.collect()
        if args.command == "teardown":
            return self.teardown(args.confirm_deployment)
        if args.command in ("demo", "status"):
            from .scenarios import scenario_command
            return scenario_command(self, args)
        if args.command in ("rotate", "revoke"):
            from .rotation import rotate_command
            return rotate_command(self, args)
        raise Blocked("unknown_lifecycle_command")

    def check(self):
        if self.value["software"] != source_fingerprint():
            raise Blocked("software_fingerprint_conflict")
        bundle = Path(self.config["bundleDir"])
        data = ReferenceData.from_bundle(bundle)
        for fixture in ("missing-width-replacement", "no-alternative"):
            ReferenceData.from_bundle(bundle, fixture=fixture)
        fingerprint = hashlib.sha256((bundle / "bundle-manifest.json").read_bytes()).hexdigest()
        if self.value.get("bundle") not in (None, fingerprint):
            raise Blocked("immutable_bundle_conflict")
        self.value["bundle"] = fingerprint
        if sys.version_info[:3] != (3, 12, 15) or platform.system() != "Linux" or platform.machine() != "x86_64":
            raise Blocked("pinned_python_platform_required")
        pins = tomllib.loads((ROOT / "stack.toml").read_text())
        tools = self.config["tools"]
        for tool in ("uv", "azd", "bicep"):
            executable = tools.get(tool, tool)
            version = self.native.run([executable, "version" if tool == "azd" else "--version"])
            if pins["tools"][tool]["version"] not in version.split():
                # Bicep prints 0.48.1 followed by a commit suffix.
                if tool != "bicep" or "version 0.48.1 " not in version:
                    raise Blocked("pinned_" + tool + "_required")
        if self.native.az("version")["azure-cli"] != pins["tools"]["azure_cli"]["version"]:
            raise Blocked("pinned_azure_cli_required")
        engine = self.native.run(["docker", "info", "--format", "{{.OSType}}/{{.Architecture}}"])
        if engine.strip() not in ("linux/x86_64", "linux/amd64"):
            raise Blocked("linux_amd64_docker_required")
        compiled = json.loads(self.native.run(
            [tools.get("bicep", "bicep"), "build", str(ROOT / "infra/main.bicep"), "--stdout"]))
        write_private(self.state.directory / "template.json", compiled)
        self.state.save()
        return {"status": "local_pass", "complete": data.fixture_gate()["complete_count"],
                "bundle": fingerprint, "cloud": "unverified"}

    def owned_groups(self):
        groups = self.native.az("group", "list", "--subscription", self.config["subscriptionId"])
        selected = []
        for group in groups:
            managed = self.value.get("managedGroups", {}).get(group["name"])
            if group["name"] in self.groups.values() or managed:
                if ((managed and group.get("managedBy", "").lower() != managed.lower())
                        or (not managed and group.get("tags", {}).get("citadel-deployment") != self.id)):
                    raise Blocked("resource_group_ownership_conflict")
                expected = self.subscription + "/resourceGroups/" + group["name"]
                if group["id"].lower() != expected.lower():
                    raise Blocked("resource_group_target_conflict")
                selected.append(group)
        return selected

    def credentials(self):
        path = self.state.directory / "credentials.json"
        if path.exists():
            return read_private(path)
        if self.value.get("foundation_started"):
            raise Blocked("existing_identity_credentials_missing")
        from .rotation import certificate
        callers = ["operator", *(w["name"] for w in WORKLOADS if w["operations"])]
        result = {
            "callerKeys": {c: {"primary": secrets.token_urlsafe(32), "secondary": secrets.token_urlsafe(32)}
                           for c in callers},
            "callerStates": dict.fromkeys(callers, "active"),
            "contextKeys": {w["name"]: {"activeId": "v1", "keys": {"v1": secrets.token_urlsafe(32)}}
                            for w in WORKLOADS},
            **certificate(self.id),
        }
        write_private(path, result)
        return result

    def parameters(self, runtime=False):
        result = {key: self.config[key] for key in ("deploymentId", "location", "publisherEmail",
                  "createResourceGroups", "collectorPrincipalIds", "modelCapacity")}
        result.update(self.credentials())
        result["deployRuntime"] = runtime
        result["applications"] = self.value.get("applications", {}) if runtime else {}
        validate_deployment_inputs(result)
        return result

    def arm(self, action, *, runtime=False):
        if runtime:
            self.require_plan_observation()
        parameters = {"parameters": {key: {"value": value} for key, value in self.parameters(runtime).items()}}
        with self.native.document(parameters) as path:
            result = self.native.az(
                "deployment", "sub", action, "--subscription", self.config["subscriptionId"],
                "--name", "citadel-" + self.id, "--location", self.config["location"],
                "--template-file", str(self.state.directory / "template.json"),
                "--parameters", "@" + path,
                *(["--validation-level", "Provider"] if action == "validate" else []), timeout=7200)
        if not isinstance(result, dict) or result.get("properties", {}).get("provisioningState") != "Succeeded":
            raise Blocked("arm_deployment_not_succeeded")
        return result

    def preflight(self):
        self.check()
        account = self.native.az("account", "show", "--subscription", self.config["subscriptionId"])
        if (account["id"] != self.config["subscriptionId"] or account["tenantId"] != self.config["tenantId"]
                or account["state"] != "Enabled"):
            raise Blocked("explicit_target_not_enabled_or_mismatched")
        existing = self.owned_groups()
        if existing and not self.value.get("foundation_started") and self.config["createResourceGroups"]:
            raise Blocked("unrecorded_existing_deployment")
        if not self.config["createResourceGroups"] and sum(g["name"] in self.groups.values() for g in existing) != 4:
            raise Blocked("four_owned_precreated_groups_required")
        if existing:
            self.inventory()
        providers = self.native.az("provider", "list", "--subscription", self.config["subscriptionId"])
        registered = {p["namespace"].lower() for p in providers if p["registrationState"] == "Registered"}
        if {name.lower() for name in PROVIDERS} - registered:
            raise Blocked("required_provider_registration_missing")
        subscription_permissions = self.native.collection(
            self.subscription + "/providers/Microsoft.Authorization/permissions", "2022-04-01")
        actions = ["Microsoft.Resources/deployments/write", "Microsoft.Resources/deployments/validate/action"]
        if self.config["createResourceGroups"]:
            actions.append("Microsoft.Resources/subscriptions/resourceGroups/write")
        if any(not permits(subscription_permissions, a) for a in actions):
            raise Blocked("subscription_deployment_permissions_missing")
        for group in self.groups.values():
            scope = self.subscription + "/resourceGroups/" + group
            permissions = (self.native.collection(scope + "/providers/Microsoft.Authorization/permissions",
                                                  "2022-04-01")
                           if any(g["name"] == group for g in existing) else subscription_permissions)
            required = ("Microsoft.Authorization/roleAssignments/write",
                        "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action",
                        "Microsoft.Resources/deployments/write",
                        "Microsoft.Storage/storageAccounts/write",
                        "Microsoft.KeyVault/vaults/write")
            if any(not permits(permissions, a) for a in required):
                raise Blocked("scoped_deployment_role_or_identity_permissions_missing")
            if group != self.groups["platform"] and any(not permits(permissions, a, data=True) for a in DATA_ACTIONS):
                raise Blocked("operator_scoped_blob_bootstrap_permissions_missing")
            if group == self.groups["platform"] and any(not permits(permissions, a) for a in (
                    "Microsoft.ContainerRegistry/registries/push/write",
                    "Microsoft.OperationalInsights/workspaces/query/read")):
                raise Blocked("operator_registry_push_or_telemetry_permissions_missing")
        policies = self.native.az("policy", "assignment", "list", "--scope", self.subscription,
                                  "--disable-scope-strict-match")
        region = self.subscription + "/providers/Microsoft.CognitiveServices/locations/westeurope"
        models = self.native.collection(region + "/models", "2024-10-01")
        try:
            candidates, sku = regional_standard_sku(models)
        except ValueError:
            raise Blocked("pinned_regional_standard_model_unavailable") from None
        limits = [r for r in sku.get("rateLimits", []) if r.get("key") == "token"]
        if len(limits) != 1 or not limits[0].get("renewalPeriod"):
            raise Blocked("independent_model_tpm_metadata_missing")
        verified_tpm = int(limits[0]["count"] * 60 / limits[0]["renewalPeriod"]) * self.config["modelCapacity"]
        if not self.config["modelTokensPerMinute"] <= verified_tpm <= 120000:
            raise Blocked("configured_tpm_not_independently_verified")
        usages = self.native.collection(region + "/usages", "2024-10-01")
        usage_name = sku.get("usageName")
        if not isinstance(usage_name, str) or not usage_name:
            raise Blocked("regional_model_quota_metadata_missing")
        usage = [u for u in usages if u.get("name", {}).get("value", "").lower() == usage_name.lower()]
        existing_capacity = 0
        model_ids = [r for r in self.value["inventory"]
                     if "/Microsoft.CognitiveServices/accounts/" in r and "/deployments/" in r]
        if model_ids:
            deployed = self.native.rest("get", model_ids[0], "2024-10-01")
            if (deployed["properties"]["model"]["name"] != "gpt-4.1-mini"
                    or deployed["properties"]["model"]["version"] != "2025-04-14"
                    or deployed["sku"]["name"] != "Standard"):
                raise Blocked("existing_model_configuration_conflict")
            existing_capacity = deployed["sku"]["capacity"]
        if len(usage) != 1 or usage[0]["limit"] - usage[0]["currentValue"] + existing_capacity < self.config["modelCapacity"]:
            raise Blocked("regional_model_quota_insufficient")
        self.arm("validate")
        self.value["preflight"] = {"time": now().isoformat(), "policyFingerprint": digest(policies),
                                   "modelMetadataFingerprint": digest(candidates),
                                   "verifiedTokensPerMinute": verified_tpm}
        self.state.event("preflight", "passed_not_live_acceptance")
        return {"status": "preflight_pass", "liveAcceptance": "unverified"}

    def capture_outputs(self, result):
        outputs = result["properties"].get("outputs", {})
        for required in ("inventory", "teamInventory", "appInventory", "gatewayUrl"):
            if required not in outputs:
                raise Blocked("deployment_inventory_outputs_missing")
        resolved = {k: v["value"] for k, v in outputs.items()}
        if resolved["inventory"]["deploymentId"] != self.id:
            raise Blocked("deployment_output_identity_conflict")
        self.value["outputs"] = resolved
        self.value["inventory"] = sorted(resource_ids(resolved) | set(self.value["inventory"]))
        self.state.save()

    def deploy(self, wheelhouse):
        self.preflight()
        self.value["foundation_started"] = True
        self.state.event("foundation", "started")
        if "outputs" in self.value:
            self.inventory()
        self.capture_outputs(self.arm("create"))
        self.value["phase"] = "foundation_pending_runtime"
        self.state.save()
        self.verify_vault_configuration()
        self.require_plan_observation()
        self.bootstrap()
        self.build(wheelhouse)
        self.arm("validate", runtime=True)
        self.capture_outputs(self.arm("create", runtime=True))
        self.value["phase"] = "deployed_unverified"
        self.state.save()
        self.verify_inventory()
        self.state.event("deploy", "deployed_unverified")
        return {"status": "deployed_unverified", "deploymentId": self.id,
                "foundationIsReadiness": False, "acceptance": "blocked_task20_and_live_proof"}

    def verify_vault_configuration(self):
        vaults = [rid for rid in self.value["inventory"]
                  if "/providers/Microsoft.KeyVault/vaults/" in rid
                  and "/" not in rid.split("/providers/Microsoft.KeyVault/vaults/", 1)[1]]
        if len(vaults) != 4:
            raise Blocked("four_owned_vaults_required")
        for rid in vaults:
            properties = self.native.rest("get", rid, "2023-07-01")["properties"]
            if (properties.get("enableRbacAuthorization") is not True
                    or properties.get("enableSoftDelete") is not True
                    or type(properties.get("softDeleteRetentionInDays")) is not int
                    or properties["softDeleteRetentionInDays"] != 7
                    or properties.get("enablePurgeProtection", False) is not False):
                raise Blocked("vault_retention_or_authorization_conflict")

    def bootstrap(self):
        outputs = self.value["outputs"]
        for item in outputs["teamInventory"]:
            team = item["resources"]["team"]
            storage = [r for r in item["resources"]["resources"]
                       if "/providers/Microsoft.Storage/storageAccounts/" in r and "/blobServices/" not in r]
            if len(storage) != 1:
                raise Blocked("allocated_storage_inventory_missing")
            account = "https://" + storage[0].split("/")[-1] + ".blob.core.windows.net"
            objects = {}
            if team == "reference":
                for name in sorted(ARTIFACT_NAMES | {"bundle-manifest.json"}):
                    objects[("reference", name)] = (Path(self.config["bundleDir"]) / name).read_bytes()
            else:
                containers = (["drafts", "findings", "assessor-operations", "reviewer-operations"]
                              if team == "evidence" else ["planner-operations", "author-operations"])
                objects = {(c, "ledger-v1.json"): canonical_bytes(empty_ledger()) for c in containers}
                if team == "planning":
                    objects[("planner-operations", "active-run-slot.json")] = b"{}"
            for (container, name), content in objects.items():
                key = team + "/" + container + "/" + name
                recorded = self.value["bootstrap"].get(key)
                current = self.native.blob_read(account, container, name)
                if current is None:
                    if recorded:
                        raise Blocked("existing_identity_bootstrap_state_missing")
                    # Persist intent before PUT; response loss can only reconcile, not overwrite.
                    self.value["bootstrap"][key] = "creating"
                    self.state.save()
                    self.native.blob_create(account, container, name, content)
                    current = self.native.blob_read(account, container, name)
                if team == "reference" or recorded in (None, "creating"):
                    if current != content:
                        raise Blocked("bootstrap_immutable_content_conflict")
                else:
                    value = json.loads(current)
                    if name == "ledger-v1.json" and (
                            type(value.get("schema_version")) is not int or value["schema_version"] != 1 or
                            not all(isinstance(value.get(k), dict) for k in empty_ledger() if k != "schema_version")):
                        raise Blocked("existing_ledger_invalid")
                    if name == "active-run-slot.json" and value != {}:
                        raise Blocked("admission_blob_invalid")
                self.value["bootstrap"][key] = "verified"
                self.state.save()

    def registry(self):
        registry = [r for r in self.value["outputs"]["inventory"]["platform"]["resources"]
                    if "/providers/Microsoft.ContainerRegistry/registries/" in r]
        if len(registry) != 1:
            raise Blocked("created_registry_missing")
        return registry[0].split("/")[-1]

    def build(self, wheelhouse):
        registry = self.registry()
        repository = "citadel/runtime"
        tag = self.value["software"][:24]
        reference = f"{registry}.azurecr.io/{repository}:{tag}"
        if "applications" in self.value:
            actual = self.native.az("acr", "repository", "show", "--name", registry,
                                    "--image", repository + ":" + tag,
                                    "--subscription", self.config["subscriptionId"])
            expected = next(iter(self.value["applications"].values()))["image"]
            if expected != f"{registry}.azurecr.io/{repository}@{actual['digest']}":
                raise Blocked("registry_digest_conflict")
            self.lock_image(registry, repository, actual["digest"])
            return
        repositories = self.native.az("acr", "repository", "list", "--name", registry,
                                       "--subscription", self.config["subscriptionId"])
        if repository in repositories:
            tags = self.native.az("acr", "repository", "show-tags", "--name", registry,
                                   "--repository", repository, "--subscription", self.config["subscriptionId"])
            if tag in tags:
                intent = self.value.get("pushIntent")
                if not isinstance(intent, dict) or intent.get("reference") != reference:
                    raise Blocked("unrecorded_registry_tag_conflict")
                actual = self.native.az("acr", "repository", "show", "--name", registry,
                                        "--image", repository + ":" + tag,
                                        "--subscription", self.config["subscriptionId"])
                local_id = self.native.run(["docker", "image", "inspect", "--format", "{{.Id}}", reference]).strip()
                if local_id != intent["localId"]:
                    raise Blocked("ambiguous_push_local_image_conflict")
                self.adopt_image(registry, repository, reference, actual["digest"])
                return
        if self.value.get("pushIntent"):
            raise Blocked("previous_registry_push_requires_explicit_reconciliation")
        build_args = ["docker", "build", "--platform", "linux/amd64", "--tag", reference]
        if wheelhouse:
            path = Path(wheelhouse).resolve(strict=True)
            build_args += ["--network=none", "--build-context", "wheelhouse=" + str(path),
                           "--build-arg", "OFFLINE=true"]
        self.native.run([*build_args, "."], timeout=1800)
        self.native.run(["docker", "run", "--rm", "--network", "none", "--read-only",
                         "--cap-drop", "ALL", "--security-opt", "no-new-privileges", reference],
                        timeout=300)
        login = self.native.az("acr", "login", "--name", registry, "--expose-token",
                               "--subscription", self.config["subscriptionId"])
        docker_config = self.state.directory / "docker"
        docker_config.mkdir(mode=0o700, exist_ok=True)
        try:
            self.native.run(["docker", "--config", str(docker_config), "login",
                             registry + ".azurecr.io", "--username",
                             "00000000-0000-0000-0000-000000000000", "--password-stdin"],
                            data=login["accessToken"].encode())
            local_id = self.native.run(["docker", "image", "inspect", "--format", "{{.Id}}", reference]).strip()
            self.value["pushIntent"] = {"reference": reference, "localId": local_id}
            self.state.save()
            self.native.run(["docker", "--config", str(docker_config), "push", reference], timeout=1800)
        finally:
            (docker_config / "config.json").unlink(missing_ok=True)
            docker_config.rmdir()
        actual = self.native.az("acr", "repository", "show", "--name", registry,
                                "--image", repository + ":" + tag,
                                "--subscription", self.config["subscriptionId"])
        self.adopt_image(registry, repository, reference, actual["digest"])

    def adopt_image(self, registry, repository, reference, image_digest):
        image = f"{registry}.azurecr.io/{repository}@{image_digest}"
        published = json.loads(self.native.run(["docker", "image", "inspect",
                              "--format", "{{json .RepoDigests}}", reference]))
        if image not in published:
            raise Blocked("pushed_digest_not_verified_against_local_image")
        self.value["applications"] = {w["name"]: {"image": image,
            "command": ["python", "-m", "citadel.runtime"], "args": [],
            "modelTokensPerMinute": self.config["modelTokensPerMinute"]} for w in WORKLOADS}
        self.parameters(runtime=True)
        self.lock_image(registry, repository, image_digest)
        self.state.save()

    def lock_image(self, registry, repository, image_digest):
        locked = self.native.az("acr", "repository", "update", "--name", registry,
                       "--image", repository + "@" + image_digest, "--write-enabled", "false",
                       "--delete-enabled", "false", "--subscription", self.config["subscriptionId"])
        if any(locked.get("changeableAttributes", {}).get(key) is not False
               for key in ("writeEnabled", "deleteEnabled")):
            raise Blocked("registry_immutability_not_verified")

    def inventory(self):
        groups = self.owned_groups()
        known = {r.lower() for r in self.value["inventory"]}
        for environment in [r for r in self.value["inventory"]
                            if "/providers/Microsoft.App/managedEnvironments/" in r
                            and r.count("/") == 8]:
            if not any(environment.lower().startswith(g["id"].lower() + "/") for g in groups):
                continue
            details = self.native.rest("get", environment, "2025-01-01")
            managed_name = details.get("properties", {}).get("infrastructureResourceGroup")
            if managed_name and managed_name not in self.value.get("managedGroups", {}):
                managed = self.native.az("group", "show", "--name", managed_name,
                                         "--subscription", self.config["subscriptionId"])
                if managed.get("managedBy", "").lower() != environment.lower():
                    raise Blocked("managed_group_ownership_not_proven")
                self.value.setdefault("managedGroups", {})[managed_name] = environment
                # The provider's explicit managedBy relationship establishes this
                # first inventory. Subsequent new/foreign resources fail closed.
                resources = self.native.az("resource", "list", "--resource-group", managed_name,
                                           "--subscription", self.config["subscriptionId"])
                if any(r.get("tags", {}).get("citadel-deployment", self.id) != self.id for r in resources):
                    raise Blocked("unrelated_managed_resource_protection")
                known.update(r["id"].lower() for r in resources)
                self.value["inventory"] += [r["id"] for r in resources]
                groups.append(managed)
        active = []
        for group in groups:
            resources = self.native.az("resource", "list", "--resource-group", group["name"],
                                       "--subscription", self.config["subscriptionId"])
            components = {r["id"].lower() for r in resources
                          if r.get("type", "").lower() == "microsoft.insights/components"
                          and r.get("tags", {}).get("citadel-deployment") == self.id
                          and r["id"].lower().startswith(group["id"].lower() + "/")}
            for resource in resources:
                rid = resource["id"]
                owned = (resource.get("tags", {}).get("citadel-deployment") == self.id or rid.lower() in known
                         or any(rid.lower().startswith(parent + "/") for parent in known if "/providers/" in parent))
                if resource.get("type", "").lower() == "microsoft.alertsmanagement/smartdetectoralertrules":
                    alert = self.native.rest("get", rid, "2021-04-01")
                    properties = alert.get("properties", {})
                    scopes = properties.get("scope", [])
                    if (alert.get("id", "").lower() != rid.lower()
                            or len(scopes) != 1 or scopes[0].lower() not in components
                            or properties.get("detector", {}).get("id") != "FailureAnomaliesDetector"):
                        raise Blocked("provider_created_alert_ownership_conflict")
                    self.value.setdefault("providerCreatedResources", {})[rid] = {
                        "parent": scopes[0], "api": "2021-04-01"}
                    owned = True
                if not owned or not rid.lower().startswith(group["id"].lower() + "/"):
                    raise Blocked("unrelated_resource_protection")
                active.append(rid)
            assignments = self.native.az("role", "assignment", "list", "--scope", group["id"],
                                          "--subscription", self.config["subscriptionId"])
            for assignment in assignments:
                scope = assignment.get("scope", assignment.get("properties", {}).get("scope", ""))
                if scope.lower().startswith(group["id"].lower()):
                    if assignment["id"].lower() not in known:
                        raise Blocked("unrelated_role_assignment_protection")
                    active.append(assignment["id"])
            active.append(group["id"])
        self.value["active"] = sorted(active)
        self.value["inventory"] = sorted(set(self.value["inventory"]) | set(active))
        self.state.save()
        return {"status": "inventory", "activeCount": len(active),
                "ageWarning24h": (now() - datetime.fromisoformat(self.value["created"])).total_seconds() >= 86400,
                "automaticDeletion": False, "monetaryCeiling": None}

    def require_plan_observation(self):
        from .plan import require_observation
        return require_observation(self)

    def verify_inventory(self):
        self.inventory()
        self.verify_vault_configuration()
        capabilities = self.value["outputs"]["inventory"]["capabilities"]
        center = self.native.rest("get", capabilities["service"], "2024-03-01")
        if center.get("properties", {}).get("provisioningState") != "Succeeded":
            raise Blocked("api_center_provider_not_succeeded")
        environments = self.native.collection(capabilities["workspace"] + "/environments", "2024-03-01")
        if {e["name"] for e in environments} != {w["name"] for w in WORKLOADS}:
            raise Blocked("api_center_environment_inventory_mismatch")
        apps = {a["app"].split("/")[-1].removeprefix(self.id + "-"): a
                for a in self.value["outputs"]["appInventory"]}
        if len({app["identity"] for app in apps.values()}) != 5:
            raise Blocked("distinct_workload_identities_required")
        teams = {"reference": "Reference Data", "evidence": "Evidence Review", "planning": "Exercise Planning"}
        observed_apps = {}
        for record in environments:
            properties = record["properties"]["customProperties"]
            app = apps[record["name"]]
            workload = next(w for w in WORKLOADS if w["name"] == record["name"])
            reference = workload["name"] == "reference-data"
            expected = {"workload": app["app"], "identity-resource-id": app["identity"],
                        "identity-kind": "Azure user-assigned managed identity; not Entra Agent ID",
                        "team": teams[workload["team"]], "protocol": "MCP" if reference else "A2A",
                        "protocol-version": "2025-11-25" if reference else "1.0.0",
                        "gateway-address": self.value["outputs"]["gatewayUrl"] + "/" + workload["name"] +
                                           ("/mcp" if reference else "/a2a")}
            if (properties != expected or record["properties"].get("kind") != "testing"
                    or record["properties"].get("server", {}).get("type") != "Azure compute service"):
                raise Blocked("api_center_identity_or_gateway_metadata_mismatch")
            deployed = self.native.rest("get", app["app"], "2025-01-01")
            observed_apps[record["name"]] = deployed
            containers = deployed["properties"]["template"]["containers"]
            environment = {e["name"]: e.get("value") for e in containers[0]["env"]}
            if (deployed["properties"]["provisioningState"] != "Succeeded"
                    or set(deployed["identity"]["userAssignedIdentities"]) != {app["identity"]}
                    or len(containers) != 1 or containers[0]["image"] != app["image"]
                    or containers[0].get("command") != ["python", "-m", "citadel.runtime"]
                    or containers[0].get("args") != []
                    or environment.get("CITADEL_TARGET") != workload["name"]
                    or environment.get("CITADEL_MODEL_TOKENS_PER_MINUTE") != str(self.config["modelTokensPerMinute"])):
                raise Blocked("deployed_workload_identity_image_mismatch")
        finding = self.native.rest("get", capabilities["restCapabilities"][0], "2024-03-01")
        if finding["properties"]["kind"] != "rest":
            raise Blocked("truthful_findings_rest_inventory_missing")
        deployment = self.native.rest("get", capabilities["restCapabilities"][1], "2024-03-01")
        if (deployment["properties"]["environmentId"] != "/workspaces/default/environments/release-reviewer"
                or deployment["properties"]["server"]["runtimeUri"] !=
                [self.value["outputs"]["gatewayUrl"] + "/release-reviewer"]):
            raise Blocked("findings_host_environment_mismatch")
        self.value["inventoryMetadataVerified"] = True
        self.state.save()
        plan = self.require_plan_observation()
        return {"center": center, "environments": environments, "applications": observed_apps,
                "finding": finding, "deployment": deployment, "plan": plan}

    def collect(self):
        deadline = time.monotonic() + 600
        previous = getattr(self.native, "deadline", None)
        self.native.deadline = min(previous, deadline) if previous is not None else deadline
        try:
            return self.collect_with_deadline(self.native.deadline)
        finally:
            self.native.deadline = previous

    def collect_with_deadline(self, deadline):
        from .plan import observation_summary
        self.inventory()
        plan = observation_summary(self)
        telemetry = []
        workspaces = [r for r in self.value["inventory"] if "/Microsoft.OperationalInsights/workspaces/" in r
                      and "/tables/" not in r]
        for workspace in workspaces:
            if not any(workspace.lower().startswith(r.lower() + "/") for r in self.value["active"]
                       if "/providers/" not in r):
                continue
            details = self.native.rest("get", workspace, "2022-10-01")
            telemetry.append(self.native.telemetry(details["properties"]["customerId"],
                since=self.value["created"], timeout=max(1, deadline - time.monotonic())))
        if self.value.get("outputs") and not workspaces:
            raise Blocked("allocated_telemetry_workspace_missing")
        report = {"schema_version": 1, "deploymentId": self.id, "software": self.value["software"],
                  "configurationFingerprint": digest(self.config),
                  "bundle": self.value.get("bundle"), "phase": self.value["phase"],
                  "events": self.value["events"], "activeCount": len(self.value["active"]),
                  "runs": self.value["runs"],
                  "configuredImages": sorted({app["image"] for app in self.value.get("applications", {}).values()}),
                  "bootstrapVerifiedCount": sum(v == "verified" for v in self.value["bootstrap"].values()),
                  "apiCenterPlan": plan,
                  "acceptance": "blocked", "required": ["task20_harness", "live_correlation",
                      "rotation_proof", "operator_prose_signoff", "two_consecutive_passes",
                      "fresh_deployment", "manual_teardown"],
                  "costInputs": ["APIM BasicV2", "ACR Basic and image operations",
                      "five warm 0.5vCPU/1GiB apps and rolling revisions", "regional Standard model tokens",
                      "storage and vault operations", "unsampled ingestion and retention",
                      "all acceptance/failed runs and probes", "residual/delayed charges"],
                  "monetaryCeiling": None, "automaticDeletion": False}
        report["telemetry"] = telemetry
        report = public_output(report, self.config, self.credentials() if self.value.get("outputs") else None)
        path = self.state.directory / "evidence.json"
        if path.exists():
            previous = read_private(path)
            archive = self.state.directory / ("evidence-" + digest(previous) + ".json")
            if not archive.exists():
                write_private(archive, previous)
            report["previousEvidence"] = archive.name
        write_private(path, report)
        summary = (f"# Citadel lifecycle evidence — {self.id}\n\n"
                   f"Schema: 1. Software: `{report['software']}`.\n\n"
                   f"Phase: `{report['phase']}`. Active resources: {report['activeCount']}. "
                   f"Recorded runs: {len(report['runs'])}.\n\n"
                   "**Acceptance: blocked.** Lifecycle export is not live authorization, "
                   "model inference, correlation, rotation or prose-signoff proof. "
                   "The separately recorded human portal observation is not automated plan verification. "
                   "See evidence.json and retained prior exports for measured data and remaining gates.\n\n"
                   "No monetary ceiling. Review all warm/model/telemetry/probe/failed-run and residual costs. "
                   "Teardown is manual; deletion does not establish immediate erasure.\n")
        write_private_bytes(self.state.directory / "evidence.md", summary.encode())
        self.value["evidenceExport"] = {"time": now().isoformat(), "sha256": digest(report)}
        self.state.save()
        return {"status": "partial_evidence", "acceptance": "blocked", "localFile": "evidence.json"}

    def teardown(self, confirmation):
        if confirmation != self.id:
            raise Blocked("manual_exact_deployment_confirmation_required")
        # Export before deleting any source. The harness must separately export
        # actual correlation evidence; a lifecycle inventory is not that proof.
        self.collect()
        failed, deleted = [], []
        targets = [(team, self.groups[team]) for team in ("planning", "evidence", "reference", "platform")]
        targets += [(name, name) for name in self.value.get("managedGroups", {})]
        for team, name in targets:
            try:
                self.inventory()
                groups = self.owned_groups()
                group = next((g for g in groups if g["name"] == name), None)
                if group is None:
                    continue
                self.native.az("group", "delete", "--name", group["name"], "--yes",
                               "--subscription", self.config["subscriptionId"], timeout=7200)
                if any(g["name"] == group["name"] for g in self.owned_groups()):
                    raise Blocked("deletion_not_verified")
                deleted.append(team)
            except Blocked:
                failed.append(team)
        self.inventory()
        if not failed and not self.value["active"] and self.value.get("foundation_started"):
            selector = "[?name=='citadel-" + self.id + "']"
            records = self.native.az("deployment", "sub", "list", "--subscription",
                                     self.config["subscriptionId"], "--query", selector)
            for record in records:
                if record.get("properties", {}).get("parameters", {}).get("deploymentId", {}).get("value") != self.id:
                    raise Blocked("subscription_deployment_record_ownership_conflict")
                self.native.az("deployment", "sub", "delete", "--name", "citadel-" + self.id,
                               "--subscription", self.config["subscriptionId"])
            if self.native.az("deployment", "sub", "list", "--subscription",
                              self.config["subscriptionId"], "--query", selector):
                failed.append("subscription-deployment-record")
        vaults = self.native.az("keyvault", "list-deleted", "--subscription", self.config["subscriptionId"])
        owned_names = {r.split("/")[-1] for r in self.value["inventory"]
                       if "/providers/Microsoft.KeyVault/vaults/" in r and "/secrets/" not in r}
        owned_vaults = {r.lower() for r in self.value["inventory"]
                        if "/providers/Microsoft.KeyVault/vaults/" in r and "/secrets/" not in r}
        recoverable = [{"kind": "vault", "name": v["name"]} for v in vaults
                       if v["name"] in owned_names and v.get("properties", {}).get("vaultId", "").lower() in owned_vaults]
        workspaces = [r for r in self.value["inventory"] if "/Microsoft.OperationalInsights/workspaces/" in r
                      and "/tables/" not in r]
        deleted_workspaces = self.native.az("monitor", "log-analytics", "workspace", "list-deleted-workspaces",
                                            "--subscription", self.config["subscriptionId"])
        recoverable += [{"kind": "workspace", "name": w["name"]}
                        for w in deleted_workspaces if w["id"].lower() in {r.lower() for r in workspaces}]
        self.value["residue"] = {"activeCount": len(self.value["active"]), "failedDeletions": failed,
                                 "recoverable": recoverable, "deletedTeams": deleted}
        self.value["phase"] = "teardown_partial" if failed or self.value["active"] else "deleted_recoverable"
        self.state.event("teardown", self.value["phase"])
        return {"status": self.value["phase"], **self.value["residue"], "immediateErasure": False}
