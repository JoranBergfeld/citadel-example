"""Private CLI administration. Never runs inside the hosted Operator process."""

import getpass
import sys
import time

from .state import Blocked, read_private, write_private
from .web import AuthConfig, hash_passphrase


def authentication(lifecycle):
    try:
        value = read_private(lifecycle.state.directory / "operator-web-auth.json")
        if not isinstance(value, dict) or set(value) != {"username", "passwordHash"}:
            raise ValueError
        AuthConfig(value["username"], value["passwordHash"], "https://configuration.invalid")
    except (OSError, KeyError, TypeError, ValueError):
        raise Blocked("private_operator_web_configuration_required") from None
    return value


def app_id(lifecycle):
    expected = lifecycle.subscription + "/resourceGroups/" + lifecycle.groups["platform"] + (
        "/providers/Microsoft.App/containerApps/" + lifecycle.id + "-operator-web")
    recorded = lifecycle.value.get("outputs", {}).get("operatorInventory", {}).get("application", {}).get("app")
    if recorded and (recorded.lower() != expected.lower() or recorded not in lifecycle.value["inventory"]):
        raise Blocked("operator_web_ownership_required")
    return recorded or (expected if expected in lifecycle.value["inventory"] else None)


def stop(lifecycle):
    resource = app_id(lifecycle)
    if not resource:
        return
    expected = lifecycle.subscription + "/resourceGroups/" + lifecycle.groups["platform"] + (
        "/providers/Microsoft.App/containerApps/" + lifecycle.id + "-operator-web")
    if resource.lower() != expected.lower() or resource not in lifecycle.value["inventory"]:
        raise Blocked("operator_web_ownership_required")
    lifecycle.inventory()
    observed = lifecycle.native.rest("get", resource, "2025-01-01")
    if (observed.get("tags") or {}).get("citadel-deployment") != lifecycle.id:
        raise Blocked("operator_web_ownership_required")
    lifecycle.native.rest("post", resource + "/stop", "2025-01-01")
    deadline = time.monotonic() + 120
    for _ in range(60):
        observed = lifecycle.native.rest("get", resource, "2025-01-01")
        if observed.get("properties", {}).get("runningStatus") == "Stopped":
            lifecycle.state.event("operator-web", "stopped_before_replacement")
            return
        if time.monotonic() >= deadline:
            break
        time.sleep(2)
    raise Blocked("operator_web_stop_not_confirmed")


def start(lifecycle):
    resource = app_id(lifecycle)
    if resource:
        lifecycle.native.rest("post", resource + "/start", "2025-01-01")
        lifecycle.state.event("operator-web", "start_requested")


def verify(lifecycle):
    resource = app_id(lifecycle)
    if not resource:
        raise Blocked("operator_web_inventory_required")
    inventory = lifecycle.value["outputs"]["operatorInventory"]
    identity = inventory["foundation"]["identity"]
    if identity in {a["identity"] for a in lifecycle.value["outputs"]["appInventory"]}:
        raise Blocked("operator_web_distinct_identity_required")
    document = lifecycle.native.rest("get", resource, "2025-01-01")
    properties = document["properties"]
    template = properties["template"]
    containers = template["containers"]
    configuration = properties["configuration"]
    ingress = configuration["ingress"]
    expected_environment = [
        {"name": "CITADEL_OPERATOR_USERNAME", "secretRef": "operator-username"},
        {"name": "CITADEL_OPERATOR_PASSWORD_HASH", "secretRef": "operator-password-hash"},
        {"name": "CITADEL_OPERATOR_ORIGIN", "value": inventory["origin"]},
    ]
    if "accounting" in inventory:
        expected_environment += [
            {"name": "AZURE_CLIENT_ID", "value": inventory["foundation"]["clientId"]},
            {"name": "CITADEL_DEPLOYMENT_ID", "value": lifecycle.id},
            {"name": "CITADEL_GATEWAY_URL", "value": lifecycle.value["outputs"]["gatewayUrl"]},
            {"name": "CITADEL_OBSERVATION_BLOB_URL", "value": inventory["accountingBlobUrl"]},
            {"name": "CITADEL_OPERATOR_SUBSCRIPTION", "secretRef": "operator-subscription"},
        ]
    if (properties.get("provisioningState") != "Succeeded"
            or (document.get("tags") or {}).get("citadel-deployment") != lifecycle.id
            or set(document["identity"]["userAssignedIdentities"]) != {identity}
            or configuration.get("activeRevisionsMode") != "Single"
            or ingress.get("allowInsecure") is not False or ingress.get("external") is not True
            or ingress.get("targetPort") != 8000
            or inventory["origin"] != "https://" + ingress.get("fqdn", "")
            or template.get("scale", {}).get("minReplicas") != 1
            or template.get("scale", {}).get("maxReplicas") != 1
            or template.get("volumes") or len(containers) != 1
            or containers[0].get("image") != inventory["application"]["image"]
            or containers[0].get("command") != ["python", "-m", "citadel.operator.web"]
            or containers[0].get("args", []) != [] or containers[0].get("volumeMounts")
            or sorted(containers[0].get("env", []), key=lambda e: e.get("name", "")) !=
               sorted(expected_environment, key=lambda e: e["name"])):
        raise Blocked("operator_web_deployment_contract_mismatch")
    return document


def configure(lifecycle, *, prompt=None):
    stop(lifecycle)
    # A rejected/interrupted replacement must not leave the old configuration deployable.
    (lifecycle.state.directory / "operator-web-auth.json").unlink(missing_ok=True)
    if prompt is None:
        if not sys.stdin.isatty():
            raise Blocked("private_interactive_terminal_required")
        prompt = getpass.getpass
    username = prompt("Operator username (hidden): ")
    phrase = prompt("Operator passphrase (15-128 characters; hidden): ")
    confirmation = prompt("Confirm passphrase (hidden): ")
    if phrase != confirmation:
        raise Blocked("operator_web_passphrase_confirmation_failed")
    try:
        encoded = hash_passphrase(phrase)
        AuthConfig(username, encoded, "https://configuration.invalid")
    except (TypeError, ValueError):
        raise Blocked("invalid_operator_web_credentials") from None
    write_private(lifecycle.state.directory / "operator-web-auth.json",
                  {"username": username, "passwordHash": encoded})
    lifecycle.state.event("configure-web-login", "configured_app_remains_stopped")
    return {"status": "configured", "nextStep": "Explicit deploy required; any existing app remains stopped."}
