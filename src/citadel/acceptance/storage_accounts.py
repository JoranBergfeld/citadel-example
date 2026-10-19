"""Fixed container ownership resolved from the exact deployed resource inventory."""

from citadel.operator.state import Blocked
from citadel.runtime.configuration import endpoint


TEAM_CONTAINERS = {
    "reference": ("reference",),
    "evidence": ("drafts", "findings", "assessor-operations", "reviewer-operations"),
    "planning": ("candidate-lists", "briefs", "planner-operations", "author-operations"),
}
CONTAINER_TEAMS = {container: team for team, containers in TEAM_CONTAINERS.items()
                   for container in containers}


def storage_accounts(lifecycle):
    inventory = lifecycle.value["inventory"]
    accounts, owners = {}, {}
    for container, team in CONTAINER_TEAMS.items():
        suffix = "/blobServices/default/containers/" + container
        matches = [resource.removesuffix(suffix) for resource in inventory
                   if "/providers/Microsoft.Storage/storageAccounts/" in resource and resource.endswith(suffix)]
        if len(matches) != 1 or matches[0] not in inventory:
            raise Blocked("exact_owned_container_storage_inventory_required")
        owner = matches[0]
        if team in owners and owners[team] != owner:
            raise Blocked("team_container_storage_inventory_conflict")
        owners[team] = owner
        accounts[container] = endpoint("https://" + owner.rsplit("/", 1)[-1]
                                       + ".blob.core.windows.net", ".blob.core.windows.net")
    if len(set(owners.values())) != len(TEAM_CONTAINERS):
        raise Blocked("distinct_team_storage_inventory_required")
    return accounts


def validate_accounts(accounts):
    if not isinstance(accounts, dict) or set(accounts) != set(CONTAINER_TEAMS):
        raise ValueError("Exact fixed-container storage allocation required")
    return {container: endpoint(account, ".blob.core.windows.net")
            for container, account in accounts.items()}


def probe_accounts(manifest, workload, own_account):
    from citadel.runtime.configuration import OPERATIONS
    accounts = validate_accounts(manifest["accounts"])
    own_container = "reference" if workload == "reference-data" else OPERATIONS[workload]
    own_team = CONTAINER_TEAMS[own_container]
    prefix = "https://" + own_team
    if accounts[own_container] != own_account or not own_account.startswith(prefix):
        raise ValueError("Probe storage allocation differs from its deployed team")
    suffix = own_account.removeprefix(prefix)
    if any(account != "https://" + CONTAINER_TEAMS[container] + suffix
           for container, account in accounts.items()):
        raise ValueError("Only the existing deployment's fixed team accounts may be probed")
    return accounts
