"""Three-team storage allocation at the external ARM boundary."""


def storage_inventory(planning="allocated", evidence="evidencefixture", reference="referencefixture"):
    resources = []
    for account, containers in (
        (reference, ("reference",)),
        (evidence, ("drafts", "findings", "assessor-operations", "reviewer-operations")),
        (planning, ("candidate-lists", "briefs", "planner-operations", "author-operations")),
    ):
        resource = "/subscriptions/s/resourceGroups/g/providers/Microsoft.Storage/storageAccounts/" + account
        resources += [resource, *[resource + "/blobServices/default/containers/" + c for c in containers]]
    return resources


def storage_accounts():
    return {container: "https://" + team + "fixture.blob.core.windows.net"
            for team, containers in (
                ("reference", ("reference",)),
                ("evidence", ("drafts", "findings", "assessor-operations", "reviewer-operations")),
                ("planning", ("candidate-lists", "briefs", "planner-operations", "author-operations")))
            for container in containers}
