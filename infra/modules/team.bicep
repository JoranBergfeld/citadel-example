param deploymentId string
param location string
param suffix string
@allowed(['reference', 'evidence', 'planning'])
param team string
param workloads array
param workspaceId string
@secure()
param callerKeys object
@secure()
param contextKeys object

var tags = { 'citadel-deployment': deploymentId, 'citadel-team': team }
var containersByTeam = {
  reference: ['reference']
  evidence: ['drafts', 'findings', 'assessor-operations', 'reviewer-operations']
  planning: ['candidate-lists', 'briefs', 'planner-operations', 'author-operations']
}
var grantsByTeam = {
  reference: [
    { actor: 'reference-data', container: 'reference', role: 'reader' }
  ]
  evidence: [
    { actor: 'evidence-assessor', container: 'drafts', role: 'contributor' }
    { actor: 'release-reviewer', container: 'drafts', role: 'reader' }
    { actor: 'release-reviewer', container: 'findings', role: 'contributor' }
    { actor: 'evidence-assessor', container: 'assessor-operations', role: 'contributor' }
    { actor: 'release-reviewer', container: 'reviewer-operations', role: 'contributor' }
  ]
  planning: [
    { actor: 'candidate-planner', container: 'candidate-lists', role: 'contributor' }
    { actor: 'briefing-author', container: 'briefs', role: 'contributor' }
    { actor: 'candidate-planner', container: 'planner-operations', role: 'contributor' }
    { actor: 'briefing-author', container: 'author-operations', role: 'contributor' }
  ]
}
resource identities 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = [for workload in workloads: {
  name: '${deploymentId}-${workload.name}'
  location: location
  tags: tags
}]
output observationPrincipalIds array = [for (w, i) in workloads: identities[i].properties.principalId]
resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: '${team}${suffix}'
  location: location
  tags: tags
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {
    publicNetworkAccess: 'Enabled'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    defaultToOAuthAuthentication: true
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
  }
}
resource blobs 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storage
  name: 'default'
  properties: {
    isVersioningEnabled: false
    deleteRetentionPolicy: { enabled: false }
    containerDeleteRetentionPolicy: { enabled: false }
  }
}
resource containers 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = [for container in containersByTeam[team]: {
  parent: blobs
  name: container
  properties: { publicAccess: 'None' }
}]
module dataRoles 'container-role.bicep' = [for grant in grantsByTeam[team]: {
  name: 'data-${grant.actor}-${grant.container}'
  params: {
    storageName: storage.name
    containerName: grant.container
    identityName: '${deploymentId}-${grant.actor}'
    role: grant.role
  }
  dependsOn: [identities, containers]
}]
resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: '${team}${suffix}'
  location: location
  tags: tags
  properties: {
    tenantId: tenant().tenantId
    sku: { family: 'A', name: 'standard' }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    accessPolicies: []
  }
}
resource contextSecrets 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = [for workload in workloads: {
  parent: vault
  name: 'context-${workload.name}'
  properties: { value: string(contextKeys[workload.name].keys) }
}]
resource contextReaders 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for (workload, i) in workloads: {
  scope: contextSecrets[i]
  name: guid(contextSecrets[i].id, identities[i].id, 'secret-reader')
  properties: {
    principalId: identities[i].properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
  }
}]
var agents = filter(workloads, w => w.name != 'reference-data')
module subscriptions 'caller-secret.bicep' = [for agent in agents: {
  name: 'credential-${agent.name}'
  params: {
    vaultName: vault.name
    identityName: '${deploymentId}-${agent.name}'
    caller: agent.name
    credential: callerKeys[agent.name].primary
  }
  dependsOn: [identities]
}]
resource blobDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: blobs
  name: 'citadel-logs'
  properties: {
    workspaceId: workspaceId
    logAnalyticsDestinationType: 'Dedicated'
    logs: [
      { category: 'StorageRead', enabled: true }
      { category: 'StorageWrite', enabled: true }
      { category: 'StorageDelete', enabled: true }
    ]
  }
}
resource vaultDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: vault
  name: 'citadel-logs'
  properties: {
    workspaceId: workspaceId
    logAnalyticsDestinationType: 'Dedicated'
    logs: [{ category: 'AuditEvent', enabled: true }]
  }
}
var identityInventory = [for (w, i) in workloads: identities[i].id]
var containerInventory = [for (c, i) in containersByTeam[team]: containers[i].id]
var contextInventory = [for (w, i) in workloads: contextSecrets[i].id]
// The pinned compiler loses the scope's named copy index through an extension resource's .id.
var readerInventory = [for (w, i) in workloads: extensionResourceId(contextSecrets[i].id, 'Microsoft.Authorization/roleAssignments', contextReaders[i].name)]
output roleInventory array = [for (g, i) in grantsByTeam[team]: dataRoles[i].outputs.assignmentId]
output credentialInventory array = [for (a, i) in agents: subscriptions[i].outputs.inventory]
output inventory object = {
  team: team
  resources: concat([storage.id, blobs.id, vault.id], identityInventory, containerInventory)
  contextSecrets: contextInventory
  contextReaders: readerInventory
  diagnostics: [blobDiagnostics.id, vaultDiagnostics.id]
}
