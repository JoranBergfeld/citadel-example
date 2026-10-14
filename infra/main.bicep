targetScope = 'subscription'

@minLength(3)
@maxLength(12)
@description('Stable lowercase alphanumeric deployment ID; never reuse for another deployment.')
param deploymentId string
@allowed(['westeurope'])
param location string = 'westeurope'
param publisherEmail string
@description('False uses the four exact existing deployment-owned groups; inventory ownership must be verified first.')
param createResourceGroups bool = true
@description('False provisions foundation only, before image build/push. True requires real digest-pinned images.')
param deployRuntime bool = true
@description('Five immutable ACR image references and actual command/args arrays, keyed by workload name.')
param applications object = {}
@secure()
@description('Four agents plus operator: {caller: {primary: value, secondary: value}}. Both keys rotate explicitly.')
param callerKeys object
param callerStates object = {
  operator: 'active'
  'candidate-planner': 'active'
  'evidence-assessor': 'active'
  'release-reviewer': 'active'
  'briefing-author': 'active'
}
@secure()
@description('Per-backend validation keys: {target: {activeId: string, keys: {id: secret}}}. Never share between targets.')
param contextKeys object
@secure()
@description('Deployment-specific exportable passwordless PKCS12, base64; externally verify exact 90-day validity.')
param gatewayCertificatePfx string
@description('Public allowlist [{sha256, not_before, not_after}]; include old/new only during explicit rotation.')
param gatewayCertificates array
@description('Explicit collector principal IDs; no automatic runtime telemetry-query grants.')
param collectorPrincipalIds array
@description('Model Standard capacity from validated quota; 120k TPM target is not a quota promise.')
@minValue(1)
@maxValue(120)
param modelCapacity int

var tags = { 'citadel-deployment': deploymentId }
var suffix = uniqueString(subscription().id, deploymentId)
var workloads = loadJsonContent('workloads.json')
var groups = {
  platform: 'citadel-${deploymentId}-platform'
  reference: 'citadel-${deploymentId}-reference'
  evidence: 'citadel-${deploymentId}-evidence'
  planning: 'citadel-${deploymentId}-planning'
}
resource platformGroup 'Microsoft.Resources/resourceGroups@2022-09-01' = if (createResourceGroups) {
  name: groups.platform
  location: location
  tags: tags
}
resource referenceGroup 'Microsoft.Resources/resourceGroups@2022-09-01' = if (createResourceGroups) {
  name: groups.reference
  location: location
  tags: tags
}
resource evidenceGroup 'Microsoft.Resources/resourceGroups@2022-09-01' = if (createResourceGroups) {
  name: groups.evidence
  location: location
  tags: tags
}
resource planningGroup 'Microsoft.Resources/resourceGroups@2022-09-01' = if (createResourceGroups) {
  name: groups.planning
  location: location
  tags: tags
}
module platform 'modules/platform.bicep' = {
  name: 'platform-${deploymentId}'
  scope: resourceGroup(groups.platform)
  params: {
    deploymentId: deploymentId
    location: location
    suffix: suffix
    publisherEmail: publisherEmail
    gatewayCertificatePfx: gatewayCertificatePfx
    collectorPrincipalIds: collectorPrincipalIds
    modelCapacity: modelCapacity
  }
  dependsOn: [platformGroup]
}
module teams 'modules/team.bicep' = [for team in ['reference', 'evidence', 'planning']: {
  name: 'team-${team}-${deploymentId}'
  scope: resourceGroup(groups[team])
  params: {
    deploymentId: deploymentId
    location: location
    team: team
    suffix: suffix
    workloads: filter(workloads, w => w.team == team)
    callerKeys: callerKeys
    contextKeys: contextKeys
    workspaceId: platform.outputs.workspaceId
  }
  dependsOn: [referenceGroup, evidenceGroup, planningGroup]
}]
module apps 'modules/app.bicep' = [for (workload, i) in workloads: if (deployRuntime) {
  name: 'app-${workload.name}-${deploymentId}'
  scope: resourceGroup(groups[workload.team])
  params: {
    deploymentId: deploymentId
    location: location
    workload: workload
    application: applications[workload.name]
    identityName: '${deploymentId}-${workload.name}'
    environmentId: platform.outputs.environmentId
    registryName: platform.outputs.registryName
    registryGroup: groups.platform
    vaultName: '${workload.team}${suffix}'
    storageName: '${workload.team}${suffix}'
    gatewayUrl: platform.outputs.gatewayUrl
    gatewayCertificates: gatewayCertificates
    insightsName: platform.outputs.insightsName
    modelDeployment: platform.outputs.modelDeployment
  }
  dependsOn: [teams]
}]
module gateway 'modules/gateway.bicep' = if (deployRuntime) {
  name: 'gateway-${deploymentId}'
  scope: resourceGroup(groups.platform)
  params: {
    deploymentId: deploymentId
    apimName: platform.outputs.apimName
    vaultName: platform.outputs.vaultName
    modelEndpoint: platform.outputs.modelEndpoint
    modelDeployment: platform.outputs.modelDeployment
    callerKeys: callerKeys
    callerStates: callerStates
    contextKeys: contextKeys
    backends: [for (workload, i) in workloads: {
      name: workload.name
      origin: apps[i]!.outputs.origin
      callers: workload.callers
    }]
  }
}

module capabilityInventory 'modules/inventory.bicep' = if (deployRuntime) {
  name: 'inventory-${deploymentId}'
  scope: resourceGroup(groups.platform)
  params: {
    centerName: platform.outputs.centerName
    gatewayUrl: platform.outputs.gatewayUrl
    workloads: [for (workload, i) in workloads: {
      name: workload.name
      team: workload.team
      appResourceId: apps[i]!.outputs.inventory.app
      identityResourceId: apps[i]!.outputs.inventory.identity
    }]
  }
  dependsOn: [gateway]
}

output teamInventory array = [for (team, i) in ['reference', 'evidence', 'planning']: {
  resources: teams[i].outputs.inventory
  assignments: teams[i].outputs.roleInventory
  credentials: teams[i].outputs.credentialInventory
}]
output appInventory array = [for (workload, i) in workloads: deployRuntime ? apps[i]!.outputs.inventory : { pending: workload.name }]
output inventory object = {
  deploymentId: deploymentId
  groups: [platformGroup!.id, referenceGroup!.id, evidenceGroup!.id, planningGroup!.id]
  platform: platform.outputs.inventory
  gateway: deployRuntime ? gateway!.outputs.inventory : { state: 'not_configured' }
  gatewayApis: deployRuntime ? gateway!.outputs.apiInventory : []
  capabilities: deployRuntime ? capabilityInventory!.outputs.inventory : { state: 'not_configured' }
  inventoryGate: 'Approved workload-environment representation; actual Free plan, metadata/provider acceptance and completeness require live verification.'
}
output gatewayUrl string = platform.outputs.gatewayUrl
