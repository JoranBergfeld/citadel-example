param deploymentId string
param location string
param suffix string
param principalIds array

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: 'observe${suffix}'
  location: location
  tags: { 'citadel-deployment': deploymentId, 'citadel-purpose': 'accounting-only' }
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
resource container 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobs
  name: 'read-accounting'
  properties: { publicAccess: 'None' }
}
resource admissionRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(resourceGroup().id, deploymentId, 'read-marker-admission')
  properties: {
    roleName: '${deploymentId} conditional read-marker admission'
    description: 'Accounting-only conditional marker writes and descriptor leases; no GET, list, delete, team content or credentials.'
    type: 'CustomRole'
    assignableScopes: [resourceGroup().id]
    permissions: [{
      actions: []
      notActions: []
      dataActions: ['Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write']
      notDataActions: []
    }]
  }
}
resource assignments 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for principalId in principalIds: {
  scope: container
  name: guid(container.id, principalId, admissionRole.id)
  properties: {
    principalId: principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: admissionRole.id
  }
}]
output blobUrl string = 'https://${storage.name}.blob.${environment().suffixes.storage}'
var assignmentInventory = [for (p, i) in principalIds: assignments[i].id]
output inventory object = {
  resources: [storage.id, blobs.id, container.id, admissionRole.id]
  assignments: assignmentInventory
  observationCapacity: 16384
  recoveryProofCapacity: 2048
}
