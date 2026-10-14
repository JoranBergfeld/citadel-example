param storageName string
param containerName string
param identityName string
@allowed(['reader', 'contributor'])
param role string
resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' existing = { name: storageName }
resource service 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' existing = { parent: storage, name: 'default' }
resource container 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' existing = { parent: service, name: containerName }
resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = { name: identityName }
var roles = {
  reader: '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1'
  contributor: 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
}
resource assignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: container
  name: guid(container.id, identity.id, roles[role])
  properties: {
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles[role])
  }
}
output assignmentId string = assignment.id
