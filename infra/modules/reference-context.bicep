param deploymentId string
param storageName string
param referencePrincipalId string

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' existing = { name: storageName }
resource blobs 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' existing = {
  parent: storage
  name: 'default'
}
resource container 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' existing = {
  parent: blobs
  name: 'planner-operations'
}
resource reader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: container
  name: guid(container.id, deploymentId, referencePrincipalId, 'reference-retained-context')
  properties: {
    principalId: referencePrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1')
    conditionVersion: '2.0'
    condition: '((!(ActionMatches{\'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read\'})) OR ((!(SubOperationMatches{\'Blob.List\'})) AND (@Resource[Microsoft.Storage/storageAccounts/blobServices/containers/blobs:path] StringEquals \'retained-runs-v1.json\')))'
  }
}
output assignments array = [reader.id]
