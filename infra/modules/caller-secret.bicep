param vaultName string
param identityName string
param caller string
@secure()
param credential string
resource vault 'Microsoft.KeyVault/vaults@2023-07-01' existing = { name: vaultName }
resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = { name: identityName }
resource secret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: vault
  name: 'subscription-${caller}'
  properties: { value: credential }
}
resource reader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: secret
  name: guid(secret.id, identity.id, 'secret-reader')
  properties: {
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
  }
}
output inventory object = { secret: secret.id, assignment: reader.id }
