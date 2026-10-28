param deploymentId string
param location string
param vaultName string
param registryName string
@secure()
param operatorAuth object
@secure()
param callerKeys object

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${deploymentId}-operator-web'
  location: location
  tags: { 'citadel-deployment': deploymentId, 'citadel-purpose': 'operator-application' }
}
resource vault 'Microsoft.KeyVault/vaults@2023-07-01' existing = { name: vaultName }
resource registry 'Microsoft.ContainerRegistry/registries@2023-07-01' existing = { name: registryName }
resource username 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: vault
  name: 'operator-web-username'
  properties: { value: operatorAuth.username }
}
resource passwordHash 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: vault
  name: 'operator-web-password-hash'
  properties: { value: operatorAuth.passwordHash }
}
resource subscription 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: vault
  name: 'subscription-operator-web'
  properties: { value: callerKeys['operator-web'].primary }
}
var secretNames = ['operator-web-username', 'operator-web-password-hash', 'subscription-operator-web']
resource allocatedSecrets 'Microsoft.KeyVault/vaults/secrets@2023-07-01' existing = [for name in secretNames: {
  parent: vault
  name: name
}]
resource readers 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for (name, i) in secretNames: {
  name: guid(vault.id, name, identity.id, 'secret-reader')
  scope: allocatedSecrets[i]
  properties: {
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
  }
  dependsOn: [username, passwordHash, subscription]
}]
resource pull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(registry.id, identity.id, 'acr-pull')
  scope: registry
  properties: {
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '7f951dda-4ed3-4680-a7ca-43fe172d538d')
  }
}
output identityId string = identity.id
output principalId string = identity.properties.principalId
output clientId string = identity.properties.clientId
output subscriptionUri string = subscription.properties.secretUriWithVersion
output usernameUrl string = username.properties.secretUriWithVersion
output verifierUri string = passwordHash.properties.secretUriWithVersion
var readerInventory = [for (name, i) in secretNames: extensionResourceId(allocatedSecrets[i].id, 'Microsoft.Authorization/roleAssignments', readers[i].name)]
output inventory object = {
  identity: identity.id
  clientId: identity.properties.clientId
  secrets: [username.id, passwordHash.id, subscription.id]
  assignments: concat([pull.id], readerInventory)
}
