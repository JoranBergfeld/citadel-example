param deploymentId string
param apimName string
param vaultName string
param modelEndpoint string
param modelDeployment string
param backends array
@secure()
param callerKeys object
param callerStates object
@secure()
param contextKeys object
resource apim 'Microsoft.ApiManagement/service@2024-05-01' existing = { name: apimName }
resource vault 'Microsoft.KeyVault/vaults@2023-07-01' existing = { name: vaultName }
resource globalPolicy 'Microsoft.ApiManagement/service/policies@2024-05-01' = {
  parent: apim
  name: 'policy'
  properties: { format: 'rawxml', value: loadTextContent('../policies/global.xml') }
}
resource certificate 'Microsoft.ApiManagement/service/certificates@2024-05-01' = {
  parent: apim
  name: 'gateway-client'
  properties: {
    keyVault: { secretIdentifier: '${vault.properties.vaultUri}secrets/gateway-certificate' }
  }
}
var callers = ['operator', 'candidate-planner', 'evidence-assessor', 'release-reviewer', 'briefing-author']
resource subscriptions 'Microsoft.ApiManagement/service/subscriptions@2024-05-01' = [for caller in callers: {
  parent: apim
  name: caller
  properties: {
    displayName: '${deploymentId}-${caller}'
    scope: '${apim.id}/apis'
    state: callerStates[caller]
    primaryKey: callerKeys[caller].primary
    secondaryKey: callerKeys[caller].secondary
    allowTracing: false
  }
}]
resource namedValues 'Microsoft.ApiManagement/service/namedValues@2024-05-01' = [for backend in backends: {
  parent: apim
  name: 'context-${backend.name}'
  properties: {
    displayName: 'context-${backend.name}'
    secret: true
    value: base64(contextKeys[backend.name].keys[contextKeys[backend.name].activeId])
  }
}]
resource origins 'Microsoft.ApiManagement/service/backends@2024-05-01' = [for backend in backends: {
  parent: apim
  name: backend.name
  properties: {
    protocol: 'http'
    url: backend.origin
    tls: { validateCertificateChain: true, validateCertificateName: true }
  }
}]
module workloadApis 'workload-api.bicep' = [for backend in backends: {
  name: 'api-${backend.name}'
  params: {
    apimName: apimName
    target: backend.name
    callers: backend.callers
    keyId: contextKeys[backend.name].activeId
  }
  dependsOn: [namedValues, origins, certificate, globalPolicy]
}]
resource modelBackend 'Microsoft.ApiManagement/service/backends@2024-05-01' = {
  parent: apim
  name: 'model'
  properties: {
    protocol: 'http'
    url: modelEndpoint
    tls: { validateCertificateChain: true, validateCertificateName: true }
  }
}
resource modelApi 'Microsoft.ApiManagement/service/apis@2024-05-01' = {
  parent: apim
  name: 'model'
  properties: {
    displayName: 'Azure OpenAI v1 Chat Completions'
    path: 'openai/v1'
    protocols: ['https']
    type: 'http'
    subscriptionRequired: true
  }
}
resource modelOperation 'Microsoft.ApiManagement/service/apis/operations@2024-05-01' = {
  parent: modelApi
  name: 'chat-completions'
  properties: { displayName: 'Chat Completions', method: 'POST', urlTemplate: '/chat/completions' }
}
resource modelPolicy 'Microsoft.ApiManagement/service/apis/policies@2024-05-01' = {
  parent: modelApi
  name: 'policy'
  properties: { format: 'rawxml', value: replace(loadTextContent('../policies/model.xml'), '__MODEL__', modelDeployment) }
  dependsOn: [modelBackend, globalPolicy]
}
var subscriptionInventory = [for (c, i) in callers: subscriptions[i].id]
var valueInventory = [for (b, i) in backends: namedValues[i].id]
var originInventory = [for (b, i) in backends: origins[i].id]
output apiInventory array = [for (b, i) in backends: workloadApis[i].outputs.inventory]
output inventory object = {
  resources: [globalPolicy.id, certificate.id, modelBackend.id, modelApi.id, modelOperation.id, modelPolicy.id]
  subscriptions: subscriptionInventory
  contextValues: valueInventory
  origins: originInventory
}
