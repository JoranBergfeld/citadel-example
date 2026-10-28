param deploymentId string
param location string
param workload object
param application object
param identityName string
param environmentId string
param registryName string
param registryGroup string
param vaultName string
param storageName string
param gatewayUrl string
param gatewayCertificates array
param modelDeployment string
param insightsName string
param observationBlobUrl string
resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = { name: identityName }
resource insights 'Microsoft.Insights/components@2020-02-02' existing = {
  name: insightsName
  scope: resourceGroup(registryGroup)
}
module platformRoles 'app-platform-roles.bicep' = {
  scope: resourceGroup(registryGroup)
  name: 'app-roles-${workload.name}'
  params: {
    registryName: registryName
    insightsName: insightsName
    principalId: identity.properties.principalId
  }
}
var baseEnvironment = [
  { name: 'AZURE_CLIENT_ID', value: identity.properties.clientId }
  { name: 'AZURE_PRINCIPAL_ID', value: identity.properties.principalId }
  { name: 'CITADEL_TARGET', value: workload.name }
  { name: 'CITADEL_DEPLOYMENT_ID', value: deploymentId }
  { name: 'CITADEL_OBSERVATION_BLOB_URL', value: observationBlobUrl }
  { name: 'CITADEL_GATEWAY_URL', value: gatewayUrl }
  { name: 'CITADEL_GATEWAY_CERTIFICATES', value: string(gatewayCertificates) }
  { name: 'CITADEL_CONTEXT_KEYS', secretRef: 'context-keys' }
  { name: 'CITADEL_VAULT_URL', value: 'https://${vaultName}${environment().suffixes.keyvaultDns}' }
  { name: 'CITADEL_BLOB_URL', value: 'https://${storageName}.blob.${environment().suffixes.storage}' }
  { name: 'CITADEL_BLOB_API_VERSION', value: '2026-10-06' }
  { name: 'CITADEL_VAULT_API_VERSION', value: '2025-07-01' }
  { name: 'CITADEL_MODEL_DEPLOYMENT', value: modelDeployment }
  { name: 'CITADEL_MODEL_TOKENS_PER_MINUTE', value: string(application.?modelTokensPerMinute ?? 0) }
  { name: 'CITADEL_LIMITS', value: string(loadJsonContent('../limits.json')) }
  { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', secretRef: 'insights-connection' }
  { name: 'APPLICATIONINSIGHTS_AUTHENTICATION_STRING', value: 'Authorization=AAD;ClientId=${identity.properties.clientId}' }
  { name: 'OTEL_TRACES_SAMPLER', value: 'always_on' }
  { name: 'CITADEL_TELEMETRY_BODY_LOGGING', value: 'disabled' }
]
resource app 'Microsoft.App/containerApps@2025-01-01' = {
  name: '${deploymentId}-${workload.name}'
  location: location
  tags: { 'citadel-deployment': deploymentId, 'citadel-team': workload.team }
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: { '${identity.id}': {} }
  }
  properties: {
    managedEnvironmentId: environmentId
    workloadProfileName: 'Consumption'
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: true
        targetPort: 8000
        transport: 'http'
        allowInsecure: false
        clientCertificateMode: 'accept'
      }
      registries: [{ server: '${registryName}.azurecr.io', identity: identity.id }]
      secrets: [
        {
          name: 'context-keys'
          identity: identity.id
          keyVaultUrl: 'https://${vaultName}${environment().suffixes.keyvaultDns}/secrets/context-${workload.name}'
        }
        { name: 'insights-connection', value: insights.properties.ConnectionString }
      ]
    }
    template: {
      containers: [{
        name: workload.name
        image: application.image
        command: application.command
        args: application.args
        resources: { cpu: json('0.5'), memory: '1Gi' }
        env: concat(baseEnvironment, workload.name == 'reference-data' ? [
          { name: 'CITADEL_REFERENCE_CONTAINER', value: 'reference' }
        ] : [
          { name: 'CITADEL_OPERATIONS_CONTAINER', value: workload.operations }
          { name: 'CITADEL_SUBSCRIPTION_SECRET_NAME', value: 'subscription-${workload.name}' }
        ])
        probes: [
          { type: 'Liveness', tcpSocket: { port: 8000 }, initialDelaySeconds: 10, periodSeconds: 30 }
          { type: 'Readiness', tcpSocket: { port: 8000 }, initialDelaySeconds: 5, periodSeconds: 10 }
        ]
      }]
      scale: { minReplicas: 1, maxReplicas: 1 }
    }
  }
  dependsOn: [platformRoles]
}
output origin string = 'https://${app.properties.configuration.ingress.fqdn}'
output inventory object = {
  app: app.id
  identity: identity.id
  identityClientId: identity.properties.clientId
  identityPrincipalId: identity.properties.principalId
  image: application.image
  assignments: platformRoles.outputs.assignments
}
