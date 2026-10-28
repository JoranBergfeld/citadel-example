param deploymentId string
param location string
param environmentId string
param environmentName string
param registryName string
param identityId string
param usernameUrl string
param verifierUri string
param application object

resource appEnvironment 'Microsoft.App/managedEnvironments@2025-01-01' existing = { name: environmentName }
resource app 'Microsoft.App/containerApps@2025-01-01' = {
  name: '${deploymentId}-operator-web'
  location: location
  tags: { 'citadel-deployment': deploymentId, 'citadel-purpose': 'operator-application' }
  identity: { type: 'UserAssigned', userAssignedIdentities: { '${identityId}': {} } }
  properties: {
    managedEnvironmentId: environmentId
    workloadProfileName: 'Consumption'
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: { external: true, targetPort: 8000, transport: 'http', allowInsecure: false }
      registries: [{ server: '${registryName}.azurecr.io', identity: identityId }]
      secrets: [
        {
          name: 'operator-username'
          identity: identityId
          keyVaultUrl: usernameUrl
        }
        {
          name: 'operator-password-hash'
          identity: identityId
          keyVaultUrl: verifierUri
        }
      ]
    }
    template: {
      containers: [{
        name: 'operator-web'
        image: application.image
        command: ['python', '-m', 'citadel.operator.web']
        args: []
        resources: { cpu: json('0.5'), memory: '1Gi' }
        env: [
          { name: 'CITADEL_OPERATOR_USERNAME', secretRef: 'operator-username' }
          { name: 'CITADEL_OPERATOR_PASSWORD_HASH', secretRef: 'operator-password-hash' }
          { name: 'CITADEL_OPERATOR_ORIGIN', value: 'https://${deploymentId}-operator-web.${appEnvironment.properties.defaultDomain}' }
        ]
        probes: [
          { type: 'Liveness', tcpSocket: { port: 8000 }, initialDelaySeconds: 10, periodSeconds: 30 }
          { type: 'Readiness', tcpSocket: { port: 8000 }, initialDelaySeconds: 5, periodSeconds: 10 }
        ]
      }]
      scale: { minReplicas: 1, maxReplicas: 1 }
    }
  }
}
output inventory object = { app: app.id, image: application.image }
output origin string = 'https://${app.properties.configuration.ingress.fqdn}'
