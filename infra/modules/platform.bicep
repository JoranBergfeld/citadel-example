param deploymentId string
param location string
param suffix string
param publisherEmail string
@secure()
param gatewayCertificatePfx string
param collectorPrincipalIds array
param modelCapacity int
param createApiCenter bool = true
var tags = { 'citadel-deployment': deploymentId }

resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: 'citadel-${deploymentId}-logs'
  location: location
  tags: tags
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
    workspaceCapping: { dailyQuotaGb: -1 }
    features: { enableLogAccessUsingOnlyResourcePermissions: false }
  }
}
var tableNames = [
  'AppRequests'
  'AppDependencies'
  'AppTraces'
  'AppExceptions'
  'AppEvents'
  'AppMetrics'
  'ApiManagementGatewayLogs'
  'ContainerAppConsoleLogs'
  'ContainerAppSystemLogs'
  'ContainerAppHTTPLogs'
  'StorageBlobLogs'
  'AZKVAuditLogs'
]
resource tables 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = [for table in tableNames: {
  parent: workspace
  name: table
  properties: { plan: 'Analytics', retentionInDays: 30, totalRetentionInDays: 30 }
}]
resource insights 'Microsoft.Insights/components@2020-02-02' = {
  name: 'citadel-${deploymentId}-insights'
  location: location
  kind: 'web'
  tags: tags
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: workspace.id
    SamplingPercentage: 100
    DisableLocalAuth: true
  }
}
resource environment 'Microsoft.App/managedEnvironments@2025-01-01' = {
  name: 'citadel-${deploymentId}-environment'
  location: location
  tags: tags
  properties: {
    workloadProfiles: [{ name: 'Consumption', workloadProfileType: 'Consumption' }]
    appLogsConfiguration: { destination: 'azure-monitor' }
  }
}
resource environmentDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: environment
  name: 'citadel-logs'
  properties: {
    workspaceId: workspace.id
    logAnalyticsDestinationType: 'Dedicated'
    logs: [
      { category: 'ContainerAppConsoleLogs', enabled: true }
      { category: 'ContainerAppSystemLogs', enabled: true }
      { category: 'ContainerAppHTTPLogs', enabled: true }
    ]
  }
}
resource registry 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: 'citadel${suffix}'
  location: location
  tags: tags
  sku: { name: 'Basic' }
  properties: { adminUserEnabled: false }
}
resource center 'Microsoft.ApiCenter/services@2024-03-01' = if (createApiCenter) {
  name: 'citadel-${deploymentId}-inventory'
  location: location
  tags: tags
  properties: {}
}
resource centerWorkspace 'Microsoft.ApiCenter/services/workspaces@2024-03-01' = {
  parent: center
  name: 'default'
  properties: { title: 'Citadel sample' }
}
resource model 'Microsoft.CognitiveServices/accounts@2024-10-01' = {
  name: 'citadel-${suffix}-model'
  location: location
  tags: tags
  kind: 'OpenAI'
  sku: { name: 'S0' }
  properties: {
    customSubDomainName: 'citadel-${suffix}-model'
    disableLocalAuth: true
    publicNetworkAccess: 'Enabled'
  }
}
resource deployment 'Microsoft.CognitiveServices/accounts/deployments@2024-10-01' = {
  parent: model
  name: 'citadel-gpt-41-mini'
  sku: { name: 'Standard', capacity: modelCapacity }
  properties: {
    model: { format: 'OpenAI', name: 'gpt-4.1-mini', version: '2025-04-14' }
    versionUpgradeOption: 'NoAutoUpgrade'
  }
}
resource apim 'Microsoft.ApiManagement/service@2024-05-01' = {
  name: 'citadel-${suffix}-gateway'
  location: location
  tags: tags
  sku: { name: 'BasicV2', capacity: 1 }
  identity: { type: 'SystemAssigned' }
  properties: {
    publisherEmail: publisherEmail
    publisherName: 'Citadel sample operator'
  }
}
resource modelRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: model
  name: guid(model.id, apim.id, 'openai-user')
  properties: {
    principalId: apim.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '5e0bd9bd-7b93-4f28-af87-19fc36ad61bd')
  }
}
resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'platform${suffix}'
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
resource certificateSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: vault
  name: 'gateway-certificate'
  properties: { value: gatewayCertificatePfx, contentType: 'application/x-pkcs12' }
}
resource certificateReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: certificateSecret
  name: guid(certificateSecret.id, apim.id, 'secret-reader')
  properties: {
    principalId: apim.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
  }
}
resource logger 'Microsoft.ApiManagement/service/loggers@2024-05-01' = {
  parent: apim
  name: 'application-insights'
  properties: {
    loggerType: 'applicationInsights'
    credentials: {
      connectionString: insights.properties.ConnectionString
      identityClientId: 'SystemAssigned'
    }
    resourceId: insights.id
    isBuffered: false
  }
}
resource apimIngestion 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: insights
  name: guid(insights.id, apim.id, 'ingestion')
  properties: {
    principalId: apim.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '3913510d-42f4-4e42-8a64-420c390055eb')
  }
}
resource diagnostics 'Microsoft.ApiManagement/service/diagnostics@2024-05-01' = {
  parent: apim
  name: 'applicationinsights'
  properties: {
    loggerId: logger.id
    alwaysLog: 'allErrors'
    sampling: { samplingType: 'fixed', percentage: 100 }
    httpCorrelationProtocol: 'W3C'
    logClientIp: false
    verbosity: 'information'
    frontend: {
      request: { headers: [], body: { bytes: 0 } }
      response: { headers: [], body: { bytes: 0 } }
    }
    backend: {
      request: { headers: [], body: { bytes: 0 } }
      response: { headers: [], body: { bytes: 0 } }
    }
  }
}
resource apimLogs 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: apim
  name: 'citadel-logs'
  properties: {
    workspaceId: workspace.id
    logAnalyticsDestinationType: 'Dedicated'
    logs: [{ category: 'GatewayLogs', enabled: true }]
  }
}
resource vaultLogs 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: vault
  name: 'citadel-logs'
  properties: {
    workspaceId: workspace.id
    logAnalyticsDestinationType: 'Dedicated'
    logs: [{ category: 'AuditEvent', enabled: true }]
  }
}
resource collectors 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for principal in collectorPrincipalIds: {
  scope: workspace
  name: guid(workspace.id, principal, 'log-reader')
  properties: {
    principalId: principal
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '73c42c96-874c-492b-b04d-ab87d138a893')
  }
}]

output workspaceId string = workspace.id
output environmentId string = environment.id
output insightsName string = insights.name
output registryName string = registry.name
output centerName string = center.name
output apimName string = apim.name
output vaultName string = vault.name
output gatewayUrl string = apim.properties.gatewayUrl
output modelEndpoint string = model.properties.endpoint
output modelDeployment string = deployment.name
var collectorInventory = [for (p, i) in collectorPrincipalIds: collectors[i].id]
var tableInventory = [for (t, i) in tableNames: tables[i].id]
output inventory object = {
  resources: [workspace.id, insights.id, environment.id, registry.id, center.id, centerWorkspace.id, model.id, deployment.id, apim.id, vault.id, certificateSecret.id]
  assignments: concat([modelRole.id, certificateReader.id, apimIngestion.id], collectorInventory)
  diagnostics: [environmentDiagnostics.id, apimLogs.id, vaultLogs.id, diagnostics.id, logger.id]
  tables: tableInventory
}
