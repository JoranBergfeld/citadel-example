param centerName string
param gatewayUrl string
param workloads array

resource center 'Microsoft.ApiCenter/services@2024-03-01' existing = { name: centerName }
resource workspace 'Microsoft.ApiCenter/services/workspaces@2024-03-01' existing = {
  parent: center
  name: 'default'
}
var metadataNames = [
  'workload'
  'protocol'
  'protocol-version'
  'team'
  'gateway-address'
  'identity-kind'
  'identity-resource-id'
]
var teamNames = {
  reference: 'Reference Data'
  evidence: 'Evidence Review'
  planning: 'Exercise Planning'
}
var protocols = {
  'reference-data': { name: 'MCP', version: '2025-11-25', path: '/mcp' }
  'evidence-assessor': { name: 'A2A', version: '1.0.0', path: '/a2a' }
  'release-reviewer': { name: 'A2A', version: '1.0.0', path: '/a2a' }
  'candidate-planner': { name: 'A2A', version: '1.0.0', path: '/a2a' }
  'briefing-author': { name: 'A2A', version: '1.0.0', path: '/a2a' }
}
resource schemas 'Microsoft.ApiCenter/services/metadataSchemas@2024-03-01' = [for property in metadataNames: {
  parent: center
  name: property
  properties: {
    schema: '{"type":"string"}'
    assignedTo: [{ entity: 'environment', required: true }]
  }
}]
resource environments 'Microsoft.ApiCenter/services/workspaces/environments@2024-03-01' = [for workload in workloads: {
  parent: workspace
  name: workload.name
  properties: {
    title: workload.name
    kind: 'testing'
    description: 'Container App workload/environment inventory, not native A2A/MCP registration or import validation. A2A uses JSON-RPC 2.0; MCP uses Streamable HTTP. Declared configuration requires live verification.'
    server: { type: 'Azure compute service' }
    customProperties: {
      workload: workload.appResourceId
      protocol: protocols[workload.name].name
      'protocol-version': protocols[workload.name].version
      team: teamNames[workload.team]
      'gateway-address': '${gatewayUrl}/${workload.name}${protocols[workload.name].path}'
      'identity-kind': 'Azure user-assigned managed identity; not Entra Agent ID'
      'identity-resource-id': workload.identityResourceId
    }
  }
  dependsOn: [schemas]
}]
resource findings 'Microsoft.ApiCenter/services/workspaces/apis@2024-03-01' = {
  parent: workspace
  name: 'released-findings'
  properties: {
    title: 'Released findings'
    kind: 'rest'
    summary: 'Read one exact released finding version.'
    description: 'GET /findings/{findingId}/versions/{version} on Release Reviewer through APIM. Separately authorized deterministic read for Candidate Planner and Briefing Author; not agent invocation or release authority. No private draft access.'
  }
}
resource findingsVersion 'Microsoft.ApiCenter/services/workspaces/apis/versions@2024-03-01' = {
  parent: findings
  name: 'v1-0-0'
  properties: {
    title: '1.0.0'
    lifecycleStage: 'testing'
  }
}
resource findingsDefinition 'Microsoft.ApiCenter/services/workspaces/apis/versions/definitions@2024-03-01' = {
  parent: findingsVersion
  name: 'declared-rest'
  properties: {
    title: 'Exact released-finding read declaration'
    description: 'Declared GET /findings/{findingId}/versions/{version} metadata only; no imported specification or operational validation is claimed.'
  }
}
resource findingsDeployment 'Microsoft.ApiCenter/services/workspaces/apis/deployments@2024-03-01' = {
  parent: findings
  name: 'gateway'
  properties: {
    title: 'Reviewer hosted findings read'
    description: 'Declared REST capability at the gateway, hosted by the Release Reviewer Container App. Provider acceptance and working allowed/denied controls require live verification; inventory is not operational proof.'
    definitionId: '/workspaces/default/apis/released-findings/versions/v1-0-0/definitions/declared-rest'
    environmentId: '/workspaces/default/environments/release-reviewer'
    server: { runtimeUri: ['${gatewayUrl}/release-reviewer'] }
  }
  dependsOn: [environments, findingsDefinition]
}
var schemaIds = [for (property, i) in metadataNames: schemas[i].id]
var environmentIds = [for (workload, i) in workloads: environments[i].id]
output inventory object = {
  service: center.id
  workspace: workspace.id
  metadataSchemas: schemaIds
  workloadEnvironments: environmentIds
  restCapabilities: [findings.id, findingsDeployment.id, findingsVersion.id, findingsDefinition.id]
  representation: 'Workload environments; not native A2A/MCP registration or import validation.'
}
