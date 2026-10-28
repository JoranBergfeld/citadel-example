param apimName string
param target string
param callers array
param keyId string
resource apim 'Microsoft.ApiManagement/service@2024-05-01' existing = { name: apimName }
resource api 'Microsoft.ApiManagement/service/apis@2024-05-01' = {
  parent: apim
  name: target
  properties: {
    displayName: target
    path: target
    protocols: ['https']
    type: 'http'
    subscriptionRequired: true
  }
}
var agentOperations = [
  { name: 'a2a', method: 'POST', path: '/a2a', parameters: [] }
  { name: 'discovery', method: 'GET', path: '/.well-known/agent-card.json', parameters: [] }
  { name: 'status', method: 'GET', path: '/operations/{operationId}', parameters: [{ name: 'operationId', required: true, type: 'string' }] }
]
var mcpOperations = [
  { name: 'mcp-post', method: 'POST', path: '/mcp', parameters: [] }
  { name: 'mcp-get', method: 'GET', path: '/mcp', parameters: [] }
  { name: 'mcp-delete', method: 'DELETE', path: '/mcp', parameters: [] }
]
var findingOperations = [{
  name: 'findings-read'
  method: 'GET'
  path: '/findings/{findingId}/versions/{version}'
  parameters: [
    { name: 'findingId', required: true, type: 'string' }
    { name: 'version', required: true, type: 'string' }
  ]
}]
var observationOperations = [
  { name: 'operator-runs', method: 'GET', path: '/operator/runs', parameters: [] }
  { name: 'operator-run-page', method: 'GET', path: '/operator/runs/page/{cursor}', parameters: [{ name: 'cursor', required: true, type: 'string' }] }
  { name: 'operator-run', method: 'GET', path: '/operator/runs/{runId}', parameters: [{ name: 'runId', required: true, type: 'string' }] }
]
var operations = target == 'reference-data' ? mcpOperations : concat(agentOperations,
  target == 'release-reviewer' ? findingOperations : [], target == 'candidate-planner' ? observationOperations : [])
resource routes 'Microsoft.ApiManagement/service/apis/operations@2024-05-01' = [for operation in operations: {
  parent: api
  name: operation.name
  properties: {
    displayName: operation.name
    method: operation.method
    urlTemplate: operation.path
    templateParameters: operation.parameters
  }
}]
var quotedCallers = map(callers, caller => '&quot;${caller}&quot;')
resource policy 'Microsoft.ApiManagement/service/apis/policies@2024-05-01' = {
  parent: api
  name: 'policy'
  properties: {
    format: 'rawxml'
    value: replace(replace(replace(loadTextContent('../policies/workload.xml'), '__TARGET__', target), '__CALLERS__', join(quotedCallers, ', ')), '__KEY_ID__', keyId)
  }
}
var routeInventory = [for (o, i) in operations: routes[i].id]
output inventory object = { api: api.id, policy: policy.id, routes: routeInventory }
