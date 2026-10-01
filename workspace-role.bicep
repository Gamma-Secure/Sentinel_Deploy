// Resource-group scope: lets a policy identity send logs to the workspace
param principalId string

var logAnalyticsContributor = '92aaf0da-9dab-42b6-94a3-d43ce8d16293'

resource role 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, principalId, logAnalyticsContributor)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', logAnalyticsContributor)
    principalId: principalId
    principalType: 'ServicePrincipal'
  }
}
