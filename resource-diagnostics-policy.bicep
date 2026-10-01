targetScope = 'subscription'

param location string
param workspaceId string
@description('Array of { key, label, resourceType }')
param sources array

var roleIds = [
  '749f88d5-cbae-40b8-bcfc-e573ddc772fa' // Monitoring Contributor
  '92aaf0da-9dab-42b6-94a3-d43ce8d16293' // Log Analytics Contributor
]
var settingName = 'setByPolicy-Sentinel'

resource defs 'Microsoft.Authorization/policyDefinitions@2023-04-01' = [for s in sources: {
  name: 'sentinel-diag-${s.key}'
  properties: {
    displayName: 'Sentinel: send ${s.label} resource logs to Log Analytics'
    policyType: 'Custom'
    mode: 'Indexed'
    parameters: {
      logAnalytics: {
        type: 'String'
        metadata: { displayName: 'Log Analytics workspace resource ID' }
      }
    }
    policyRule: {
      if: {
        field: 'type'
        equals: s.resourceType
      }
      then: {
        effect: 'deployIfNotExists'
        details: {
          type: 'Microsoft.Insights/diagnosticSettings'
          name: settingName
          existenceCondition: {
            allOf: [
              {
                field: 'Microsoft.Insights/diagnosticSettings/workspaceId'
                equals: '[parameters(\'logAnalytics\')]'
              }
            ]
          }
          roleDefinitionIds: [for r in roleIds: '/providers/Microsoft.Authorization/roleDefinitions/${r}']
          deployment: {
            properties: {
              mode: 'incremental'
              template: {
                '$schema': 'http://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#'
                contentVersion: '1.0.0.0'
                parameters: {
                  resourceName: { type: 'string' }
                  location: { type: 'string' }
                  logAnalytics: { type: 'string' }
                }
                resources: [
                  {
                    type: '${s.resourceType}/providers/diagnosticSettings'
                    apiVersion: '2021-05-01-preview'
                    name: '[concat(parameters(\'resourceName\'), \'/Microsoft.Insights/${settingName}\')]'
                    location: '[parameters(\'location\')]'
                    properties: {
                      workspaceId: '[parameters(\'logAnalytics\')]'
                      logs: [
                        { categoryGroup: 'allLogs', enabled: true }
                      ]
                    }
                  }
                ]
              }
              parameters: {
                resourceName: { value: '[field(\'name\')]' }
                location: { value: '[field(\'location\')]' }
                logAnalytics: { value: '[parameters(\'logAnalytics\')]' }
              }
            }
          }
        }
      }
    }
  }
}]

resource assigns 'Microsoft.Authorization/policyAssignments@2024-04-01' = [for (s, i) in sources: {
  name: 'sentinel-diag-${s.key}'
  location: location
  identity: { type: 'SystemAssigned' }
  properties: {
    displayName: 'Sentinel: ${s.label} logs to Log Analytics'
    policyDefinitionId: defs[i].id
    parameters: {
      logAnalytics: { value: workspaceId }
    }
  }
}]

// Two role assignments per policy identity (index i/2 = source, i%2 = role)
resource roles 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for i in range(0, length(sources) * 2): {
  name: guid(subscription().id, sources[i / 2].key, roleIds[i % 2])
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds[i % 2])
    principalId: assigns[i / 2].identity.principalId
    principalType: 'ServicePrincipal'
  }
}]

output assignmentNames array = [for (s, i) in sources: assigns[i].name]
