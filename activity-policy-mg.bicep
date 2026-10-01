targetScope = 'managementGroup'

param location string
param workspaceId string

var settingName = 'setByPolicy-SentinelActivity'
var monitoringContributor = '749f88d5-cbae-40b8-bcfc-e573ddc772fa'
var activityCategories = [
  'Administrative'
  'Security'
  'ServiceHealth'
  'Alert'
  'Recommendation'
  'Policy'
  'Autoscale'
  'ResourceHealth'
]

resource def 'Microsoft.Authorization/policyDefinitions@2023-04-01' = {
  name: 'sentinel-activity-logs'
  properties: {
    displayName: 'Sentinel: send subscription Activity Log to Log Analytics'
    policyType: 'Custom'
    mode: 'All'
    parameters: {
      logAnalytics: {
        type: 'String'
        metadata: { displayName: 'Log Analytics workspace resource ID' }
      }
    }
    policyRule: {
      if: {
        field: 'type'
        equals: 'Microsoft.Resources/subscriptions'
      }
      then: {
        effect: 'deployIfNotExists'
        details: {
          type: 'Microsoft.Insights/diagnosticSettings'
          name: settingName
          deploymentScope: 'subscription'
          existenceScope: 'subscription'
          existenceCondition: {
            field: 'Microsoft.Insights/diagnosticSettings/workspaceId'
            equals: '[parameters(\'logAnalytics\')]'
          }
          roleDefinitionIds: [
            '/providers/Microsoft.Authorization/roleDefinitions/${monitoringContributor}'
          ]
          deployment: {
            location: location
            properties: {
              mode: 'incremental'
              template: {
                '$schema': 'https://schema.management.azure.com/schemas/2018-05-01/subscriptionDeploymentTemplate.json#'
                contentVersion: '1.0.0.0'
                parameters: {
                  logAnalytics: { type: 'string' }
                }
                resources: [
                  {
                    type: 'Microsoft.Insights/diagnosticSettings'
                    apiVersion: '2021-05-01-preview'
                    name: settingName
                    properties: {
                      workspaceId: '[parameters(\'logAnalytics\')]'
                      logs: [for c in activityCategories: {
                        category: c
                        enabled: true
                      }]
                    }
                  }
                ]
              }
              parameters: {
                logAnalytics: { value: '[parameters(\'logAnalytics\')]' }
              }
            }
          }
        }
      }
    }
  }
}

resource assign 'Microsoft.Authorization/policyAssignments@2024-04-01' = {
  name: 'sentinel-activity-logs'
  location: location
  identity: { type: 'SystemAssigned' }
  properties: {
    displayName: 'Sentinel: subscription Activity Log to Log Analytics'
    policyDefinitionId: def.id
    parameters: {
      logAnalytics: { value: workspaceId }
    }
  }
}

// Lets the policy identity write diagnostic settings on every subscription in the group
resource monitoringRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(managementGroup().id, 'sentinel-activity-logs', monitoringContributor)
  properties: {
    roleDefinitionId: tenantResourceId('Microsoft.Authorization/roleDefinitions', monitoringContributor)
    principalId: assign.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

output principalId string = assign.identity.principalId
output assignmentName string = assign.name
