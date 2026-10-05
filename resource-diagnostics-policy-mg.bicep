// Management-group scope: same policies as resource-diagnostics-policy.bicep, covering every subscription in the group.
targetScope = 'managementGroup'

param location string
param workspaceId string
@description('Prefix for policy definition, assignment and remediation names (MG assignment names are limited to 24 characters)')
param namePrefix string = 'gammasecure'
param workspaceSubscriptionId string
param workspaceResourceGroup string
@description('Array of { key, label, resourceType }')
param sources array
@description('Create remediation tasks (re-evaluates compliance first) so existing resources are fixed now')
param remediateExisting bool = true

var monitoringContributor = '749f88d5-cbae-40b8-bcfc-e573ddc772fa'
var logAnalyticsContributor = '92aaf0da-9dab-42b6-94a3-d43ce8d16293'
var settingName = 'setByPolicy-Sentinel'

resource defs 'Microsoft.Authorization/policyDefinitions@2023-04-01' = [for s in sources: {
  name: '${namePrefix}-${s.key}'
  properties: {
    displayName: 'Gamma Secure - ${s.label} Logging Policy'
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
          roleDefinitionIds: [
            '/providers/Microsoft.Authorization/roleDefinitions/${monitoringContributor}'
            '/providers/Microsoft.Authorization/roleDefinitions/${logAnalyticsContributor}'
          ]
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
  name: '${namePrefix}-${s.key}'
  location: location
  identity: { type: 'SystemAssigned' }
  properties: {
    displayName: 'Gamma Secure - ${s.label} Logs to Sentinel'
    policyDefinitionId: defs[i].id
    parameters: {
      logAnalytics: { value: workspaceId }
    }
  }
}]

// Monitoring Contributor over the scope the policy applies to (to write diagnostic settings)
resource monitoringRoles 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for (s, i) in sources: {
  name: guid(managementGroup().id, s.key, monitoringContributor)
  properties: {
    roleDefinitionId: tenantResourceId('Microsoft.Authorization/roleDefinitions', monitoringContributor)
    principalId: assigns[i].identity.principalId
    principalType: 'ServicePrincipal'
  }
}]

// Log Analytics Contributor only on the workspace's resource group (works across subscriptions)
module workspaceRoles 'workspace-role.bicep' = [for (s, i) in sources: {
  name: 'wsrole-${s.key}-${uniqueString(managementGroup().id)}'
  scope: resourceGroup(workspaceSubscriptionId, workspaceResourceGroup)
  params: {
    principalId: assigns[i].identity.principalId
  }
}]

// ReEvaluateCompliance makes the task scan first, so it works straight after assignment.
resource remediations 'Microsoft.PolicyInsights/remediations@2021-10-01' = [for (s, i) in sources: if (remediateExisting) {
  name: '${namePrefix}-${s.key}'
  properties: {
    policyAssignmentId: assigns[i].id
    resourceDiscoveryMode: 'ReEvaluateCompliance'
  }
  dependsOn: [ monitoringRoles, workspaceRoles ]
}]

output assignmentNames array = [for (s, i) in sources: assigns[i].name]
