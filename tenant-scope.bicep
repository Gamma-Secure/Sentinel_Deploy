// Everything that lives above subscription scope. Needs Owner at tenant root ("/") to deploy.
targetScope = 'tenant'

param location string
param workspaceId string
param subscriptionId string
param resourceGroupName string
param entraCategories array
param enableActivityPolicy bool
param managementGroupId string

// Entra ID logs -> workspace (tenant-level diagnostic setting)
resource entraDiag 'microsoft.aadiam/diagnosticSettings@2017-04-01' = if (!empty(entraCategories)) {
  name: 'sentinel-entra-logs'
  properties: {
    workspaceId: workspaceId
    logs: [for c in entraCategories: {
      category: c
      enabled: true
    }]
  }
}

// Azure Activity for every subscription under a management group
module activityPolicy 'activity-policy-mg.bicep' = if (enableActivityPolicy) {
  name: 'sentinel-activity-policy'
  scope: managementGroup(managementGroupId)
  params: {
    location: location
    workspaceId: workspaceId
  }
}

module activityPolicyWorkspaceRole 'workspace-role.bicep' = if (enableActivityPolicy) {
  name: 'sentinel-activity-policy-workspace-role'
  scope: resourceGroup(subscriptionId, resourceGroupName)
  params: {
    principalId: activityPolicy!.outputs.principalId
  }
}
