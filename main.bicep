targetScope = 'subscription'

@description('Region for the resource group and workspace')
param location string
param resourceGroupName string
param workspaceName string
@minValue(30)
@maxValue(730)
param retentionInDays int = 90
@description('Daily ingestion cap in GB. -1 = no cap')
param dailyQuotaGb int = -1

// Sentinel connectors / subscription-level sources
param enableAzureActivity bool = true
param enableDefenderXdr bool = false
param enableDefenderXdrAlerts bool = false
param enableDefenderForCloud bool = false
param enableDefenderForCloudApps bool = false
param enableDefenderForCloudAppsDiscovery bool = false
param enableDefenderForIdentity bool = false
param enableDefenderForEndpoint bool = false
param enableDefenderForOffice365 bool = false
param enableEntraIdProtection bool = false

// Microsoft 365
param enableO365Exchange bool = false
param enableO365SharePoint bool = false
param enableO365Teams bool = false
param enableInsiderRisk bool = false
param enablePowerBI bool = false
param enableDynamics365 bool = false
param enableProject bool = false
param enablePurviewInfoProtection bool = false

// Threat intelligence
param enableMdti bool = false
param enableTip bool = false

// AWS (AWS-side IAM role / SQS must already exist)
param enableAwsCloudTrail bool = false
param awsCloudTrailRoleArn string = ''
param enableAwsS3 bool = false
param awsS3RoleArn string = ''
param awsS3SqsUrl string = ''
param awsS3Table string = 'AWSCloudTrail'

// Azure resource logs (deployed as Azure Policy, covers existing + new resources)
param remediateExistingResources bool = true
@description('Optional: comma-separated IDs of OTHER subscriptions to cover (Activity + resource log policies). Do not list the subscription you deploy into.')
param additionalSubscriptionIds string = ''
param enableKeyVaultLogs bool = false
param enableNsgLogs bool = false
param enableFirewallLogs bool = false
param enableAppGatewayLogs bool = false
param enableAksLogs bool = false
param enableAppServiceLogs bool = false

// Detection foundations
param enableHealthDiagnostics bool = true
param enableAnomalies bool = true
param enableUeba bool = false

param tags object = {}

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

var additionalSubs = empty(additionalSubscriptionIds) ? [] : split(replace(additionalSubscriptionIds, ' ', ''), ',')

var selectedResourceSources = concat(
  enableKeyVaultLogs ? [ { key: 'keyvault', label: 'Key Vault', resourceType: 'Microsoft.KeyVault/vaults' } ] : [],
  enableNsgLogs ? [ { key: 'nsg', label: 'Network Security Group', resourceType: 'Microsoft.Network/networkSecurityGroups' } ] : [],
  enableFirewallLogs ? [ { key: 'firewall', label: 'Azure Firewall', resourceType: 'Microsoft.Network/azureFirewalls' } ] : [],
  enableAppGatewayLogs ? [ { key: 'appgw', label: 'Application Gateway / WAF', resourceType: 'Microsoft.Network/applicationGateways' } ] : [],
  enableAksLogs ? [ { key: 'aks', label: 'AKS', resourceType: 'Microsoft.ContainerService/managedClusters' } ] : [],
  enableAppServiceLogs ? [ { key: 'appservice', label: 'App Service', resourceType: 'Microsoft.Web/sites' } ] : []
)

resource rg 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: resourceGroupName
  location: location
  tags: tags
}

module sentinel 'sentinel.bicep' = {
  scope: rg
  name: 'sentinel-core'
  params: {
    location: location
    workspaceName: workspaceName
    retentionInDays: retentionInDays
    dailyQuotaGb: dailyQuotaGb
    tenantId: tenant().tenantId
    subscriptionId: subscription().subscriptionId
    enableDefenderXdr: enableDefenderXdr
    enableDefenderXdrAlerts: enableDefenderXdrAlerts
    enableDefenderForCloud: enableDefenderForCloud
    enableDefenderForCloudApps: enableDefenderForCloudApps
    enableDefenderForCloudAppsDiscovery: enableDefenderForCloudAppsDiscovery
    enableDefenderForIdentity: enableDefenderForIdentity
    enableDefenderForEndpoint: enableDefenderForEndpoint
    enableDefenderForOffice365: enableDefenderForOffice365
    enableEntraIdProtection: enableEntraIdProtection
    enableO365Exchange: enableO365Exchange
    enableO365SharePoint: enableO365SharePoint
    enableO365Teams: enableO365Teams
    enableInsiderRisk: enableInsiderRisk
    enablePowerBI: enablePowerBI
    enableDynamics365: enableDynamics365
    enableProject: enableProject
    enablePurviewInfoProtection: enablePurviewInfoProtection
    enableMdti: enableMdti
    enableTip: enableTip
    enableAwsCloudTrail: enableAwsCloudTrail
    awsCloudTrailRoleArn: awsCloudTrailRoleArn
    enableAwsS3: enableAwsS3
    awsS3RoleArn: awsS3RoleArn
    awsS3SqsUrl: awsS3SqsUrl
    awsS3Table: awsS3Table
    enableHealthDiagnostics: enableHealthDiagnostics
    enableAnomalies: enableAnomalies
    enableUeba: enableUeba
    tags: tags
  }
}

// Azure Activity: subscription-level diagnostic setting -> workspace
resource activityDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = if (enableAzureActivity) {
  name: 'sentinel-activity-logs'
  properties: {
    workspaceId: sentinel.outputs.workspaceId
    logs: [for c in activityCategories: {
      category: c
      enabled: true
    }]
  }
}

// Key Vault, NSG, Firewall etc: DeployIfNotExists policies at subscription scope
module resourceLogs 'resource-diagnostics-policy.bicep' = if (!empty(selectedResourceSources)) {
  name: 'sentinel-resource-diagnostics'
  params: {
    location: location
    workspaceId: sentinel.outputs.workspaceId
    workspaceSubscriptionId: subscription().subscriptionId
    workspaceResourceGroup: resourceGroupName
    sources: selectedResourceSources
    remediateExisting: remediateExistingResources
  }
}

// ---- Additional subscriptions (per-subscription coverage) ----
module activityOther 'activity-diag.bicep' = [for subId in additionalSubs: if (enableAzureActivity) {
  name: 'sentinel-activity-${subId}'
  scope: subscription(subId)
  params: {
    workspaceId: sentinel.outputs.workspaceId
  }
}]

module resourceLogsOther 'resource-diagnostics-policy.bicep' = [for subId in additionalSubs: if (!empty(selectedResourceSources)) {
  name: 'sentinel-resource-diagnostics-${subId}'
  scope: subscription(subId)
  params: {
    location: location
    workspaceId: sentinel.outputs.workspaceId
    workspaceSubscriptionId: subscription().subscriptionId
    workspaceResourceGroup: resourceGroupName
    sources: selectedResourceSources
    remediateExisting: remediateExistingResources
  }
}]

output workspaceId string = sentinel.outputs.workspaceId
output workspaceName string = workspaceName
output workspaceCustomerId string = sentinel.outputs.workspaceCustomerId
