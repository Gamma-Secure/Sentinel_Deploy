param location string
param workspaceName string
param retentionInDays int
param dailyQuotaGb int
param tenantId string
param subscriptionId string
param tags object

// Microsoft Defender
param enableDefenderXdr bool
param enableDefenderXdrAlerts bool
param enableDefenderForCloud bool
param enableDefenderForCloudApps bool
param enableDefenderForCloudAppsDiscovery bool
param enableDefenderForIdentity bool
param enableDefenderForEndpoint bool
param enableDefenderForOffice365 bool
// Entra
param enableEntraIdProtection bool
// Microsoft 365
param enableO365Exchange bool
param enableO365SharePoint bool
param enableO365Teams bool
param enableInsiderRisk bool
param enablePowerBI bool
param enableDynamics365 bool
param enableProject bool
param enablePurviewInfoProtection bool
// Threat intelligence
param enableMdti bool
param enableTip bool
// AWS
param enableAwsCloudTrail bool
param awsCloudTrailRoleArn string
param enableAwsS3 bool
param awsS3RoleArn string
param awsS3SqsUrl string
param awsS3Table string

var allHistory = '1970-01-01T00:00:00.000Z'
var enableO365 = enableO365Exchange || enableO365SharePoint || enableO365Teams

resource law 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: workspaceName
  location: location
  tags: tags
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: retentionInDays
    workspaceCapping: dailyQuotaGb > 0 ? { dailyQuotaGb: dailyQuotaGb } : null
  }
}

resource onboard 'Microsoft.SecurityInsights/onboardingStates@2024-03-01' = {
  name: 'default'
  scope: law
  properties: {}
}

// ---------- Stable API (2025-09-01) ----------

resource defenderForCloud 'Microsoft.SecurityInsights/dataConnectors@2025-09-01' = if (enableDefenderForCloud) {
  name: guid(law.id, 'AzureSecurityCenter')
  scope: law
  kind: 'AzureSecurityCenter'
  dependsOn: [ onboard ]
  properties: {
    subscriptionId: subscriptionId
    dataTypes: { alerts: { state: 'Enabled' } }
  }
}

resource entraProtection 'Microsoft.SecurityInsights/dataConnectors@2025-09-01' = if (enableEntraIdProtection) {
  name: guid(law.id, 'AzureActiveDirectory')
  scope: law
  kind: 'AzureActiveDirectory'
  dependsOn: [ onboard ]
  properties: {
    tenantId: tenantId
    dataTypes: { alerts: { state: 'Enabled' } }
  }
}

resource defenderForIdentity 'Microsoft.SecurityInsights/dataConnectors@2025-09-01' = if (enableDefenderForIdentity) {
  name: guid(law.id, 'AzureAdvancedThreatProtection')
  scope: law
  kind: 'AzureAdvancedThreatProtection'
  dependsOn: [ onboard ]
  properties: {
    tenantId: tenantId
    dataTypes: { alerts: { state: 'Enabled' } }
  }
}

resource defenderForCloudApps 'Microsoft.SecurityInsights/dataConnectors@2025-09-01' = if (enableDefenderForCloudApps) {
  name: guid(law.id, 'MicrosoftCloudAppSecurity')
  scope: law
  kind: 'MicrosoftCloudAppSecurity'
  dependsOn: [ onboard ]
  properties: {
    tenantId: tenantId
    dataTypes: {
      alerts: { state: 'Enabled' }
      discoveryLogs: { state: (enableDefenderForCloudAppsDiscovery ? 'Enabled' : 'Disabled') }
    }
  }
}

resource defenderForEndpoint 'Microsoft.SecurityInsights/dataConnectors@2025-09-01' = if (enableDefenderForEndpoint) {
  name: guid(law.id, 'MicrosoftDefenderAdvancedThreatProtection')
  scope: law
  kind: 'MicrosoftDefenderAdvancedThreatProtection'
  dependsOn: [ onboard ]
  properties: {
    tenantId: tenantId
    dataTypes: { alerts: { state: 'Enabled' } }
  }
}

resource office365 'Microsoft.SecurityInsights/dataConnectors@2025-09-01' = if (enableO365) {
  name: guid(law.id, 'Office365')
  scope: law
  kind: 'Office365'
  dependsOn: [ onboard ]
  properties: {
    tenantId: tenantId
    dataTypes: {
      exchange: { state: (enableO365Exchange ? 'Enabled' : 'Disabled') }
      sharePoint: { state: (enableO365SharePoint ? 'Enabled' : 'Disabled') }
      teams: { state: (enableO365Teams ? 'Enabled' : 'Disabled') }
    }
  }
}

resource mdti 'Microsoft.SecurityInsights/dataConnectors@2025-09-01' = if (enableMdti) {
  name: guid(law.id, 'MicrosoftThreatIntelligence')
  scope: law
  kind: 'MicrosoftThreatIntelligence'
  dependsOn: [ onboard ]
  properties: {
    tenantId: tenantId
    dataTypes: {
      microsoftEmergingThreatFeed: {
        lookbackPeriod: allHistory
        state: 'Enabled'
      }
    }
  }
}

resource tip 'Microsoft.SecurityInsights/dataConnectors@2025-09-01' = if (enableTip) {
  name: guid(law.id, 'ThreatIntelligence')
  scope: law
  kind: 'ThreatIntelligence'
  dependsOn: [ onboard ]
  properties: {
    tenantId: tenantId
    tipLookbackPeriod: allHistory
    dataTypes: { indicators: { state: 'Enabled' } }
  }
}

resource awsCloudTrail 'Microsoft.SecurityInsights/dataConnectors@2025-09-01' = if (enableAwsCloudTrail) {
  name: guid(law.id, 'AmazonWebServicesCloudTrail')
  scope: law
  kind: 'AmazonWebServicesCloudTrail'
  dependsOn: [ onboard ]
  properties: {
    awsRoleArn: awsCloudTrailRoleArn
    dataTypes: { logs: { state: 'Enabled' } }
  }
}

// ---------- Preview API only (no stable version exposes these kinds) ----------

resource defenderXdr 'Microsoft.SecurityInsights/dataConnectors@2025-07-01-preview' = if (enableDefenderXdr) {
  name: guid(law.id, 'MicrosoftThreatProtection')
  scope: law
  kind: 'MicrosoftThreatProtection'
  dependsOn: [ onboard ]
  properties: {
    tenantId: tenantId
    dataTypes: {
      incidents: { state: 'Enabled' }
      alerts: { state: enableDefenderXdrAlerts ? 'Enabled' : 'Disabled' }
    }
  }
}

resource defenderForOffice365 'Microsoft.SecurityInsights/dataConnectors@2025-07-01-preview' = if (enableDefenderForOffice365) {
  name: guid(law.id, 'OfficeATP')
  scope: law
  kind: 'OfficeATP'
  dependsOn: [ onboard ]
  properties: {
    tenantId: tenantId
    dataTypes: { alerts: { state: 'Enabled' } }
  }
}

resource insiderRisk 'Microsoft.SecurityInsights/dataConnectors@2025-07-01-preview' = if (enableInsiderRisk) {
  name: guid(law.id, 'OfficeIRM')
  scope: law
  kind: 'OfficeIRM'
  dependsOn: [ onboard ]
  properties: {
    tenantId: tenantId
    dataTypes: { alerts: { state: 'Enabled' } }
  }
}

resource powerBI 'Microsoft.SecurityInsights/dataConnectors@2025-07-01-preview' = if (enablePowerBI) {
  name: guid(law.id, 'OfficePowerBI')
  scope: law
  kind: 'OfficePowerBI'
  dependsOn: [ onboard ]
  properties: {
    tenantId: tenantId
    dataTypes: { logs: { state: 'Enabled' } }
  }
}

resource dynamics365 'Microsoft.SecurityInsights/dataConnectors@2025-07-01-preview' = if (enableDynamics365) {
  name: guid(law.id, 'Dynamics365')
  scope: law
  kind: 'Dynamics365'
  dependsOn: [ onboard ]
  properties: {
    tenantId: tenantId
    dataTypes: { dynamics365CdsActivities: { state: 'Enabled' } }
  }
}

resource project 'Microsoft.SecurityInsights/dataConnectors@2025-07-01-preview' = if (enableProject) {
  name: guid(law.id, 'Office365Project')
  scope: law
  kind: 'Office365Project'
  dependsOn: [ onboard ]
  properties: {
    tenantId: tenantId
    dataTypes: { logs: { state: 'Enabled' } }
  }
}

resource purviewInfoProtection 'Microsoft.SecurityInsights/dataConnectors@2025-07-01-preview' = if (enablePurviewInfoProtection) {
  name: guid(law.id, 'MicrosoftPurviewInformationProtection')
  scope: law
  kind: 'MicrosoftPurviewInformationProtection'
  dependsOn: [ onboard ]
  properties: {
    tenantId: tenantId
    dataTypes: { logs: { state: 'Enabled' } }
  }
}

resource awsS3 'Microsoft.SecurityInsights/dataConnectors@2025-07-01-preview' = if (enableAwsS3) {
  name: guid(law.id, 'AmazonWebServicesS3', awsS3Table)
  scope: law
  kind: 'AmazonWebServicesS3'
  dependsOn: [ onboard ]
  properties: {
    destinationTable: awsS3Table
    roleArn: awsS3RoleArn
    sqsUrls: [ awsS3SqsUrl ]
    dataTypes: { logs: { state: 'Enabled' } }
  }
}

output workspaceId string = law.id
output workspaceCustomerId string = law.properties.customerId
