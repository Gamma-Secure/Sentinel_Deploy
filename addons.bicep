// Tenant add-ons: Entra ID logs + Azure Activity for a whole management group.
// Deployed separately from the core template so a permissions failure here can never block Sentinel itself.
// Needs Owner at the tenant root ("/"). The workspace must already exist (deploy the core template first).
targetScope = 'subscription'

param location string
param resourceGroupName string
param workspaceName string

param enableEntraSignInLogs bool = false
param enableEntraAuditLogs bool = false
param enableEntraRiskLogs bool = false
param enableEntraGraphLogs bool = false

param enableActivityPolicy bool = false
param managementGroupId string = ''

var entraSignIn = enableEntraSignInLogs ? [ 'SignInLogs', 'NonInteractiveUserSignInLogs', 'ServicePrincipalSignInLogs', 'ManagedIdentitySignInLogs' ] : []
var entraAudit = enableEntraAuditLogs ? [ 'AuditLogs', 'ProvisioningLogs' ] : []
var entraRisk = enableEntraRiskLogs ? [ 'RiskyUsers', 'UserRiskEvents', 'RiskyServicePrincipals', 'ServicePrincipalRiskEvents' ] : []
var entraGraph = enableEntraGraphLogs ? [ 'MicrosoftGraphActivityLogs' ] : []
var entraCategories = concat(entraSignIn, entraAudit, entraRisk, entraGraph)

module tenantScope 'tenant-scope.bicep' = if (!empty(entraCategories) || enableActivityPolicy) {
  name: 'sentinel-tenant-scope'
  scope: tenant()
  params: {
    location: location
    workspaceId: resourceId(subscription().subscriptionId, resourceGroupName, 'Microsoft.OperationalInsights/workspaces', workspaceName)
    subscriptionId: subscription().subscriptionId
    resourceGroupName: resourceGroupName
    entraCategories: entraCategories
    enableActivityPolicy: enableActivityPolicy
    managementGroupId: managementGroupId
  }
}
