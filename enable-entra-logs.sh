#!/usr/bin/env bash
# Sends Entra ID logs to the Sentinel workspace. Run in Azure Cloud Shell (bash) as a
# Global Administrator or Security Administrator who can also write to the workspace.
# Usage: ./enable-entra-logs.sh "<workspace resource ID>"   (the workspaceId output of the deployment)
set -euo pipefail
WS_ID="${1:?Pass the workspace resource ID}"
# Trim categories you don't need. RiskyUsers/UserRiskEvents need P2; MicrosoftGraphActivityLogs is high volume.
CATS=(SignInLogs NonInteractiveUserSignInLogs ServicePrincipalSignInLogs ManagedIdentitySignInLogs AuditLogs ProvisioningLogs)
LOGS=$(printf '{"category":"%s","enabled":true},' "${CATS[@]}"); LOGS="[${LOGS%,}]"
az rest --method put \
  --uri "https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings/sentinel-entra-logs?api-version=2017-04-01-preview" \
  --body "{\"properties\":{\"workspaceId\":\"$WS_ID\",\"logs\":$LOGS}}"
