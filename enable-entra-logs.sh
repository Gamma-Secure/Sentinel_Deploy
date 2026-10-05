#!/usr/bin/env bash
# Sends Entra ID logs to the Sentinel workspace. Run in Azure Cloud Shell (bash) as a
# Global Administrator or Security Administrator who can also write to the workspace.
# Usage: ./enable-entra-logs.sh "<workspace resource ID>" [setting-name]
# Entra allows at most 5 diagnostic settings per tenant, so this lists what exists first.
set -euo pipefail
WS_ID="${1:?Pass the workspace resource ID}"
NAME="${2:-gammasecure-entra-logs}"
API="2017-04-01-preview"
URI="https://management.azure.com/providers/microsoft.aadiam/diagnosticSettings"
# Trim categories you don't need. RiskyUsers/UserRiskEvents need P2; MicrosoftGraphActivityLogs is high volume.
CATS=(SignInLogs NonInteractiveUserSignInLogs ServicePrincipalSignInLogs ManagedIdentitySignInLogs AuditLogs ProvisioningLogs)

echo "Existing Entra diagnostic settings:"
az rest --method get --uri "$URI?api-version=$API" \
  --query "value[].{name:name, workspace:properties.workspaceId, eventHub:properties.eventHubName, storage:properties.storageAccountId}" -o table
COUNT=$(az rest --method get --uri "$URI?api-version=$API" --query "length(value)" -o tsv)
EXISTS=$(az rest --method get --uri "$URI?api-version=$API" --query "length(value[?name=='$NAME'])" -o tsv)
if [ "$COUNT" -ge 5 ] && [ "$EXISTS" = "0" ]; then
  echo "The tenant already has 5 diagnostic settings (the maximum). Delete one you no longer need, or add this workspace to an existing setting in the Entra admin center, then rerun." >&2
  exit 1
fi

LOGS=$(printf '{"category":"%s","enabled":true},' "${CATS[@]}"); LOGS="[${LOGS%,}]"
az rest --method put --uri "$URI/$NAME?api-version=$API" \
  --body "{\"properties\":{\"workspaceId\":\"$WS_ID\",\"logs\":$LOGS}}"
echo "Done: $NAME. Sign-in rows appear in SigninLogs within about 15-30 minutes."
