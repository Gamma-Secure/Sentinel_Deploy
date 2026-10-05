#!/usr/bin/env bash
# Sends the Activity Log of EVERY subscription under a management group to the Sentinel workspace,
# using an Azure Policy (DeployIfNotExists). Run in Cloud Shell (bash) as Owner on the management group.
# Usage: ./enable-activity-policy.sh <management-group-id> "<workspace resource ID>" <region>
# (workspace resource ID = the workspaceId output of the wizard deployment; region e.g. uksouth)
set -euo pipefail
MG="${1:?management group ID}"; WS_ID="${2:?workspace resource ID}"; LOC="${3:-uksouth}"
OUT=$(az deployment mg create --management-group-id "$MG" --location "$LOC" \
  --template-file activity-policy-mg.bicep --parameters location="$LOC" workspaceId="$WS_ID" \
  --query properties.outputs.principalId.value -o tsv)
# The policy identity also needs to write to the workspace. Scope it to the workspace's resource group.
RG_ID="${WS_ID%/providers/*}"
az role assignment create --assignee-object-id "$OUT" --assignee-principal-type ServicePrincipal \
  --role "Log Analytics Contributor" --scope "$RG_ID"
echo "Done. After ~30 min, remediate existing subscriptions:"
echo "az policy remediation create -n activity-fix --management-group $MG --policy-assignment gammasecure-activity"
