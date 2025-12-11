param(
  [string]$mapCsvPath = "config/map.csv",
  [string]$dcrSubscriptionId,
  [string]$dcrResourceGroup
)

$ErrorActionPreference = 'Stop'
$rows = Import-Csv -Path $mapCsvPath
$pairs = $rows | Select-Object subscriptionId,resourceGroup,vmName,dcrName -Unique

foreach ($p in $pairs) {
  $sub = $p.subscriptionId
  $rg  = $p.resourceGroup
  $vm  = $p.vmName
  $dcr = $p.dcrName

  az account set --subscription $sub | Out-Null

  $osType = az vm show --resource-group $rg --name $vm --query "storageProfile.osDisk.osType" -o tsv
  if (-not $osType) { $osType = "Linux" }

  $vmId = "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.Compute/virtualMachines/$vm"
  Write-Host "Associating $vmId with DCR '$dcr' (OS=$osType)"

  if ($osType -eq "Windows") {
    az vm extension set --ids $vmId --name AzureMonitorWindowsAgent --publisher Microsoft.Azure.Monitor --force-update --no-wait | Out-Null
  } else {
    az vm extension set --ids $vmId --name AzureMonitorLinuxAgent --publisher Microsoft.Azure.Monitor --force-update --no-wait | Out-Null
  }

  $dcrId = "/subscriptions/$dcrSubscriptionId/resourceGroups/$dcrResourceGroup/providers/Microsoft.Insights/dataCollectionRules/$dcr"

  az monitor data-collection rule association create `
    --name "assoc-$vm-$dcr" `
    --resource $vmId `
    --rule-id $dcrId `
    --type azurevm `
    --only-show-errors | Out-Null

  Write-Host "OK: assoc-$vm-$dcr"
}
