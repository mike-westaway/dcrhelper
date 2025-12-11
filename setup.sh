
set -euo pipefail

mkdir -p scripts config

# ------------------------------
# config/map.csv (VM→Pattern→DCR)
# ------------------------------
cat > config/map.csv <<'CSV'
subscriptionId,resourceGroup,vmName,dcrName,pattern,encoding,firstLineRegex,dcrLocation,streamName,destinationAlias,workspaceResourceId
11111111-1111-1111-1111-111111111111,rg-app-eu,vm-app-01,dcr-app-eu,/var/log/app/*.log,utf-8,.*,westeurope,Custom-AppLogs,laDest,/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-monitoring/providers/Microsoft.OperationalInsights/workspaces/la-workspace-01
11111111-1111-1111-1111-111111111111,rg-app-eu,vm-app-02,dcr-app-eu,/data/logs/**/*.log,utf-8,.*,westeurope,Custom-AppLogs,laDest,/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-monitoring/providers/Microsoft.OperationalInsights/workspaces/la-workspace-01
22222222-2222-2222-2222-222222222222,rg-ops-uk,vm-batch-01,dcr-ops-uk,/opt/myapp/logs/**/*.log,utf-8,.*,uksouth,Ops-Stream,opsDest,/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-monitoring/providers/Microsoft.OperationalInsights/workspaces/la-workspace-uk
CSV

# ------------------------------------
# scripts/windows_scan.ps1 (PowerShell)
# ------------------------------------
cat > scripts/windows_scan.ps1 <<'POWERSHELL'
param(
  [string[]]$patterns,
  [int]$limit = 200
)

$ErrorActionPreference = 'SilentlyContinue'
$matched = New-Object System.Collections.Generic.List[string]

# Parent folders of each pattern
$roots = $patterns | ForEach-Object { Split-Path -Parent $_ } | Where-Object { $_ } | Select-Object -Unique

foreach ($root in $roots) {
  try {
    Get-ChildItem -Path $root -Recurse -File | ForEach-Object {
      $full = $_.FullName
      foreach ($pat in $patterns) {
        # Use WildcardPattern to match across the full path
        if ([System.Management.Automation.WildcardPattern]::new($pat, [System.Management.Automation.WildcardOptions]::IgnoreCase).IsMatch($full)) {
          $matched.Add($full)
          break
        }
      }
      if ($matched.Count -ge $limit) { break }
    }
  } catch {}
  if ($matched.Count -ge $limit) { break }
}

# Output compact JSON (for Run Command)
$payload = @{ count = $matched.Count; files = $matched }
$payload | ConvertTo-Json -Depth 4
POWERSHELL

# -------------------------------
# scripts/linux_scan.sh (Bash)
# -------------------------------
cat > scripts/linux_scan.sh <<'BASH'
#!/usr/bin/env bash
# linux_scan.sh: expand glob patterns, cap results, emit JSON (no jq)
set -euo pipefail

PAT_JOINED="${1:-}"
LIMIT="${2:-200}"

IFS='|' read -r -a PATTERNS <<< "$PAT_JOINED"

# Enable ** recursive globs
shopt -s globstar nullglob

declare -a MATCHED
count=0

for pat in "${PATTERNS[@]}"; do
  # Expand the glob; bash globstar makes ** traverse dirs
  for f in $pat; do
    [[ -f "$f" ]] || continue
    MATCHED+=("$f")
    count=$((count+1))
    if (( count >= LIMIT )); then
      break 2
    fi
  done
done

# Minimal JSON writer (escape backslashes and quotes)
printf '{ "count": %d, "files": [' "$count"
for i in "${!MATCHED[@]}"; do
  esc=$(printf '%s' "${MATCHED[$i]}" | sed 's/\\/\\\\/g; s/"/\\"/g')
  [[ $i -gt 0 ]] && printf ', '
  printf '"%s"' "$esc"
done
printf '] }'
BASH
chmod +x scripts/linux_scan.sh

# ------------------------------------
# scripts/build_dcr.ps1 (DCR generator)
# ------------------------------------
cat > scripts/build_dcr.ps1 <<'POWERSHELL'
param(
  [string]$mapCsvPath = "config/map.csv",
  [string]$outDir = "dcr_out",
  [string]$dcrLocationDefault = "westeurope",
  [string]$streamNameDefault = "Custom-AppLogs",
  [string]$destAliasDefault = "laDest",
  [string]$laWorkspaceResourceIdDefault = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-monitoring/providers/Microsoft.OperationalInsights/workspaces/la-workspace-01"
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$rows = Import-Csv -Path $mapCsvPath

# group rows by dcrName
$byDcr = $rows | Group-Object -Property dcrName
foreach ($grp in $byDcr) {
  $dcrName = $grp.Name
  $rowsForDcr = $grp.Group

  $loc = ($rowsForDcr | Where-Object dcrLocation | Select-Object -First 1 -ExpandProperty dcrLocation)
  if (-not $loc) { $loc = $dcrLocationDefault }

  $stream = ($rowsForDcr | Where-Object streamName | Select-Object -First 1 -ExpandProperty streamName)
  if (-not $stream) { $stream = $streamNameDefault }

  $dest = ($rowsForDcr | Where-Object destinationAlias | Select-Object -First 1 -ExpandProperty destinationAlias)
  if (-not $dest) { $dest = $destAliasDefault }

  $laId = ($rowsForDcr | Where-Object workspaceResourceId | Select-Object -First 1 -ExpandProperty workspaceResourceId)
  if (-not $laId) { $laId = $laWorkspaceResourceIdDefault }

  # Merge patterns by encoding+regex
  $grouped = $rowsForDcr | Group-Object { "{0}|{1}" -f ($_.encoding ?? 'utf-8'), ($_.firstLineRegex ?? '.*') }
  $fileCollect = @()
  foreach ($g in $grouped) {
    $parts = $g.Name.Split('|')
    $enc = $parts[0]; if (-not $enc) { $enc = 'utf-8' }
    $rx  = $parts[1]; if (-not $rx)  { $rx  = '.*' }
    $patterns = $g.Group | Select-Object -ExpandProperty pattern | Where-Object { $_ -and $_.Trim() } | Select-Object -Unique
    $fileCollect += [ordered]@{
      filePatterns  = $patterns
      fileEncodings = @($enc)
      multiline     = @{ firstLineRegex = $rx; matchStartOfLine = $true }
    }
  }

  $dcr = [ordered]@{
    location   = $loc
    properties = @{
      dataSources = @{
        extensions = @(
          @{
            streams           = @($stream)
            extensionName     = "FileCollection"
            extensionSettings = @{ fileCollect = $fileCollect }
          }
        )
      }
      destinations = @{
        logAnalytics = @(
          @{
            workspaceResourceId = $laId
            name = $dest
          }
        )
      }
      dataFlows = @(
        @{
          streams      = @($stream)
          destinations = @($dest)
        }
      )
    }
  }

  $outPath = Join-Path $outDir ("dcr_{0}.json" -f $dcrName)
  ($dcr | ConvertTo-Json -Depth 20) | Set-Content -Path $outPath
  Write-Host "Wrote $outPath"
}
POWERSHELL

# -----------------------------------
# scripts/associate.ps1 (install AMA & associate)
# -----------------------------------
cat > scripts/associate.ps1 <<'POWERSHELL'
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
POWERSHELL

# --------------------------------
# azure-pipelines.yml (DevOps CI/CD)
# --------------------------------
cat > azure-pipelines.yml <<'YAML'
trigger:
  branches:
    include:
      - main

variables:
  azureSubscription: 'azure-spn'                # Azure DevOps service connection
  dcrSubscriptionId: '00000000-0000-0000-0000-000000000000'
  dcrResourceGroup:  'rg-monitoring'
  dcrLocationDefault: 'westeurope'
  laWorkspaceResourceIdDefault: '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-monitoring/providers/Microsoft.OperationalInsights/workspaces/la-workspace-01'
  streamNameDefault: 'Custom-AppLogs'
  destinationAliasDefault: 'laDest'
  mapCsvPath: 'config/map.csv'
  maxScanFilesPerVm: '200'
  forceDeployDcr: 'false'

pool:
  vmImage: 'ubuntu-latest'

stages:
# 1) Validate CSV
- stage: Validate_Config
  jobs:
    - job: validate
      steps:
        - task: PowerShell@2
          displayName: 'Check map.csv presence & required columns'
          inputs:
            targetType: 'inline'
            script: |
              $ErrorActionPreference = 'Stop'
              if (-not (Test-Path "$(mapCsvPath)")) { throw "Missing $(mapCsvPath)" }
              $map = Import-Csv -Path "$(mapCsvPath)"
              if ($map.Count -eq 0) { throw "map.csv is empty." }
              $required = @('subscriptionId','resourceGroup','vmName','dcrName','pattern')
              foreach ($c in $required) {
                if (-not ($map | Get-Member -Name $c -MemberType NoteProperty)) { throw "map.csv missing '$c'" }
              }
              Write-Host "map.csv OK."

# 2) Scan all VMs
- stage: Scan_All_VMs
  dependsOn: Validate_Config
  jobs:
    - job: scan
      steps:
        - task: AzureCLI@2
          displayName: 'Run per-VM scan: Windows(PowerShell) / Linux(Bash)'
          inputs:
            azureSubscription: '$(azureSubscription)'
            scriptType: 'ps'
            scriptLocation: 'inlineScript'
            inlineScript: |
              $ErrorActionPreference = 'Stop'
              $outDir = "scan_out"
              New-Item -ItemType Directory -Force -Path $outDir | Out-Null

              $mapRows = Import-Csv -Path "$(mapCsvPath)"
              $rowsByVm = $mapRows | Group-Object { "{0}|{1}|{2}" -f $_.subscriptionId, $_.resourceGroup, $_.vmName }
              $limit = [int]"$(maxScanFilesPerVm)"
              $total = 0

              $winScript = Get-Content -Raw -Path "scripts/windows_scan.ps1"
              $bashScript = Get-Content -Raw -Path "scripts/linux_scan.sh"

              foreach ($group in $rowsByVm) {
                $parts = $group.Name.Split('|')
                $sub = $parts[0]; $rg = $parts[1]; $vm = $parts[2]
                az account set --subscription $sub | Out-Null

                $patterns = $group.Group | Select-Object -ExpandProperty pattern | Where-Object { $_ -and $_.Trim() } | Select-Object -Unique
                if (-not $patterns -or $patterns.Count -eq 0) { Write-Warning "No patterns for $rg/$vm"; continue }

                $osType = az vm show --resource-group $rg --name $vm --query "storageProfile.osDisk.osType" -o tsv
                if (-not $osType) { $osType = "Linux" }

                Write-Host "Scanning $sub/$rg/$vm (OS=$osType) patterns: $($patterns -join ', ')"

                if ($osType -eq "Windows") {
                  $result = az vm run-command invoke --resource-group $rg --name $vm `
                    --command-id RunPowerShellScript `
                    --scripts $winScript `
                    --parameters "patterns=$($patterns -join ' ')" "limit=$limit" `
                    --query "value[0].message" -o tsv
                } else {
                  $joined = ($patterns -join '|')
                  $result = az vm run-command invoke --resource-group $rg --name $vm `
                    --command-id RunShellScript `
                    --scripts "cat >/tmp/linux_scan.sh <<'EOF'\n$bashScript\nEOF\nbash /tmp/linux_scan.sh '$joined' $limit" `
                    --query "value[0].message" -o tsv
                }

                $last = ($result -split "`n")[-1]
                try {
                  $json = $last | ConvertFrom-Json
                  $cnt = [int]$json.count
                  $total += $cnt
                  $outPath = Join-Path $outDir ("{0}_{1}_scan.json" -f $rg, $vm)
                  ($json | ConvertTo-Json -Depth 10) | Set-Content -Path $outPath
                  Write-Host "Saved $outPath (count=$cnt)"
                } catch {
                  Write-Warning "Non-JSON output for $rg/$vm; saving raw."
                  Set-Content -Path (Join-Path $outDir ("{0}_{1}_raw.txt" -f $rg, $vm)) -Value $result
                }
              }

              Write-Host "##vso[task.setvariable variable=totalScanMatches]$total"
              Write-Host "Total scan matches: $total"

        - task: PublishBuildArtifacts@1
          displayName: 'Publish scan artifacts'
          inputs:
            pathToPublish: 'scan_out'
            artifactName: 'vm-scans'
            publishLocation: 'Container'

# 3) Build & deploy DCRs + associate VMs
- stage: Build_And_Deploy_DCRs
  dependsOn: Scan_All_VMs
  condition: or(eq(variables['forceDeployDcr'], 'true'), gt(variables['totalScanMatches'], '0'))
  jobs:
    - job: dcr
      steps:
        - task: AzureCLI@2
          displayName: 'Generate dcr_out/*.json (per dcrName)'
          inputs:
            azureSubscription: '$(azureSubscription)'
            scriptType: 'ps'
            scriptLocation: 'inlineScript'
            inlineScript: |
              & "scripts/build_dcr.ps1" `
                -mapCsvPath "$(mapCsvPath)" `
                -outDir "dcr_out" `
                -dcrLocationDefault "$(dcrLocationDefault)" `
                -streamNameDefault "$(streamNameDefault)" `
                -destAliasDefault "$(destinationAliasDefault)" `
                -laWorkspaceResourceIdDefault "$(laWorkspaceResourceIdDefault)"

        - task: AzureCLI@2
          displayName: 'Deploy each DCR (ARM group deployments)'
          inputs:
            azureSubscription: '$(azureSubscription)'
            scriptType: 'ps'
            scriptLocation: 'inlineScript'
            inlineScript: |
              $ErrorActionPreference = 'Stop'
              az account set --subscription "$(dcrSubscriptionId)" | Out-Null
              $files = Get-ChildItem -Path "dcr_out" -Filter "dcr_*.json"
              if ($files.Count -eq 0) { throw "No DCR payloads" }

              foreach ($f in $files) {
                $dcrName = $f.BaseName.Substring(4)
                $tmplPath = Join-Path "dcr_out" ("deploy_{0}.json" -f $dcrName)
                $props = Get-Content -Raw -Path $f.FullName

                @"
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.Insights/dataCollectionRules",
      "apiVersion": "2022-06-01",
      "name": "$dcrName",
      "location": "$(dcrLocationDefault)",
      "properties": $props
    }
  ]
}
"@ | Set-Content -Path $tmplPath

                $state = az deployment group create `
                  --resource-group "$(dcrResourceGroup)" `
                  --name "dcr-$dcrName-$(Get-Date -UFormat %s)" `
                  --template-file $tmplPath `
                  --query "properties.provisioningState" -o tsv
                Write-Host "Deployed $dcrName (state=$state)"
              }

        - task: AzureCLI@2
          displayName: 'Install AMA and associate VMs'
          inputs:
            azureSubscription: '$(azureSubscription)'
            scriptType: 'ps'
            scriptLocation: 'inlineScript'
            inlineScript: |
              & "scripts/associate.ps1" `
                -mapCsvPath "$(mapCsvPath)" `
                -dcrSubscriptionId "$(dcrSubscriptionId)" `
                -dcrResourceGroup "$(dcrResourceGroup)"

        - task: PublishBuildArtifacts@1
          displayName: 'Publish DCR payloads'
          inputs:
            pathToPublish: 'dcr_out'
            artifactName: 'dcrs'
            publishLocation: 'Container'
YAML

# ---------------
# README.md
# ---------------
cat > README.md <<'MD'
# dcrhelper

Azure DevOps pipeline + scripts to:
1. **Scan** Azure VMs for files matching glob patterns  
2. **Build** one **Data Collection Rule (DCR)** per `dcrName` aggregating patterns  
3. **Deploy** each DCR and **associate** mapped VMs (installs AMA as needed)

## How it works

- **Mapping** comes from `config/map.csv` (one row per VM+pattern+DCR).
- **Windows** VMs scan via **RunPowerShellScript** (`scripts/windows_scan.ps1`).
- **Linux** VMs scan via **RunShellScript** using **Bash** (`scripts/linux_scan.sh`) with `globstar` for `**` recursion.
- DCRs use **FileCollection** extension with per‑pattern **encoding** and **firstLineRegex**, then send to **Log Analytics**.

See Microsoft Learn overview and samples for DCR/AMA details:
- Data collection rules in Azure Monitor [4](https://learn.microsoft.com/en-us/azure/azure-monitor/data-collection/data-collection-rule-overview)  
- Sample data collection rules (DCRs) [5](https://learn.microsoft.com/en-us/azure/azure-monitor/data-collection/data-collection-rule-samples)

Your internal notes on wildcard behavior: [DCR Wildcard Helper.docx](https://microsoft.sharepoint.com/teams/GSKTeam/_layouts/15/Doc.aspx?sourcedoc=%7B2CEAA142-1208-40F5-B013-08A9081FC670%7D&file=DCR%20Wildcard%20Helper.docx&action=default&mobileredirect=true&DefaultItemOpen=1&EntityRepresentationId=0c571c88-46cb-4c81-962b-33a7068b8bf9) (consider copying into `/docs`). [1](https://microsofteur-my.sharepoint.com/personal/miwestaw_microsoft_com/_layouts/15/Doc.aspx?sourcedoc=%7B350DA624-EA06-45E9-BBBA-8B32126D4C35%7D&file=DCR%20Wildcard%20Helper.docx&action=default&mobileredirect=true&DefaultItemOpen=1)

## Quick start

1. Edit **pipeline variables** in `azure-pipelines.yml`:
   - `azureSubscription` → your Azure DevOps service connection
   - `dcrSubscriptionId`, `dcrResourceGroup`, `dcrLocationDefault`
   - `laWorkspaceResourceIdDefault`, `streamNameDefault`, `destinationAliasDefault`

2. Populate **`config/map.csv`** (see sample header in file).

3. Commit, push, and run the pipeline.  
   Stage flow: **Validate → Scan → Build&Deploy → Associate**.

## Notes

- Patterns are **shell globs**. Linux supports `**` via Bash `globstar`. Windows scanning walks directories and matches with `WildcardPattern`.
- Over‑matching patterns are harmless; AMA only collects where files exist.
- Multiple DCRs are fine; associate any VM to multiple DCRs when needed.
MD

echo "✅ Files written. Now 'git add . && git commit -m \"dcrhelper scaffold\" && git push

