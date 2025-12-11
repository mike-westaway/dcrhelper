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
