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
