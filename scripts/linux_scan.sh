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
