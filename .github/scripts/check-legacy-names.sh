#!/usr/bin/env bash
#
# Naming CI gate: fail on any new legacy product-name reference in the
# migration-owned production surfaces, and on stale allowlist entries.
#
# Scope (tracked files only): the Rust workspace, the Rust production image
# definition, the Rust compose files, the new UI sources, and package.json.
# The legacy PHP/JS runtime (snappymail/, dev/, plugins/, integrations/) is
# intentionally out of scope until its removal phases run. Note: `git grep`
# sees tracked files only, so the gate evaluates committed code in CI.
#
# Usage: .github/scripts/check-legacy-names.sh [repo-root]
# Exit 0 when every hit is allowlisted and every entry is live; exit 1
# otherwise, listing the offending lines.
set -euo pipefail

ROOT="${1:-$(git rev-parse --show-toplevel)}"
cd "$ROOT"

ALLOWLIST=".github/naming-allowlist.txt"
SCOPE=(
  frickmail-server
  .docker/release/rust/Dockerfile
  docker-compose.rust.yml
  docker-compose.rust-production.yml
  frickmail-ui
  package.json
)
PATTERN='snappymail|rainloop'

existing=()
for path in "${SCOPE[@]}"; do
  if [ -e "$path" ]; then
    existing+=("$path")
  fi
done

mapfile -t hits < <(git grep -n -i -E -e "$PATTERN" -- "${existing[@]}" || true)

declare -a prefixes=()
declare -a patterns=()
declare -a used=()
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in
    ''|'#'*) continue ;;
  esac
  IFS='|' read -r prefix pattern _owner _phase _reason <<< "$line"
  prefixes+=("$prefix")
  patterns+=("$pattern")
  used+=(0)
done < "$ALLOWLIST"

failures=0
for hit in ${hits[@]+"${hits[@]}"}; do
  file="${hit%%:*}"
  content="${hit#*:}"
  content="${content#*:}"
  matched=0
  for i in "${!prefixes[@]}"; do
    if [[ "$file" == "${prefixes[$i]}"* ]] && printf '%s' "$content" | grep -E -q -i -e "${patterns[$i]}"; then
      matched=1
      used[$i]=1
      break
    fi
  done
  if [ "$matched" -eq 0 ]; then
    echo "UNALLOWLISTED legacy-name reference: $hit"
    failures=1
  fi
done

index=0
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in
    ''|'#'*) continue ;;
  esac
  if [ "${used[$index]}" -eq 0 ]; then
    echo "STALE allowlist entry (matches nothing): $line"
    failures=1
  fi
  index=$((index + 1))
done < "$ALLOWLIST"

if [ "$failures" -eq 0 ]; then
  echo "naming gate passed: ${#hits[@]} tracked hit(s) across ${#prefixes[@]} allowlist entries, none stale."
fi
exit "$failures"
