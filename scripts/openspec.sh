#!/usr/bin/env bash
# Run the pinned OpenSpec CLI against this repo's openspec/ tree.
#
# The version and every transitive package's integrity hash live in
# scripts/openspec/package-lock.json, so this installs exactly what was
# reviewed (npm ci, install scripts off) instead of whatever `npx` resolves
# today. CI's openspec job runs it the same way.
#
# Usage:
#   scripts/openspec.sh validate --all --strict --no-interactive
#   scripts/openspec.sh list --specs
#   scripts/openspec.sh <any openspec subcommand>
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pin="$root/scripts/openspec"
bin="$pin/node_modules/.bin/openspec"

# Reinstall when the lockfile is newer than the install, so a bumped pin is
# picked up without a manual clean.
if [[ ! -x "$bin" || "$pin/package-lock.json" -nt "$pin/node_modules/.package-lock.json" ]]; then
  npm ci --prefix "$pin" --ignore-scripts --no-audit --no-fund --loglevel=error --update-notifier=false >&2
fi

# No telemetry and no npm update check: a run makes no network call.
export OPENSPEC_TELEMETRY="${OPENSPEC_TELEMETRY:-0}"
export OPENSPEC_NO_UPDATE_CHECK="${OPENSPEC_NO_UPDATE_CHECK:-1}"
cd "$root"
exec "$bin" "$@"
