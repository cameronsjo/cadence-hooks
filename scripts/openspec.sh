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

# No telemetry and no npm update check. The first run (or a bumped pin) still
# downloads the pinned packages with npm ci.
export OPENSPEC_TELEMETRY="${OPENSPEC_TELEMETRY:-0}"
export OPENSPEC_NO_UPDATE_CHECK="${OPENSPEC_NO_UPDATE_CHECK:-1}"
# Subcommands that reach outside this repo: `feedback` files a GitHub issue
# upstream with your gh login, `completion` writes your shell rc, `config`
# edits the global config or opens $EDITOR, and `workset` launches an
# opener. None is part of the spec workflow, so they need an explicit opt-in.
# The first argument that is not an option is the subcommand (`--no-color
# feedback` is still feedback).
sub=""
for arg in "$@"; do
  case "$arg" in
    -*) ;;
    *) sub="$arg"; break ;;
  esac
done
case "$sub" in
  feedback | completion | config | workset)
    if [[ "${OPENSPEC_ALLOW_OUTSIDE:-}" != 1 ]]; then
      echo "openspec.sh: '$sub' reaches outside this repo; rerun with OPENSPEC_ALLOW_OUTSIDE=1 to allow it" >&2
      exit 2
    fi
    ;;
  context)
    # `context --code-workspace <path> --force` overwrites any file with
    # workspace JSON, and the skills pre-allow `context`.
    for arg in "$@"; do
      case "$arg" in
        --code-workspace | --code-workspace=*)
          if [[ "${OPENSPEC_ALLOW_OUTSIDE:-}" != 1 ]]; then
            echo "openspec.sh: 'context --code-workspace' writes outside this repo; rerun with OPENSPEC_ALLOW_OUTSIDE=1 to allow it" >&2
            exit 2
          fi
          ;;
      esac
    done
    ;;
esac

cd "$root"
exec "$bin" "$@"
