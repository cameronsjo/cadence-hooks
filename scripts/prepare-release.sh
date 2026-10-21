#!/usr/bin/env bash
# Prepare the next release from CHANGELOG.md's [Unreleased] section
# (cadence-ecosystem ADR-0044). Run from a clean checkout of main by
# .github/workflows/prepare-release.yml; safe to run by hand.
#
# Usage: scripts/prepare-release.sh [YYYY-MM-DD]   (date defaults to today, UTC)
#
# Prints `action=close` when [Unreleased] is empty. Otherwise bumps the version
# (`### Fixed` only -> patch, anything else -> minor) and prints `action=open`,
# `version=X.Y.Z`, `bump=patch|minor`. It edits exactly three files, in a shape
# the ship gate accepts:
#   Cargo.toml    `make bump` changes the one [workspace.package] version line
#   Cargo.lock    the workspace members' `version` lines, nothing else
#   CHANGELOG.md  additions only: a `## [X.Y.Z] - DATE` heading goes in under
#                 `## [Unreleased]`, which stays and is left empty
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATE="${1:-$(date -u +%Y-%m-%d)}"
[[ "$DATE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || { echo "bad date: $DATE" >&2; exit 2; }
CHANGELOG="$ROOT/CHANGELOG.md"

# The [Unreleased] body: every line after its heading, up to the next `## `.
unreleased() {
  awk '/^## \[Unreleased\]$/ {f = 1; next} f && /^## / {exit} f' "$CHANGELOG"
}

# kind <body>: empty | patch | minor. Anything that is not a `### Fixed`
# subsection (another heading, or text before the first heading) is minor.
kind() {
  awk '
    /^[[:space:]]*$/ {next}
    /^### / {h = $0; sub(/^### /, "", h); sub(/[[:space:]]+$/, "", h); if (h != "Fixed") minor = 1; seen = 1; next}
    {any = 1; if (!seen) minor = 1}
    END {print (!any && !seen) ? "empty" : (minor ? "minor" : "patch")}'
}

heads="$(grep -c '^## \[Unreleased\]$' "$CHANGELOG" || true)"
[[ "$heads" == 1 ]] || { echo "CHANGELOG.md has ${heads} '## [Unreleased]' headings, expected 1" >&2; exit 1; }

bump="$(unreleased | kind)"
if [[ "$bump" == empty ]]; then
  echo "action=close"
  exit 0
fi

current="$(awk '/^\[/ {s = $0; next} s == "[workspace.package]" && /^version = "/ {
  v = $0; sub(/^version = "/, "", v); sub(/"$/, "", v); print v; exit}' "$ROOT/Cargo.toml")"
[[ "$current" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] \
  || { echo "no X.Y.Z [workspace.package] version in Cargo.toml: '${current}'" >&2; exit 1; }
major="${BASH_REMATCH[1]}" minor="${BASH_REMATCH[2]}" patch="${BASH_REMATCH[3]}"
if [[ "$bump" == minor ]]; then
  version="${major}.$((minor + 1)).0"
else
  version="${major}.${minor}.$((patch + 1))"
fi
if grep -q "^## \[${version//./\\.}\]" "$CHANGELOG"; then
  echo "CHANGELOG.md already has a ## [${version}] section" >&2
  exit 1
fi

make -C "$ROOT" --no-print-directory bump VERSION="$version" >&2

# Workspace members are the lock entries with no `source` line. Each entry is
# buffered whole because `source` follows `version`.
lock="$ROOT/Cargo.lock"
awk -v old="version = \"${current}\"" -v new="version = \"${version}\"" '
  function flush(   i) {
    for (i = 1; i <= n; i++) print ((!src && buf[i] == old) ? new : buf[i])
    n = 0; src = 0
  }
  /^\[\[package\]\]$/ {flush()}
  /^source = / {src = 1}
  {buf[++n] = $0}
  END {flush()}' "$lock" > "$lock.next"
mv "$lock.next" "$lock"

# perl, not awk: awk would add a final newline the file may lack, and that
# shows up as a deleted line, which the gate refuses.
HEADING="## [${version}] - ${DATE}" perl -0777 -pi -e \
  's/^(## \[Unreleased\]\n)/$1\n$ENV{HEADING}\n/m' "$CHANGELOG"

printf 'action=open\nversion=%s\nbump=%s\n' "$version" "$bump"
