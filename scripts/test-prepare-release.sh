#!/usr/bin/env bash
# Exercise scripts/prepare-release.sh on throwaway copies of a tiny workspace.
# prepare-release.yml runs this before every prepare, so a regression stops
# the release PR instead of shipping a diff the ship gate refuses.
#
# Usage: bash scripts/test-prepare-release.sh [repo-root]
set -uo pipefail

WT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fails=0

# ws <dir> <unreleased body>: a workspace at 0.5.3 whose lock also holds a
# registry crate at 0.5.3, which must never be touched. CHANGELOG.md has no
# final newline on purpose.
ws() {
  mkdir -p "$1/scripts"
  cp "$WT/Makefile" "$1/" || exit 1
  cp "$WT/scripts/bump-version.sh" "$WT/scripts/prepare-release.sh" "$1/scripts/" || exit 1
  printf '[workspace]\nmembers = ["crates/*"]\n\n[workspace.package]\nversion = "0.5.3"\n\n[package]\nname = "demo"\nversion.workspace = true\n' > "$1/Cargo.toml"
  printf 'version = 4\n\n[[package]]\nname = "demo"\nversion = "0.5.3"\n\n[[package]]\nname = "demo-core"\nversion = "0.5.3"\ndependencies = [\n "other",\n]\n\n[[package]]\nname = "other"\nversion = "0.5.3"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n' > "$1/Cargo.lock"
  printf '# Changelog\n\n## [Unreleased]\n%s\n## [0.5.3] - 2026-01-01\n\n### Fixed\n\n- old' "$2" > "$1/CHANGELOG.md"
  cp -R "$1" "$1.orig"
}

check() { # <name> <condition...>
  local name="$1"; shift
  if "$@"; then echo "ok   - $name"; else echo "FAIL - $name"; fails=$((fails + 1)); fi
}
# Every original line survives, in order: the diff adds and never deletes.
adds_only() { ! diff "$1.orig/$2" "$1/$2" | grep -q '^<'; }
has() { grep -qxF -- "$2" "$1"; }

run() { # <dir> -> stdout of the script, exit in $rc
  out="$(bash "$1/scripts/prepare-release.sh" 2026-02-03 2>/dev/null)"; rc=$?
}

ws "$TMP/patch" $'\n### Fixed\n\n- a fix\n'
run "$TMP/patch"
check "Fixed only is a patch" test "$out" = $'action=open\nversion=0.5.4\nbump=patch'
check "Cargo.toml has the new version" has "$TMP/patch/Cargo.toml" 'version = "0.5.4"'
check "both workspace lock entries move" test "$(grep -c '^version = "0.5.4"$' "$TMP/patch/Cargo.lock")" = 2
check "the registry crate keeps 0.5.3" test "$(grep -c '^version = "0.5.3"$' "$TMP/patch/Cargo.lock")" = 1
check "CHANGELOG.md gains the release heading" has "$TMP/patch/CHANGELOG.md" '## [0.5.4] - 2026-02-03'
check "CHANGELOG.md keeps [Unreleased]" has "$TMP/patch/CHANGELOG.md" '## [Unreleased]'
check "CHANGELOG.md diff is additions only" adds_only "$TMP/patch" CHANGELOG.md
check "CHANGELOG.md still has no final newline" test "$(tail -c1 "$TMP/patch/CHANGELOG.md")" = d
check "Cargo.toml changes one line" test "$(diff "$TMP/patch.orig/Cargo.toml" "$TMP/patch/Cargo.toml" | grep -c '^>')" = 1

ws "$TMP/minor" $'\n### Added\n\n- a feature\n\n### Fixed\n\n- a fix\n'
run "$TMP/minor"
check "Added plus Fixed is a minor" test "$out" = $'action=open\nversion=0.6.0\nbump=minor'

ws "$TMP/security" $'\n### Security\n\n- a guard\n'
run "$TMP/security"
check "Security only is a minor" test "$out" = $'action=open\nversion=0.6.0\nbump=minor'

ws "$TMP/loose" $'\n- a bullet with no subsection\n'
run "$TMP/loose"
check "text outside a subsection is a minor" test "$out" = $'action=open\nversion=0.6.0\nbump=minor'

ws "$TMP/empty" $'\n\n'
run "$TMP/empty"
check "empty [Unreleased] closes" test "$out" = action=close
check "close leaves every file alone" diff -r "$TMP/empty.orig" "$TMP/empty"

ws "$TMP/twice" $'\n### Fixed\n\n- a\n\n## [Unreleased]\n'
run "$TMP/twice"
check "two [Unreleased] headings exit 1" test "$rc" = 1

if [[ "$fails" -gt 0 ]]; then echo "$fails failure(s)"; exit 1; fi
echo "all passed"
