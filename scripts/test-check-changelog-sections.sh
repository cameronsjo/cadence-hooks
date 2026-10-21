#!/usr/bin/env bash
# Exercise scripts/check-changelog-sections.sh on throwaway git repos.
# ci.yml runs this before the check itself.
#
# Usage: bash scripts/test-check-changelog-sections.sh [repo-root]
set -uo pipefail

WT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fails=0

export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t
g() { git -C "$repo" -c core.hooksPath=/dev/null -c init.defaultBranch=main "$@" > /dev/null; }

# repo <name> <changelog>: a repo on main with one commit, and branch `feat`.
repo() {
  repo="$TMP/$1"
  mkdir -p "$repo/scripts"
  cp "$WT/scripts/check-changelog-sections.sh" "$repo/scripts/"
  printf '%s' "$2" > "$repo/CHANGELOG.md"
  g init -q && g add -A && g commit -qm base && g branch feat
}
# edit <branch> <perl substitution> <message>: commit an edit on <branch>.
edit() {
  g switch -q "$1"
  perl -0777 -pi -e "$2" "$repo/CHANGELOG.md"
  g commit -qam "$3"
}
run() { # <base> -> exit in $rc, output in $out
  out="$(cd "$repo" && bash scripts/check-changelog-sections.sh "$1" 2>&1)"; rc=$?
}
check() { # <name> <condition...>
  local name="$1"; shift
  if "$@"; then echo "ok   - $name"; else echo "FAIL - $name"; echo "$out" | sed 's/^/       /'; fails=$((fails + 1)); fi
}

empty=$'# Changelog\n\n## [Unreleased]\n\n## [0.1.0] - 2026-01-01\n\n### Fixed\n\n- old\n'
held=$'# Changelog\n\n## [Unreleased]\n\n### Fixed\n\n- a\n\n## [0.1.0] - 2026-01-01\n\n### Fixed\n\n- old\n'
stamp='s/^(## \[Unreleased\]\n)/$1\n## [0.2.0] - 2026-02-01\n/m'

repo ok "$empty"
edit feat 's/^(## \[Unreleased\]\n)/$1\n### Fixed\n\n- new\n/m' add
run main
check "a bullet under [Unreleased] passes" test "$rc" = 0

repo old "$empty"
edit feat 's/^(- old\n)/$1- new\n/m' add
run main
check "a bullet under a released version fails" test "$rc" = 1
check "the failure names the line and heading" grep -qF 'CHANGELOG.md:10: new bullet under "## [0.1.0] - 2026-01-01"' <<< "$out"

repo mergeup "$held"
edit feat 's/^(- a\n)/$1- b\n/m' add
edit main "$stamp" release
g switch -q feat && g merge -q --no-edit main
run main
check "a merge-up under a new release heading fails" test "$rc" = 1
check "it names the new heading" grep -qF 'new bullet under "## [0.2.0] - 2026-02-01"' <<< "$out"

repo prmerge "$held"
edit feat 's/^(- a\n)/$1- b\n/m' add
edit main "$stamp" release
g switch -q main && g merge -q --no-edit feat
run 'HEAD^1'
check "the PR merge commit against its first parent fails the same way" test "$rc" = 1

repo typo "$empty"
edit feat 's/^- old$/- older/m' typo
run main
check "editing a released bullet passes" test "$rc" = 0

repo release "$held"
edit feat "$stamp" release
run main
check "the release stamp itself passes" test "$rc" = 0

repo none "$empty"
g switch -q feat && printf 'x\n' > "$repo/other" && g add other && g commit -qm other
run main
check "no CHANGELOG change passes" test "$rc" = 0

run no-such-ref
check "an unknown base exits 2" test "$rc" = 2

if [[ "$fails" -gt 0 ]]; then echo "$fails failure(s)"; exit 1; fi
echo "all passed"
