#!/usr/bin/env bash
# Fail when this branch adds a CHANGELOG.md bullet outside `## [Unreleased]`.
#
# A release commit on main adds a `## [X.Y.Z]` heading under `## [Unreleased]`
# (scripts/prepare-release.sh). A branch cut before it whose bullet sits under
# the old heading then merges cleanly, with the bullet under the new version:
# a release that does not contain the change. No conflict fires, so CI runs
# this instead.
#
# Usage: scripts/check-changelog-sections.sh [BASE]   (BASE defaults to origin/main)
#
# Judges `git diff BASE...HEAD -- CHANGELOG.md`. A top-level bullet (`- `) in a
# hunk that deletes nothing is a new entry and must sit under `## [Unreleased]`
# in HEAD's CHANGELOG.md. A hunk that also deletes lines edits an existing
# entry, and is left alone. Exit 0 when every new bullet is in place, 1 when
# one is not, 2 on a git error.
set -euo pipefail

BASE="${1:-origin/main}"
cd "$(dirname "${BASH_SOURCE[0]}")/.."

diff="$(git diff -U0 --no-color --no-ext-diff "${BASE}...HEAD" -- CHANGELOG.md)" || exit 2

# New-file line numbers of the new top-level bullets.
lines="$(awk '
  /^@@ / {
    hunk = 1
    split($2, old, ","); dels = (old[2] == "") ? 1 : old[2] + 0
    split($3, new, ","); ln = substr(new[1], 2) + 0
    next
  }
  !hunk {next}
  /^\+/ {if (dels == 0 && substr($0, 2, 2) == "- ") print ln; ln++}
' <<< "$diff")"

if [[ -z "$lines" ]]; then
  echo "CHANGELOG.md: no new bullets"
  exit 0
fi

git show "HEAD:CHANGELOG.md" | awk -v want="$lines" '
  BEGIN {n = split(want, w, "\n"); for (i = 1; i <= n; i++) need[w[i]] = 1}
  /^## / {heading = $0}
  (NR in need) && heading != "## [Unreleased]" {
    printf "CHANGELOG.md:%d: new bullet under \"%s\", not \"## [Unreleased]\"\n", NR, heading
    bad++
  }
  END {
    if (bad) {
      print "Move each one under ## [Unreleased]. A release heading that landed on main after this branch was cut sits above it; a merge-up does not move the bullet."
      exit 1
    }
    print "CHANGELOG.md: every new bullet is under [Unreleased]"
  }'
