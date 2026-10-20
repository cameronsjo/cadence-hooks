#!/usr/bin/env bash
# Point the generated OpenSpec skills and /opsx commands at the pinned CLI.
#
# `openspec init` and `openspec update` write files that run a bare
# `openspec`, pre-allowed by `allowed-tools: Bash(openspec:*)`. Here that
# would run whatever `openspec` is on PATH, unpinned, with no prompt; with
# none on PATH an agent tends to reach for `npx openspec`, which on npm is an
# unrelated package. This rewrites the allowance to the wrapper and adds a
# note under each file's frontmatter. tests/openspec_skills.rs fails
# until it has run, so rerun it after every `openspec update`. Idempotent.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
marker='<!-- cadence-hooks: pinned openspec CLI -->'
note="$marker
**In this repo, run every \`openspec ...\` command below as \`scripts/openspec.sh ...\`** (same arguments). It runs the pinned CLI from \`scripts/openspec/package-lock.json\`. Never run \`npx openspec\`: that npm name is an unrelated package."

shopt -s nullglob
for f in "$root"/.claude/skills/openspec-*/SKILL.md "$root"/.claude/commands/opsx/*.md "$root"/.agents/skills/openspec-*/SKILL.md; do
  sed -i.bak 's#^allowed-tools: Bash(openspec:\*)$#allowed-tools: Bash(scripts/openspec.sh:*)#' "$f"
  rm -f "$f.bak"
  if ! grep -qF "$marker" "$f"; then
    # Insert the note after the closing frontmatter delimiter (the second ---).
    # ENVIRON, not -v: a -v value holding a newline is an error in some awks.
    NOTE="$note" awk '{ print } /^---$/ && ++n == 2 { print ""; print ENVIRON["NOTE"] }' "$f" >"$f.tmp"
    mv "$f.tmp" "$f"
  fi
done
