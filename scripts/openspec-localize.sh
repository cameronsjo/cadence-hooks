#!/usr/bin/env bash
# Point the generated OpenSpec skills and /opsx commands at the pinned CLI,
# and narrow what they pre-allow.
#
# `openspec init` and `openspec update` write files that pre-allow a bare
# `openspec` with `allowed-tools: Bash(openspec:*)`. That runs whatever
# `openspec` is on PATH, unpinned, with no prompt, and covers every
# subcommand, including `feedback` (files a GitHub issue upstream with your
# gh login) and `completion install` (writes your shell rc). With none on
# PATH an agent tends to reach for `npx openspec`, which on npm is an
# unrelated package.
#
# This replaces that line with ALLOWED below: the pinned wrapper, one rule
# per subcommand the skill bodies run. Everything else (init, update,
# archive, feedback, completion, config, workset) still asks. It also adds a note
# under each file's frontmatter. Rerun it after every `openspec update`; CI
# fails until you do. Idempotent. It fails on an allowed-tools line it does
# not recognize, so a changed upstream template is looked at, not passed.
# Last, it checks every markdown file under the agent directories: no bare
# `Bash(openspec` grant anywhere, at most one allowed-tools key per file, no
# indented continuation of it, and no allowed-tools naming openspec other
# than ALLOWED.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
marker='<!-- cadence-hooks: pinned openspec CLI -->'
ALLOWED='allowed-tools: Bash(scripts/openspec.sh list:*), Bash(scripts/openspec.sh status:*), Bash(scripts/openspec.sh instructions:*), Bash(scripts/openspec.sh context:*), Bash(scripts/openspec.sh new change:*), Bash(scripts/openspec.sh show:*), Bash(scripts/openspec.sh validate:*), Bash(scripts/openspec.sh schemas:*), Bash(scripts/openspec.sh store list:*)'
note="$marker
**In this repo, run every \`openspec ...\` command below as \`scripts/openspec.sh ...\`** (same arguments). It runs the pinned CLI from \`scripts/openspec/package-lock.json\`. Never run \`npx openspec\`: that npm name is an unrelated package."

shopt -s nullglob
status=0
found=0
for f in "$root"/.claude/skills/openspec-*/SKILL.md "$root"/.claude/commands/opsx/*.md "$root"/.agents/skills/openspec-*/SKILL.md; do
  found=$((found + 1))
  line="$(grep -m1 '^allowed-tools:' "$f" || true)"
  case "$line" in
    'allowed-tools: Bash(openspec:*)' | 'allowed-tools: Bash(scripts/openspec.sh:*)' | "$ALLOWED")
      ALLOWED="$ALLOWED" awk '/^allowed-tools:/ && !done { print ENVIRON["ALLOWED"]; done = 1; next } { print }' "$f" >"$f.tmp"
      mv "$f.tmp" "$f"
      ;;
    *)
      echo "openspec-localize: $f: unrecognized allowed-tools line, not rewritten: ${line:-<none>}" >&2
      status=1
      continue
      ;;
  esac
  if ! grep -qF "$marker" "$f"; then
    # Insert the note after the closing frontmatter delimiter (the second ---).
    # ENVIRON, not -v: a -v value holding a newline is an error in some awks.
    NOTE="$note" awk '{ print } /^---$/ && ++n == 2 { print ""; print ENVIRON["NOTE"] }' "$f" >"$f.tmp"
    mv "$f.tmp" "$f"
  fi
done

if [ "$found" -eq 0 ]; then
  echo "openspec-localize: no generated OpenSpec skills found; the glob matched nothing" >&2
  status=1
fi

while IFS= read -r -d '' f; do
  if grep -qE 'Bash\((npx )?openspec' "$f"; then
    echo "openspec-localize: $f: pre-allows a bare openspec" >&2
    status=1
  fi
  # Frontmatter only: the lines between the first two --- delimiters.
  report="$(ALLOWED="$ALLOWED" awk '
    { sub(/\r$/, "") }
    NR == 1 { sub(/^\xef\xbb\xbf/, "") }
    NR == 1 && $0 != "---" { exit }
    /^---$/ { if (++d == 2) exit; next }
    /^"?allowed-tools"?[ \t]*:/ {
      if (++n > 1) print "more than one allowed-tools key"
      if ($0 ~ /openspec/ && $0 != ENVIRON["ALLOWED"]) print "allowed-tools names openspec but is not the narrowed list"
      grant = 1; next
    }
    grant && /^[ \t]/ { print "allowed-tools continues on an indented line"; grant = 0; next }
    { grant = 0 }
  ' "$f")"
  if [ -n "$report" ]; then
    printf 'openspec-localize: %s: %s\n' "$f" "$report" >&2
    status=1
  fi
done < <(find "$root"/.claude "$root"/.agents -name '*.md' -print0 2>/dev/null)
exit "$status"
