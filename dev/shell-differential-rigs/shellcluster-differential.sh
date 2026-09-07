#!/usr/bin/env bash
# Differential: real bash vs the guard parser (shell-parser cluster).
#
# For each payload template containing the token PAYLOAD:
#   - bash run:   PAYLOAD -> `touch $MARK`. Did bash actually execute it?
#   - guard run:  PAYLOAD -> `rm -rf ~/Documents`. Did guard-rm block?
#
# A MISS is: bash EXECUTES but the guard ALLOWS. That is the dangerous
# direction and the only one that matters for a guard-feeding parser.
# bash-does-not-execute + guard-blocks is a bounded false block, counted
# separately and not a failure.
set -uo pipefail
BIN=$HOME/wt/shellcluster/target/release/cadence-hooks
PY=$(command -v python3)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/shdiff.XXXXXX")
MARK="$WORK/executed"

miss=0; fp=0; agree=0

check() {
  local label="$1" tmpl="$2"
  rm -f "$MARK"

  # --- did real bash execute it? ---
  local bash_src="${tmpl//PAYLOAD/touch \"$MARK\"}"
  ( cd "$WORK" && bash -c "$bash_src" ) >/dev/null 2>&1
  local executed=no
  [ -e "$MARK" ] && executed=yes

  # --- did the guard block the dangerous twin? ---
  local guard_src="${tmpl//PAYLOAD/rm -rf ~/Documents}"
  local payload out rc
  payload=$("$PY" -c 'import json,sys; print(json.dumps({"tool_name":"Bash","tool_input":{"command":sys.argv[1]},"cwd":sys.argv[2],"hook_event_name":"PreToolUse"}))' "$guard_src" "$HOME/wt/shellcluster")
  out=$(printf '%s' "$payload" | env -u CADENCE_ALLOW_MAIN -u CADENCE_NO_ENFORCE_WORKTREE "$BIN" guardrails guard-rm 2>&1)
  rc=$?
  local blocked=no
  [ "$rc" = "2" ] && blocked=yes

  local verdict
  if [ "$executed" = yes ] && [ "$blocked" = no ]; then
    verdict="*** MISS ***"; miss=$((miss+1))
  elif [ "$executed" = no ] && [ "$blocked" = yes ]; then
    verdict="(false block)"; fp=$((fp+1))
  else
    verdict="ok"; agree=$((agree+1))
  fi
  printf '%-44s bash_exec=%-4s guard_block=%-4s %s\n' "$label" "$executed" "$blocked" "$verdict"
}

echo "=== comment-rule differentials (#490) ==="
check "trailing comment, apostrophe"  "echo hi # it's fine
PAYLOAD"
check "trailing comment, plain"       'echo hi # fine
PAYLOAD'
check "whole-line comment"            "# it's a note
PAYLOAD"
check "comment after ;"               'echo hi;# note
PAYLOAD'
check "comment after )"               '(echo hi)# note
PAYLOAD'
check "comment after |"               'echo hi |# note
PAYLOAD'
check "comment inside multiline \$()" 'echo $(echo a # note
PAYLOAD)'
check "hash glued to word"            'echo foo#bar
PAYLOAD'
check "hash in param expansion"       'x=abc; echo ${x#a}
PAYLOAD'
check "hash in arithmetic"            'echo $((2#101))
PAYLOAD'
check "escaped hash"                  'echo hi \# fine
PAYLOAD'
check "hash in single quotes"         "echo '# not a comment'
PAYLOAD"
check "hash in double quotes"         'echo "# not a comment"
PAYLOAD'
check "comment on heredoc intro line" 'cat <<EOF # note
prose
EOF
PAYLOAD'
check "tab before hash"               'echo hi	# note
PAYLOAD'

echo
echo "=== clobber-parity differentials (#491) ==="
check "escaped gt then pipe (odd)"    'echo hi \>| PAYLOAD'
check "plain pipe"                    'echo hi | PAYLOAD'

echo
echo "=== wrapper differentials (#496) ==="
check "bash -c -- script"             "bash -c -- 'PAYLOAD'"
check "bash -c script"                "bash -c 'PAYLOAD'"
check "sh -c -- script"               "sh -c -- 'PAYLOAD'"

echo
printf 'agree=%s  miss=%s  false_block=%s\n' "$agree" "$miss" "$fp"
rm -rf "$WORK"
if [ "$miss" -gt 0 ]; then echo "VERDICT: FAIL - $miss parser miss(es)"; exit 1; fi
echo "VERDICT: PASS - no case where bash executes and the guard allows"
