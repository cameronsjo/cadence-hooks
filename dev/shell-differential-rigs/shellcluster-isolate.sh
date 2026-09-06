#!/usr/bin/env bash
# Isolate the one remaining miss: is it the comment arm, or the glued
# trailing backtick defeating guard-rm's operand match?
set -uo pipefail
BIN=$HOME/wt/shellcluster/target/release/cadence-hooks
PY=$(command -v python3)

probe() {
  local cmd="$1" label="$2" payload rc
  payload=$("$PY" -c 'import json,sys; print(json.dumps({"tool_name":"Bash","tool_input":{"command":sys.argv[1]},"cwd":sys.argv[2],"hook_event_name":"PreToolUse"}))' "$cmd" "$HOME/wt/shellcluster")
  printf '%s' "$payload" | env -u CADENCE_ALLOW_MAIN -u CADENCE_NO_ENFORCE_WORKTREE "$BIN" guardrails guard-rm >/dev/null 2>&1
  rc=$?
  printf '%-54s rc=%s\n' "$label" "$rc"
}

echo "--- is it the comment, or the glued trailing backtick operand? ---"
probe 'rm -rf ~/Documents`'  'bare operand, glued backtick, NO comment anywhere'
probe 'rm -rf ~/Documents'   'bare operand, clean (positive control)'
probe 'echo `echo a
rm -rf ~/Documents`'         'backticks multiline, NO comment'
probe 'echo $(echo a # note
rm -rf ~/Documents)'         'same shape, $( ) instead of backticks'
probe 'echo `echo a # note
rm -rf ~/Documents` ; true'  'backticks + comment, backtick not last char'
