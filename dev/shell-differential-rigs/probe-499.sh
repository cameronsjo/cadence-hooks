#!/usr/bin/env bash
# Does the glued trailing delimiter ever flip a verdict? Compare the SAME
# command on the last line of a carried span vs an earlier line of it.
set -uo pipefail
BIN=/tmp/wt-shellcluster/target/release/cadence-hooks
PY=$(command -v python3)

run() {
  local label="$1" sub="$2" hook="$3" cmd="$4"
  local payload rc out
  payload=$("$PY" -c 'import json,sys; print(json.dumps({"tool_name":"Bash","tool_input":{"command":sys.argv[1]},"cwd":sys.argv[2],"hook_event_name":"PreToolUse"}))' "$cmd" "$PWD")
  out=$(printf '%s' "$payload" | env -u CADENCE_ALLOW_MAIN -u CADENCE_NO_ENFORCE_WORKTREE "$BIN" "$sub" "$hook" 2>&1); rc=$?
  printf '%-52s rc=%s  %s\n' "$label" "$rc" "$(printf '%s' "$out" | head -c 70 | tr '\n' ' ')"
}

echo "=== git-safety / enforce-worktree, same asymmetry ==="
run "CONTROL bare        git reset --hard"     cadence git-safety 'git reset --hard HEAD~1'
run "CONTROL bare        ...HEAD~1)"           cadence git-safety 'git reset --hard HEAD~1)'
run "span LAST line"                           cadence git-safety 'cat <<EOF
p $(echo a
git reset --hard HEAD~1)
EOF'
