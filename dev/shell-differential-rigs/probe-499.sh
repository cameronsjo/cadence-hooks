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

echo "=== guard-rm: exact-path rules, delimiter glued vs not ==="
run "CONTROL bare        rm -rf /"            guardrails guard-rm 'rm -rf /'
run "CONTROL bare        rm -rf /)"           guardrails guard-rm 'rm -rf /)'
run "span EARLIER line   rm -rf /"            guardrails guard-rm 'cat <<EOF
p $(rm -rf /
echo a)
EOF'
run "span LAST line      rm -rf /"            guardrails guard-rm 'cat <<EOF
p $(echo a
rm -rf /)
EOF'
run "CONTROL bare        rm -rf ~"            guardrails guard-rm 'rm -rf ~'
run "CONTROL bare        rm -rf ~)"           guardrails guard-rm 'rm -rf ~)'
run "span LAST line      rm -rf ~"            guardrails guard-rm 'cat <<EOF
p $(echo a
rm -rf ~)
EOF'
run "CONTROL bare        rm -rf .git"          guardrails guard-rm 'rm -rf .git'
run "CONTROL bare        rm -rf .git)"         guardrails guard-rm 'rm -rf .git)'
run "span LAST line      rm -rf .git"          guardrails guard-rm 'cat <<EOF
p $(echo a
rm -rf .git)
EOF'
echo
echo "=== backtick form (no paren; trailing char is a backtick) ==="
run "CONTROL bare        rm -rf ~/Documents\`" guardrails guard-rm 'rm -rf ~/Documents`'
run "span LAST line btick rm -rf ~/Documents"  guardrails guard-rm 'cat <<EOF
p `echo a
rm -rf ~/Documents`
EOF'
echo
echo "=== git-safety / enforce-worktree, same asymmetry ==="
run "CONTROL bare        git reset --hard"     cadence git-safety 'git reset --hard HEAD~1'
run "CONTROL bare        ...HEAD~1)"           cadence git-safety 'git reset --hard HEAD~1)'
run "span LAST line"                           cadence git-safety 'cat <<EOF
p $(echo a
git reset --hard HEAD~1)
EOF'
