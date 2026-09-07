#!/usr/bin/env bash
# Scratch probe — end-to-end guard verdicts for the five issue repros.
# Every payload row is paired with a positive control that MUST block.
set -uo pipefail
BIN=/tmp/wt-shellcluster/target/release/cadence-hooks
PY=$(command -v python3)

run() { # run <label> <subcmd> <hook> <command>
  local label="$1" sub="$2" hook="$3" cmd="$4"
  local payload
  payload=$("$PY" -c 'import json,sys; print(json.dumps({"tool_name":"Bash","tool_input":{"command":sys.argv[1]},"cwd":sys.argv[2],"hook_event_name":"PreToolUse"}))' "$cmd" "$PWD")
  local out
  out=$(printf '%s' "$payload" | env -u CADENCE_ALLOW_MAIN -u CADENCE_NO_ENFORCE_WORKTREE "$BIN" "$sub" "$hook" 2>&1)
  local rc=$?
  printf '%-46s rc=%s  %s\n' "$label" "$rc" "$(printf '%s' "$out" | head -c 90 | tr '\n' ' ')"
}

echo "===== guard-rm (block-capable; rc=2 means BLOCK) ====="
run "CONTROL bare rm"                guardrails guard-rm 'rm -rf ~/Documents'
run "CONTROL after ;"                guardrails guard-rm 'echo hi ; rm -rf ~/Documents'
run "CONTROL comment, no apostrophe" guardrails guard-rm 'echo hi # fine
rm -rf ~/Documents'
run "#490 apostrophe in comment"     guardrails guard-rm "echo hi # it's fine
rm -rf ~/Documents"
run "CONTROL plain pipe"             guardrails guard-rm 'echo hi | rm -rf ~/Documents'
run "#491 escaped > before pipe"     guardrails guard-rm 'echo hi \>| rm -rf ~/Documents'
run "CONTROL bash -c"                guardrails guard-rm "bash -c 'rm -rf ~/Documents'"
run "#496 bash -c -- script"         guardrails guard-rm "bash -c -- 'rm -rf ~/Documents'"
run "CONTROL sudo bash -c"           guardrails guard-rm "sudo bash -c 'rm -rf ~/Documents'"
run "#497 sudo -E bash -c"           guardrails guard-rm "sudo -E bash -c 'rm -rf ~/Documents'"
run "#497 sudo -u root bash -c"      guardrails guard-rm "sudo -u root bash -c 'rm -rf ~/Documents'"
run "#499 span, cmd on earlier line" guardrails guard-rm 'cat <<EOF
prose $(rm -rf ~/Documents
echo a)
EOF'
run "#499 span, cmd on LAST line"    guardrails guard-rm 'cat <<EOF
prose $(echo a
rm -rf ~/Documents)
EOF'

echo
echo "===== prevent-secret-leaks (block-capable) ====="
run "CONTROL bare cat .env"           cadence prevent-secret-leaks 'cat .env'
run "CONTROL after ;"                 cadence prevent-secret-leaks 'echo hi ; cat .env'
run "CONTROL comment, no apostrophe"  cadence prevent-secret-leaks 'echo hi # fine
cat .env'
run "#490 apostrophe in comment"      cadence prevent-secret-leaks "echo hi # it's fine
cat .env"
run "CONTROL plain pipe"              cadence prevent-secret-leaks 'echo hi | cat .env'
run "#491 escaped > before pipe"      cadence prevent-secret-leaks 'echo hi \>| cat .env'
run "CONTROL bash -c"                 cadence prevent-secret-leaks "bash -c 'cat .env'"
run "#496 bash -c -- script"          cadence prevent-secret-leaks "bash -c -- 'cat .env'"
run "CONTROL sudo bash -c"            cadence prevent-secret-leaks "sudo bash -c 'cat .env'"
run "#497 sudo -E bash -c"            cadence prevent-secret-leaks "sudo -E bash -c 'cat .env'"
run "#499 span, cmd on LAST line"     cadence prevent-secret-leaks 'cat <<EOF
prose $(echo a
cat .env)
EOF'

echo
echo "===== guard-gh-write (block-capable) ====="
run "CONTROL bare gh"                 guardrails guard-gh-write 'gh issue create -R evil/target -t x -b y'
run "CONTROL comment, no apostrophe"  guardrails guard-gh-write 'echo hi # fine
gh issue create -R evil/target -t x -b y'
run "#490 apostrophe in comment"      guardrails guard-gh-write "echo hi # it's fine
gh issue create -R evil/target -t x -b y"
run "#491 escaped > before pipe"      guardrails guard-gh-write 'echo hi \>| gh issue create -R evil/target -t x -b y'
run "#496 bash -c -- script"          guardrails guard-gh-write "bash -c -- 'gh issue create -R evil/target -t x -b y'"
run "#497 sudo -E bash -c"            guardrails guard-gh-write "sudo -E bash -c 'gh issue create -R evil/target -t x -b y'"
