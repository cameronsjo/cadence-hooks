#!/usr/bin/env bash
set -uo pipefail
BIN=/tmp/wt-shellcluster/target/release/cadence-hooks
PY=$(command -v python3)
run() {
  local label="$1" sub="$2" hook="$3" cmd="$4" payload rc out
  payload=$("$PY" -c 'import json,sys; print(json.dumps({"tool_name":"Bash","tool_input":{"command":sys.argv[1]},"cwd":sys.argv[2],"hook_event_name":"PreToolUse"}))' "$cmd" "$PWD")
  out=$(printf '%s' "$payload" | env -u CADENCE_ALLOW_MAIN -u CADENCE_NO_ENFORCE_WORKTREE "$BIN" "$sub" "$hook" 2>&1); rc=$?
  printf '%-40s rc=%s  %s\n' "$label" "$rc" "$(printf '%s' "$out" | head -c 62 | tr '\n' ' ')"
}
for pair in "cadence git-safety:git reset --hard HEAD~1" "guardrails guard-gh-dangerous:gh repo delete evil/target --yes" "guardrails guard-op-vault-scan:op item list --vault Private"; do
  sub_hook="${pair%%:*}"; payload="${pair#*:}"
  set -- $sub_hook
  echo "===== $2 ====="
  run "CONTROL bare"           "$1" "$2" "$payload"
  run "CONTROL comment no apos" "$1" "$2" "echo hi # fine
$payload"
  run "#490 apostrophe comment" "$1" "$2" "echo hi # it's fine
$payload"
  run "#491 escaped > pipe"     "$1" "$2" "echo hi \\>| $payload"
  run "#496 bash -c --"         "$1" "$2" "bash -c -- '$payload'"
  run "#497 sudo -E bash -c"    "$1" "$2" "sudo -E bash -c '$payload'"
  echo
done
