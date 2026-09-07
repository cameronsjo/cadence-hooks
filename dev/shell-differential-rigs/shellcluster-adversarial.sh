#!/usr/bin/env bash
# Adversarial differential — the security pass, run empirically.
# Same contract as shellcluster-differential.sh: a MISS is bash EXECUTES
# but the guard ALLOWS. Targets the specific hazards of the four fixes.
set -uo pipefail
BIN="${BIN:-$HOME/wt/shellcluster/target/release/cadence-hooks}"
PY=$(command -v python3)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/shadv.XXXXXX")
MARK="$WORK/executed"
miss=0; fp=0; agree=0

check() {
  local label="$1" tmpl="$2"
  rm -f "$MARK"
  local bash_src="${tmpl//PAYLOAD/touch \"$MARK\"}"
  ( cd "$WORK" && bash -c "$bash_src" ) >/dev/null 2>&1
  local executed=no; [ -e "$MARK" ] && executed=yes
  local guard_src="${tmpl//PAYLOAD/rm -rf ~/Documents}"
  local payload out rc
  payload=$("$PY" -c 'import json,sys; print(json.dumps({"tool_name":"Bash","tool_input":{"command":sys.argv[1]},"cwd":sys.argv[2],"hook_event_name":"PreToolUse"}))' "$guard_src" "$HOME/wt/shellcluster")
  out=$(printf '%s' "$payload" | env -u CADENCE_ALLOW_MAIN -u CADENCE_NO_ENFORCE_WORKTREE "$BIN" guardrails guard-rm 2>&1); rc=$?
  local blocked=no; [ "$rc" = "2" ] && blocked=yes
  local verdict
  if [ "$executed" = yes ] && [ "$blocked" = no ]; then verdict="*** MISS ***"; miss=$((miss+1))
  elif [ "$executed" = no ] && [ "$blocked" = yes ]; then verdict="(false block)"; fp=$((fp+1))
  else verdict="ok"; agree=$((agree+1)); fi
  printf '%-46s bash_exec=%-4s guard_block=%-4s %s\n' "$label" "$executed" "$blocked" "$verdict"
}

echo "=== comment arm: can it DROP executed text? ==="
check "hash after {"                    'x() { echo hi; }# note
PAYLOAD'
check "hash after }"                    'if true; then echo a; fi# note
PAYLOAD'
check "hash inside ANSI-C string"       "echo \$'a#b'
PAYLOAD"
check "ANSI-C string then comment"      "echo \$'a\\'b' # note
PAYLOAD"
check "hash after && "                  'echo hi && # note
PAYLOAD'
check "hash after backslash-newline"    'echo hi \
# note
PAYLOAD'
check "hash inside backticks multiline" 'echo `echo a # note
PAYLOAD`'
check "hash in double-quoted then close" 'echo "a # b"
PAYLOAD'
check "CRLF before comment"             "$(printf 'echo hi # note\r\nPAYLOAD')"
check "comment only, then newline cmd"  '#
PAYLOAD'
check "nested quotes then comment"      "echo \"it's\" # note
PAYLOAD"
check "hash after export assignment"    'export X=1 # note
PAYLOAD'

echo
echo "=== clobber parity: longer backslash runs ==="
check "3 backslashes then >|"           'echo hi \\\>| PAYLOAD'
check "4 backslashes then >|"           'echo hi \\\\>| '"$WORK"'/c4; PAYLOAD'
check "2>| stream-prefixed"             'echo hi 2>| '"$WORK"'/c5; PAYLOAD'
check "gt inside quotes then pipe"      'echo "a > b" | PAYLOAD'

echo
echo "=== wrapper walks ==="
check "sh -c -- with -lc cluster"       "bash -lc -- 'PAYLOAD'"
check "-- as last token (no script)"    "bash -c -- ; PAYLOAD"
check "command bash -c --"              "command bash -c -- 'PAYLOAD'"
check "env bash -c --"                  "env bash -c -- 'PAYLOAD'"

echo
printf 'agree=%s  miss=%s  false_block=%s\n' "$agree" "$miss" "$fp"
rm -rf "$WORK"
if [ "$miss" -gt 0 ]; then echo "VERDICT: FAIL - $miss miss(es)"; exit 1; fi
echo "VERDICT: PASS - no case where bash executes and the guard allows"
