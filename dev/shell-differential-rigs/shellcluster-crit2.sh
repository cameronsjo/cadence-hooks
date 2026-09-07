#!/usr/bin/env bash
# The seat's two Criticals, verified independently.
# C1: one depth counter for ${ and $( — a data `)` inside ${…} closes it.
# C2: take_logical_line joins a backslash-newline that is INSIDE a comment;
#     bash does not continue a comment line.
set -uo pipefail
BIN="${BIN:-$HOME/wt/shellcluster/target/release/cadence-hooks}"
PY=$(command -v python3)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/shc2.XXXXXX")
MARK="$WORK/executed"
miss=0; agree=0

check() {
  local label="$1" tmpl="$2" hook="${3:-guard-rm}" sub="${4:-guardrails}" bad="${5:-rm -rf ~/Documents}"
  rm -f "$MARK"
  local bash_src="${tmpl//PAYLOAD/touch \"$MARK\"}"
  ( cd "$WORK" && bash -c "$bash_src" ) >/dev/null 2>&1
  local executed=no; [ -e "$MARK" ] && executed=yes
  local guard_src="${tmpl//PAYLOAD/$bad}"
  local payload rc
  payload=$("$PY" -c 'import json,sys; print(json.dumps({"tool_name":"Bash","tool_input":{"command":sys.argv[1]},"cwd":sys.argv[2],"hook_event_name":"PreToolUse"}))' "$guard_src" "$HOME/wt/shellcluster")
  printf '%s' "$payload" | env -u CADENCE_ALLOW_MAIN -u CADENCE_NO_ENFORCE_WORKTREE "$BIN" "$sub" "$hook" >/dev/null 2>&1
  rc=$?
  local blocked=no; [ "$rc" = "2" ] && blocked=yes
  local verdict="ok"
  if [ "$executed" = yes ] && [ "$blocked" = no ]; then verdict="*** MISS ***"; miss=$((miss+1)); else agree=$((agree+1)); fi
  printf '%-50s bash_exec=%-4s guard_block=%-4s %s\n' "$label" "$executed" "$blocked" "$verdict"
}

echo "===== CRITICAL 1: data ')' inside \${…} closes the counter ====="
check 'C1 bare )      ${x:-a)b # c} ;'   'echo ${x:-a)b # c} ; PAYLOAD'
check 'C1 nested $()  ${x:-$(echo a))b # c} ;' 'echo ${x:-$(echo a))b # c} ; PAYLOAD'
check 'C1 := form'                        'echo ${x:=a)b # c} && PAYLOAD'
check 'C1 :+ form'                        'echo ${x:+a)b # c} && PAYLOAD'
check 'C1 % suffix'                       'echo ${x%a)b # c} ; PAYLOAD'
check 'C1 // replace'                     'echo ${x//a)b # c} ; PAYLOAD'
check 'C1 pipe separator'                 'echo ${x:-a)b # c} | PAYLOAD'
echo "-- control: double-quoted expansion (quote branch runs first) --"
check 'C1 quoted (must be ok)'            'echo "${x:-a)b # c}" ; PAYLOAD'

echo
echo "===== CRITICAL 2: backslash-newline INSIDE a comment ====="
check 'C2 #;\ continuation'  'echo a #;\
PAYLOAD'
check 'C2 #|\ continuation'  'echo a #|\
PAYLOAD'
check 'C2 plain #...\ '      'echo a # see notes \
PAYLOAD'

echo
echo "===== controls that must stay green ====="
check 'plain trailing comment'  "echo hi # it's fine
PAYLOAD"
check 'real continuation joins' 'echo one \
two ; PAYLOAD'
check 'expansion no paren'      'echo ${x:-a # c} ; PAYLOAD'

echo
printf 'agree=%s  miss=%s\n' "$agree" "$miss"
rm -rf "$WORK"
[ "$miss" -gt 0 ] && { echo "VERDICT: FAIL - $miss miss(es)"; exit 1; }
echo "VERDICT: PASS"
