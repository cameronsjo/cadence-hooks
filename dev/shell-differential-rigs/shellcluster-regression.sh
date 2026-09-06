#!/usr/bin/env bash
# Verify the security seat's Critical-1 rows independently.
# bash side runs `touch $MARK` (never the destructive twin); guard side runs
# the destructive twin through guard-rm. MISS = bash executes, guard allows.
set -uo pipefail
BIN="${BIN:-$HOME/wt/shellcluster/target/release/cadence-hooks}"
PY=$(command -v python3)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/shreg.XXXXXX")
MARK="$WORK/executed"
miss=0; agree=0

check() {
  local label="$1" tmpl="$2"
  rm -f "$MARK"
  local bash_src="${tmpl//PAYLOAD/touch \"$MARK\"}"
  ( cd "$WORK" && bash -c "$bash_src" ) >/dev/null 2>&1
  local executed=no; [ -e "$MARK" ] && executed=yes

  local guard_src="${tmpl//PAYLOAD/rm -rf ~/Documents}"
  local payload rc
  payload=$("$PY" -c 'import json,sys; print(json.dumps({"tool_name":"Bash","tool_input":{"command":sys.argv[1]},"cwd":sys.argv[2],"hook_event_name":"PreToolUse"}))' "$guard_src" "$HOME/wt/shellcluster")
  printf '%s' "$payload" | env -u CADENCE_ALLOW_MAIN -u CADENCE_NO_ENFORCE_WORKTREE "$BIN" guardrails guard-rm >/dev/null 2>&1
  rc=$?
  local blocked=no; [ "$rc" = "2" ] && blocked=yes

  local verdict="ok"
  if [ "$executed" = yes ] && [ "$blocked" = no ]; then verdict="*** MISS ***"; miss=$((miss+1)); else agree=$((agree+1)); fi
  printf '%-52s bash_exec=%-4s guard_block=%-4s %s\n' "$label" "$executed" "$blocked" "$verdict"
}

echo "===== Critical 1: expansion contexts + escaped whitespace ====="
check 'row1  ${x:- # } ; PAYLOAD'       'echo ${x:- # } ; PAYLOAD'
check 'row2  `date # x`; PAYLOAD'       'echo `date # x`; PAYLOAD'
check 'row3  a\ #x && PAYLOAD'          'echo a\ #x && PAYLOAD'
check 'row4  ${B:-a # b} && PAYLOAD'    'echo ${B:-a # b} && PAYLOAD'
check 'row5  $(cmd # x) newline PAYLOAD' 'echo $(echo a # x
) ; PAYLOAD'
check 'row6  ${x:-#} no space'          'echo ${x:-#} ; PAYLOAD'

echo
echo "===== Critical 2: heredoc terminator never matched ====="
check 'unterminated heredoc, # before $()' 'cat <<EOF
prose # $(PAYLOAD)'

echo
echo "===== Important 3: commented-out heredoc introducer ====="
check 'commented <<EOF introducer'      'echo hi # cat <<EOF
PAYLOAD
EOF'

echo
echo "===== controls that must keep working ====="
check 'plain trailing comment (#490)'   "echo hi # it's fine
PAYLOAD"
check 'quoted hash'                     "echo '# nope'
PAYLOAD"

echo
printf 'agree=%s  miss=%s\n' "$agree" "$miss"
rm -rf "$WORK"
[ "$miss" -gt 0 ] && { echo "VERDICT: FAIL - $miss miss(es)"; exit 1; }
echo "VERDICT: PASS"
