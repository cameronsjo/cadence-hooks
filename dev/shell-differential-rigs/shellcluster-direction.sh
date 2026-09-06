#!/usr/bin/env bash
# Directional test for the new depth counter: for each nesting / malformed
# input, does comment stripping fail SAFE (disabled -> text stays under
# inspection) or UNSAFE (fires where bash has data -> text dropped)?
# MISS = bash executes AND guard allows. false_block = parser over-inspects.
set -uo pipefail
BIN="${BIN:-$HOME/wt/shellcluster/target/release/cadence-hooks}"
PY=$(command -v python3)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/shdir.XXXXXX")
MARK="$WORK/executed"
miss=0; agree=0; fb=0
check() {
  local label="$1" tmpl="$2"
  rm -f "$MARK"
  ( cd "$WORK" && bash -c "${tmpl//PAYLOAD/touch \"$MARK\"}" ) >/dev/null 2>&1
  local executed=no; [ -e "$MARK" ] && executed=yes
  local guard_src="${tmpl//PAYLOAD/rm -rf ~/Documents}" payload rc
  payload=$("$PY" -c 'import json,sys; print(json.dumps({"tool_name":"Bash","tool_input":{"command":sys.argv[1]},"cwd":sys.argv[2],"hook_event_name":"PreToolUse"}))' "$guard_src" "/tmp")
  printf '%s' "$payload" | env -u CADENCE_ALLOW_MAIN -u CADENCE_NO_ENFORCE_WORKTREE "$BIN" guardrails guard-rm >/dev/null 2>&1
  rc=$?
  local blocked=no; [ "$rc" = "2" ] && blocked=yes
  local v="ok"
  if [ "$executed" = yes ] && [ "$blocked" = no ]; then v="*** MISS (UNSAFE) ***"; miss=$((miss+1))
  elif [ "$executed" = no ] && [ "$blocked" = yes ]; then v="(over-inspect: SAFE)"; fb=$((fb+1))
  else agree=$((agree+1)); fi
  printf '%-46s bash=%-4s block=%-4s %s\n' "$label" "$executed" "$blocked" "$v"
}
echo "=== controls ==="
check 'CTRL bare payload'                 'PAYLOAD'
check 'CTRL real trailing comment'        'echo hi # note
PAYLOAD'
echo "=== unbalanced OPENERS (expect: strip disabled = safe) ==="
check 'lone ${ then # then ;'             'echo ${x # y ; PAYLOAD'
check 'lone $( then # then ;'             'echo $(x # y ; PAYLOAD'
check 'lone $(( then # then ;'            'echo $((x # y ; PAYLOAD'
check 'lone backtick then # then ;'       'echo `x # y ; PAYLOAD'
check 'lone { then # then ;'              'echo { # y
PAYLOAD'
check 'lone ( then # then ;'              'echo ( # y
PAYLOAD'
echo "=== unbalanced CLOSERS at depth 0 (underflow check) ==="
check 'stray ) then # then ;'             'echo a ) # y
PAYLOAD'
check 'stray } then # then ;'             'echo a } # y
PAYLOAD'
check 'stray )) then # then ;'            'echo a )) # y
PAYLOAD'
check 'stray }} then # then ;'            'echo a }} # y
PAYLOAD'
echo "=== nesting: \${ in \$( and reverse ==="
check '${ } inside $( )'                  'echo $(echo ${x:-a} # b) ; PAYLOAD'
check '$( ) inside ${ }'                  'echo ${x:-$(echo a # b)} ; PAYLOAD'
check '${ } inside $( ) w/ ) in default'  'echo $(echo ${x:-a)b} # c) ; PAYLOAD'
check '$( ) inside ${ } w/ ) after'       'echo ${x:-$(echo a))b # c} ; PAYLOAD'
echo "=== nesting: backtick in \$( ) and reverse ==="
check 'backtick inside $( )'              'echo $(echo `echo a` # b) ; PAYLOAD'
check '$( ) inside backticks'             'echo `echo $(echo a) # b` ; PAYLOAD'
check 'backtick inside ${ }'              'echo ${x:-`echo a` # b} ; PAYLOAD'
echo "=== \$(( vs \$( disambiguation ==="
check '$(( )) then # then ;'              'echo $((1+2)) # y
PAYLOAD'
check '$(( )) with ) inside'              'echo $((1)) ) # y
PAYLOAD'
check '$( (( )) ) nested arith'           'echo $( ((1)) ) # y
PAYLOAD'
check '$(( )) inside ${ }'                'echo ${x:-$((1+2)) # b} ; PAYLOAD'
check 'arith cmd (( )) top level'         '((1)) ; echo a # y
PAYLOAD'
echo
echo "agree=$agree  miss=$miss  over_inspect=$fb"
[ "$miss" = 0 ] && echo "VERDICT: no unsafe direction in this set" || echo "VERDICT: FAIL - $miss unsafe"
rm -rf "$WORK"
