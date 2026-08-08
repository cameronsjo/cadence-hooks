#!/usr/bin/env bash
# Exercise scripts/advisory-issue.sh against a stub `gh`, so every branch runs
# without touching GitHub.
#
# Committed rather than run once by hand: advisory-issue.sh only ever executes
# on the weekly schedule, and only on the weeks the audit is unhappy. That is
# the longest possible feedback loop for a regression — a break would sit
# undetected until the run that most needed to work.
#
# Usage: bash scripts/test-advisory-issue.sh [repo-root]
set -uo pipefail

WT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
SHIM="$(mktemp -d)"
STATE="$SHIM/state"
export GH_CALLS="$SHIM/calls.log"
: >"$GH_CALLS"

cat >"$SHIM/gh" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$GH_CALLS"
case "$1 $2" in
  "label list") printf '%s\n' "${STUB_LABELS:-security}" ;;
  "issue list")
      # One TSV row per issue: number<TAB>title
      [ -n "${STUB_OPEN_ISSUE:-}" ] && printf '%s\t%s\n' "$STUB_OPEN_ISSUE" "security: the weekly cargo audit sweep is failing on main"
      # A decoy that must never be matched.
      printf '%s\t%s\n' "999" "security: something else entirely" ;;
  "issue create") echo "https://github.com/o/r/issues/1234" ;;
  *) : ;;
esac
exit 0
STUB
chmod +x "$SHIM/gh"
export PATH="$SHIM:$PATH"
export STATE

fail=0
check() {
  if printf '%s' "$2" | command grep -qF -- "$3"; then
    echo "  PASS: $1"
  else
    echo "  FAIL: $1"
    printf '    wanted substring: %s\n    got: %s\n' "$3" "$2"
    fail=$((fail + 1))
  fi
}

REPORT="$SHIM/report.txt"
printf 'Crate:     nasty\nVersion:   0.1.0\nTitle:     %b[31mRCE%b[0m in nasty\nID:        RUSTSEC-2026-0001\n' '\033' '\033' >"$REPORT"

echo "=== 1. report with NO existing issue -> creates one ==="
: >"$GH_CALLS"; unset STUB_OPEN_ISSUE
out=$(bash "$WT/scripts/advisory-issue.sh" report "$REPORT" 2>&1); echo "  exit=$?"
check "narrates filing" "$out" "No advisory issue open, filing one."
check "reports the url" "$out" "https://github.com/o/r/issues/1234"
check "called issue create" "$(cat "$GH_CALLS")" "issue create --title security: the weekly cargo audit sweep is failing on main"
check "used --body-file" "$(cat "$GH_CALLS")" "--body-file"
check "did NOT comment" "$(command grep -c 'issue comment' "$GH_CALLS")" "0"

echo "=== 2. report with an existing issue -> comments, no duplicate ==="
: >"$GH_CALLS"; export STUB_OPEN_ISSUE=77
out=$(bash "$WT/scripts/advisory-issue.sh" report "$REPORT" 2>&1); echo "  exit=$?"
check "found the open issue" "$out" "#77 already open"
check "commented on it" "$(cat "$GH_CALLS")" "issue comment 77"
check "did NOT create a duplicate" "$(command grep -c 'issue create' "$GH_CALLS")" "0"

echo "=== 3. resolve with an existing issue -> closes it ==="
: >"$GH_CALLS"; export STUB_OPEN_ISSUE=77
out=$(bash "$WT/scripts/advisory-issue.sh" resolve 2>&1); echo "  exit=$?"
check "closed it" "$(cat "$GH_CALLS")" "issue close 77 --reason completed"

echo "=== 4. resolve with NO issue -> no-op, exit 0 ==="
: >"$GH_CALLS"; unset STUB_OPEN_ISSUE
out=$(bash "$WT/scripts/advisory-issue.sh" resolve 2>&1); rc=$?
check "narrates the no-op" "$out" "Nothing to resolve."
check "exit 0" "$rc" "0"
check "closed nothing" "$(command grep -c 'issue close' "$GH_CALLS")" "0"

echo "=== 5. decoy title is never matched ==="
: >"$GH_CALLS"; unset STUB_OPEN_ISSUE
out=$(bash "$WT/scripts/advisory-issue.sh" resolve 2>&1)
check "ignored issue 999" "$out" "Nothing to resolve."

echo "=== 6. missing label is self-healed ==="
: >"$GH_CALLS"; unset STUB_OPEN_ISSUE; export STUB_LABELS="chore"
out=$(bash "$WT/scripts/advisory-issue.sh" report "$REPORT" 2>&1)
check "narrates label creation" "$out" "Label security missing"
check "created the label" "$(cat "$GH_CALLS")" "label create security"
unset STUB_LABELS

echo "=== 7. ANSI escapes are stripped from the body ==="
: >"$GH_CALLS"; unset STUB_OPEN_ISSUE
# Re-run capturing the body file the script builds, by making the stub copy it.
cat >"$SHIM/gh" <<'STUB2'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$GH_CALLS"
prev=""
for a in "$@"; do [ "$prev" = "--body-file" ] && cp "$a" "$STATE.body"; prev="$a"; done
case "$1 $2" in
  "label list") echo security ;;
  "issue list") printf '%s\t%s\n' "999" "security: something else entirely" ;;
  "issue create") echo "https://github.com/o/r/issues/1234" ;;
esac
exit 0
STUB2
chmod +x "$SHIM/gh"
bash "$WT/scripts/advisory-issue.sh" report "$REPORT" >/dev/null 2>&1
body=$(cat "$STATE.body" 2>/dev/null)
check "kept the advisory id" "$body" "RUSTSEC-2026-0001"
check "kept the title text" "$body" "RCE"
check "fenced the report" "$body" '```text'
if printf '%s' "$body" | command grep -q $'\033'; then
  echo "  FAIL: ANSI escapes survived into the body"; fail=$((fail + 1))
else
  echo "  PASS: ANSI escapes stripped"
fi

echo "=== 8. a report with no RUSTSEC id is labelled a tooling failure ==="
printf 'error: couldn'"'"'t fetch advisory database: connection reset\n' >"$SHIM/blip.txt"
bash "$WT/scripts/advisory-issue.sh" report "$SHIM/blip.txt" >/dev/null 2>&1
body=$(cat "$STATE.body" 2>/dev/null)
check "names it a tooling failure" "$body" "more likely a"
if printf '%s' "$body" | command grep -qF -- "reported advisories against"; then
  echo "  FAIL: a network blip was announced as an advisory"; fail=$((fail + 1))
else
  echo "  PASS: did not call a blip an advisory"
fi

echo "=== 9. a backtick-fence in advisory text cannot break out ==="
printf 'ID:        RUSTSEC-2026-0002\nTitle:     evil ```` here\n' >"$SHIM/eviltext.txt"
bash "$WT/scripts/advisory-issue.sh" report "$SHIM/eviltext.txt" >/dev/null 2>&1
body=$(cat "$STATE.body" 2>/dev/null)
# Assert the property, not an arithmetic constant: the fence must be strictly
# longer than the longest backtick run in the payload, whatever those lengths are.
opener=$(printf '%s' "$body" | command grep -m1 'text$' | tr -d '\n')
fence_len=$(( ${#opener} - 4 ))   # minus the "text" info string
payload_len=$(command grep -o '`\{1,\}' "$SHIM/eviltext.txt" | awk '{ if (length($0) > n) n = length($0) } END { print n + 0 }')
if [ "$fence_len" -gt "$payload_len" ]; then
  echo "  PASS: fence (${fence_len}) is longer than the payload's longest run (${payload_len})"
else
  echo "  FAIL: fence ${fence_len} cannot contain a run of ${payload_len}"; fail=$((fail + 1))
fi

echo "=== 10. an oversized report truncates instead of dying ==="
python3 -c "print('ID:        RUSTSEC-2026-0003'); print('x' * 200000)" >"$SHIM/huge.txt"
bash "$WT/scripts/advisory-issue.sh" report "$SHIM/huge.txt" >/dev/null 2>&1; rc=$?
check "exited 0, not 141" "$rc" "0"
body=$(cat "$STATE.body" 2>/dev/null)
check "notes the truncation" "$body" "Output truncated at"
bytes=$(printf '%s' "$body" | wc -c | tr -d ' ')
if [ "$bytes" -lt 65536 ]; then
  echo "  PASS: body is ${bytes} bytes, under GitHub's 65536 limit"
else
  echo "  FAIL: body is ${bytes} bytes, over the limit"; fail=$((fail + 1))
fi

rm -rf "$SHIM"
echo
if [ "$fail" -eq 0 ]; then
  echo "VERDICT: advisory-issue.sh passes all branches"
else
  echo "VERDICT: $fail assertion(s) failed"
fi
exit "$fail"
