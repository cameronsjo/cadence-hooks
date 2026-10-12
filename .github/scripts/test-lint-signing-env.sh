#!/usr/bin/env bash
# test-lint-signing-env.sh: cases for lint-signing-env.sh. Each case writes one
# workflow into a scratch dir and checks the lint's exit status.
#
#   bash .github/scripts/test-lint-signing-env.sh [lint-script]
#
# The optional argument runs a different copy of the lint, to confirm a case
# goes red against a broken version. Exit status is the fail count.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
lint="${1:-$here/lint-signing-env.sh}"
root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT
fails=0

case_() {  # label, want-exit, workflow body
  local d="$root/$RANDOM$RANDOM"
  mkdir -p "$d"
  printf '%s\n' "$3" > "$d/w.yml"
  bash "$lint" "$d" >/dev/null 2>&1
  local got=$?
  if [[ "$got" == "$2" ]]; then
    echo "  PASS $1"
  else
    echo "  FAIL $1 (want exit $2, got $got)"
    fails=$((fails + 1))
  fi
}

good_job() {  # environment line
  cat <<EOF
on:
  push:
    tags: ['v*']
jobs:
  sign:
    if: startsWith(github.ref, 'refs/tags/v')
    $1
    runs-on: macos-latest
    steps: [{run: 'true'}]
EOF
}

branch_job() {  # environment line, on a branch trigger
  cat <<EOF
on:
  push:
    branches: [main]
jobs:
  sign:
    $1
    runs-on: macos-latest
    steps: [{run: 'true'}]
EOF
}

case_ "tag-only workflow with the exact gate is clean" 0 "$(good_job 'environment: macos-signing')"
case_ "environment as a map is matched" 1 "$(branch_job 'environment: {name: macos-signing}')"
case_ "branch trigger is refused" 1 "$(branch_job 'environment: macos-signing')"
case_ "a different case is still matched" 1 "$(branch_job 'environment: MACOS-Signing')"
case_ "an expression environment is refused" 1 "$(branch_job "environment: \${{ 'macos-signing' }}")"
case_ "an expression in a map name is refused" 1 "$(branch_job "environment: {name: \"\${{ inputs.env }}\"}")"
case_ "an unrelated environment on a branch is clean" 0 "$(branch_job 'environment: release')"
case_ "no environment on a branch is clean" 0 "$(branch_job '')"
case_ "a trailing space is still matched" 1 "$(branch_job "environment: 'macos-signing '")"
case_ "a custom-tagged environment is refused" 1 "$(branch_job 'environment: !x macos-signing')"
alias_job() {  # environment line using an anchor defined at the top level
  cat <<EOF
x-env: &e $1
on:
  push:
    branches: [main]
jobs:
  sign:
    $2
    runs-on: macos-latest
    steps: [{run: 'true'}]
EOF
}
case_ "an alias to the name is matched" 1 "$(alias_job macos-signing 'environment: *e')"
case_ "an alias inside a map name is matched" 1 "$(alias_job macos-signing 'environment: {name: *e}')"
case_ "an alias to an expression is refused" 1 "$(alias_job "\"\${{ 'macos-signing' }}\"" 'environment: *e')"
# A whole job written as an alias is the shape only `explode` resolves:
# yq follows the other aliases on its own while walking a path.
case_ "a job that is an alias is matched" 1 "$(cat <<'EOF'
x-job: &j
  environment: macos-signing
  runs-on: macos-latest
  steps: [{run: 'true'}]
on:
  push:
    branches: [main]
jobs:
  sign: *j
EOF
)"

if [[ "$fails" -eq 0 ]]; then echo "RESULT: all checks passed"; else echo "RESULT: $fails check(s) FAILED"; fi
exit "$fails"
