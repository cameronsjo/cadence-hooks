#!/usr/bin/env bash
# lint-release-env.sh: refuse any workflow that names the `release`
# environment and can be triggered by `pull_request_target`, `workflow_run`,
# or `issue_comment` (ADR-0044 (i)).
#
# Those three triggers run on the default branch, so the environment's
# deployment policy lets them through. A job there that names `release`
# would hand the App key to code an outside PR or comment can steer.
#
# Canonical copy: cadence-ecosystem scripts/release/lint-release-env.sh.
# Repos vendor it at .github/scripts/lint-release-env.sh and run it in CI.
#
#   bash .github/scripts/lint-release-env.sh [workflows-dir]
#
# Exit 0: clean. Exit 1: a violation (each printed). Exit 2: a workflow
# yq cannot parse, which is a failure, not a pass.
set -euo pipefail

dir="${1:-.github/workflows}"
[[ -d "$dir" ]] || { echo "lint-release-env: no directory $dir" >&2; exit 2; }
command -v yq >/dev/null || { echo "lint-release-env: yq is required" >&2; exit 2; }

bad=0
shopt -s nullglob
for wf in "$dir"/*.yml "$dir"/*.yaml; do
  # `on` parses as the boolean key `true` in YAML 1.1; accept both spellings.
  triggers="$(yq -r '(.on // .true) | (select(tag == "!!str") // (select(tag == "!!seq") | .[]) // (select(tag == "!!map") | keys | .[]))' "$wf")" \
    || { echo "lint-release-env: cannot parse $wf" >&2; exit 2; }
  envs="$(yq -r '.jobs[] | .environment | (select(tag == "!!str") // .name // "")' "$wf")" \
    || { echo "lint-release-env: cannot parse $wf" >&2; exit 2; }
  grep -qx release <<< "$envs" || continue
  for t in pull_request_target workflow_run issue_comment; do
    if grep -qx "$t" <<< "$triggers"; then
      echo "::error file=$wf::names the release environment and is triggered by $t (ADR-0044 (i))"
      bad=1
    fi
  done
done
exit "$bad"
