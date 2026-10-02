#!/usr/bin/env bash
# lint-signing-env.sh: refuse any workflow that names the `macos-signing`
# environment unless the workflow runs only on pushed `v*` tags and every job
# naming the environment repeats that with a tag-ref `if:`
# (cameronsjo/cadence-hooks#280).
#
# The environment holds the Developer ID key and the notary password, and its
# deployment policy admits tag `v*` alone. This lint is the in-repo half of
# that rule: a workflow that could run the environment from a branch, a PR, a
# dispatch or another workflow's run fails here, before the policy is the only
# thing in the way. Kept beside the vendored lint-release-env.sh (the
# cadence-ecosystem canonical copy, left unmodified) and run by the same job.
#
#   bash .github/scripts/lint-signing-env.sh [workflows-dir]
#
# Exit 0: clean. Exit 1: a violation (each printed). Exit 2: a workflow yq
# cannot parse, which is a failure, not a pass.
set -euo pipefail

dir="${1:-.github/workflows}"
env_name="macos-signing"
[[ -d "$dir" ]] || { echo "lint-signing-env: no directory $dir" >&2; exit 2; }
command -v yq >/dev/null || { echo "lint-signing-env: yq is required" >&2; exit 2; }

bad=0
fail() {
  echo "::error file=$1::$2 (cameronsjo/cadence-hooks#280)"
  bad=1
}

shopt -s nullglob
for wf in "$dir"/*.yml "$dir"/*.yaml; do
  jobs="$(yq -r '.jobs // {} | to_entries[] | select((.value.environment | (select(tag == "!!str") // .name // "")) == "'"$env_name"'") | .key' "$wf")" \
    || { echo "lint-signing-env: cannot parse $wf" >&2; exit 2; }
  [[ -n "$jobs" ]] || continue

  # `on` parses as the boolean key `true` in YAML 1.1; accept both spellings.
  # The trigger must be a map whose only key is `push`, and that push must
  # name tags only: no branches, no path filters that could stand in for them.
  on_tag="$(yq -r '(.on // .true) | tag' "$wf")" || { echo "lint-signing-env: cannot parse $wf" >&2; exit 2; }
  if [[ "$on_tag" != "!!map" ]]; then
    fail "$wf" "names the $env_name environment but its trigger is not a push-on-tags map"
  else
    triggers="$(yq -r '(.on // .true) | keys | .[]' "$wf")"
    [[ "$triggers" == "push" ]] || fail "$wf" "names the $env_name environment and has triggers other than push: $(tr '\n' ' ' <<< "$triggers")"
    push_keys="$(yq -r '(.on // .true).push | select(tag == "!!map") | keys | .[]' "$wf")"
    [[ "$push_keys" == "tags" ]] || fail "$wf" "names the $env_name environment but its push trigger is not tags-only (keys: $(tr '\n' ' ' <<< "$push_keys"))"
    tags="$(yq -r '(.on // .true).push.tags | (select(tag == "!!seq") | .[]) // (select(tag == "!!str"))' "$wf")"
    [[ -n "$tags" ]] || fail "$wf" "names the $env_name environment but its push trigger lists no tags"
    while IFS= read -r t; do
      [[ -z "$t" || "$t" == v* ]] || fail "$wf" "names the $env_name environment and triggers on tag pattern '$t', not v*"
    done <<< "$tags"
  fi

  # Each job naming the environment must gate on a v* tag ref itself, with
  # exactly that condition: a substring match would accept `... || true`.
  while IFS= read -r job; do
    cond="$(yq -r ".jobs.\"$job\".if // \"\"" "$wf")"
    case "$cond" in
      "startsWith(github.ref, 'refs/tags/v')" | "\${{ startsWith(github.ref, 'refs/tags/v') }}") ;;
      *) fail "$wf" "job '$job' names the $env_name environment without exactly if: startsWith(github.ref, 'refs/tags/v')" ;;
    esac
  done <<< "$jobs"
done
exit "$bad"
