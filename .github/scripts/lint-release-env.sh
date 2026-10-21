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
fail() {
  echo "::error file=$1::$2 (ADR-0044 (i))"
  bad=1
}

shopt -s nullglob
for wf in "$dir"/*.yml "$dir"/*.yaml; do
  # `on` parses as the boolean key `true` in YAML 1.1; accept both spellings.
  # Aliases are expanded so `on: *anchor` is read as GitHub reads it.
  triggers="$(yq -r 'explode(.) | (.on // .true) | (select(tag == "!!str") // (select(tag == "!!seq") | .[]) // (select(tag == "!!map") | keys | .[]))' "$wf")" \
    || { echo "lint-release-env: cannot parse $wf" >&2; exit 2; }

  # Judge the name GitHub resolves, not the YAML as written: aliases are
  # expanded (`explode`), and names are trimmed and lowercased (GitHub
  # resolves `Release ` to release). Two node shapes are readable, a plain
  # string or a map whose `name` is a plain string. Three shapes set no
  # environment and pass: a null, a map with no `name`, and a map whose `name`
  # is null. Any other shape (a custom tag, a sequence) is unreadable. Ported
  # from cadence-hooks .github/scripts/lint-signing-env.sh, but yq prints raw
  # facts and bash classifies them: yq v4.44 has no if/then/else and emits a
  # literal even after an empty select, and v4.47 tags a missing key
  # differently. Only jobs that set `environment` print a line, `|`-separated
  # (job ids cannot hold one):
  # <job>|<environment tag>|<name tag, or ->|<trimmed lowercase name>.
  # shellcheck disable=SC2016 # $e is a yq variable, not a shell one.
  envs="$(yq -r 'explode(.) | .jobs // {} | to_entries[]
      | select(.value | tag == "!!map") | select(.value | has("environment"))
      | .value.environment as $e | .key
      + "|" + ($e | tag)
      + "|" + (($e | select(tag == "!!map") | select(has("name")) | .name | tag) // "-")
      + "|" + (($e | select(tag == "!!str") | trim | downcase)
          // ($e | select(tag == "!!map") | select(has("name")) | .name | select(tag == "!!str") | trim | downcase)
          // "")' "$wf")" \
    || { echo "lint-release-env: cannot parse $wf" >&2; exit 2; }

  named=0
  unreadable=""
  while IFS='|' read -r job etag ntag name; do
    [[ -n "$job" ]] || continue
    case "$etag:$ntag" in
      '!!null:-' | '!!map:-' | '!!map:!!null') ;;
      '!!str:-' | '!!map:!!str')
        # shellcheck disable=SC2016 # a literal ${{ is what marks an expression.
        if [[ "$name" == *'${{'* ]]; then
          unreadable+="$job"$'\t'"an expression"$'\n'
        elif [[ "$name" == release ]]; then
          named=1
        fi ;;
      :*) echo "lint-release-env: unexpected row for job '$job' in $wf" >&2; exit 2 ;;
      *)
        what="$etag"
        if [[ "$ntag" != - ]]; then what+=" with a $ntag name"; fi
        unreadable+="$job"$'\t'"a node this lint cannot read ($what)"$'\n' ;;
    esac
  done <<< "$envs"

  # An expression or an unreadable node is refused only under the three
  # triggers, where it could resolve to `release` with nothing else in the
  # way. Under any other trigger GitHub applies the environment's deployment
  # policy to the ref that runs, so a PR branch that resolves to `release` is
  # refused by GitHub itself, and expressions are ordinary there (a matrix of
  # environments). Refusing them everywhere would block clean workflows.
  for t in pull_request_target workflow_run issue_comment; do
    grep -qx "$t" <<< "$triggers" || continue
    if [[ "$named" == 1 ]]; then
      fail "$wf" "names the release environment and is triggered by $t"
    fi
    while IFS=$'\t' read -r job what; do
      [[ -n "$job" ]] || continue
      fail "$wf" "job '$job' sets its environment with $what, which could resolve to release, and is triggered by $t; name the environment literally"
    done <<< "$unreadable"
  done
done
exit "$bad"
