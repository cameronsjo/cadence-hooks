#!/usr/bin/env bash
# ship-gate.sh: decide whether tonight's release PR may merge (ADR-0044 (c)).
#
# Canonical copy: cadence-ecosystem scripts/release/ship-gate.sh. Repos vendor
# it byte-for-byte at .github/scripts/ship-gate.sh; the release radar compares
# sha256 against the canonical file, so edit here and re-vendor.
#
# Reads only. Needs bash (3.2+), gh, jq (1.6+). Inputs come from env (see
# validate_inputs). Writes go/pr/head_sha/title/reason to $GITHUB_OUTPUT on
# every exit path.
#
# Exit 0: paused | no-pr | ci-red | go.   Exit 1: half-shipped | not-verified | error.
set -euo pipefail

TITLE_RE='^chore(\(main\))?: release v?[0-9]+\.[0-9]+\.[0-9]+$'
PENDING_LABEL='autorelease: pending'
MANIFEST=.release-please-manifest.json
RAW='Accept: application/vnd.github.raw+json'

GO=false PR='' HEAD_SHA='' TITLE='' REASON=error DETAIL='' NOTE='' DECIDED=0
WORK="$(mktemp -d)"
# fail() inside $(...) cannot reach the parent's DETAIL; it leaves the cause here.
ERR_FILE="$WORK/err"

# Pure helpers, prepended to the jq programs that need them. Blobs arrive as
# raw text through --rawfile, never argv (Linux caps one argument at 128 KiB).
# shellcheck disable=SC2016  # jq source, not shell
JQ_LIB='
def semver: if type == "string" and test("^[0-9]+\\.[0-9]+\\.[0-9]+$")
  then split(".") | map(tonumber) else null end;
def obj: (try fromjson catch null) | if type == "object" then . else null end;
def vline: test("^version = \"[^\"]*\"$");
# [package] version of a Cargo.toml, or null.
def cargo_version: reduce split("\n")[] as $l ({sec: "", v: null};
  if ($l | test("^\\s*\\[")) then .sec = ($l | gsub("\\s"; ""))
  elif .sec == "[package]" and .v == null and ($l | vline)
  then .v = ($l | capture("^version = \"(?<v>[^\"]*)\"$").v) else . end) | .v;
# Same line count; every changed line is a version line on both sides and
# now reads the title version.
def version_lines_only($b; $h; $v; $one):
  ($b | split("\n")) as $bl | ($h | split("\n")) as $hl
  | if ($bl | length) != ($hl | length) then "line count changed"
    else [range(0; $bl | length) | select($bl[.] != $hl[.])] as $d
    | if any($d[]; ($bl[.] | vline | not) or $hl[.] != "version = \"\($v)\"")
      then "a line other than version = \"\($v)\" changed"
      elif ($d | length) == 0 then "no version line changed"
      elif $one and ($d | length) != 1 then "\($d | length) version lines changed, expected one"
      else "" end end;
def content_rule($name; $b; $h; $v):
  if $name == "Cargo.toml" then version_lines_only($b; $h; $v; true)
  elif $name == "Cargo.lock" then version_lines_only($b; $h; $v; false)
  else ($b | obj) as $B | ($h | obj) as $H
  | if $B == null or $H == null then "not a JSON object on both sides"
    elif $name == "package.json" or $name == "manifest.json" then
      if ($B | del(.version)) == ($H | del(.version)) then "" else "changed more than .version" end
    elif $name == "package-lock.json" then
      if ($B | del(.version, .packages[""].version)) == ($H | del(.version, .packages[""].version))
      then "" else "changed more than the root version fields" end
    elif $name == ".release-please-manifest.json" then
      if ($B | keys) != ($H | keys) then "key set changed"
      elif any($H[]; semver == null) then "a value is not X.Y.Z" else "" end
    elif $name == "versions.json" then
      (($H | keys) - ($B | keys)) as $new
      | if ($new | length) != 1 or ($B | keys - ($H | keys) | length) != 0
        then "expected exactly one added key"
        elif ($H | del(.[$new[0]])) != $B then "existing entries changed" else "" end
    else "no content rule" end end;
'

# shellcheck disable=SC2329  # invoked by the EXIT trap
finish() {
  local rc=$?
  if [[ "$DECIDED" != 1 ]]; then
    GO=false REASON=error PR='' HEAD_SHA='' TITLE=''
    [[ -n "$DETAIL" ]] || DETAIL="$(head -n1 "$ERR_FILE" 2>/dev/null || true)"
    [[ -n "$DETAIL" ]] || DETAIL="unexpected failure (exit ${rc})"
    rc=1
  fi
  rm -rf "$WORK"
  # API-derived text goes into a workflow-command line below; keep it to a
  # charset that cannot start a new line or command.
  DETAIL="${DETAIL//[^A-Za-z0-9._\/ :#@()=,&?\[\]-]/?}"
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    local delim
    delim="EOF_$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
    {
      printf 'go=%s\n' "$GO"
      printf 'reason=%s\n' "$REASON"
      printf 'pr<<%s\n%s\n%s\n' "$delim" "$PR" "$delim"
      printf 'head_sha<<%s\n%s\n%s\n' "$delim" "$HEAD_SHA" "$delim"
      printf 'title<<%s\n%s\n%s\n' "$delim" "$TITLE" "$delim"
    } >> "$GITHUB_OUTPUT"
  fi
  echo "ship-gate: reason=${REASON} go=${GO} pr=${PR:-none} head=${HEAD_SHA:-none} ${DETAIL}"
  if [[ "$rc" == 0 ]]; then
    echo "::notice::ship-gate ${REASON}: ${DETAIL}"
  else
    echo "::error::ship-gate ${REASON}: ${DETAIL}"
  fi
  exit "$rc"
}
trap finish EXIT

# decide <reason> <exit-code> <detail>. NOTE carries context for every verdict.
decide() {
  REASON="$1" DETAIL="$3${NOTE}" DECIDED=1
  [[ "$REASON" == go ]] && GO=true
  exit "$2"
}

fail() {
  DETAIL="$1"
  echo "$1" >> "$ERR_FILE"
  echo "ship-gate: error: $1" >&2
  exit 1
}

validate_inputs() {
  [[ "${REPO:-}" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]] || fail "bad REPO"
  [[ "${BRANCH:-}" =~ ^[A-Za-z0-9._/-]+$ ]] || fail "bad BRANCH"
  [[ "${BOT_LOGIN:-}" =~ ^[A-Za-z0-9-]+\[bot\]$ ]] || fail "bad BOT_LOGIN"
  [[ "${TAG_PREFIX-x}" =~ ^v?$ ]] || fail "bad TAG_PREFIX"
  [[ "${EVENT_NAME:-}" =~ ^(schedule|workflow_dispatch)$ ]] || fail "bad EVENT_NAME"
  [[ -n "${GH_TOKEN:-}" ]] || fail "GH_TOKEN is empty"
  local line count=0
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^[A-Za-z0-9._/-]+$ ]] || fail "bad ALLOWLIST entry"
    count=$((count + 1))
  done <<< "${ALLOWLIST:-}"
  [[ "$count" -gt 0 ]] || fail "ALLOWLIST is empty"
  while IFS= read -r line; do
    [[ -z "$line" || "$line" =~ ^[A-Za-z0-9\ ._/()-]+$ ]] || fail "bad REQUIRED_CHECKS entry"
  done <<< "${REQUIRED_CHECKS:-}"
}

# api_obj <endpoint>: one JSON object, or fail.
api_obj() {
  local raw
  raw="$(gh api "$1")" || fail "gh api failed: $1"
  jq -ce 'if type == "object" then . else error("not an object") end' <<< "$raw" \
    || fail "non-object JSON from $1"
}

# api_list <endpoint> <key>: every page merged into one array, or fail. <key>
# names the array inside each page ("" when the page is the array). An empty
# body is unknown, not zero, so it fails.
api_list() {
  local raw
  raw="$(gh api --paginate "$1")" || fail "gh api failed: $1"
  jq -sce --arg k "$2" '
    if length == 0 then error("empty body") else . end
    | map(if $k == "" then . else .[$k] end)
    | if all(type == "array") then add else error("not an array") end
  ' <<< "$raw" || fail "non-array JSON from $1"
}

# fetch <path> <ref> <out>: raw file contents at a ref (up to 100 MB), or fail.
fetch() {
  gh api -H "$RAW" "repos/${REPO}/contents/$1?ref=$2" > "$3" || fail "gh api failed: contents/$1 at $2"
}

# version_at <version file> <ref>: the X.Y.Z it records, or fail.
version_at() {
  fetch "$1" "$2" "$WORK/v"
  jq -rn --rawfile t "$WORK/v" --arg f "$1" --arg m "$MANIFEST" "$JQ_LIB"'
    (if $f == $m then ($t | obj | .["."]?) else ($t | cargo_version) end)
    | if semver == null then error("no X.Y.Z") else . end' || fail "no X.Y.Z version in $1 at $2"
}

validate_inputs

# (1) Pause switch: only the clock obeys it.
if [[ "$EVENT_NAME" == schedule && "${SHIP_NIGHTLY:-}" != on ]]; then
  decide paused 0 "SHIP_NIGHTLY is not on"
fi

# (2) Candidates: open PRs into BRANCH whose title looks like a release,
# whoever wrote them. A fork PR is dropped (anyone can open one); a same-repo
# human-authored match is a failure, not a skip.
open="$(api_list "repos/${REPO}/pulls?state=open&base=${BRANCH}&per_page=100" "")"
cands="$(jq -ce --arg re "$TITLE_RE" --arg repo "$REPO" '
  map(select((.title | type) == "string" and (.title | test($re))))
  | {same: map(select(.head.repo.full_name? == $repo)),
     forks: map(select(.head.repo.full_name? != $repo)) | length}' <<< "$open")" \
  || fail "bad open-PR shape"
nfork="$(jq '.forks' <<< "$cands")"
[[ "$nfork" == 0 ]] || NOTE="; ignored ${nfork} fork PR(s) with a release title"
ncand="$(jq '.same | length' <<< "$cands")"

if [[ "$ncand" == 1 ]]; then
  num="$(jq -r '.same[0].number' <<< "$cands")"
  [[ "$num" =~ ^[0-9]+$ ]] || fail "PR number is not a number"
  PR="$num"
  # The single-PR endpoint is authoritative for head, base, draft, fork, and
  # the counts used to prove the lists are complete.
  pr="$(api_obj "repos/${REPO}/pulls/${PR}")"
  sha="$(jq -r '.head.sha' <<< "$pr")"
  [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || fail "head sha is not 40-hex"
  HEAD_SHA="$sha"
  base_sha="$(jq -r '.base.sha' <<< "$pr")"
  [[ "$base_sha" =~ ^[0-9a-f]{40}$ ]] || fail "base sha is not 40-hex"
  files="$(api_list "repos/${REPO}/pulls/${PR}/files?per_page=100" "")"
fi

# The version file: the manifest if the PR changes it, else Cargo.toml if the
# PR changes it; with no single candidate, whichever exists at BRANCH.
vfile=''
if [[ "$ncand" == 1 ]]; then
  vfile="$(jq -r --arg m "$MANIFEST" '[.[].filename] as $n
    | if $n | index($m) then $m elif $n | index("Cargo.toml") then "Cargo.toml" else "" end' \
    <<< "$files")" || fail "bad files shape"
fi
if [[ -z "$vfile" ]]; then
  root="$(api_list "repos/${REPO}/contents?ref=${BRANCH}" "")"
  vfile="$(jq -r --arg m "$MANIFEST" '[.[] | select(.type == "file") | .name] as $n
    | if $n | index($m) then $m elif $n | index("Cargo.toml") then "Cargo.toml" else "" end' \
    <<< "$root")" || fail "bad root listing shape"
  [[ -n "$vfile" ]] || fail "no ${MANIFEST} or Cargo.toml at ${BRANCH}"
fi

# (3) Half-shipped, anchored on state: the version BRANCH records must be
# tagged and published. Only a repo with no X.Y.Z tag at all skips this.
base_version="$(version_at "$vfile" "$BRANCH")"
closed="$(api_list "repos/${REPO}/pulls?state=closed&base=${BRANCH}&sort=updated&direction=desc&per_page=100" "")"
pending="$(jq -r --arg re "$TITLE_RE" --arg bot "$BOT_LOGIN" --arg l "$PENDING_LABEL" '
  map(select(.merged_at != null and (.title | test($re)) and .user.login == $bot))
  | sort_by(.merged_at) | last // {} | [.labels[]?.name] | index($l) != null' <<< "$closed")" \
  || fail "bad closed-PR shape"
[[ "$pending" != true ]] || decide half-shipped 1 "merged release PR still labelled ${PENDING_LABEL}"
tag="${TAG_PREFIX}${base_version}"
refs="$(api_list "repos/${REPO}/git/matching-refs/tags${TAG_PREFIX:+/$TAG_PREFIX}" "")"
tagged="$(jq -r --arg r "refs/tags/${tag}" --arg p "$TAG_PREFIX" '
  if any(.[]; .ref == $r) then "yes"
  elif any(.[]; .ref | test("^refs/tags/\($p)[0-9]+\\.[0-9]+\\.[0-9]+$")) then "no"
  else "never" end' <<< "$refs")" || fail "bad tag-refs shape"
[[ "$tagged" != no ]] || decide half-shipped 1 "${BRANCH} is at ${base_version} but tag ${tag} does not exist"
if [[ "$tagged" == yes ]]; then
  releases="$(api_list "repos/${REPO}/releases?per_page=100" "")"
  has_rel="$(jq -r --arg t "$tag" 'any(.[]; .tag_name == $t and .draft == false)' <<< "$releases")" \
    || fail "bad releases shape"
  [[ "$has_rel" == true ]] || decide half-shipped 1 "tag ${tag} has no published GitHub release"
fi

[[ "$ncand" != 0 ]] || decide no-pr 0 "no open release PR into ${BRANCH}"
[[ "$ncand" == 1 ]] || decide not-verified 1 "${ncand} open release PRs, expected one"

# (4) Provenance.
problem="$(jq -r --arg bot "$BOT_LOGIN" --arg repo "$REPO" --arg br "$BRANCH" --arg re "$TITLE_RE" '
  if (.title | test($re)) | not then "title changed"
  elif .user.login != $bot then "author is not \($bot)"
  elif .user.type != "Bot" then "author type is not Bot"
  elif .draft != false then "PR is draft"
  elif .head.repo.full_name != $repo then "head is not in \($repo)"
  elif .base.ref != $br then "base is not \($br)"
  elif (.commits | type) != "number" or (.changed_files | type) != "number" then "missing counts"
  elif .commits > 100 or .changed_files > 100 then "more than 100 commits or files"
  else "" end' <<< "$pr")" || fail "bad PR shape"
[[ -z "$problem" ]] || decide not-verified 1 "PR #${PR}: ${problem}"
TITLE="$(jq -r '.title' <<< "$pr")"
version="${TITLE##* }"
version="${version#v}"

# Author and committer logins come from commit emails, which a pusher sets
# freely; GitHub's signature verification is what binds them.
commits="$(api_list "repos/${REPO}/pulls/${PR}/commits?per_page=100" "")"
problem="$(jq -r --arg bot "$BOT_LOGIN" --argjson n "$(jq '.commits' <<< "$pr")" '
  if length != $n then "commit list has \(length) of \($n)"
  else (map(select(.author.login != $bot
                   or ((.committer.login // "") | IN($bot, "web-flow") | not)))
        | if length > 0 then "commit \(.[0].sha[0:12]) not made by the bot" else "" end)
    + (map(select(.commit.verification.verified != true
                  or .commit.verification.reason != "valid"))
        | if length > 0 then "commit \(.[0].sha[0:12]) signature is not verified" else "" end)
  end' <<< "$commits")" || fail "bad commits shape"
[[ -z "$problem" ]] || decide not-verified 1 "PR #${PR}: ${problem}"

# (5) Content: paths inside the allowlist, then each file bound to a
# version-only diff by its filename's rule. No rule means no merge.
problem="$(jq -r --arg allow "$ALLOWLIST" --argjson n "$(jq '.changed_files' <<< "$pr")" '
  ($allow | split("\n") | map(select(length > 0))) as $ok
  | if length != $n then "file list has \(length) of \($n)"
    else ([.[] | .filename, (.previous_filename // empty)]
          | map(select(IN($ok[]) | not))
          | if length > 0 then "file not in allowlist: \(.[0])" else "" end)
    end' <<< "$files")" || fail "bad files shape"
[[ -z "$problem" ]] || decide not-verified 1 "PR #${PR}: ${problem}"

rows="$(jq -r '.[] | [.filename, (.status | tostring),
  (.deletions | if type == "number" then tostring else error("deletions") end)] | @tsv' \
  <<< "$files")" || fail "bad files shape"
while IFS=$'\t' read -r f st dels; do
  [[ "$st" == modified ]] || decide not-verified 1 "PR #${PR}: ${f} is ${st}, not modified"
  name="${f##*/}"
  case "$name" in
    CHANGELOG.md)
      [[ "$dels" == 0 ]] || decide not-verified 1 "PR #${PR}: ${f} deletes ${dels} line(s)"
      continue ;;
    Cargo.toml | Cargo.lock | package.json | manifest.json | package-lock.json | "$MANIFEST" | versions.json) ;;
    *) decide not-verified 1 "PR #${PR}: no content rule for ${f}" ;;
  esac
  fetch "$f" "$base_sha" "$WORK/b"
  fetch "$f" "$HEAD_SHA" "$WORK/h"
  problem="$(jq -rn --rawfile b "$WORK/b" --rawfile h "$WORK/h" --arg n "$name" --arg v "$version" \
    "$JQ_LIB"'content_rule($n; $b; $h; $v)')" || fail "content rule failed for ${f}"
  [[ -z "$problem" ]] || decide not-verified 1 "PR #${PR}: ${f}: ${problem}"
done <<< "$rows"

# auto-tag tags the file's version, not the title's, so they must agree; and
# a release only moves forward.
head_version="$(version_at "$vfile" "$HEAD_SHA")"
[[ "$head_version" == "$version" ]] \
  || decide not-verified 1 "PR #${PR}: title says ${version} but ${vfile} says ${head_version}"
order="$(jq -rn --arg a "$version" --arg b "$base_version" "$JQ_LIB"'
  ($a | semver) as $x | ($b | semver) as $y
  | if $x <= $y then "stale" elif $x[0] > $y[0] then "major" else "ok" end')" || fail "version compare failed"
[[ "$order" != stale ]] || decide not-verified 1 "PR #${PR}: ${version} is not newer than ${base_version}"
[[ "$order" != major ]] || NOTE="${NOTE}; major bump ${base_version} to ${version}"

# (6) CI at head: at least one run, all green, every required check a
# success, and every check suite finished.
runs="$(api_list "repos/${REPO}/commits/${HEAD_SHA}/check-runs?per_page=100" check_runs)"
problem="$(jq -r --arg req "${REQUIRED_CHECKS:-}" '
  . as $runs
  | if length == 0 then "no check runs at head"
    else (map(select(.status != "completed"
                     or ((.conclusion // "") | IN("success", "skipped", "neutral") | not)))
          | if length > 0 then "check \(.[0].name) is \(.[0].status)/\(.[0].conclusion)" else "" end)
      + ([$req | split("\n")[] | select(length > 0)
          | select(. as $n | any($runs[]; .name == $n and .conclusion == "success") | not)]
          | if length > 0 then "required check \(.[0]) has no success at head" else "" end)
    end' <<< "$runs")" || fail "bad check-runs shape"
[[ -z "$problem" ]] || decide ci-red 0 "PR #${PR}: ${problem}"

suites="$(api_list "repos/${REPO}/commits/${HEAD_SHA}/check-suites?per_page=100" check_suites)"
# A suite with zero runs is an app that registered and never ran (live on
# forgectl: claude, codecov, sentry, coderabbitai stay queued forever). It has
# nothing to judge; real runs were judged above.
problem="$(jq -r '
  if all(.[]; (.latest_check_runs_count | type) == "number") | not
  then error("latest_check_runs_count") else . end
  | map(select(.latest_check_runs_count > 0))
  | map(select(.status != "completed"
             or ((.conclusion // "") | IN("success", "skipped", "neutral") | not)))
  | if length > 0 then "check suite \(.[0].app.slug // .[0].id) is \(.[0].status)/\(.[0].conclusion)"
    else "" end' <<< "$suites")" || fail "bad check-suites shape"
[[ -z "$problem" ]] || decide ci-red 0 "PR #${PR}: ${problem}"

status="$(api_obj "repos/${REPO}/commits/${HEAD_SHA}/status")"
problem="$(jq -r '
  if (.total_count | type) != "number" then error("no total_count")
  elif .total_count == 0 or .state == "success" then ""
  else "combined status is \(.state)" end' <<< "$status")" || fail "bad status shape"
[[ -z "$problem" ]] || decide ci-red 0 "PR #${PR}: ${problem}"

decide go 0 "PR #${PR} verified at ${HEAD_SHA}"
