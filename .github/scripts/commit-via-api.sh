#!/usr/bin/env bash
# Commit files onto a branch through the GitHub REST API (git/blobs ->
# git/trees -> git/commits -> refs), so GitHub signs the commit as the token's
# App. A `git push` commit is unsigned, and the ship gate refuses unsigned
# release commits (cadence-ecosystem ADR-0044 (c) item 4).
#
# Usage: commit-via-api.sh <path>...
# Env:   GH_TOKEN, REPO (owner/name), BRANCH (created or force-moved),
#        BASE_SHA (the one parent), MESSAGE, FILES_DIR (holds each <path>).
# Prints `unchanged` when BRANCH already holds this tree on BASE_SHA,
# otherwise `commit=<sha>`. Refuses a commit GitHub did not sign.
set -euo pipefail

[[ "${REPO:-}" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]] || { echo "bad REPO" >&2; exit 2; }
[[ "${BRANCH:-}" =~ ^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$ && "$BRANCH" != main ]] || { echo "bad BRANCH" >&2; exit 2; }
[[ "${BASE_SHA:-}" =~ ^[0-9a-f]{40}$ ]] || { echo "bad BASE_SHA" >&2; exit 2; }
[[ -n "${MESSAGE:-}" && -d "${FILES_DIR:-}" && $# -gt 0 ]] || { echo "usage: commit-via-api.sh <path>..." >&2; exit 2; }

api="repos/${REPO}/git"
entries='[]'
for path in "$@"; do
  [[ "$path" =~ ^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$ ]] || { echo "bad path: $path" >&2; exit 2; }
  [[ -f "$FILES_DIR/$path" ]] || { echo "missing $FILES_DIR/$path" >&2; exit 2; }
  blob="$(jq -n --rawfile c "$FILES_DIR/$path" '{content: ($c | @base64), encoding: "base64"}' \
    | gh api -X POST "$api/blobs" --input - --jq .sha)"
  [[ "$blob" =~ ^[0-9a-f]{40}$ ]] || { echo "blob for $path: unexpected response" >&2; exit 1; }
  entries="$(jq -c --arg p "$path" --arg s "$blob" '. + [{path: $p, mode: "100644", type: "blob", sha: $s}]' <<< "$entries")"
done

base_tree="$(gh api "$api/commits/${BASE_SHA}" --jq .tree.sha)"
tree="$(jq -n --arg b "$base_tree" --argjson e "$entries" '{base_tree: $b, tree: $e}' \
  | gh api -X POST "$api/trees" --input - --jq .sha)"
[[ "$tree" =~ ^[0-9a-f]{40}$ ]] || { echo "tree: unexpected response" >&2; exit 1; }

# An exact-ref lookup that returns [] instead of a 404 when the branch is new.
current="$(gh api "$api/matching-refs/heads/${BRANCH}" \
  | jq -r --arg r "refs/heads/${BRANCH}" '[.[] | select(.ref == $r) | .object.sha][0] // ""')"
if [[ -n "$current" ]]; then
  # Unchanged only if the tree and parent match and GitHub signed it too.
  same="$(gh api "$api/commits/${current}" | jq -r --arg t "$tree" --arg p "$BASE_SHA" \
    '.tree.sha == $t and ([.parents[].sha] == [$p]) and .verification.verified == true and .verification.reason == "valid"')"
  if [[ "$same" == true ]]; then echo unchanged; exit 0; fi
fi

# No author or committer: GitHub fills in the App and signs the commit.
made="$(jq -n --arg m "$MESSAGE" --arg t "$tree" --arg p "$BASE_SHA" '{message: $m, tree: $t, parents: [$p]}' \
  | gh api -X POST "$api/commits" --input -)"
sha="$(jq -r .sha <<< "$made")"
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || { echo "commit: unexpected response" >&2; exit 1; }
verified="$(jq -r '"\(.verification.verified)/\(.verification.reason)"' <<< "$made")"
[[ "$verified" == true/valid ]] || { echo "commit ${sha} is not signed by GitHub (${verified})" >&2; exit 1; }

if [[ -n "$current" ]]; then
  gh api -X PATCH "$api/refs/heads/${BRANCH}" -f sha="$sha" -F force=true > /dev/null
else
  gh api -X POST "$api/refs" -f ref="refs/heads/${BRANCH}" -f sha="$sha" > /dev/null
fi
echo "commit=${sha}"
