#!/usr/bin/env bash
#
# Refresh tests/fixtures/registration-audit/ from the cadence monorepo's
# default branch.
#
# The fixture is what carries the hook-registration audit on CI, which has no
# sibling monorepo checkout. `fixture_manifests_match_the_monorepo_default_branch`
# goes red locally when the two disagree; this is the repair.
#
# Reads `origin/main`, never the sibling's working tree — a checkout parked on a
# feature branch or behind origin/main would otherwise be copied in as if it
# were what ships. Fetch first: origin/main is only as current as the last fetch.
#
# Every hook's `if:` value is replaced with a placeholder. The audit reads only
# whether an `if:` key is present, never its content, so this costs no coverage
# and keeps the per-guard command prefilters out of a public repository. See
# tests/fixtures/registration-audit/README.md.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
fixture_root="$repo_root/tests/fixtures/registration-audit/cadence/plugins"

# The workspace root is the grandparent of git's COMMON dir, matching
# `workspace_root()` in tests/hook_registration_audit.rs. `--show-toplevel`
# would answer with the linked worktree (`.claude/worktrees/<name>`), whose
# parent has no plugin siblings — so a toplevel-relative guess sends this
# script hunting a monorepo in `.claude/worktrees/cadence` from exactly the
# tree a developer works in.
git_common_dir="$(git rev-parse --path-format=absolute --git-common-dir)"
workspace_root="$(dirname "$(dirname "$git_common_dir")")"
monorepo="${CADENCE_MONOREPO:-$workspace_root/cadence}"

if [ ! -d "$monorepo/.git" ]; then
  echo "FAIL: no cadence monorepo checkout at $monorepo" >&2
  echo "      set CADENCE_MONOREPO to its path" >&2
  exit 1
fi

if ! git -C "$monorepo" rev-parse --verify --quiet origin/main >/dev/null; then
  echo "FAIL: $monorepo has no origin/main — run: git -C $monorepo fetch origin" >&2
  exit 1
fi

echo "monorepo:   $monorepo"
echo "default:    $(git -C "$monorepo" rev-parse --short origin/main)"
echo "fixture:    $fixture_root"
echo

# The plugins BINARY_PLUGIN_DIRS names. Derived from the fixture's own layout so
# this script cannot silently refresh a subset after a plugin is added: the
# audit fails on a fixture manifest that is missing, and adding one here is the
# same edit as adding it to BINARY_PLUGIN_DIRS.
for dir in "$fixture_root"/*/; do
  plugin="$(basename "$dir")"
  src="plugins/$plugin/hooks/hooks.json"

  if ! git -C "$monorepo" cat-file -e "origin/main:$src" 2>/dev/null; then
    echo "FAIL: origin/main has no $src" >&2
    echo "      the plugin was renamed or retired — update BINARY_PLUGIN_DIRS" >&2
    echo "      in tests/hook_registration_audit.rs and remove its fixture dir" >&2
    exit 1
  fi

  # Produce into a temp file and move it into place only on success. A direct
  # `> "$dir/hooks/hooks.json"` truncates the fixture before python runs, so a
  # malformed blob upstream would leave an empty manifest behind — and the next
  # test run panics reading it rather than reporting the real problem.
  tmp="$(mktemp)"

  # shellcheck disable=SC2016  # single quotes are required: this is Python
  # source, and shell expansion inside it would corrupt the program.
  git -C "$monorepo" show "origin/main:$src" \
    | python3 -c '
import json, sys
PLACEHOLDER = "<redacted in the public fixture; the audit reads only whether an `if:` is present>"
doc = json.load(sys.stdin)
for blocks in doc.get("hooks", {}).values():
    for block in blocks:
        for hook in block.get("hooks", []):
            if "if" in hook:
                hook["if"] = PLACEHOLDER
json.dump(doc, sys.stdout, indent=2)
sys.stdout.write("\n")
' > "$tmp"

  mv "$tmp" "$dir/hooks/hooks.json"
  echo "  refreshed $plugin"
done

echo
echo "PASS: fixture refreshed — run: cargo test --test hook_registration_audit"
