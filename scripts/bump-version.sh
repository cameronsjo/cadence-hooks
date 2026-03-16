#!/usr/bin/env bash
# Bump the workspace version in Cargo.toml and any other version references.
# Usage: scripts/bump-version.sh 0.4.0
set -euo pipefail

VERSION="${1:-}"

if [[ -z "$VERSION" ]]; then
  echo "Usage: $0 <semver>" >&2
  echo "Example: $0 0.4.0" >&2
  exit 1
fi

if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Error: '$VERSION' is not valid semver (expected X.Y.Z)" >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CARGO_TOML="$REPO_ROOT/Cargo.toml"

# Read current version from workspace
CURRENT=$(grep -A1 '^\[workspace\.package\]' "$CARGO_TOML" | grep '^version' | sed 's/.*= *"\(.*\)"/\1/')

if [[ "$CURRENT" == "$VERSION" ]]; then
  echo "Already at version $VERSION" >&2
  exit 0
fi

echo "Bumping version: $CURRENT -> $VERSION"

# Update workspace version in Cargo.toml
# The workspace.package version line follows [workspace.package]
if [[ "$(uname)" == "Darwin" ]]; then
  sed -i '' "s/^version = \"$CURRENT\"/version = \"$VERSION\"/" "$CARGO_TOML"
else
  sed -i "s/^version = \"$CURRENT\"/version = \"$VERSION\"/" "$CARGO_TOML"
fi

# Verify the change took effect
UPDATED=$(grep -A1 '^\[workspace\.package\]' "$CARGO_TOML" | grep '^version' | sed 's/.*= *"\(.*\)"/\1/')
if [[ "$UPDATED" != "$VERSION" ]]; then
  echo "Error: version update failed. Cargo.toml still shows $UPDATED" >&2
  exit 1
fi

echo "Updated Cargo.toml workspace version to $VERSION"
echo ""
echo "Next steps:"
echo "  git add Cargo.toml"
echo "  git commit -m \"chore: bump version to $VERSION\""
echo "  git tag v$VERSION"
echo "  git push --tags"
