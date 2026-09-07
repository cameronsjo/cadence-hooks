#!/usr/bin/env bash
# Replicate the redaction identity-tier term source onto this machine.
#
# The term source lives outside every repo by design (cadence-hooks#561), which
# means it does not travel with a git clone — so a second machine runs with the
# identity tier silently inert until this is run there. Pulls the backup from
# 1Password and writes ~/.config/cadence/redaction.toml with 0600 perms.
#
# Run interactively: `op` prompts for auth and cannot do so without a terminal.
# Safe to re-run: refuses to overwrite an existing armed term source.
set -uo pipefail

ITEM="cadence-redaction-terms"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/cadence"
TARGET="$CONFIG_DIR/redaction.toml"
LEGACY="$CONFIG_DIR/redaction-terms.txt"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[1m'; N=$'\e[0m'
else
  R=""; G=""; Y=""; B=""; N=""
fi
say()  { printf '%s\n' "$*"; }
ok()   { printf '%s\n' "${G}✓${N} $*"; }
warn() { printf '%s\n' "${Y}!${N} $*" >&2; }
die()  { printf '%s\n' "${R}✗ $*${N}" >&2; exit 1; }

say "${B}Replicating the redaction term source${N}"
say "  target: $TARGET"
say ""

command -v op >/dev/null 2>&1 || die "1Password CLI (op) not found. brew install 1password-cli"

# `grep -c` PRINTS a count and exits 1 when it matches nothing, so the obvious
# `|| echo 0` fallback appends a second zero and yields the string "0\n0" —
# which makes the `-gt` test throw rather than compare, silently, since there is
# no `set -e`. grep's own output is already the default we want.
count_terms() {
  local c
  c=$(grep -c '^\[\[terms\]\]' "$1" 2>/dev/null)
  printf '%s' "${c:-0}"
}

# Independent confirmation from the binary, not this script's own bookkeeping.
# Factored out because the reentrant path needs it too: counting `[[terms]]`
# headers proves a header exists, not that the file parses — a TOML truncated
# mid-entry, or with a broken `mode`, has a header and is still inert.
verify_with_binary() {
  local count="$1"
  say ""
  if ! command -v cadence-hooks >/dev/null 2>&1; then
    warn "cadence-hooks not installed here — cannot self-verify."
    say "VERDICT: terms-installed-unverified ($count terms) — install cadence-hooks, then run: cadence-hooks cadence redact-scan --status"
    exit 0
  fi
  # Check the VERSION before the status flag. An older binary rejects `--status`
  # with its own message and its own exit code — NOT clap's 2, as an earlier
  # version of this script assumed — so exit-code archaeology mislabeled a
  # perfectly healthy provisioning as "binary reports NOT ARMED", which reads
  # like a corrupt terms file and sends the operator to inspect the wrong thing.
  # A version comparison is deterministic and needs no guessing.
  local ver
  ver=$(cadence-hooks --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  if [ -z "$ver" ]; then
    warn "Could not read cadence-hooks --version."
    say "VERDICT: terms-installed-unverified ($count terms) — check 'cadence-hooks cadence redact-scan --status' by hand"
    exit 0
  fi
  # Sort-based compare: MIN_BINARY is the first release carrying the tier.
  local MIN_BINARY="0.72.0"
  if [ "$(printf '%s\n%s\n' "$MIN_BINARY" "$ver" | sort -V | head -1)" != "$MIN_BINARY" ]; then
    warn "Installed cadence-hooks is $ver — the identity tier needs $MIN_BINARY or newer."
    say "The terms are in place and correct; the binary simply cannot use them yet."
    say ""
    say "VERDICT: terms-installed-but-binary-too-old ($count terms, have $ver) — run: brew update && brew upgrade cadence-hooks"
    exit 0
  fi

  say "Verifying with the binary ($ver):"
  # Capture the exit code DIRECTLY. An `if cmd; then …; fi` whose condition
  # fails and has no else returns 0, so a trailing `rc=$?` reads 0 regardless.
  cadence-hooks cadence redact-scan --status
  local rc=$?
  say ""
  if [ "$rc" -eq 0 ]; then
    say "VERDICT: ${G}armed${N} ($count terms)"
    exit 0
  fi
  say "VERDICT: ${R}terms present but binary $ver reports NOT ARMED${N} — inspect $TARGET"
  exit 1
}

if [ -s "$TARGET" ]; then
  n=$(count_terms "$TARGET")
  if [ "$n" -gt 0 ]; then
    ok "Already armed — $n term(s) at $TARGET."
    # Still ask the binary. The whole point of this script is that a machine
    # can look provisioned while the tier is inert; short-circuiting on our own
    # header count would reproduce exactly that failure on the re-run path,
    # which is the path a re-run is for.
    verify_with_binary "$n"
  fi
  warn "$TARGET exists but carries zero terms — replacing it."
  # The migrate script refuses to overwrite an existing target, and its stderr
  # is swallowed below — so without this removal the legacy path would die with
  # a generic "conversion failed" and the "replacing it" promise would be a lie.
  rm -f "$TARGET"
fi

# `op` needs a controlling terminal. Checked here rather than up top so an
# already-armed machine short-circuits without needing one. Without this guard
# the failure reads as an auth problem when it is really a surface problem, and
# the tell — no prompt ever appeared — is easy to miss. `[ -t 0 ]` is not
# enough: stdin can be a terminal while the process has no controlling one.
: < /dev/tty 2>/dev/null || die "No controlling terminal. Run this in a real terminal — 1Password cannot prompt without one."

say "Preparing: fetching the backup from 1Password (it may prompt)…"
# `--fields` alone returns the value CSV-QUOTED when it is multi-line: a literal
# `"` is prepended and appended. That single character corrupted two
# provisioning runs before anyone spotted it — on the legacy text format the
# leading quote made the first comment line stop starting with `#`, so it
# counted as a term (a machine came up with 19 instead of 18, one of them a
# prose fragment and one real term displaced); on TOML it breaks parsing
# outright with `invalid basic string`. Both failures look like a bad terms
# file and send you to inspect the wrong thing.
#
# `--format json` returns the value unquoted and unescaped. Verified: the JSON
# path parses clean and its term set matches the source exactly.
BODY="$(op item get "$ITEM" --format json --fields label=notesPlain --reveal 2>/dev/null \
  | python3 -c 'import json,sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(1)
v = d[0].get("value", "") if isinstance(d, list) else d.get("value", "")
sys.stdout.write(v)' 2>/dev/null)"
if [ -z "$BODY" ]; then
  # op exits 0 while yielding nothing in some auth states — treat empty as failure.
  die "Could not read 1Password item '$ITEM' (empty result). Sign in with 'op signin' and re-run."
fi
ok "Fetched the backup."

mkdir -p "$CONFIG_DIR" || die "Could not create $CONFIG_DIR"
chmod 700 "$CONFIG_DIR" 2>/dev/null

# The backup may be either format: the pre-migration line-based .txt, or the
# .toml. Detect rather than assume — writing a .txt to the .toml path would
# parse as zero terms and leave the tier inert while looking installed.
if printf '%s' "$BODY" | grep -q '^\[\[terms\]\]'; then
  say "Preparing: backup is already TOML — writing directly."
  umask 077
  printf '%s\n' "$BODY" > "$TARGET" || die "Write failed: $TARGET"
else
  say "Preparing: backup is the legacy line format — converting."
  MIG="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/migrate-redaction-terms.py"
  [ -f "$MIG" ] || die "Legacy backup needs $MIG to convert, which is missing. Pull the cadence-hooks repo and re-run from its scripts/ dir."
  umask 077
  printf '%s\n' "$BODY" > "$LEGACY" || die "Write failed: $LEGACY"
  python3 "$MIG" >/dev/null 2>&1 || die "Conversion failed. Run '$MIG' by hand to see why."
  # Drop the intermediate. On a machine being provisioned there is no reason to
  # leave a second copy of the deny-list on disk — the operator's ruling to keep
  # the legacy file applied to the ORIGINAL machine mid-migration, not to a
  # fresh one, and the 1Password item is the backup either way.
  rm -f "$LEGACY" && ok "Removed the intermediate legacy file."
fi

chmod 600 "$TARGET" 2>/dev/null || warn "Could not chmod 600 $TARGET — check its permissions by hand."
[ -s "$TARGET" ] || die "Wrote nothing to $TARGET"
COUNT=$(count_terms "$TARGET")
[ "$COUNT" -gt 0 ] || die "Wrote $TARGET but it parses to ZERO terms — the tier would be inert. Inspect it by hand."

# A count floor, because `> 0` accepts a truncated fetch or the wrong note
# entirely: one garbage line still writes, still counts as a term, and would
# very likely still satisfy the binary's own "parses, has terms" check. There
# is no way to know the canonical count from a machine that has never had the
# file, so this is a smell test, not a checksum — deliberately low, and a
# warning rather than a failure so a genuinely short list still provisions.
MIN_EXPECTED=5
if [ "$COUNT" -lt "$MIN_EXPECTED" ]; then
  warn "Only $COUNT term(s) — fewer than the $MIN_EXPECTED this normally carries."
  warn "A truncated fetch or the wrong 1Password item looks exactly like this. Compare against the source machine before trusting it."
fi

# PARSE the file, do not just count lines in it. Counting `[[terms]]` headers
# proves headers exist; it says nothing about whether the TOML is valid, and a
# file that does not parse leaves the tier completely inert. A CSV-quoting bug
# in the fetch produced exactly that — 18 headers, 18 values, and a document
# that failed on line 1 — and every line-counting check reported success.
if command -v python3 >/dev/null 2>&1; then
  if ! python3 -c 'import sys,tomllib; tomllib.load(open(sys.argv[1],"rb"))' "$TARGET" 2>/dev/null; then
    # tomllib is 3.11+; distinguish "cannot check" from "checked and bad".
    if python3 -c 'import tomllib' 2>/dev/null; then
      die "$TARGET is not valid TOML — the tier would be inert. Do not trust this file."
    fi
    warn "python3 has no tomllib (needs 3.11+) — could not validate the TOML."
  else
    ok "TOML parses."
  fi
else
  warn "python3 not found — could not validate the TOML."
fi

# Structural completeness: a fetch truncated mid-entry leaves a trailing
# `[[terms]]` header with no `term =` under it, which counts but never matches.
if [ "$(grep -c '^[[:space:]]*term[[:space:]]*=' "$TARGET" 2>/dev/null || true)" -lt "$COUNT" ]; then
  die "$TARGET has $COUNT [[terms]] header(s) but fewer term values — the fetch looks truncated. Not trusting it."
fi
ok "Wrote $COUNT term(s) to $TARGET (0600)."

verify_with_binary "$COUNT"
