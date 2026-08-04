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

if [ -s "$TARGET" ]; then
  n=$(count_terms "$TARGET")
  if [ "$n" -gt 0 ]; then
    ok "Already armed — $n term(s) at $TARGET. Nothing to do."
    say ""
    say "VERDICT: already-armed ($n terms)"
    exit 0
  fi
  warn "$TARGET exists but carries zero terms — will replace it."
fi

# `op` needs a controlling terminal. Checked here rather than up top so an
# already-armed machine short-circuits without needing one. Without this guard
# the failure reads as an auth problem when it is really a surface problem, and
# the tell — no prompt ever appeared — is easy to miss. `[ -t 0 ]` is not
# enough: stdin can be a terminal while the process has no controlling one.
: < /dev/tty 2>/dev/null || die "No controlling terminal. Run this in a real terminal — 1Password cannot prompt without one."

say "Preparing: fetching the backup from 1Password (it may prompt)…"
BODY="$(op item get "$ITEM" --fields label=notesPlain --reveal 2>/dev/null)"
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

chmod 600 "$TARGET" 2>/dev/null
[ -s "$TARGET" ] || die "Wrote nothing to $TARGET"
COUNT=$(count_terms "$TARGET")
[ "$COUNT" -gt 0 ] || die "Wrote $TARGET but it parses to ZERO terms — the tier would be inert. Inspect it by hand."
ok "Wrote $COUNT term(s) to $TARGET (0600)."

# Independent confirmation from the binary, not from this script's own bookkeeping.
say ""
if command -v cadence-hooks >/dev/null 2>&1; then
  say "Verifying with the binary:"
  # Capture the exit code DIRECTLY. An `if cmd; then …; fi` whose condition
  # fails and has no else returns 0, so a trailing `rc=$?` reads 0 no matter
  # what cmd did — which would have made the too-old branch below unreachable
  # and misreported a healthy provisioning as a failure.
  cadence-hooks cadence redact-scan --status
  rc=$?
  say ""
  case "$rc" in
    0)
      say "VERDICT: ${G}armed${N} ($COUNT terms)"
      exit 0
      ;;
    2)
      warn "The installed cadence-hooks predates the identity tier (--status is unrecognized)."
      say "VERDICT: terms-installed-but-binary-too-old ($COUNT terms) — run: brew upgrade cadence-hooks"
      exit 0
      ;;
    *)
      say "VERDICT: ${R}terms written but binary reports NOT ARMED${N} — inspect $TARGET"
      exit 1
      ;;
  esac
fi
warn "cadence-hooks not installed here — cannot self-verify."
say "VERDICT: terms-installed-unverified ($COUNT terms) — install cadence-hooks, then run: cadence-hooks cadence redact-scan --status"
exit 0
