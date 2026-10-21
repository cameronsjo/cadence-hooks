## Why

Since 0.129.0 (cameronsjo/cadence-hooks#1409, #1425) `prevent-secret-leaks` blocked any Bash command that defined a shell function and named a secret file anywhere, whatever the function did, so `die(){ echo "$*" >&2; exit 1; }; [ -f .env ] || die "missing .env"` and `f(){ echo hi; }; f; git commit -m '.env'` blocked. cadence-ecosystem ADR-0046 rule 1 puts function indirection out of scope. Part of cameronsjo/cadence-hooks#1443 (ADR-0046 phase 2), shipped in cameronsjo/cadence-hooks#1465.

## What Changes

- A function definition no longer makes a command block. The reader rules judge the command as they would without it.
- A literal read still blocks, in a function body or out (`f(){ cat .env; }; f`).
- A secret named only as a function's argument (`f(){ cat "$1"; }; f .env`) is allowed, as the ADR accepts.
- The positional-parameter half of the requirement stays; cameronsjo/cadence-hooks#1468 removes it.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `secret-reads`: "Secret names in untraced command shapes block" loses its function half.

## Impact

- `cadence-hooks cadence prevent-secret-leaks` (PreToolUse, Bash): a command that defines a function and names a secret outside a reader's operands exits 0, not 2. The block message for the remaining shape is unchanged. No env var, config key, ledger or marker file changes.
- No hooks.json change in cameronsjo/cadence.
