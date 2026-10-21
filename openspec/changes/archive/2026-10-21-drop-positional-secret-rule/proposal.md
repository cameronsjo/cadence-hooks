## Why

Since 0.129.0 (cameronsjo/cadence-hooks#1422) `prevent-secret-leaks` blocked any Bash command that set positional parameters and named a secret file anywhere, whatever its script did, so `bash -c 'echo hi' _ x; git commit -m 'mention .env'`, `set -- a b; git commit -m 'mention .env'` and `docker run --env-file .env img sh -c 'x' _ y` blocked. cadence-ecosystem ADR-0046 rule 1 puts positional-parameter indirection out of scope. With the function half gone (cameronsjo/cadence-hooks#1465), no line of "Secret names in untraced command shapes block" stays true. Part of cameronsjo/cadence-hooks#1443 (ADR-0046 phase 2), shipped in cameronsjo/cadence-hooks#1468.

## What Changes

- Setting positional parameters no longer makes a command block. The reader rules judge every command.
- A literal read still blocks, including one in a `-c` script behind a shell option cluster (`bash -eo pipefail -c 'cat .env'`) or behind a runner the guard peels (`find -exec`, `xargs`, `env`, `sudo`, `timeout`, `nohup`).
- A secret named only as an argument (`bash -c 'cat "$1"' _ .env`, `set -- .env; cat "$1"`) is allowed, as the ADR accepts.
- Accepted cost: a literal read in a `-c` script behind a wrapper the guard does not peel, or whose operands it re-joins without their quotes (`parallel`, `fd -x`/`-X`, `bash -s` with operands, `flock FILE CMD…`, BSD `script FILE CMD…`), was caught only by this rule and now passes. The guard does not peel `parallel` or `fd`, so their direct forms already passed. For `flock` and BSD `script`, core re-joins the operands with their quotes stripped (`flock L sh -c 'cat .env'` reaches the reader as `sh -c cat .env`), so the read is hidden; their direct forms (`flock L cat .env`, `script -q /dev/null cat .env`) still block. Peeling the first pair and quoting the re-join are separate changes.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `secret-reads`: "Secret names in untraced command shapes block" is removed. "A literal read blocks whatever the command's shape" replaces it, and "A script the guard does not read is allowed" names the accepted cost.

## Impact

- `cadence-hooks cadence prevent-secret-leaks` (PreToolUse, Bash): a command that sets positional parameters and names a secret outside a reader's operands exits 0, not 2. The "in a command that sets positional parameters" block message is gone. No env var, config key, ledger or marker file changes.
- No hooks.json change in cameronsjo/cadence.
