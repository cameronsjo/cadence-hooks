## MODIFIED Requirements

### Requirement: Confirmed vault listing
`guard-op-vault-scan` SHALL be in the confirm tier, keyed by the whole command (every segment, spaces and tabs collapsed, ends trimmed) beside the scans it holds. A retry of the same command SHALL pair; any other difference MUST NOT. An identity set by an earlier, separate command (an exported variable, a prior sign-in) is not part of the key. Neither is one carried by a token in the environment.

#### Scenario: The same command again
- **WHEN** `op item list | grep api` blocks in session S1 and S1 then runs the same command
- **THEN** the second command is allowed with a `confirmed` bypass row

#### Scenario: Spacing only
- **WHEN** `op item list --vault Private` blocks and the next attempt is `op  item list   --vault Private`
- **THEN** the second command is allowed with a `confirmed` bypass row

#### Scenario: Another identity in the same command
- **WHEN** `op item list` blocks and the next attempt is `export OP_ACCOUNT=b; op item list`, `op signin --account b && op item list`, or `eval $(op signin --account b) && op item list`
- **THEN** the second command blocks with the `Are you sure?` line

#### Scenario: Retry with another pipe
- **WHEN** `op item list` blocks in session S1 and S1 then runs `op item list | grep api`
- **THEN** the second command blocks with the `Are you sure?` line

#### Scenario: Another vault
- **WHEN** `op item list --vault Private` blocks and the next attempt is `op item list --vault Work`
- **THEN** the second command blocks

#### Scenario: Another account
- **WHEN** `op item list --account a.example` blocks and the next attempt is `op item list --account b.example`
- **THEN** the second command blocks

#### Scenario: Another session token
- **WHEN** `op item list --session tok1` blocks and the next attempt is `op item list --session tok2`
- **THEN** the second command blocks

## REMOVED Requirements

### Requirement: Vault listing account
**Reason**: The whole-command key covers every way of naming the account in the command, so the guard no longer reads `--account` or `OP_ACCOUNT=` on its own.
**Migration**: None; a retry that names the account the same way still pairs.
