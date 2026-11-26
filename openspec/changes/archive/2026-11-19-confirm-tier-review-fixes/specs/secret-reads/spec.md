## MODIFIED Requirements

### Requirement: Confirmed vault listing
`guard-op-vault-scan` SHALL be in the confirm tier, keyed by the scans it read: `op item list` or `op vault list`, each with the account and the `--vault` value it names. A retry that differs only outside those (another pipe, `--vault=X` for `--vault X`) SHALL pair with the blocked attempt; a listing of another vault or another account, or one naming an account where the blocked attempt named none, MUST NOT.

#### Scenario: Retry with another pipe
- **WHEN** `op item list` blocks in session S1 and S1 then runs `op item list | grep api`
- **THEN** the second command is allowed with a `confirmed` bypass row

#### Scenario: Another vault
- **WHEN** `op item list --vault Private` blocks and the next attempt is `op item list --vault Work`
- **THEN** the second command blocks

#### Scenario: Another account
- **WHEN** `op item list --account a.example` blocks and the next attempt is `op item list --account b.example`
- **THEN** the second command blocks

## ADDED Requirements

### Requirement: Vault listing account
The account in a vault listing's confirm key SHALL be the value of `--account x` or `--account=x`, else of an `OP_ACCOUNT=x` word before the command (a shell prefix or an `env` operand). The flag MUST win over the environment word, as it does for `op`. An `OP_ACCOUNT` exported earlier or set in the session environment is not read.

#### Scenario: Same account through the environment
- **WHEN** `op item list --account a.example` blocks and the next attempt is `OP_ACCOUNT=a.example op item list`
- **THEN** the second command is allowed with a `confirmed` bypass row

#### Scenario: The flag wins
- **WHEN** `op item list --account a.example` blocks and the next attempt is `OP_ACCOUNT=b.example op item list --account a.example`
- **THEN** the second command is allowed with a `confirmed` bypass row
