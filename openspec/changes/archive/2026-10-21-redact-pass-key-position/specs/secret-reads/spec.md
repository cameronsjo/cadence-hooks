## MODIFIED Requirements

### Requirement: Mask secrets in Bash output
On PostToolUse for Bash, `redact-secret-output` SHALL replace, in place in stdout and stderr, credential tokens, private key blocks, URL passwords, and values whose name is secret-shaped (env, YAML, JSON, flag, header, table, `.netrc`). Each masked span MUST read `[redacted: secret-named value]` or `[redacted: <kind>]`. It SHALL return the full output object (`stdout`, `stderr`, `interrupted`, `isImage`) as `updatedToolOutput` only when something was masked, and MUST NOT rewrite image output.

#### Scenario: Token in output
- **WHEN** a Bash command prints `GITHUB_TOKEN=ghp_` followed by 36 alphanumerics
- **THEN** the hook returns `updatedToolOutput` with the value replaced by a `[redacted: …]` marker

#### Scenario: Placeholders and metadata left alone
- **WHEN** a Bash command prints `password: [REDACTED]`, `max_tokens: 4096`, or `secretName: my-secret`
- **THEN** the hook emits no rewrite

#### Scenario: Ordinary output
- **WHEN** a Bash command prints a passing test run
- **THEN** the hook emits no rewrite

#### Scenario: A bare pass in prose
- **WHEN** a Bash command prints `+ // one record per pass: x` or `the second pass: done`
- **THEN** the hook emits no rewrite

#### Scenario: A bare pass key behind a grep prefix
- **WHEN** a Bash command prints `config/db.yml:3:  pass: hunter2`
- **THEN** the hook masks `hunter2`

#### Scenario: A bare pass key in a map
- **WHEN** a Bash command prints `{ pass: hunter2 }`
- **THEN** the hook masks `hunter2`

#### Scenario: A credential after a bare pass in prose
- **WHEN** a Bash command prints `DB pass: Zq9vKhunter7Xw`
- **THEN** the hook masks `Zq9vKhunter7Xw`, because the first word of the value is shaped like a credential

#### Scenario: A credential and a note after a bare pass in prose
- **WHEN** a Bash command prints `Admin pass: Zq9vKhunter7Xw (change on first login)`
- **THEN** the hook masks `Zq9vKhunter7Xw`, because the first word of the value is shaped like a credential and the value runs to the end of the line, so what follows that word does not change the verdict
