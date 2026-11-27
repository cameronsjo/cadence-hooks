## ADDED Requirements

### Requirement: Watch a created PR
After a Bash call whose command runs `gh pr create` and whose stdout holds exactly one github.com pull request URL, `cadence-hooks guardrails watch-created-pr` SHALL run `forgectl events watch --session <session_id> <owner/repo#N>`. It SHALL exit 0 with no output in every case, and run nothing when the payload has no session id or one forgectl would refuse (outside 1 to 128 of `[A-Za-z0-9._-]`, or starting with `.`).

#### Scenario: PR opened
- **WHEN** `gh pr create --body-file b` prints `https://github.com/o/r/pull/12`
- **THEN** the hook runs `forgectl events watch --session <id> o/r#12` and exits 0 with no output

#### Scenario: Two URLs in the output
- **WHEN** stdout holds two different PR URLs
- **THEN** nothing is run
