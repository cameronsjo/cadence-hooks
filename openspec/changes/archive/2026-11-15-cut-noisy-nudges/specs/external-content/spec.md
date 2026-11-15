## ADDED Requirements

### Requirement: Overshare audit fires once per session per repo
`warn-overshare` SHALL nudge at most once per session per repo. The repo is the git root above the edited file's directory, or above `cwd` for Bash, else that directory. Later matching calls in the same session and repo MUST exit 0 with no output.

#### Scenario: Second push in the same session
- **WHEN** a Bash call runs `git push origin main` after an earlier call in the same session and repo already nudged
- **THEN** the hook exits 0 with no output

#### Scenario: Another repo
- **WHEN** the same session then pushes from a different repo
- **THEN** the hook nudges again
