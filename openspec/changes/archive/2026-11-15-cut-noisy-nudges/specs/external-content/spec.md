## ADDED Requirements

### Requirement: Overshare audit fires once per agent per target
`warn-overshare` SHALL nudge at most once per session, per agent (`agent_id`), per trigger (Bash, or a field-report Write/Edit), per target, and only for an allowlisted form. A Write or Edit is keyed on the git root above the edited file. A Bash command is gated only when its line has no `cd ` or `pushd ` and every posting segment is allowlisted: a plain `git commit`, a plain `git push`, or a `gh` post. Later calls for a target already reminded MUST exit 0 with no output.

#### Scenario: The allowlisted forms
- **WHEN** a Bash call is `git commit …` with no global option, `git push …` with no global option and no argument containing `://` or starting with `git@`, `/`, `./`, `../` or `~`, or a `gh` post other than `api` or `gist` with no argument containing `://` or `github.com/`
- **THEN** it is keyed on the git root above `cwd`, or for `gh` on a literal `-R`/`--repo owner/repo` slug, and nudges only the first time

#### Scenario: Second push in the same session
- **WHEN** a Bash call runs `git push origin main` after an earlier call by the same agent in the same session and repo already nudged
- **THEN** the hook exits 0 with no output

#### Scenario: Another repo or agent
- **WHEN** the same session then pushes from a different repo, or a subagent with its own `agent_id` pushes from the same repo
- **THEN** the hook nudges again

#### Scenario: A post to another repo by -R
- **WHEN** the same agent, after a nudge in repo A, runs `gh issue create -R owner/public …` from A
- **THEN** the hook nudges once for `owner/public`

### Requirement: Overshare audit nudges every time off the allowlist
Every Bash trigger that is not an allowlisted form MUST nudge every time, so a post to a repo other than the one keyed is never silenced by that repo's marker. That includes `gh api`, `gh gist`, a URL argument, a leading `VAR=` assignment or runner (`GH_REPO=`, `env`, `sudo`), a `cd` or `pushd` anywhere in the line, a `git` global option such as `-C`, a push to a URL or path, a non-literal `-R`, and every `tea` post.

#### Scenario: Posts that name another target
- **WHEN** after a nudge in repo A the same agent runs `gh api repos/o/r/issues/5/comments -f body=x`, `gh pr comment https://github.com/o/r/pull/5 --body x`, `GH_REPO=o/r gh issue create …`, `gh gist create …`, `pushd ../b && git push`, or `git push https://github.com/o/r.git HEAD`, each twice
- **THEN** the hook nudges every time
