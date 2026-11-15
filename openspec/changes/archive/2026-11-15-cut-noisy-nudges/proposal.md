## Why

Three nudges fired thousands of times in two weeks and added text to the model's context each time (cameronsjo/cadence-hooks#1443, cadence-ecosystem ADR-0046 rule 3: a nudge must name a concrete action, and uncertain means allow).

- `warn-alias-parsing` and `warn-curl-alias` told the model that `cat`, `ls`, `du`, `df`, `top` or `curl` is aliased to a replacement "on this machine" without checking. In Claude Code's shells (`CLAUDECODE=1`) the operator's dotfiles define no such alias, so the claim is false where the model reads it.
- `git-safety`'s "cannot see inside a script file / an eval / a command named by a substitution" note fired on every script run, including the write-a-script-then-run-it pattern the operator's rules ask for, and named no concrete action.
- `warn-overshare` repeated the same pre-ship audit text on every commit, push and post.

## What Changes

- `warn-alias-parsing` and `warn-curl-alias` are retired. Their subcommands stay and exit 0 with no output, because plugin `hooks.json` files still call them until cameronsjo/cadence removes that wiring. An unknown subcommand would print a version notice and exit 1 on every matching call.
- `git-safety` allows a command it cannot read without a note. Every block and every history-rewrite nudge is unchanged.
- `warn-overshare` nudges at most once per session, per agent, per trigger and per target, through the shared session marker. A command that names a target the existing readers do not resolve exactly nudges every time. What it matches is unchanged.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `tool-nudges`: the two alias requirements are removed; "Retired alias hooks exit silently" is added; "Advisory tool nudges are suppressible per repo" is replaced by "Advisory tool nudges can be silenced per repo", which no longer names the retired hooks.
- `git-safety`: "Unseen execution nudges" is removed; "Commands the guard cannot read are allowed silently" replaces it.
- `external-content`: "Overshare audit fires once per agent per target" is added.

## Impact

- `cadence-hooks guardrails warn-alias-parsing` and `cadence-hooks guardrails warn-curl-alias` (PreToolUse, Bash): always exit 0 with no output.
- `cadence-hooks cadence git-safety` (PreToolUse, Bash): a script run, an `eval` of text built at run time, or a command named by a substitution exits 0 with no output. No block changes.
- `cadence-hooks cadence warn-overshare` (PreToolUse, Bash, Write, Edit): writes an `overshare-warned-bash` or `overshare-warned-write` marker keyed on the target, `agent_id` and session in the private marker dir on its first nudge, and allows silently while the marker exists.
- The plugin wiring that still calls the retired subcommands is removed in a separate cameronsjo/cadence change.
