# ADR-0003: The identity-term boundary is egress, not derivation

## Status

Accepted (2026-09-30). Rules cadence-hooks#827.

## Context

The identity tier of `redact-external-content` blocks a post, commit message or
authored file that carries a term from `~/.config/cadence/redaction.toml`. Its
block message names the matched term, on purpose: a block has to say what
tripped it or the agent cannot fix the draft. So the term reaches the agent's
context, and from there the session transcript on disk.

Transcripts feed other artifacts: transcript search, session mining into a
vault, field reports, and anything that quotes a hook's stderr. #827 asked
where the boundary sits for those derived artifacts. There were two options:

1. The term source's own exemption covers them, because they stay on the
   machine.
2. Every mining or search tool runs the identity scan before it writes a
   derived artifact anywhere.

## Decision

**The boundary is where content leaves the machine, not where it is copied on
the machine.**

Transcripts, session logs, vault notes, search indexes and field reports that
stay local are covered by the same exemption as the term source itself. The
terms are the user's own, `redaction.toml` already holds every one of them in
plain text, and a copy in a second local file publishes nothing. Tools that
derive local artifacts do **not** run the identity scan, and they need no
cadence-hooks dependency to stay correct.

The identity scan runs at each egress point the binary can see:

- the body of an external post (`gh pr`/`issue`/`release`/`gist`/`discussion`,
  `tea`) and a `git commit` message;
- the content a `Write`/`Edit` introduces, which covers a derived artifact the
  agent itself writes into a repository.

A derived artifact that is later published goes through one of those points at
publication time. That is the check that matters, and it runs whichever tool
produced the artifact.

## Consequences

- No code change follows from this ruling. The block message keeps naming the
  term.
- **Known residual:** a script or tool other than `Write`/`Edit` that copies a
  derived artifact into a checkout, followed by a `git commit` and push. The
  commit-message scan does not read committed file content. This is the same
  commit-path residual cadence-hooks#583 tracks (a native pre-commit hook for
  the identity tier). It is not a separate gap, so nothing new is filed for it.
- A tool that *publishes* derived content by a route the binary cannot see
  (a direct API upload, for example) owns its own scan. That follows from the
  same rule: whoever performs the egress runs the check.
