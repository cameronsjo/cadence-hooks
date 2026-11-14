## Why

A security review of cameronsjo/cadence#2131 found that `redact-external-content` read an MCP call only through `content`, `new_string` and `edits` (Linear CAM-714). GitHub's issue and pull-request tools post `body` and `title`, Linear's `save_issue` posts `description`, and review tools post `comment`, so a work-identifiable term in any of them went out unscanned. The reviewer reproduced it with an armed test term: `create_issue`, `create_pull_request` and `update_issue` with the term in `body` exited 0.

## What Changes

- An `mcp__*` call runs the identity tier over every string value in its input, at any depth, object keys included. Every string, not an allowlist of text fields per tool family: field names belong to each MCP server, and an allowlist misses the next server's names silently.
- The input is read as the payload sent it, before the typed parse drops a field that fails its shape, so a `content` array of blocks or an object `description` is still read.
- Not scanned as published text: the top-level `file_path`/`path` (it decides the exemptions; scanning it would refuse every clean MCP write into a directory named after a term) and a shell `command`, which still gets the Bash-surface checks (posted bodies, credential tier).
- Old-side text (`old_string`, `oldString`, `old_str`, `old_text`, `oldText`) is not scanned and is counted only against its paired new-side value, so an MCP edit that removes a term still goes through while a commit message beside it is scanned in full. The old side is counted with the term matcher, which is case-insensitive, on Write/Edit too.
- The term-source and provably-local exemptions cover only the file's content; a comment beside a local attachment is scanned. With no term source the check allows.
- The shaped tier still does not run on MCP calls: it judges the audience from a shell command's target repo, which an MCP call does not have, and would fall back to public and nudge on local paths in tools that never leave the machine.

## Impact

- Code: `crates/cadence/src/redact_external_content.rs`, `crates/core/src/lib.rs` (`HookInput::mcp_tool_input`).
- Which MCP tools reach the check is the cadence plugin's hook matcher (`mcp__.*(write|edit|create|update|delete|remove|move|rename).*`), not this binary. Linear's `save_*` and GitHub's `add_*` comment tools do not match it today.
