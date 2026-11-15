## Why

A security review of cameronsjo/cadence#2131 found that `redact-external-content` read an MCP call only through `content`, `new_string` and `edits` (Linear CAM-714). GitHub's issue and pull-request tools post `body` and `title`, Linear's `save_issue` posts `description`, and review tools post `comment`, so a work-identifiable term in any of them went out unscanned. The reviewer reproduced it with an armed test term: `create_issue`, `create_pull_request` and `update_issue` with the term in `body` exited 0.

## What Changes

- An `mcp__*` call runs the identity tier over every string value in its input, at any depth, object keys included. Every string, not an allowlist of text fields per tool family: field names belong to each MCP server, and an allowlist misses the next server's names silently.
- The input is read as the payload sent it, before the typed parse drops a field that fails its shape, so a `content` array of blocks or an object `description` is still read.
- Not scanned as published text: the top-level `file_path`/`path` (it decides the exemptions; scanning it would refuse every clean MCP write into a directory named after a term) and a shell `command`, which still gets the Bash-surface checks (posted bodies, credential tier).
- Old-side text (`old_string`, `oldString`, `old_str`, `old_text`, `oldText`) is not scanned and is counted only against its paired new-side value, so an MCP edit that removes a term still goes through while a commit message beside it is scanned in full. The old side is counted with the term matcher, which is case-insensitive, on Write/Edit too.
- The term-source and provably-local exemptions cover only the file's content; a comment beside a local attachment is scanned. With no term source the check allows.
- The credential tier runs on the same strings, with or without a term source, as it does on a Bash post. Before, a token in an MCP `body` went out.
- Calls to the local servers `c3`, `easel`, `herdr-bridge` and `rea` are not scanned: they publish nothing to a tracker, chat, mail or repo. Read, search and navigation calls to other servers are scanned, since their arguments go to the server. The list is explicit and matched exactly on the server segment, so a server nobody listed is scanned. A shell `command` such a call carries still gets the Bash-surface checks.
- The shaped tier still does not run on MCP calls: it judges the audience from a shell command's target repo, which an MCP call does not have, and would fall back to public and nudge on local paths in tools that never leave the machine.

## Impact

- Code: `crates/cadence/src/redact_external_content.rs`, `crates/core/src/lib.rs` (`HookInput::mcp_tool_input`).
- Which MCP tools reach the check is the cadence plugin's hook matcher, not this binary. It matched only names containing a write-shaped verb, so Linear's `save_*` and GitHub's `add_*` comment tools never reached it. cameronsjo/cadence#2149 routes every `mcp__*` call to the hook, and `tests/fixtures/registration-audit/` carries that wiring.
