## 1. Scan every string of an MCP call

- [x] 1.1 Capture an MCP call's `tool_input` before the typed salvage (`HookInput::mcp_tool_input`)
- [x] 1.2 Route `mcp__*` calls to an identity pass over every string, keys included, at any depth
- [x] 1.3 Leave old-side text unscanned and subtract its occurrences from its siblings'
- [x] 1.4 Keep the term-source and provably-local exemptions and the fail-open on no term source

## 2. Tests

- [x] 2.1 `body`, `title`, `description`, `comment`, nested-array, mistyped `content`/`description` and `content` inputs each block with an armed term; a clean input allows
- [x] 2.2 A removal edit allows and an added occurrence blocks; no term source allows
- [x] 2.3 Stage the MCP route off once and confirm the new tests go red
- [x] 2.4 Review round: path and command keys left out, old side paired with its new side only, exemptions scoped to file content, old side counted with the term matcher; each staged off once and seen red
