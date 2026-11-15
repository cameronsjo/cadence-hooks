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

## 3. Credential tier and routing

- [x] 3.1 Run the credential tier over every scanned MCP string, term source or not
- [x] 3.2 Exempt the local servers `c3`, `easel`, `herdr-bridge` and `rea` in the binary, matched exactly on the server segment
- [x] 3.3 Route every `mcp__*` call to the hook in the registration-audit fixture, once per call
- [x] 3.4 Tests: a token in an MCP `body` blocks, the same token through `gh` blocks, a clean call allows, a removal edit allows, listed servers allow and look-alikes block, every posting probe reaches the hook once; each staged off once and seen red

## 4. Review round 3

- [x] 4.1 Run the credential tier on every MCP call, local tools included; narrow the identity exemption to exact local tool names (rea by name markers)
- [x] 4.2 Block MCP calls that carry text when the term source is unreadable (#1617)
- [x] 4.3 Scan `command`/`cmd` on every tool but a local shell tool's Bash-read key
- [x] 4.4 Scan a lone old-side value; split tool names at the first `__` and scan an ambiguous one
- [x] 4.5 Tests for each, each staged off once and seen red

## 5. Review round 4

- [x] 5.1 Credential tier on the top-level `file_path`/`path`; identity tier skips it only when absolute and proven local
- [x] 5.2 A local shell tool's command skips the identity tier only
- [x] 5.3 Keep a warn-mode finding from the string scan when the call also carries a command
- [x] 5.4 Unreadable term source blocks only calls whose input holds a string value
- [x] 5.5 rea exemption from rea's effect audit (exact, case-sensitive list), pinned by a test
- [x] 5.6 Tests for each, each staged off once and seen red

## 6. Review round 5

- [x] 6.1 No path exemption on MCP calls: both tiers read every path and the content beside it
- [x] 6.2 Unreadable term source blocks any MCP call that carries a string, object keys included
- [x] 6.3 Keep a bypass record when the MCP verdict is merged with the Bash surface's
- [x] 6.4 Leave rea's file-writing tools off `REA_LOCAL_TOOLS`; `scripts/generate-rea-local-tools.py` derives the list
- [x] 6.5 `Write` and `Edit` probes in the exactly-once wiring test; cite cameronsjo/cadence-hooks#1624 at the parse fail-open
- [x] 6.6 Tests for each, each staged off once and seen red
