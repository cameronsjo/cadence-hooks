#!/usr/bin/env python3
"""Derive `REA_LOCAL_TOOLS` from rea's tool-effects audit.

rea (the reverse-engineering MCP server) records each public tool's effects in
`src/contracts/toolEffects.ts` (`TOOL_EFFECTS`). A tool that neither launches
a process, reaches the network, nor writes files (`launchesProcess`,
`accessesNetwork` and `writesFilesystem` all false) reads and annotates local
artifacts only; `redact-external-content` lets those skip the identity tier.
A file writer is left out because the file can land in a work tree.

Usage:
  generate-rea-local-tools.py <path/to/toolEffects.ts>
      Print the Rust array body: one `"name",` line per tool, sorted.
  generate-rea-local-tools.py <path/to/toolEffects.ts> --check <rust file>
      Exit 1 and list the difference when the file's REA_LOCAL_TOOLS does
      not match the audit; exit 0 when it does.

Exit 2 on a source this parser cannot read (a table entry that is neither
`effects({...})` nor a named effects constant), so a format change in rea
fails loudly instead of yielding a short list.
"""

import pathlib
import re
import sys

FLAGS = ("launchesProcess", "accessesNetwork", "writesFilesystem")


def parse(source: str) -> dict[str, bool]:
    """Map each tool name to whether it is open-world."""
    consts = {
        m.group(1): m.group(2)
        for m in re.finditer(
            r"^const (\w+) = effects\(\{(.*?)\}\);", source, re.DOTALL | re.MULTILINE
        )
    }
    start = source.index("export const TOOL_EFFECTS")
    body = source[source.index("{", start) + 1 :]
    depth = 1
    for i, ch in enumerate(body):
        depth += (ch == "{") - (ch == "}")
        if depth == 0:
            body = body[:i]
            break
    tools: dict[str, bool] = {}
    for entry in re.split(r"\n(?=  [a-z_0-9]+:)", "\n" + body):
        m = re.match(r"\s*([a-z_0-9]+):\s*(.*)", entry, re.DOTALL)
        if not m:
            continue
        name, value = m.group(1), m.group(2)
        named = [c for c in consts if re.match(rf"\s*{c}\b", value)]
        if not (value.lstrip().startswith("effects(") or named):
            sys.exit(f"cannot read the effects of {name!r}: {value[:60]!r}")
        text = "".join(consts[c] for c in named) + value
        tools[name] = any(re.search(rf"\b{f}:\s*true\b", text) for f in FLAGS)
    if not tools:
        sys.exit("no TOOL_EFFECTS entries found")
    return tools


def listed(rust: str) -> list[str]:
    """The names in a Rust file's REA_LOCAL_TOOLS array."""
    m = re.search(r"const REA_LOCAL_TOOLS: &\[&str\] = &\[(.*?)\];", rust, re.DOTALL)
    if not m:
        sys.exit("REA_LOCAL_TOOLS not found")
    return re.findall(r'"([^"]+)"', m.group(1))


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 4) or (len(argv) == 4 and argv[2] != "--check"):
        print(__doc__, file=sys.stderr)
        return 2
    try:
        tools = parse(pathlib.Path(argv[1]).read_text())
    except SystemExit as e:
        print(f"generate-rea-local-tools: {e.code}", file=sys.stderr)
        return 2
    local = sorted(t for t, open_world in tools.items() if not open_world)
    if len(argv) == 2:
        print("".join(f'    "{t}",\n' for t in local), end="")
        return 0
    have = listed(pathlib.Path(argv[3]).read_text())
    missing = sorted(set(local) - set(have))
    extra = sorted(set(have) - set(local))
    if have != sorted(have) or len(have) != len(set(have)):
        print("REA_LOCAL_TOOLS is not sorted and unique", file=sys.stderr)
        return 1
    for name in missing:
        print(f"missing (local in rea's audit): {name}")
    for name in extra:
        print(f"extra (not local, or gone, in rea's audit): {name}")
    return 1 if missing or extra else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
