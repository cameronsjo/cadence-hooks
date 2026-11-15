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

Exit 2, naming the entry, on any form this parser cannot read: a table entry
that is neither `effects({...})` nor a named effects constant, or a field
that is not `name: true|false` (a spread `...BASE`, a shorthand
`launchesProcess,`, a computed value). Read as "no flags", any of those
would exempt the tool, so a format change in rea fails loudly instead.
"""

import pathlib
import re
import sys

FLAGS = ("launchesProcess", "accessesNetwork", "writesFilesystem")

# One field of an effects object: `name: true` or `name: false`, nothing else.
FIELD = re.compile(r"\s*([A-Za-z]+)\s*:\s*(true|false)\s*")
CONST = re.compile(r"^const (\w+) = effects\((.*?)\);", re.DOTALL | re.MULTILINE)
CALL = re.compile(r"effects\(\s*(?:\{(.*)\})?\s*\)\s*,?\s*", re.DOTALL)
NAMED = re.compile(r"(\w+)\s*,?\s*")


class Unreadable(Exception):
    """An effects form this parser does not read."""


def strip_comments(text: str) -> str:
    """Drop `//` line comments and `/* */` blocks."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", text)


def fields(body: str, where: str) -> dict[str, bool]:
    """The fields of an effects object body; anything but `name: bool` fails.

    A spread (`...BASE`), a shorthand field (`launchesProcess,`) or a computed
    value would otherwise read as "no flags set" and exempt the tool.
    """
    out: dict[str, bool] = {}
    for item in body.split(","):
        if not item.strip():
            continue
        m = FIELD.fullmatch(item)
        if not m:
            raise Unreadable(f"{where}: cannot read {item.strip()!r}")
        out[m.group(1)] = m.group(2) == "true"
    return out


def call_fields(value: str, where: str) -> dict[str, bool]:
    """The fields of an `effects(...)` call, `effects()` included."""
    m = CALL.fullmatch(value)
    if not m:
        raise Unreadable(f"{where}: cannot read {value.strip()[:60]!r}")
    return fields(m.group(1) or "", where)


def parse(source: str) -> dict[str, bool]:
    """Map each tool name to whether it is scanned (any of FLAGS set)."""
    source = strip_comments(source)
    consts = {
        m.group(1): call_fields(f"effects({m.group(2)})", f"const {m.group(1)}")
        for m in CONST.finditer(source)
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
        if not entry.strip():
            continue
        m = re.match(r"\s*([a-z_0-9]+):\s*(.*)", entry, re.DOTALL)
        if not m:
            raise Unreadable(f"cannot read the entry {entry.strip()[:60]!r}")
        name, value = m.group(1), m.group(2).strip()
        named = NAMED.fullmatch(value)
        if named and named.group(1) in consts:
            flags = consts[named.group(1)]
        elif value.startswith("effects("):
            flags = call_fields(value, name)
        else:
            raise Unreadable(f"{name}: cannot read {value[:60]!r}")
        tools[name] = any(flags.get(f, False) for f in FLAGS)
    if not tools:
        raise Unreadable("no TOOL_EFFECTS entries found")
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
    except Unreadable as e:
        print(f"generate-rea-local-tools: {e}", file=sys.stderr)
        return 2
    local = sorted(t for t, scanned in tools.items() if not scanned)
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
