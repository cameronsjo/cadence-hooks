#!/usr/bin/env python3
"""Derive `REA_LOCAL_TOOLS` from rea's tool-effects audit.

rea (the reverse-engineering MCP server) records each public tool's effects in
`src/contracts/toolEffects.ts` (`TOOL_EFFECTS`). A tool with every flag in
FLAGS false (it neither launches a process, reaches the network, writes
files, runs foreign code, nor changes a device) reads and annotates local
artifacts only; `redact-external-content` lets those skip the identity tier.
A file writer is left out because the file can land in a work tree.

Usage:
  generate-rea-local-tools.py <path/to/toolEffects.ts>
      Print the Rust array body: one `"name",` line per tool, sorted.
  generate-rea-local-tools.py <path/to/toolEffects.ts> --check <rust file>
      Exit 1 and list the difference when the file's REA_LOCAL_TOOLS does
      not match the audit; exit 0 when it does.

Exit 2, naming the entry, on anything this parser cannot vouch for:
- a field `ToolEffects` does not declare (a renamed or misspelled flag), or
  a flag it declares that is neither in FLAGS nor in REVIEWED_UNJUDGED;
- zero or several `export const TOOL_EFFECTS` tables, or an unterminated
  string or block comment;
- a judged flag the interface does not declare or `effects()` does not
  default (a flag renamed across the file);
- a table entry that is neither `effects({...})` nor a named effects
  constant, or a field that is not `name: true|false` (a spread `...BASE`,
  a shorthand `launchesProcess,`, a computed value).
Read as "no flags", any of those would exempt the tool, so a format change
in rea fails toward scanning instead.
"""

import pathlib
import re
import sys

# Flags that make a tool scanned: any of them true and the identity tier runs.
FLAGS = (
    "launchesProcess",
    "accessesNetwork",
    "writesFilesystem",
    "executesForeignCode",
    "mutatesDevice",
)

# Flags reviewed as not reaching beyond rea itself, so they do not decide
# anything here. Every flag `ToolEffects` declares must be in FLAGS or here; a
# new one fails the run until someone reviews it into one of the two.
REVIEWED_UNJUDGED = {
    "mutatesTarget": "rea's own analysis state for the opened artifact (names, comments)",
    "mutatesSession": "rea's session and Evidence records",
    "changesUiState": "rea's own navigation and view state",
    "mayDiscardData": "loss of rea state, not text sent anywhere",
    "idempotent": "retry safety, not an effect",
}

# One field of an effects object: `name: true` or `name: false`, nothing else.
FIELD = re.compile(r"\s*([A-Za-z]+)\s*:\s*(true|false)\s*")
CONST = re.compile(r"^const (\w+) = effects\((.*?)\);", re.DOTALL | re.MULTILINE)
INTERFACE = re.compile(
    r"^export interface ToolEffects \{(.*?)\n\}", re.DOTALL | re.MULTILINE
)
TABLE = re.compile(r"^export const TOOL_EFFECTS\b(?=\s*[:=])", re.MULTILINE)
DECLARED = re.compile(r"readonly (\w+): boolean;")
DEFAULTS = re.compile(
    r"const effects = \([^)]*\)[^=]*=>\s*\(\{(.*?)\.\.\.overrides,?\s*\}\);", re.DOTALL
)
CALL = re.compile(r"effects\(\s*(?:\{(.*)\})?\s*\)\s*,?\s*", re.DOTALL)
NAMED = re.compile(r"(\w+)\s*,?\s*")


class Unreadable(Exception):
    """An effects form this parser does not read."""


def strip_comments(text: str) -> str:
    """Drop `//` and `/* */` comments in one pass that tracks strings.

    A comment marker inside a string (`"https://x"`) or the other comment
    kind (`// see lib/*.so`) is text, not a comment: stripping block comments
    first would let `lib/*.so` open one that eats live flags. An unterminated
    string or block comment fails.
    """
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        two = text[i : i + 2]
        if two == "//":
            end = text.find("\n", i)
            i = n if end < 0 else end
        elif two == "/*":
            end = text.find("*/", i + 2)
            if end < 0:
                raise Unreadable("an unterminated /* comment")
            i = end + 2
        elif ch in "\"'`":
            j = i + 1
            while j < n and text[j] != ch:
                if text[j] == "\\":
                    j += 1
                elif ch != "`" and text[j] == "\n":
                    raise Unreadable(f"an unterminated {ch} string")
                j += 1
            if j >= n:
                raise Unreadable(f"an unterminated {ch} string")
            out.append(text[i : j + 1])
            i = j + 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


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


def declared_and_defaults(source: str) -> tuple[set[str], dict[str, bool]]:
    """The flags `ToolEffects` declares, and the defaults `effects()` sets.

    Every flag in FLAGS must be declared and given an explicit default, or a
    renamed or dropped flag would read as false everywhere and exempt tools.
    """
    m = INTERFACE.search(source)
    if not m:
        raise Unreadable("no `export interface ToolEffects` block found")
    declared = set(DECLARED.findall(m.group(1)))
    for flag in FLAGS:
        if flag not in declared:
            raise Unreadable(f"ToolEffects does not declare {flag!r}")
    for flag in sorted(declared):
        if flag not in FLAGS and flag not in REVIEWED_UNJUDGED:
            raise Unreadable(
                f"ToolEffects declares {flag!r}, which is neither judged (FLAGS) "
                "nor reviewed as not mattering (REVIEWED_UNJUDGED)"
            )
    d = DEFAULTS.search(source)
    if not d:
        raise Unreadable("no `effects()` defaults helper found")
    defaults = fields(d.group(1), "effects() defaults")
    for flag in FLAGS:
        if flag not in defaults:
            raise Unreadable(f"effects() defaults do not set {flag!r}")
    return declared, defaults


def known(flags: dict[str, bool], declared: set[str], where: str) -> dict[str, bool]:
    """`flags`, refusing a name `ToolEffects` does not declare."""
    for name in flags:
        if name not in declared:
            raise Unreadable(f"{where}: unknown effect flag {name!r}")
    return flags


def parse(source: str) -> dict[str, bool]:
    """Map each tool name to whether it is scanned (any of FLAGS set)."""
    source = strip_comments(source)
    declared, defaults = declared_and_defaults(source)
    consts = {
        m.group(1): known(
            call_fields(f"effects({m.group(2)})", f"const {m.group(1)}"),
            declared,
            f"const {m.group(1)}",
        )
        for m in CONST.finditer(source)
    }
    tables = list(TABLE.finditer(source))
    if len(tables) != 1:
        raise Unreadable(
            f"expected one `export const TOOL_EFFECTS`, found {len(tables)}"
        )
    start = tables[0].start()
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
            overrides = consts[named.group(1)]
        elif value.startswith("effects("):
            overrides = known(call_fields(value, name), declared, name)
        else:
            raise Unreadable(f"{name}: cannot read {value[:60]!r}")
        merged = {**defaults, **overrides}
        tools[name] = any(merged[f] for f in FLAGS)
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
