#!/usr/bin/env python3
"""Offline tests for scripts/generate-rea-local-tools.py.

Every source is an inline string shaped like rea's `toolEffects.ts`. Run with
``python3 scripts/test_generate_rea_local_tools.py``.
"""

import importlib.util
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location(
    "generate_rea", HERE / "generate-rea-local-tools.py"
)
assert _spec and _spec.loader
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)

INTERFACE = """\
export interface ToolEffects {
  readonly mutatesSession: boolean;
  readonly writesFilesystem: boolean;
  readonly launchesProcess: boolean;
  readonly accessesNetwork: boolean;
  readonly executesForeignCode: boolean;
  readonly mutatesDevice: boolean;
  readonly idempotent: boolean;
}
"""

DEFAULTS = """\
const effects = (overrides: Partial<ToolEffects> = {}): ToolEffects => ({
  mutatesSession: false,
  writesFilesystem: false,
  launchesProcess: false,
  accessesNetwork: false,
  executesForeignCode: false,
  mutatesDevice: false,
  idempotent: true,
  ...overrides,
});
"""

PRELUDE = (
    INTERFACE
    + DEFAULTS
    + """

const evidence = effects({ mutatesSession: true });
const nativeEvidence = effects({ mutatesSession: true, launchesProcess: true });
"""
)


def table(*entries: str, prelude: str = PRELUDE) -> str:
    return prelude + "\nexport const TOOL_EFFECTS = {\n" + "".join(entries) + "};\n"


class ParseTest(unittest.TestCase):
    def test_reads_calls_constants_and_comments(self) -> None:
        source = table(
            "  list_strings: effects(),\n",
            "  set_comment: evidence,\n",
            "  gdb_console: nativeEvidence,\n",
            "  export_evidence_bundle: effects({\n    writesFilesystem: true, // a file\n  }),\n",
            "  read_bytes: effects({\n    idempotent: false,\n  }),\n",
        )
        self.assertEqual(
            gen.parse(source),
            {
                "list_strings": False,
                "set_comment": False,
                "gdb_console": True,
                "export_evidence_bundle": True,
                "read_bytes": False,
            },
        )

    def test_a_spread_fails_loud(self) -> None:
        source = table("  fetch_page: effects({\n    ...BASE,\n  }),\n")
        with self.assertRaisesRegex(
            gen.Unreadable, r"fetch_page: cannot read '\.\.\.BASE'"
        ):
            gen.parse(source)

    def test_a_shorthand_flag_fails_loud(self) -> None:
        source = table("  run_tool: effects({\n    launchesProcess,\n  }),\n")
        with self.assertRaisesRegex(
            gen.Unreadable, r"run_tool: cannot read 'launchesProcess'"
        ):
            gen.parse(source)

    def test_an_unknown_constant_fails_loud(self) -> None:
        source = table("  open_url: networkEvidence,\n")
        with self.assertRaisesRegex(gen.Unreadable, r"open_url: cannot read"):
            gen.parse(source)

    def test_a_renamed_flag_in_an_entry_fails_loud(self) -> None:
        # Read as an unknown field, a misspelled flag would leave the real one
        # at its false default and exempt a process launcher.
        source = table("  gdb_console: effects({\n    launchesProces: true,\n  }),\n")
        with self.assertRaisesRegex(
            gen.Unreadable, r"gdb_console: unknown effect flag 'launchesProces'"
        ):
            gen.parse(source)

    def test_a_flag_the_interface_no_longer_declares_fails_loud(self) -> None:
        # Renamed across the whole file: every entry would read the old name
        # as false.
        renamed = (INTERFACE + DEFAULTS).replace("accessesNetwork", "usesNetwork")
        source = table(
            "  fetch_page: effects({\n    usesNetwork: true,\n  }),\n",
            prelude=renamed + "\n",
        )
        with self.assertRaisesRegex(
            gen.Unreadable, r"ToolEffects does not declare 'accessesNetwork'"
        ):
            gen.parse(source)

    def test_a_flag_without_a_default_fails_loud(self) -> None:
        missing = INTERFACE + DEFAULTS.replace("  writesFilesystem: false,\n", "")
        source = table("  list_strings: effects(),\n", prelude=missing + "\n")
        with self.assertRaisesRegex(
            gen.Unreadable, r"defaults do not set 'writesFilesystem'"
        ):
            gen.parse(source)

    def test_a_declared_flag_nobody_reviewed_fails_loud(self) -> None:
        # A new flag rea adds (sendsTelemetry) is set true; ignoring it would
        # exempt the tool.
        added = (
            (INTERFACE + DEFAULTS)
            .replace(
                "  readonly idempotent: boolean;\n",
                "  readonly idempotent: boolean;\n  readonly sendsTelemetry: boolean;\n",
            )
            .replace(
                "  idempotent: true,\n",
                "  idempotent: true,\n  sendsTelemetry: false,\n",
            )
        )
        source = table(
            "  ping: effects({\n    sendsTelemetry: true,\n  }),\n",
            prelude=added + "\n",
        )
        with self.assertRaisesRegex(
            gen.Unreadable, r"declares 'sendsTelemetry', which is neither judged"
        ):
            gen.parse(source)

    def test_foreign_code_and_device_changes_are_judged(self) -> None:
        source = table(
            "  instrument: effects({\n    executesForeignCode: true,\n  }),\n",
            "  push_file: effects({\n    mutatesDevice: true,\n  }),\n",
        )
        self.assertEqual(gen.parse(source), {"instrument": True, "push_file": True})

    def test_a_block_comment_marker_in_a_line_comment_keeps_the_flags(self) -> None:
        # Stripping /* */ first, `lib/*.so` would open a comment that runs to
        # the next `*/` and deletes `launchesProcess: true`.
        source = table(
            "  run_tool: effects({\n    launchesProcess: true, // see lib/*.so\n  }),\n",
            "  list_strings: effects(), /* local */\n",
        )
        self.assertEqual(gen.parse(source), {"run_tool": True, "list_strings": False})

    def test_a_comment_marker_in_a_string_is_text(self) -> None:
        # No `//` in the string, so only string tracking keeps it text: read as
        # code, its `/*` would run to the `*/` below and swallow the table
        # header with it.
        source = table(
            "  fetch_page: effects({\n    accessesNetwork: true, /* remote */\n  }),\n",
            prelude=PRELUDE + 'const LIBS = "lib/*.so";\n',
        )
        self.assertEqual(gen.parse(source), {"fetch_page": True})

    def test_an_escaped_quote_does_not_end_a_string(self) -> None:
        # Without the backslash skip, `\"` would end the string and its
        # `/*` would open a comment running to the `*/` below.
        source = table(
            "  fetch_page: effects({\n    accessesNetwork: true, /* remote */\n  }),\n",
            prelude=PRELUDE + 'const NOTE = "a \\" /* b";\n',
        )
        self.assertEqual(gen.parse(source), {"fetch_page": True})

    def test_an_unterminated_string_fails_loud(self) -> None:
        source = table(
            "  list_strings: effects(),\n",
            prelude=PRELUDE + 'const NOTE = "never closed;\n',
        )
        with self.assertRaisesRegex(gen.Unreadable, r'unterminated " string'):
            gen.parse(source)

    def test_an_unterminated_block_comment_fails_loud(self) -> None:
        source = table("  list_strings: effects(), /* never closed\n")
        with self.assertRaisesRegex(gen.Unreadable, r"unterminated /\* comment"):
            gen.parse(source)

    def test_the_table_name_is_matched_exactly(self) -> None:
        older = (
            PRELUDE
            + "export const TOOL_EFFECTS_V1 = {\n  gdb_console: effects(),\n};\n"
        )
        source = table("  gdb_console: nativeEvidence,\n", prelude=older)
        self.assertEqual(gen.parse(source), {"gdb_console": True})
        twice = (
            table("  a: effects(),\n")
            + "export const TOOL_EFFECTS = {\n  b: effects(),\n};\n"
        )
        with self.assertRaisesRegex(gen.Unreadable, r"found 2"):
            gen.parse(twice)
        with self.assertRaisesRegex(gen.Unreadable, r"found 0"):
            gen.parse(PRELUDE)

    def test_the_cli_exits_2_and_names_the_entry(self) -> None:
        source = table("  fetch_page: effects({ ...BASE }),\n")
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "toolEffects.ts"
            path.write_text(source)
            self.assertEqual(gen.main(["generate-rea-local-tools.py", str(path)]), 2)


if __name__ == "__main__":
    unittest.main()
