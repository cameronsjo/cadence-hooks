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
  readonly idempotent: boolean;
}
"""

DEFAULTS = """\
const effects = (overrides: Partial<ToolEffects> = {}): ToolEffects => ({
  mutatesSession: false,
  writesFilesystem: false,
  launchesProcess: false,
  accessesNetwork: false,
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

    def test_the_cli_exits_2_and_names_the_entry(self) -> None:
        source = table("  fetch_page: effects({ ...BASE }),\n")
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "toolEffects.ts"
            path.write_text(source)
            self.assertEqual(gen.main(["generate-rea-local-tools.py", str(path)]), 2)


if __name__ == "__main__":
    unittest.main()
