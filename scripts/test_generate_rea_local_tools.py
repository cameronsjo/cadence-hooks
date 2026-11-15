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
_spec = importlib.util.spec_from_file_location("generate_rea", HERE / "generate-rea-local-tools.py")
assert _spec and _spec.loader
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)

PRELUDE = """\
const effects = (overrides: Partial<ToolEffects> = {}): ToolEffects => ({
  mutatesTarget: false,
  ...overrides,
});

const evidence = effects({ mutatesSession: true });
const nativeEvidence = effects({ mutatesSession: true, launchesProcess: true });
"""


def table(*entries: str) -> str:
    return PRELUDE + "\nexport const TOOL_EFFECTS = {\n" + "".join(entries) + "};\n"


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
        with self.assertRaisesRegex(gen.Unreadable, r"fetch_page: cannot read '\.\.\.BASE'"):
            gen.parse(source)

    def test_a_shorthand_flag_fails_loud(self) -> None:
        source = table("  run_tool: effects({\n    launchesProcess,\n  }),\n")
        with self.assertRaisesRegex(gen.Unreadable, r"run_tool: cannot read 'launchesProcess'"):
            gen.parse(source)

    def test_an_unknown_constant_fails_loud(self) -> None:
        source = table("  open_url: networkEvidence,\n")
        with self.assertRaisesRegex(gen.Unreadable, r"open_url: cannot read"):
            gen.parse(source)

    def test_the_cli_exits_2_and_names_the_entry(self) -> None:
        source = table("  fetch_page: effects({ ...BASE }),\n")
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "toolEffects.ts"
            path.write_text(source)
            self.assertEqual(gen.main(["generate-rea-local-tools.py", str(path)]), 2)


if __name__ == "__main__":
    unittest.main()
