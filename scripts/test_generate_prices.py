#!/usr/bin/env python3
"""Offline tests for scripts/generate-prices.py (cadence-hooks#866).

Never touches the network: every page is the saved fixture in
``scripts/testdata/pricing-page.md`` or an inline string. Run with
``python3 scripts/test_generate_prices.py``.
"""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "testdata" / "pricing-page.md"

_spec = importlib.util.spec_from_file_location("generate_prices", HERE / "generate-prices.py")
gp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gp)

HEADER = (
    "| Model | Base input tokens | 5m cache writes | 1h cache writes | "
    "Cache hits and refreshes | Output tokens |\n| :-- | :-- | :-- | :-- | :-- | :-- |\n"
)


def page(*rows: str) -> str:
    return "## Model pricing\n\n" + HEADER + "\n".join(rows) + "\n\nprose after\n"


def row(name: str, *rates: str) -> str:
    return f"| {name} | " + " | ".join(rates) + " |"


OPUS = row("Claude Opus 5", "$5 / MTok", "$6.25 / MTok", "$10 / MTok", "$0.50 / MTok", "$25 / MTok")


def committed(models: dict, last_verified: str = "2026-01-01") -> dict:
    return {
        "_meta": {"lastVerified": last_verified, "source": gp.SOURCE_URL, "notes": "n"},
        "models": models,
    }


OPUS_RATES = {
    "inputPerMTok": 5.0,
    "outputPerMTok": 25.0,
    "cacheWritePerMTok": 6.25,
    "cacheWrite1hPerMTok": 10.0,
    "cacheReadPerMTok": 0.5,
}


class ParseTable(unittest.TestCase):
    def test_fixture_parses_only_the_model_pricing_table(self):
        models = gp.parse_table(FIXTURE.read_text(encoding="utf-8"))
        # 19 rows in the saved page; the fast-mode and batch tables below it
        # also start with `| Model` and must not be picked up.
        self.assertEqual(len(models), 19)
        self.assertEqual(models["claude-opus-5"], OPUS_RATES)
        self.assertEqual(models["claude-fable-5-1"]["cacheReadPerMTok"], 0.25)
        self.assertEqual(models["claude-sonnet-5"]["inputPerMTok"], 2.0)  # <sup>3</sup> stripped
        self.assertIn("claude-opus-4-1", models)  # "(retired, …)" link stripped
        self.assertIn("claude-mythos-5-1", models)  # "(limited availability)" stripped
        # The two display-name artifacts named in #866: written as parsed.
        self.assertIn("claude-opus-4", models)
        self.assertIn("claude-sonnet-4", models)

    def test_all_zero_page_is_rejected(self):
        zero = row("Claude Opus 5", *["$0.00 / MTok"] * 5)
        with self.assertRaises(gp.PricingError):
            gp.parse_table(page(zero))

    def test_rate_above_ceiling_is_rejected(self):
        high = row("Claude Opus 5", "$1001 / MTok", "$1 / MTok", "$1 / MTok", "$1 / MTok", "$1 / MTok")
        with self.assertRaises(gp.PricingError):
            gp.parse_table(page(high))

    def test_second_anchor_line_is_rejected(self):
        with self.assertRaises(gp.PricingError):
            gp.parse_table(page(OPUS) + "\nBase input tokens again\n")

    def test_missing_table_is_rejected(self):
        with self.assertRaises(gp.PricingError):
            gp.parse_table("no table here")

    def test_unrecognized_model_name_is_rejected(self):
        bad = row("Claude <b>Opus</b> 5", "$5 / MTok", "$6.25 / MTok", "$10 / MTok", "$0.50 / MTok", "$25 / MTok")
        with self.assertRaises(gp.PricingError):
            gp.parse_table(page(bad))

    def test_duplicate_row_is_rejected(self):
        with self.assertRaises(gp.PricingError):
            gp.parse_table(page(OPUS, OPUS))

    def test_error_messages_carry_no_page_text(self):
        marker = "INJECTED-MARKER"
        bad = row(f"Claude Opus 5 {marker}", "$5 / MTok", "$1 / MTok", "$1 / MTok", "$1 / MTok", "$1 / MTok")
        with self.assertRaises(gp.PricingError) as ctx:
            gp.parse_table(page(bad))
        self.assertNotIn(marker, str(ctx.exception))


class Refresh(unittest.TestCase):
    def test_unchanged_rates_freeze_last_verified(self):
        meta, models, changes, _ = gp.refresh(
            committed({"claude-opus-5": OPUS_RATES}),
            {"claude-opus-5": dict(OPUS_RATES)},
            allow_removals=False,
            today="2026-09-29",
        )
        self.assertEqual(meta["lastVerified"], "2026-01-01")
        self.assertEqual(changes, [])
        self.assertEqual(models, {"claude-opus-5": OPUS_RATES})

    def test_changed_rate_moves_last_verified(self):
        new = dict(OPUS_RATES, inputPerMTok=4.0)
        meta, models, changes, _ = gp.refresh(
            committed({"claude-opus-5": OPUS_RATES}),
            {"claude-opus-5": new},
            allow_removals=False,
            today="2026-09-29",
        )
        self.assertEqual(meta["lastVerified"], "2026-09-29")
        self.assertEqual(models["claude-opus-5"]["inputPerMTok"], 4.0)
        self.assertEqual(len(changes), 1)

    def test_more_than_tenfold_move_is_rejected(self):
        with self.assertRaises(gp.PricingError):
            gp.refresh(
                committed({"claude-opus-5": OPUS_RATES}),
                {"claude-opus-5": dict(OPUS_RATES, outputPerMTok=251.0)},
                allow_removals=False,
                today="2026-09-29",
            )

    def test_removal_blocks_without_flag_and_keeps_row_with_it(self):
        old = committed({"claude-opus-5": OPUS_RATES, "claude-opus-3": OPUS_RATES})
        page_models = {"claude-opus-5": dict(OPUS_RATES)}
        with self.assertRaises(gp.PricingError):
            gp.refresh(old, page_models, allow_removals=False, today="2026-09-29")
        meta, models, _, notes = gp.refresh(old, page_models, allow_removals=True, today="2026-09-29")
        self.assertIn("claude-opus-3", models)
        self.assertEqual(meta["lastVerified"], "2026-01-01")
        self.assertTrue(any("claude-opus-3" in note for note in notes))

    def test_multiplier_drift_is_a_note_not_a_block(self):
        cheap_read = dict(OPUS_RATES, cacheReadPerMTok=0.125)
        _, models, _, notes = gp.refresh(
            committed({"claude-opus-5": OPUS_RATES}),
            {"claude-opus-5": cheap_read},
            allow_removals=False,
            today="2026-09-29",
        )
        self.assertEqual(models["claude-opus-5"]["cacheReadPerMTok"], 0.125)
        self.assertTrue(any("cacheReadPerMTok" in note for note in notes))


class RenderAndCheck(unittest.TestCase):
    def test_render_is_sorted_and_round_trips(self):
        text = gp.render(
            {"lastVerified": "d", "source": "s", "notes": "n"},
            {"claude-zed-1": OPUS_RATES, "claude-abc-1": dict(OPUS_RATES, cacheReadPerMTok=0.025)},
        )
        data = json.loads(text)
        self.assertEqual(list(data["models"]), ["claude-abc-1", "claude-zed-1"])
        self.assertIn('"cacheReadPerMTok": 0.025', text)
        self.assertIn('"inputPerMTok": 5.00', text)
        self.assertEqual(gp.canonical_text(data), text)

    def test_committed_prices_json_passes_check(self):
        self.assertEqual(gp.main(["--check"]), 0)

    def test_check_rejects_a_non_canonical_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "prices.json"
            path.write_text(json.dumps(committed({"claude-opus-5": OPUS_RATES})), encoding="utf-8")
            self.assertEqual(gp.main(["--check", "--prices", str(path)]), 1)
            self.assertEqual(gp.main(["--format", "--prices", str(path)]), 0)
            self.assertEqual(gp.main(["--check", "--prices", str(path)]), 0)

    def test_check_rejects_a_zero_rate(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "prices.json"
            zero = dict(OPUS_RATES, inputPerMTok=0.0)
            path.write_text(json.dumps(committed({"claude-opus-5": zero})), encoding="utf-8")
            self.assertEqual(gp.main(["--check", "--prices", str(path)]), 1)

    def test_refresh_from_saved_page_writes_body_without_page_prose(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "prices.json"
            body = Path(tmp) / "body.md"
            path.write_text(
                gp.render(
                    {"lastVerified": "2026-01-01", "source": gp.SOURCE_URL, "notes": "n"},
                    {"claude-opus-5": OPUS_RATES},
                ),
                encoding="utf-8",
            )
            rc = gp.main(
                ["--refresh", "--page", str(FIXTURE), "--prices", str(path),
                 "--body-file", str(body), "--today", "2026-09-29"]
            )
            self.assertEqual(rc, 0)
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(len(data["models"]), 19)
            self.assertEqual(data["_meta"]["lastVerified"], "2026-09-29")
            text = body.read_text(encoding="utf-8")
            self.assertIn("claude-opus-5-5 added", text)
            self.assertNotIn("glasswing", text)  # a link on the page, never echoed
            self.assertNotIn("Batch", text)


class FetchGuards(unittest.TestCase):
    def test_media_type_ignores_parameters(self):
        self.assertEqual(gp.media_type("text/markdown; charset=utf-8"), "text/markdown")
        self.assertEqual(gp.media_type("Text/Markdown"), "text/markdown")
        self.assertNotEqual(gp.media_type("text/html; charset=utf-8"), "text/markdown")
        self.assertNotEqual(gp.media_type(None), "text/markdown")

    def test_url_allowlist(self):
        gp.assert_allowed_url(gp.SOURCE_URL)
        for url in (
            "http://platform.claude.com/docs/en/about-claude/pricing.md",
            "https://evil.example/pricing.md",
            "https://platform.claude.com.evil.example/x",
            "file:///etc/passwd",
        ):
            with self.assertRaises(gp.PricingError, msg=url):
                gp.assert_allowed_url(url)


if __name__ == "__main__":
    unittest.main(verbosity=2)
