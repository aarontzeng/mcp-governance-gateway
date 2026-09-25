"""scripts/changelog-section.py: the release body the release workflow publishes."""
from __future__ import annotations

import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "changelog-section.py"

spec = importlib.util.spec_from_file_location("changelog_section", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

SAMPLE = """# Changelog

## [Unreleased]

- not yet

## [0.4.0] — 2026-09-25

### Fixed

- one
- two

## [0.3.0] — 2026-09-11

- older
"""


class SectionTests(unittest.TestCase):
    def test_the_section_is_the_body_under_the_heading_without_the_heading(self):
        self.assertEqual(module.section(SAMPLE, "0.4.0"), "### Fixed\n\n- one\n- two\n")

    def test_the_last_section_runs_to_the_end(self):
        self.assertEqual(module.section(SAMPLE, "0.3.0"), "- older\n")

    def test_a_prefix_match_is_not_a_match(self):
        self.assertIsNone(module.section(SAMPLE, "0.4"))
        self.assertIsNone(module.section(SAMPLE, "9.9.9"))

    def test_the_real_changelog_yields_the_current_version(self):
        from mcp_governance_gateway import __version__
        done = subprocess.run([sys.executable, str(SCRIPT), f"v{__version__}"], cwd=ROOT,
                              capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertTrue(done.stdout.startswith("### "), done.stdout[:80])
        self.assertNotIn(f"## [{__version__}]", done.stdout)

    def test_a_missing_section_fails_and_names_the_version(self):
        done = subprocess.run([sys.executable, str(SCRIPT), "9.9.9"], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(done.returncode, 1)
        self.assertIn("9.9.9", done.stderr)


if __name__ == "__main__":
    unittest.main()
