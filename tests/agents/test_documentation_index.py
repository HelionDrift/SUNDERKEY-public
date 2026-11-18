"""Check the curated public documentation index."""

from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class DocumentationIndexTests(unittest.TestCase):
    def test_public_indexes_do_not_link_to_withheld_history(self) -> None:
        for relative in ("docs/README.md", "docs/reference-index.md"):
            text = (ROOT / relative).read_text(encoding="utf-8")
            with self.subTest(relative=relative):
                self.assertIn("Safety Boundary Reference", text)
                self.assertNotIn("development-history.md", text)
                self.assertNotIn("phase-index.md", text)


if __name__ == "__main__":
    unittest.main()
