"""Check public entry points and their local links."""

from __future__ import annotations

import re
import tomllib
import unittest
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[2]
DOCUMENTS = (ROOT / "README.md", ROOT / "docs/README.md", ROOT / "docs/reference-index.md")
LINK = re.compile(r"\[[^\]\n]+\]\(([^)\n]+)\)")


class ReadmeNavigationTests(unittest.TestCase):
    def test_project_metadata_and_release_boundary(self) -> None:
        readme = DOCUMENTS[0].read_text(encoding="utf-8")
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        self.assertEqual(project["name"], "sunderkey")
        self.assertEqual(project["license"], "Apache-2.0")
        self.assertIn("target owner's authorization", readme)
        self.assertIn("Installing it does not grant target access", readme)
        self.assertIn("A real deployment must independently validate", readme)
        self.assertLessEqual(len(readme.splitlines()), 120)

    def test_public_navigation_links_exist(self) -> None:
        for source in DOCUMENTS:
            for target in LINK.findall(source.read_text(encoding="utf-8")):
                url = urlsplit(target)
                if url.scheme or not url.path:
                    continue
                resolved = (source.parent / unquote(url.path)).resolve()
                with self.subTest(source=source.name, target=target):
                    self.assertTrue(resolved.is_relative_to(ROOT))
                    self.assertTrue(resolved.is_file())


if __name__ == "__main__":
    unittest.main()
