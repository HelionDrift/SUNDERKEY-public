from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

from sunderkey.content_guard import (
    require_clean_repository_text,
    scan_file,
    scan_text,
)

ROOT = Path(__file__).resolve().parents[2]


class ContentGuardTests(unittest.TestCase):
    def test_em_dash_is_reported_with_location(self) -> None:
        text = "safe\nbad" + chr(0x2014) + "value\n"
        findings = scan_text(Path("sample.txt"), text)

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.line, 2)
        self.assertEqual(finding.column, 4)
        self.assertEqual(finding.code_point, 0x2014)
        self.assertEqual(finding.reason, "em dash")

    def test_invisible_format_controls_are_reported(self) -> None:
        controls = (
            (0x200B, "invisible format control"),
            (0x202E, "bidirectional override"),
            (0x2066, "bidirectional isolate"),
            (0xFEFF, "byte order mark"),
        )
        for code_point, reason in controls:
            with self.subTest(code_point=code_point):
                findings = scan_text(
                    Path("sample.txt"),
                    "left" + chr(code_point) + "right",
                )
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].code_point, code_point)
                self.assertEqual(findings[0].reason, reason)

    def test_office_lock_file_is_reported_without_reading_it(self) -> None:
        findings = scan_file(Path("~$draft.docx"))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].reason, "Office lock file")

    def test_hidden_word_text_and_forbidden_text_are_reported(self) -> None:
        document_xml = (
            "<w:document><w:r><w:rPr><w:vanish/></w:rPr>"
            "<w:t>hidden" + chr(0x2014) + "text</w:t></w:r></w:document>"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.docx"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("word/document.xml", document_xml)

            findings = scan_file(path)

        reasons = {finding.reason for finding in findings}
        self.assertIn("em dash", reasons)
        self.assertTrue(any(reason.startswith("hidden Word text") for reason in reasons))

    def test_review_and_metadata_markers_are_reported(self) -> None:
        document_xml = (
            '<w:document xmlns:w="urn:test"><w:body>'
            "<w:ins><w:r><w:t>revision</w:t></w:r></w:ins>"
            "</w:body></w:document>"
        )
        core_xml = (
            "<cp:coreProperties "
            'xmlns:cp="http://schemas.openxmlformats.org/package/2006/'
            'metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/">'
            "<dc:creator>hidden author</dc:creator>"
            "<cp:lastModifiedBy>hidden editor</cp:lastModifiedBy>"
            "</cp:coreProperties>"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.docx"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("word/document.xml", document_xml)
                archive.writestr("word/comments.xml", "<comments/>")
                archive.writestr("docProps/core.xml", core_xml)
                archive.writestr("docProps/custom.xml", "<properties/>")

            findings = scan_file(path)

        reasons = {finding.reason for finding in findings}
        self.assertTrue(any(reason.startswith("tracked Word insertion") for reason in reasons))
        self.assertTrue(any(reason.startswith("Word comments part") for reason in reasons))
        self.assertIn("custom document properties", reasons)
        self.assertIn("document creator metadata", reasons)
        self.assertIn("last-modified-by metadata", reasons)

    def test_repository_text_is_clean(self) -> None:
        require_clean_repository_text(ROOT)


if __name__ == "__main__":
    unittest.main()
