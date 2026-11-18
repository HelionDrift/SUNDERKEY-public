"""The real remediation CLI emits the bounded canonical bytes it validated."""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sunderkey.cli import build_parser
from sunderkey.errors import SunderkeyError
from sunderkey.remediation_case_review_io import (
    build_remediation_case_review_from_request,
    load_remediation_case_review,
    serialize_remediation_case_review,
    verify_remediation_case_review_from_request,
)
from sunderkey.remediation_validation_contracts import canonical_json
from tests.agents.test_remediation_case_review_io import request

ROOT = Path(__file__).resolve().parents[2]
RUN_SCRIPT = "\n".join(
    (
        "import sys",
        "import sunderkey.remediation_case_review_io as review_io",
        "from sunderkey.cli import main",
        "review_io.MAX_REVIEW_BYTES = int(sys.argv[1])",
        "sys.argv = ['sunderkey', 'remediation-case-review', '--input', sys.argv[2]]",
        "main()",
    )
)


class RemediationCliOutputBytesTests(unittest.TestCase):
    def run_cli(self, source: Path, byte_cap: int):
        environment = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
        return subprocess.run(
            [sys.executable, "-c", RUN_SCRIPT, str(byte_cap), str(source)],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            check=False,
            timeout=30,
        )

    def test_real_cli_stdout_fits_the_exact_cap_and_replays_through_the_loader(self) -> None:
        raw = request()
        review = build_remediation_case_review_from_request(raw)
        expected = serialize_remediation_case_review(review).encode("ascii")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.json"
            source.write_bytes(canonical_json(raw).encode("ascii"))
            before = source.read_bytes()
            result = self.run_cli(source, len(expected))
            self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", errors="replace"))
            self.assertEqual(result.stderr, b"")
            self.assertEqual(result.stdout, expected)
            self.assertEqual(result.stdout[-1:], b"\n")
            self.assertFalse(result.stdout.endswith(b"\r\n"))
            self.assertEqual(set(root.iterdir()), {source})
            self.assertEqual(source.read_bytes(), before)
            saved = root / "review.json"
            saved.write_bytes(result.stdout)
            with patch("sunderkey.remediation_case_review_io.MAX_REVIEW_BYTES", len(expected)):
                loaded = load_remediation_case_review(saved)
            verify_remediation_case_review_from_request(raw, loaded)

    def test_real_cli_oversized_result_publishes_no_stdout_bytes(self) -> None:
        raw = request()
        review = build_remediation_case_review_from_request(raw)
        cap_without_newline = len(canonical_json(review).encode("ascii"))
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source.json"
            source.write_bytes(canonical_json(raw).encode("ascii"))
            result = self.run_cli(source, cap_without_newline)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"")
            self.assertIn(b"byte limit", result.stderr)

    def test_binary_stream_is_used_instead_of_newline_translating_text_stream(self) -> None:
        raw = request()
        expected = serialize_remediation_case_review(
            build_remediation_case_review_from_request(raw)
        ).encode("ascii")

        class TranslatingOutput:
            def __init__(self):
                self.buffer = io.BytesIO()

            def write(self, value):
                raise AssertionError("text newline transformation must not be invoked")

        output = TranslatingOutput()
        args = build_parser().parse_args(["remediation-case-review", "--input", "source.json"])
        with patch("sunderkey.cli.load_remediation_case_request", return_value=raw):
            with contextlib.redirect_stdout(output):
                args.handler(args)
        self.assertEqual(output.buffer.getvalue(), expected)

    def test_invalid_sources_do_not_touch_a_binary_output_buffer(self) -> None:
        raw = request()
        raw["execute"] = True
        output = io.TextIOWrapper(io.BytesIO(), encoding="utf-8", newline="\r\n")
        args = build_parser().parse_args(["remediation-case-review", "--input", "source.json"])
        try:
            with patch("sunderkey.cli.load_remediation_case_request", return_value=raw):
                with contextlib.redirect_stdout(output):
                    with self.assertRaises(SunderkeyError):
                        args.handler(args)
            self.assertEqual(output.buffer.getvalue(), b"")
        finally:
            output.close()

    def test_binary_output_bypasses_incompatible_text_encoding(self) -> None:
        raw = request()
        review = build_remediation_case_review_from_request(raw)
        output = io.TextIOWrapper(io.BytesIO(), encoding="utf-16", newline="\r\n")
        args = build_parser().parse_args(["remediation-case-review", "--input", "source.json"])
        try:
            with patch("sunderkey.cli.load_remediation_case_request", return_value=raw):
                with contextlib.redirect_stdout(output):
                    args.handler(args)
            self.assertEqual(
                output.buffer.getvalue(), serialize_remediation_case_review(review).encode("ascii")
            )
        finally:
            output.close()

    def test_text_only_captures_remain_supported_without_any_authority_effect(self) -> None:
        raw = request()
        output = io.StringIO()
        args = build_parser().parse_args(["remediation-case-review", "--input", "source.json"])
        with patch("sunderkey.cli.load_remediation_case_request", return_value=raw):
            with contextlib.redirect_stdout(output):
                args.handler(args)
        review = json.loads(output.getvalue())
        self.assertEqual(review["case_status"], "review_required")
        self.assertTrue(all(value is False for value in review["claims"].values()))
        self.assertTrue(all(value == "none" for value in review["effects"].values()))


if __name__ == "__main__":
    unittest.main()
