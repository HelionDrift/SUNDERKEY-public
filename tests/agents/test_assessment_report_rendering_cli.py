"""Explicit disposable local report exports preserve canonical custody inputs."""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from scripts import render_assessment_report as rendering_cli
from sunderkey.assessment_report_rendering import (
    render_assessment_report_html,
    render_assessment_report_text,
)
from sunderkey.assessment_reporting import NO_EFFECTS, canonical_json
from tests.agents import test_assessment_reporting_phase161 as report_fixtures

ROOT = Path(__file__).resolve().parents[2]


class AssessmentReportRenderingCliTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="sunderkey-report-cli-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.fixture = report_fixtures.AssessmentReportingPhase161Tests("runTest")
        self.bundle = self.fixture.bundle()
        self.input = self.directory / "bundle.json"
        self.input.write_bytes(self.bundle.to_json().encode("utf-8"))
        self.original_bytes = self.input.read_bytes()

    def _arguments(self, *, output: Path | str | None = None, format: str = "html") -> list[str]:
        return [
            "--bundle",
            str(self.input),
            "--format",
            format,
            "--output",
            str(output if output is not None else self.directory / "report.html"),
        ]

    def _invoke(self, arguments: list[str]) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                code = rendering_cli.main(arguments)
            except SystemExit as exc:
                code = exc.code
        return code, stdout.getvalue(), stderr.getvalue()

    def _rejected_bytes(self, data: bytes, *, format: str = "html") -> None:
        self.input.write_bytes(data)
        output = self.directory / ("rejected." + format)
        code, stdout, stderr = self._invoke(self._arguments(output=output, format=format))
        self.assertEqual(code, 1)
        self.assertEqual(stdout, "")
        self.assertIn("No output was created.", stderr)
        self.assertLess(len(stderr), 512)
        self.assertFalse(output.exists())
        self.assertEqual(self.input.read_bytes(), data)

    def test_html_and_text_are_exact_renderer_bytes_with_truthful_success_summary(self) -> None:
        for format, renderer in (
            ("html", render_assessment_report_html),
            ("text", render_assessment_report_text),
        ):
            with self.subTest(format=format):
                output = self.directory / ("report." + format)
                code, stdout, stderr = self._invoke(self._arguments(output=output, format=format))
                self.assertEqual((code, stderr), (0, ""))
                self.assertEqual(output.read_bytes(), renderer(self.bundle).encode("utf-8"))
                summary = json.loads(stdout)
                self.assertIs(summary["local_file_created"], True)
                self.assertEqual(summary["format"], format)
                self.assertEqual(summary["output_bytes"], output.stat().st_size)
                self.assertEqual(summary["bundle_id"], self.bundle.bundle_id)
                self.assertEqual(summary["bundle_sha256"], self.bundle.bundle_sha256)
                self.assertEqual(summary["report_sha256"], self.bundle.report.report_sha256)
                self.assertEqual(
                    summary["assessment_sha256"], self.bundle.report.assessment.assessment_sha256
                )
                self.assertEqual(summary["authority_effect"], "none")
                self.assertEqual(summary["qualification_effect"], "none")
                self.assertEqual(summary["effects"], NO_EFFECTS)
                self.assertEqual(summary["effects_source"], "unchanged_assessment_bundle")
                self.assertEqual(summary["output"], os.path.normcase(os.path.abspath(output)))
                self.assertEqual(self.input.read_bytes(), self.original_bytes)
                self.assertEqual(self.bundle.to_json().encode("utf-8"), self.original_bytes)

    def test_real_script_entrypoint_uses_only_explicit_disposable_paths(self) -> None:
        output = self.directory / "subprocess.txt"
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(ROOT / "src")
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                str(ROOT / "scripts" / "render_assessment_report.py"),
                *self._arguments(output=output, format="text"),
            ],
            cwd=self.directory,
            env=environment,
            capture_output=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b"")
        self.assertTrue(json.loads(result.stdout)["local_file_created"])
        self.assertEqual(output.read_bytes(), render_assessment_report_text(self.bundle).encode())
        self.assertEqual(self.input.read_bytes(), self.original_bytes)
        self.assertEqual(
            {path.name for path in self.directory.iterdir()}, {"bundle.json", "subprocess.txt"}
        )

    def test_pretty_json_is_rejected_without_normalization(self) -> None:
        self._rejected_bytes(json.dumps(self.bundle.to_dict(), indent=2, sort_keys=True).encode())

    def test_old_hash_cannot_cover_changed_native_types(self) -> None:
        for path, value in (
            (("schema_version",), True),
            (("report", "executive_summary", "coverage_metrics", "tested"), True),
            (("report", "assessment", "coverage_metrics", "total_areas"), 2.0),
            (("report", "executive_summary", "coverage_metrics", "coverage_basis_points"), 10000.0),
        ):
            with self.subTest(path=path, value=value):
                document = self.bundle.to_dict()
                selected = document
                for key in path[:-1]:
                    selected = selected[key]
                selected[path[-1]] = value
                self._rejected_bytes(canonical_json(document).encode())

    def test_hash_and_content_tampering_create_no_output(self) -> None:
        for change in ("hash", "title", "effects", "compliance"):
            with self.subTest(change=change):
                document = self.bundle.to_dict()
                if change == "hash":
                    document["bundle_sha256"] = report_fixtures.DIGESTS[15]
                elif change == "title":
                    document["report"]["findings"][0]["title"] = "Different title"
                elif change == "effects":
                    document["effects"]["qualification"] = "allowed"
                else:
                    document["attestation"]["compliance_claim"] = "compliant"
                self._rejected_bytes(canonical_json(document).encode())

    def test_duplicate_keys_at_outer_and_nested_positions_create_no_output(self) -> None:
        document = self.bundle.to_json()
        duplicates = (
            document[:-1] + ',"bundle_id":' + json.dumps(self.bundle.bundle_id) + "}",
            document.replace('"tested":1', '"tested":1,"tested":1', 1),
        )
        for changed in duplicates:
            with self.subTest(changed=changed != document):
                self.assertNotEqual(changed, document)
                self._rejected_bytes(changed.encode())

    def test_invalid_utf8_and_empty_input_create_no_output(self) -> None:
        for data in (b"", b"\xff\xfe", b"\xef\xbb\xbf" + self.original_bytes):
            with self.subTest(data_length=len(data)):
                self._rejected_bytes(data)

    def test_oversized_read_stops_at_limit_plus_one_before_parser_or_output(self) -> None:
        data = b" " * (rendering_cli.MAX_BUNDLE_BYTES + 100)
        self.input.write_bytes(data)
        original_open = Path.open
        read_sizes: list[int] = []

        class ObservedRead:
            def __enter__(inner_self):
                inner_self.stream = original_open(self.input, "rb")
                return inner_self

            def read(inner_self, size: int) -> bytes:
                read_sizes.append(size)
                return inner_self.stream.read(size)

            def __exit__(inner_self, *args) -> None:
                inner_self.stream.close()

        def observed_open(path, mode="r", *args, **kwargs):
            if path == self.input and mode == "rb":
                return ObservedRead()
            return original_open(path, mode, *args, **kwargs)

        output = self.directory / "oversized.html"
        with (
            patch.object(Path, "open", observed_open),
            patch.object(
                rendering_cli.AssessmentReportBundle,
                "from_json",
                side_effect=AssertionError("parser must not run"),
            ),
        ):
            code, stdout, stderr = self._invoke(self._arguments(output=output))
        self.assertEqual(code, 1)
        self.assertEqual(stdout, "")
        self.assertIn("No output was created.", stderr)
        self.assertEqual(read_sizes, [rendering_cli.MAX_BUNDLE_BYTES + 1])
        self.assertFalse(output.exists())
        self.assertEqual(self.input.read_bytes(), data)

    def test_deep_and_primitive_json_failures_are_bounded_rejections(self) -> None:
        for data in (
            b"null",
            b"true",
            b"1",
            b"[]",
            b"[" * 2000 + b"0" + b"]" * 2000,
            b'{"number":' + b"1" * 5000 + b"}",
        ):
            with self.subTest(data_length=len(data)):
                self._rejected_bytes(data)

    def test_non_utf8_rendered_scalar_rejects_before_output_creation(self) -> None:
        asset = replace(
            self.bundle.report.assessment.assets[0], display_name="Recorded \ud800 name"
        )
        assessment = replace(self.bundle.report.assessment, assets=(asset,))
        report_reviewers, attestation_reviewers = self.fixture.reviewers()
        bundle = report_fixtures.build_assessment_report_bundle(
            assessment,
            self.bundle.report.findings,
            report_reviewers=report_reviewers,
            attestation_reviewers=attestation_reviewers,
            attested_at="2026-09-20T03:22:00Z",
        )
        for format in ("html", "text"):
            with self.subTest(format=format):
                self._rejected_bytes(bundle.to_json().encode("ascii"), format=format)

    def test_existing_output_is_preserved_including_directory_entry(self) -> None:
        output = self.directory / "existing.txt"
        output.write_bytes(b"existing local content")
        code, stdout, stderr = self._invoke(self._arguments(output=output, format="text"))
        self.assertEqual((code, stdout), (1, ""))
        self.assertIn("Existing paths are not overwritten", stderr)
        self.assertEqual(output.read_bytes(), b"existing local content")
        self.assertEqual(self.input.read_bytes(), self.original_bytes)
        directory = self.directory / "existing-directory"
        directory.mkdir()
        self.assertEqual(self._invoke(self._arguments(output=directory))[0], 1)
        self.assertTrue(directory.is_dir())

    def test_hardlink_output_cannot_overwrite_source(self) -> None:
        output = self.directory / "linked.txt"
        os.link(self.input, output)
        code, stdout, _ = self._invoke(self._arguments(output=output))
        self.assertEqual((code, stdout), (1, ""))
        self.assertEqual(output.read_bytes(), self.original_bytes)
        self.assertEqual(self.input.read_bytes(), self.original_bytes)

    def test_existing_and_dangling_symlink_output_are_not_followed(self) -> None:
        for target in (self.input, self.directory / "absent-target"):
            output = self.directory / ("existing-link" if target == self.input else "dangling-link")
            try:
                output.symlink_to(target)
            except OSError as exc:
                self.skipTest(
                    "platform cannot create a disposable symlink: "
                    + str(getattr(exc, "winerror", exc.errno))
                )
            code, stdout, _ = self._invoke(self._arguments(output=output))
            self.assertEqual((code, stdout), (1, ""))
            self.assertTrue(output.is_symlink())
            if target != self.input:
                self.assertFalse(target.exists())
            self.assertEqual(self.input.read_bytes(), self.original_bytes)

    def test_input_output_collision_and_normalized_alias_do_not_modify_input(self) -> None:
        aliases = (self.input, self.directory / "not-created" / ".." / self.input.name)
        for output in aliases:
            with self.subTest(output=str(output)):
                code, stdout, stderr = self._invoke(self._arguments(output=output))
                self.assertEqual((code, stdout), (1, ""))
                self.assertIn("No output was created.", stderr)
                self.assertEqual(self.input.read_bytes(), self.original_bytes)
        self.assertFalse((self.directory / "not-created").exists())

    def test_nonexistent_parent_is_not_created_and_missing_input_has_no_output(self) -> None:
        output = self.directory / "missing-parent" / "report.html"
        code, stdout, _ = self._invoke(self._arguments(output=output))
        self.assertEqual((code, stdout), (1, ""))
        self.assertFalse(output.parent.exists())
        self.input.unlink()
        output = self.directory / "missing-input.html"
        self.assertEqual(self._invoke(self._arguments(output=output))[0], 1)
        self.assertFalse(output.exists())

    def test_paths_format_and_bundle_are_required_and_remote_or_stdin_is_rejected(self) -> None:
        cases = (
            [],
            ["--bundle", str(self.input), "--format", "html"],
            ["--bundle", str(self.input), "--output", str(self.directory / "report.html")],
            ["--format", "html", "--output", str(self.directory / "report.html")],
            self._arguments(format="pdf"),
        )
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            for arguments in cases:
                self.assertEqual(self._invoke(arguments)[0], 2)
            for path in (
                "-",
                "https://untrusted.invalid/bundle",
                "file:///local/bundle",
                "https:relative",
                "\\\\server\\share\\bundle",
                "//server/share/bundle",
                "",
            ):
                for argument in ("--bundle", "--output"):
                    arguments = self._arguments()
                    arguments[arguments.index(argument) + 1] = path
                    with self.subTest(argument=argument, path=path):
                        self.assertEqual(self._invoke(arguments)[0], 2)
        self.assertEqual({path.name for path in self.directory.iterdir()}, {"bundle.json"})

    def test_help_reads_writes_and_opens_no_socket(self) -> None:
        with (
            patch.object(Path, "open", side_effect=AssertionError("file access forbidden")),
            patch("socket.socket", side_effect=AssertionError("network forbidden")),
        ):
            code, stdout, stderr = self._invoke(["--help"])
        self.assertEqual((code, stderr), (0, ""))
        self.assertIn("--bundle", stdout)
        self.assertIn("--format", stdout)
        self.assertIn("--output", stdout)
        self.assertIn("not atomic publication", stdout)
        self.assertIn("partial newly created file", stdout)

    def test_partial_write_failure_is_reported_and_new_path_is_not_deleted(self) -> None:
        output = self.directory / "partial.html"
        original_open = Path.open

        class PartialWrite:
            def __enter__(inner_self):
                inner_self.stream = original_open(output, "xb")
                return inner_self

            def write(inner_self, data: bytes) -> int:
                inner_self.stream.write(data[:64])
                raise OSError("synthetic output failure")

            def __exit__(inner_self, *args) -> None:
                inner_self.stream.close()

        def partial_open(path, mode="r", *args, **kwargs):
            if path == output and mode == "xb":
                return PartialWrite()
            return original_open(path, mode, *args, **kwargs)

        with (
            patch.object(Path, "open", partial_open),
            patch.object(Path, "unlink", side_effect=AssertionError("output deletion forbidden")),
        ):
            code, stdout, stderr = self._invoke(self._arguments(output=output))
        self.assertEqual((code, stdout), (1, ""))
        self.assertIn("partial newly created file may remain", stderr)
        self.assertEqual(
            output.read_bytes(), render_assessment_report_html(self.bundle).encode()[:64]
        )
        self.assertEqual(self.input.read_bytes(), self.original_bytes)

    def test_valid_export_uses_no_socket_or_hidden_output(self) -> None:
        output = self.directory / "offline.html"
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            self.assertEqual(self._invoke(self._arguments(output=output))[0], 0)
        self.assertEqual(
            {path.name for path in self.directory.iterdir()}, {"bundle.json", "offline.html"}
        )


if __name__ == "__main__":
    unittest.main()
