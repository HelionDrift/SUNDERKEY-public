"""Focused verified local rendering with exact supplied finding originals."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import render_verified_assessment_report as rendering_cli
from sunderkey.assessment_reporting import build_assessment_report_bundle
from sunderkey.offline_verified_report_render import (
    MANIFEST_KIND,
    OfflineVerifiedReportRenderError,
    parse_canonical_origin_manifest,
    render_verified_assessment_report,
)
from tests.agents import test_offline_report_finding_origins as origin_fixture

ROOT = Path(__file__).resolve().parents[2]


def canonical(value: dict) -> bytes:
    return json.dumps(
        value, allow_nan=False, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")


class OfflineVerifiedReportRenderTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        fixture = origin_fixture.OfflineReportFindingOriginsTests()
        fixture.setUp()
        self.history = fixture.history
        report_roles, attestation_roles = fixture.fixture.reviewers()
        self.bundle = build_assessment_report_bundle(
            fixture.report.assessment,
            fixture.report.findings,
            report_reviewers=report_roles,
            attestation_reviewers=attestation_roles,
            attested_at="2026-09-20T03:22:00Z",
        )
        self.manifest = {
            "kind": MANIFEST_KIND,
            "schema_version": 1,
            "histories": [
                {
                    "finding_id": self.history[-1].finding_id,
                    "snapshots": [snapshot.to_dict() for snapshot in self.history],
                }
            ],
        }
        self.bundle_path = self.directory / "bundle.json"
        self.origin_path = self.directory / "origins.json"
        self.bundle_path.write_bytes(self.bundle.to_json().encode("ascii"))
        self.origin_path.write_bytes(canonical(self.manifest))

    def _invoke(self, output: Path, *, format: str = "text") -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = rendering_cli.main(
                [
                    "--bundle",
                    str(self.bundle_path),
                    "--origins",
                    str(self.origin_path),
                    "--format",
                    format,
                    "--output",
                    str(output),
                ]
            )
        return code, stdout.getvalue(), stderr.getvalue()

    def _rejected(self, manifest: dict | bytes) -> None:
        contents = manifest if type(manifest) is bytes else canonical(manifest)
        self.origin_path.write_bytes(contents)
        output = self.directory / "rejected.txt"
        code, stdout, stderr = self._invoke(output)
        self.assertEqual(code, 1)
        self.assertEqual(stdout, "")
        self.assertIn("No output was created.", stderr)
        self.assertFalse(output.exists())
        self.assertEqual(self.origin_path.read_bytes(), contents)

    def test_valid_text_and_html_have_explicit_limited_origin_notice(self) -> None:
        before_bundle = self.bundle_path.read_bytes()
        before_origins = self.origin_path.read_bytes()
        for format in ("text", "html"):
            with self.subTest(format=format):
                output = self.directory / f"report.{format}"
                code, stdout, stderr = self._invoke(output, format=format)
                self.assertEqual((code, stderr), (0, ""))
                rendered = output.read_text(encoding="utf-8")
                self.assertIn("Finding Origins: Matched Local Originals Only", rendered)
                self.assertIn("publication approval", rendered)
                result = json.loads(stdout)
                self.assertEqual(result["status"], "origins_matched_local_only")
                self.assertEqual(result["finding_count"], 1)
                self.assertEqual(result["live_source_currentness"], "not_proven")
                self.assertEqual(result["authenticated_review"], "not_proven")
                self.assertFalse(result["publication_approved"])
                self.assertEqual(result["authorization_effect"], "none")
                self.assertEqual(result["qualification_effect"], "none")
                self.assertEqual(result["target_effect"], "none")
                self.assertEqual(result["output_bytes"], output.stat().st_size)
        self.assertEqual(self.bundle_path.read_bytes(), before_bundle)
        self.assertEqual(self.origin_path.read_bytes(), before_origins)

    def test_missing_extra_forged_and_stale_origins_create_no_output(self) -> None:
        missing = copy.deepcopy(self.manifest)
        missing["histories"] = []
        extra = copy.deepcopy(self.manifest)
        extra["histories"].append(
            {"finding_id": "FND-extra", "snapshots": [self.history[0].to_dict()]}
        )
        forged = copy.deepcopy(self.manifest)
        forged["histories"][0]["snapshots"][-1]["snapshot_sha256"] = "sha256:" + "b" * 64
        stale = copy.deepcopy(self.manifest)
        stale["histories"][0]["snapshots"] = stale["histories"][0]["snapshots"][:-1]
        for name, manifest in (
            ("missing", missing),
            ("extra", extra),
            ("forged", forged),
            ("stale", stale),
        ):
            with self.subTest(name=name):
                self._rejected(manifest)

    def test_noncanonical_duplicate_raw_and_oversized_inputs_fail(self) -> None:
        pretty = json.dumps(self.manifest, indent=2, sort_keys=True).encode("ascii")
        raw = copy.deepcopy(self.manifest)
        raw["histories"][0]["snapshots"][0]["raw_response_body"] = "secret"
        duplicate = (
            b'{"histories":[],"histories":[],"kind":"'
            + MANIFEST_KIND.encode()
            + b'","schema_version":1}'
        )
        for manifest in (
            pretty,
            duplicate,
            raw,
        ):
            with self.subTest(manifest_type=type(manifest).__name__):
                self._rejected(manifest)
        self.origin_path.write_bytes(canonical(self.manifest))
        with mock.patch.object(rendering_cli, "MAX_MANIFEST_BYTES", 1):
            output = self.directory / "oversized.txt"
            code, stdout, stderr = self._invoke(output)
        self.assertEqual(code, 1)
        self.assertEqual(stdout, "")
        self.assertIn("No output was created.", stderr)
        self.assertFalse(output.exists())

    def test_existing_output_is_not_overwritten(self) -> None:
        output = self.directory / "existing.txt"
        output.write_bytes(b"keep-original")
        code, stdout, stderr = self._invoke(output)
        self.assertEqual(code, 1)
        self.assertEqual(stdout, "")
        self.assertIn("not overwritten", stderr)
        self.assertEqual(output.read_bytes(), b"keep-original")

    def test_standalone_entrypoint_uses_only_explicit_local_files(self) -> None:
        output = self.directory / "subprocess.txt"
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(ROOT / "src")
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                str(ROOT / "scripts" / "render_verified_assessment_report.py"),
                "--bundle",
                str(self.bundle_path),
                "--origins",
                str(self.origin_path),
                "--format",
                "text",
                "--output",
                str(output),
            ],
            cwd=self.directory,
            env=environment,
            capture_output=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b"")
        self.assertIn(b"Matched Local Originals Only", output.read_bytes())
        self.assertEqual(json.loads(result.stdout)["status"], "origins_matched_local_only")
        self.assertEqual(
            {path.name for path in self.directory.iterdir()},
            {"bundle.json", "origins.json", "subprocess.txt"},
        )

    def test_parser_and_renderer_reject_invalid_native_inputs(self) -> None:
        histories, address = parse_canonical_origin_manifest(canonical(self.manifest))
        self.assertEqual(set(histories), {self.history[-1].finding_id})
        self.assertTrue(address.startswith("sha256:"))
        with self.assertRaises(OfflineVerifiedReportRenderError):
            parse_canonical_origin_manifest(bytearray(canonical(self.manifest)))
        with self.assertRaises(OfflineVerifiedReportRenderError):
            render_verified_assessment_report(
                bundle=self.bundle,
                origin_manifest=canonical(self.manifest),
                format="pdf",
            )


if __name__ == "__main__":
    unittest.main()
