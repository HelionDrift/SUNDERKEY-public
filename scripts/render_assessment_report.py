#!/usr/bin/env python3
"""Render an existing canonical assessment bundle to one new explicit local file."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Sequence
from pathlib import Path

from sunderkey.assessment_report_rendering import (
    render_assessment_report_html,
    render_assessment_report_text,
)
from sunderkey.assessment_reporting import AssessmentReportBundle

MAX_BUNDLE_BYTES = 16 * 1024 * 1024
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_ABSOLUTE_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")


def _local_path(value: str) -> Path:
    if not value.strip() or value == "-" or "\x00" in value:
        raise argparse.ArgumentTypeError("an explicit local file path is required")
    if value.startswith(("\\\\", "//")) or (
        _SCHEME.match(value) is not None and _ABSOLUTE_DRIVE.match(value) is None
    ):
        raise argparse.ArgumentTypeError("URLs, UNC paths and stdin are not accepted")
    return Path(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=(
            "Creates a local file only, without signing, publication, authority or "
            "qualification. No directories are created and existing output paths are "
            "never overwritten. A failed write may leave a partial newly created file; "
            "the command does not remove that path. This is not atomic publication, "
            "encryption or a file-permission guarantee."
        ),
    )
    parser.add_argument(
        "--bundle",
        type=_local_path,
        required=True,
        help="existing local UTF-8 canonical AssessmentReportBundle JSON (maximum 16 MiB)",
    )
    parser.add_argument("--format", choices=("html", "text"), required=True)
    parser.add_argument(
        "--output",
        type=_local_path,
        required=True,
        help="new explicit local file; its parent directory must already exist",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        input_name = os.path.normcase(os.path.abspath(args.bundle))
        output_name = os.path.normcase(os.path.abspath(args.output))
        if input_name == output_name:
            raise ValueError("input and output paths collide")
        if not args.bundle.is_file():
            raise ValueError("input is not a regular local file")
        with args.bundle.open("rb") as stream:
            data = stream.read(MAX_BUNDLE_BYTES + 1)
        if len(data) > MAX_BUNDLE_BYTES:
            raise ValueError("input exceeds the byte limit")
        bundle = AssessmentReportBundle.from_json(data.decode("utf-8", errors="strict"))
        renderer = (
            render_assessment_report_html
            if args.format == "html"
            else render_assessment_report_text
        )
        rendered_bytes = renderer(bundle).encode("utf-8", errors="strict")
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        AttributeError,
        RecursionError,
        OverflowError,
    ):
        print(
            "Assessment report rejected: require a distinct readable local input, at most "
            "16 MiB, exact UTF-8 canonical bundle JSON and valid addressed contents. "
            "No output was created.",
            file=sys.stderr,
        )
        return 1

    try:
        with args.output.open("xb") as stream:
            if stream.write(rendered_bytes) != len(rendered_bytes):
                raise OSError("incomplete local output write")
    except OSError:
        print(
            "Local output creation or write failed. Existing paths are not overwritten. "
            "A partial newly created file may remain; no path was deleted.",
            file=sys.stderr,
        )
        return 1

    summary = {
        "assessment_sha256": bundle.report.assessment.assessment_sha256,
        "authority_effect": "none",
        "bundle_id": bundle.bundle_id,
        "bundle_sha256": bundle.bundle_sha256,
        "effects": bundle.to_dict()["effects"],
        "effects_source": "unchanged_assessment_bundle",
        "format": args.format,
        "local_file_created": True,
        "output": output_name,
        "output_bytes": len(rendered_bytes),
        "qualification_effect": "none",
        "report_sha256": bundle.report.report_sha256,
    }
    print(json.dumps(summary, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
