#!/usr/bin/env python3
"""Render a canonical assessment bundle after local finding-origin comparison."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Sequence
from pathlib import Path

from sunderkey.assessment_reporting import AssessmentReportBundle
from sunderkey.offline_verified_report_render import (
    MAX_MANIFEST_BYTES,
    render_verified_assessment_report,
)

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


def _read_bounded(path: Path, maximum: int) -> bytes:
    if not path.is_file():
        raise ValueError("input is not a regular local file")
    with path.open("rb") as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError("input exceeds the byte limit")
    return data


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=(
            "Creates a local file only. Matching supplied local originals is not "
            "authenticated review, currentness, publication approval, authority, "
            "or product qualification. Existing output paths are never overwritten."
        ),
    )
    parser.add_argument("--bundle", type=_local_path, required=True)
    parser.add_argument("--origins", type=_local_path, required=True)
    parser.add_argument("--format", choices=("html", "text"), required=True)
    parser.add_argument("--output", type=_local_path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        input_names = {
            os.path.normcase(os.path.abspath(args.bundle)),
            os.path.normcase(os.path.abspath(args.origins)),
        }
        output_name = os.path.normcase(os.path.abspath(args.output))
        if output_name in input_names or len(input_names) != 2:
            raise ValueError("input and output paths collide")
        bundle_document = _read_bounded(args.bundle, MAX_BUNDLE_BYTES)
        origin_document = _read_bounded(args.origins, MAX_MANIFEST_BYTES)
        bundle = AssessmentReportBundle.from_json(bundle_document.decode("utf-8", errors="strict"))
        rendered, summary = render_verified_assessment_report(
            bundle=bundle,
            origin_manifest=origin_document,
            format=args.format,
        )
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        AttributeError,
        UnicodeError,
        RecursionError,
        OverflowError,
    ):
        print(
            "Verified report rejected: require distinct, bounded canonical local "
            "bundle and origin files with exact matching finding histories. "
            "No output was created.",
            file=sys.stderr,
        )
        return 1

    try:
        with args.output.open("xb") as stream:
            if stream.write(rendered) != len(rendered):
                raise OSError("incomplete local output write")
    except OSError:
        print(
            "Local output creation or write failed. Existing paths were not overwritten. "
            "A partial newly created file may remain.",
            file=sys.stderr,
        )
        return 1

    summary = {
        **summary,
        "local_file_created": True,
        "output": output_name,
        "output_bytes": len(rendered),
    }
    print(json.dumps(summary, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
