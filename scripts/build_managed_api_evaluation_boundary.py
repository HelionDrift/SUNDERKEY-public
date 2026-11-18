"""Build the approved D010 managed API evaluation boundary."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from sunderkey.managed_api_evaluation import build_managed_api_evaluation_boundary


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    source = root / "examples" / "implementation" / "passive-osint"
    parser = argparse.ArgumentParser(
        description="Build the approved managed API evaluation boundary"
    )
    parser.add_argument(
        "--candidates",
        default=str(source / "candidate-implementations-v1.json"),
    )
    parser.add_argument(
        "--suite",
        default=str(source / "evaluation-suite-v1.json"),
    )
    parser.add_argument(
        "--output",
        default=str(source / "managed-api-evaluation-boundary-v1.json"),
    )
    return parser


def _read_json(path: str) -> dict[str, Any]:
    resolved = Path(path).resolve()
    value = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object: {resolved}")
    return value


def build_record(args: argparse.Namespace) -> dict[str, Any]:
    return build_managed_api_evaluation_boundary(
        _read_json(args.candidates),
        _read_json(args.suite),
    ).to_dict()


def main() -> None:
    args = build_parser().parse_args()
    record = build_record(args)
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(record, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"Wrote {record['decision_id']} {record['decision_status']}: {output}")


if __name__ == "__main__":
    main()
