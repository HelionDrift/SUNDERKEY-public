"""Build the approved D001 through D005 collaboration authority decision."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sunderkey.collaboration_authority_decision import (
    load_collaboration_authority_decision_submission,
    record_collaboration_authority_decision,
)
from sunderkey.collaboration_authority_dossier import (
    load_collaboration_authority_decision_dossier,
)


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    registry = root / "registry"
    parser = argparse.ArgumentParser(description="Build the collaboration decision")
    parser.add_argument(
        "--dossier",
        default=str(registry / "collaboration-authority-dossier-d001-d005.json"),
    )
    parser.add_argument(
        "--submission",
        default=str(registry / "collaboration-authority-decision-submission-d001-d005.json"),
    )
    parser.add_argument(
        "--output",
        default=str(registry / "collaboration-authority-decision-d001-d005.json"),
    )
    return parser


def build_record(args: argparse.Namespace) -> dict[str, object]:
    return record_collaboration_authority_decision(
        load_collaboration_authority_decision_dossier(args.dossier),
        load_collaboration_authority_decision_submission(args.submission),
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
    print(f"Wrote {record['record_id']}: {output}")


if __name__ == "__main__":
    main()
