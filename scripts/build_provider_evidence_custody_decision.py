"""Build the deterministic approved D013 evidence custody decision."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sunderkey.provider_evidence_custody_decision import (
    load_provider_evidence_custody_decision_submission,
    record_provider_evidence_custody_decision,
)
from sunderkey.provider_evidence_custody_dossier import (
    load_provider_evidence_custody_dossier,
)


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    registry = root / "registry"
    parser = argparse.ArgumentParser(description="Build the approved D013 decision")
    parser.add_argument(
        "--dossier",
        default=str(registry / "provider-evidence-custody-dossier-d013.json"),
    )
    parser.add_argument(
        "--submission",
        default=str(registry / "provider-evidence-custody-decision-submission-d013.json"),
    )
    parser.add_argument(
        "--output",
        default=str(registry / "provider-evidence-custody-decision-d013.json"),
    )
    return parser


def build_record(args: argparse.Namespace) -> dict[str, object]:
    return record_provider_evidence_custody_decision(
        load_provider_evidence_custody_dossier(args.dossier),
        load_provider_evidence_custody_decision_submission(args.submission),
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
