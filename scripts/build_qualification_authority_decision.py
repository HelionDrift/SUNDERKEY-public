"""Build the deterministic approved D008 qualification authority record."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sunderkey.qualification_authority_decision import (
    record_qualification_authority_decision,
)
from sunderkey.qualification_authority_dossier import (
    QualificationAuthorityDecisionDossier,
)


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    registry = root / "registry"
    parser = argparse.ArgumentParser(
        description="Build the approved D008 qualification authority record"
    )
    parser.add_argument(
        "--dossier",
        default=str(registry / "qualification-authority-dossier-d008.json"),
    )
    parser.add_argument(
        "--output",
        default=str(registry / "qualification-authority-decision-d008.json"),
    )
    return parser


def build_record(args: argparse.Namespace) -> dict[str, object]:
    dossier_path = Path(args.dossier)
    dossier = QualificationAuthorityDecisionDossier.from_dict(
        json.loads(dossier_path.read_text(encoding="utf-8"))
    )
    return record_qualification_authority_decision(dossier).to_dict()


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
    print(
        "Wrote "
        f"{record['decision_id']} {record['decision_status']}: {output}"
    )


if __name__ == "__main__":
    main()
