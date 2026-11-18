"""Build the checked provider-neutral D012 production custody contract."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sunderkey.candidate_enrollment_production_custody_contract import (
    build_production_custody_provider_contract,
)
from sunderkey.candidate_enrollment_production_custody_decision import (
    load_candidate_enrollment_production_custody_decision_record,
)
from sunderkey.candidate_enrollment_production_custody_dossier import (
    load_candidate_enrollment_production_custody_dossier,
)

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "registry"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build the provider-neutral D012 production custody contract"
    )
    parser.add_argument(
        "--dossier",
        default=str(REGISTRY / "candidate-enrollment-production-custody-dossier-d012.json"),
    )
    parser.add_argument(
        "--decision",
        default=str(REGISTRY / "candidate-enrollment-production-custody-decision-d012.json"),
    )
    parser.add_argument(
        "--output",
        default=str(REGISTRY / "candidate-enrollment-production-custody-contract-d012.json"),
    )
    return parser


def build_contract(args: argparse.Namespace) -> dict[str, object]:
    dossier = load_candidate_enrollment_production_custody_dossier(args.dossier)
    decision = load_candidate_enrollment_production_custody_decision_record(args.decision)
    return build_production_custody_provider_contract(dossier, decision).to_dict()


def main() -> None:
    args = build_parser().parse_args()
    contract = build_contract(args)
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(contract, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"Wrote {contract['contract_id']}: {output}")


if __name__ == "__main__":
    main()
