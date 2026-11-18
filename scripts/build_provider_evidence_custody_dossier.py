# ruff: noqa: E501
"""Build the deterministic D013 provider evidence custody dossier."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from sunderkey.provider_evidence_custody_dossier import (
    build_provider_evidence_custody_dossier,
)


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    registry = root / "registry"
    parser = argparse.ArgumentParser(description="Build the D013 evidence custody dossier")
    parser.add_argument(
        "--provider-report-authentication-schema",
        default=str(
            registry
            / "schemas"
            / "collaboration-executor-provider-report-authentication-v1.schema.json"
        ),
    )
    parser.add_argument(
        "--provider-evidence-verification-receipt-schema",
        default=str(
            registry
            / "schemas"
            / "collaboration-executor-provider-evidence-verification-receipt-v1.schema.json"
        ),
    )
    parser.add_argument(
        "--output",
        default=str(registry / "provider-evidence-custody-dossier-d013.json"),
    )
    return parser


def _digest(path: str) -> str:
    return "sha256:" + hashlib.sha256(Path(path).read_bytes()).hexdigest()


def build_dossier(args: argparse.Namespace) -> dict[str, object]:
    return build_provider_evidence_custody_dossier(
        {
            "provider_report_authentication": {
                "artifact_path": "registry/schemas/collaboration-executor-provider-report-authentication-v1.schema.json",
                "sha256": _digest(args.provider_report_authentication_schema),
            },
            "provider_evidence_verification_receipt": {
                "artifact_path": "registry/schemas/collaboration-executor-provider-evidence-verification-receipt-v1.schema.json",
                "sha256": _digest(args.provider_evidence_verification_receipt_schema),
            },
        }
    ).to_dict()


def main() -> None:
    args = build_parser().parse_args()
    dossier = build_dossier(args)
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(dossier, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"Wrote {dossier['report_id']}: {output}")


if __name__ == "__main__":
    main()
