"""Build the provider-neutral D014 production deployment decision dossier."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from sunderkey.candidate_backend_conformance import (
    load_containment_conformance_suite_catalog,
)
from sunderkey.candidate_enrollment_production_custody_decision import (
    load_candidate_enrollment_production_custody_decision_record,
)
from sunderkey.candidate_enrollment_release_contract import (
    load_candidate_enrollment_release_policy,
)
from sunderkey.deployment_manifests import DeploymentManifestBundle
from sunderkey.production_deployment_decision_dossier import (
    build_production_deployment_decision_dossier,
    expected_repository_evidence,
)
from sunderkey.provider_evidence_custody_decision import (
    load_provider_evidence_custody_decision_record,
)
from sunderkey.validation import loads_json_without_duplicate_keys

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "registry"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--production-custody-decision",
        default=str(REGISTRY / "candidate-enrollment-production-custody-decision-d012.json"),
    )
    parser.add_argument(
        "--evidence-custody-decision",
        default=str(REGISTRY / "provider-evidence-custody-decision-d013.json"),
    )
    parser.add_argument(
        "--deployment-manifest",
        default=str(REGISTRY / "deployment-manifest-bundle-v1.json"),
    )
    parser.add_argument(
        "--containment-catalog",
        default=str(REGISTRY / "candidate-containment-conformance-suites-v1.json"),
    )
    parser.add_argument(
        "--release-policy",
        default=str(REGISTRY / "candidate-enrollment-release-policy-d011.json"),
    )
    parser.add_argument(
        "--repository-root",
        default=str(ROOT),
    )
    parser.add_argument(
        "--output",
        default=str(REGISTRY / "production-deployment-decision-dossier-d014.json"),
    )
    return parser


def _load_mapping(path: str | Path, label: str) -> dict[str, object]:
    resolved = Path(path).resolve()
    try:
        value = loads_json_without_duplicate_keys(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValueError(f"Could not load {label}: {resolved}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _repository_evidence(root: Path) -> list[dict[str, str]]:
    evidence: list[dict[str, str]] = []
    for expected in expected_repository_evidence():
        relative = expected["repository_path"]
        source = (root / relative).resolve()
        if not source.is_relative_to(root.resolve()):
            raise ValueError("Repository evidence path escapes the repository root")
        try:
            digest = "sha256:" + hashlib.sha256(source.read_bytes()).hexdigest()
        except OSError as exc:
            raise ValueError(f"Could not load repository evidence: {source}") from exc
        evidence.append(
            {
                "evidence_area": expected["evidence_area"],
                "evidence_kind": expected["evidence_kind"],
                "repository_path": relative,
                "file_sha256": digest,
            }
        )
    return evidence


def build_dossier(args: argparse.Namespace) -> dict[str, object]:
    deployment_manifest = DeploymentManifestBundle.from_dict(
        _load_mapping(args.deployment_manifest, "deployment manifest")
    )
    return build_production_deployment_decision_dossier(
        production_custody_decision=(
            load_candidate_enrollment_production_custody_decision_record(
                args.production_custody_decision
            )
        ),
        evidence_custody_decision=load_provider_evidence_custody_decision_record(
            args.evidence_custody_decision
        ),
        deployment_manifest=deployment_manifest,
        containment_catalog=load_containment_conformance_suite_catalog(args.containment_catalog),
        release_policy=load_candidate_enrollment_release_policy(args.release_policy),
        repository_evidence=_repository_evidence(Path(args.repository_root).resolve()),
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
    print(f"Wrote {dossier['dossier_id']}: {output}")


if __name__ == "__main__":
    main()
