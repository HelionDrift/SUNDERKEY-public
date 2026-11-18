"""Build the deterministic synthetic candidate evaluation submission."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from sunderkey.candidate_blueprints import load_candidate_blueprint_catalog
from sunderkey.candidate_components import (
    CandidateOnboardingReport,
    assess_candidate_onboarding,
    load_candidate_component_catalog,
)
from sunderkey.candidate_inventory import (
    load_candidate_implementation_catalog,
)
from sunderkey.candidate_preflight import (
    compute_candidate_evaluation_submission_sha256,
)
from sunderkey.qualification import (
    load_qualification_plan_catalog,
    load_qualification_standard,
)
from sunderkey.qualification_evaluation import (
    load_qualification_evaluation_suite,
)
from sunderkey.registry import load_registry
from sunderkey.routing import load_capability_catalog

PROFILE_ID = "AOE-GA-D01-S01"
CANDIDATE_ID = "fixture.passive-osint"
CANDIDATE_VERSION = "1.0.0"


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Build the synthetic candidate evaluation submission"
    )
    parser.add_argument(
        "--registry", default=str(root / "registry" / "army-v1.json")
    )
    parser.add_argument(
        "--capabilities",
        default=str(root / "registry" / "capabilities-army-v1.json"),
    )
    parser.add_argument(
        "--standard",
        default=str(root / "registry" / "qualification-standard-v1.json"),
    )
    parser.add_argument(
        "--plans",
        default=str(
            root / "registry" / "qualification-plans-army-v1.json"
        ),
    )
    parser.add_argument(
        "--blueprints",
        default=str(
            root / "registry" / "candidate-blueprints-army-v1.json"
        ),
    )
    parser.add_argument(
        "--components",
        default=str(root / "registry" / "candidate-components-v1.json"),
    )
    parser.add_argument(
        "--candidates",
        default=str(
            root / "registry" / "candidate-implementations-v1.json"
        ),
    )
    parser.add_argument(
        "--suite",
        default=str(
            root / "examples" / "qualification" / "passive-osint-suite.json"
        ),
    )
    parser.add_argument(
        "--onboarding-output",
        default=str(
            root
            / "examples"
            / "qualification"
            / "passive-osint-onboarding.json"
        ),
    )
    parser.add_argument(
        "--submission-output",
        default=str(
            root
            / "examples"
            / "qualification"
            / "passive-osint-submission.json"
        ),
    )
    return parser


def build_submission(
    standard: Any,
    plans: Any,
    blueprints: Any,
    components: Any,
    candidates: Any,
    onboarding: CandidateOnboardingReport,
    suite: Any,
) -> dict[str, Any]:
    candidate = next(
        item
        for item in candidates.candidates
        if item.candidate_id == CANDIDATE_ID
        and item.candidate_version == CANDIDATE_VERSION
    )
    plan = plans.plans_by_profile_id[PROFILE_ID]
    blueprint = blueprints.blueprints_by_profile_id[PROFILE_ID]
    body = {
        "schema_version": 1,
        "submission_id": "fixture.passive-osint.evaluation-submission",
        "submission_version": "1.0.0",
        "submission_mode": "synthetic_contract_fixture",
        "advisory_only": True,
        "profile_id": PROFILE_ID,
        "candidate": {
            "candidate_id": candidate.candidate_id,
            "candidate_version": candidate.candidate_version,
            "candidate_artifact_sha256": (
                candidate.candidate_artifact_sha256
            ),
        },
        "candidate_blueprint_sha256": blueprint.blueprint_sha256,
        "candidate_component_catalog": {
            "id": components.component_catalog_id,
            "version": components.component_catalog_version,
            "sha256": components.canonical_sha256,
        },
        "candidate_onboarding_report": {
            "report_id": onboarding.report_id,
            "sha256": onboarding.report_sha256,
        },
        "qualification_suite": {
            "id": suite.suite_id,
            "version": suite.suite_version,
            "sha256": suite.canonical_sha256,
        },
        "requested_gate_ids": list(plan.required_gate_ids),
        "review_requirements": standard.decision_policy.to_dict(),
        "reviewer_assignment_state": "not_performed",
        "evidence_manifest_state": "not_provided",
    }
    return {
        **body,
        "submission_sha256": (
            compute_candidate_evaluation_submission_sha256(body)
        ),
    }


def _write_json(path: str, value: dict[str, Any]) -> Path:
    output = Path(path).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(value, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return output


def main() -> None:
    args = build_parser().parse_args()
    registry = load_registry(args.registry)
    capabilities = load_capability_catalog(args.capabilities, registry)
    standard = load_qualification_standard(
        args.standard, registry, capabilities
    )
    plans = load_qualification_plan_catalog(
        args.plans, registry, capabilities, standard
    )
    blueprints = load_candidate_blueprint_catalog(
        args.blueprints,
        registry,
        capabilities,
        standard,
        plans,
    )
    components = load_candidate_component_catalog(
        args.components, blueprints
    )
    candidates = load_candidate_implementation_catalog(
        args.candidates,
        registry,
        capabilities,
        standard,
        plans,
        blueprints,
    )
    onboarding = assess_candidate_onboarding(
        registry,
        capabilities,
        standard,
        plans,
        blueprints,
        components,
        candidates,
    )
    suite = load_qualification_evaluation_suite(
        args.suite,
        registry,
        capabilities,
        standard,
        plans,
    )
    submission = build_submission(
        standard,
        plans,
        blueprints,
        components,
        candidates,
        onboarding,
        suite,
    )
    onboarding_output = _write_json(
        args.onboarding_output, onboarding.to_dict()
    )
    submission_output = _write_json(args.submission_output, submission)
    print(f"Wrote onboarding fixture: {onboarding_output}")
    print(f"Wrote evaluation submission: {submission_output}")


if __name__ == "__main__":
    main()
