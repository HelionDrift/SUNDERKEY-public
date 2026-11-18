"""Unsigned candidate evaluation submission and preflight contracts."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .candidate_blueprints import CandidateBlueprintCatalog
from .candidate_components import (
    CandidateComponentCatalog,
    CandidateOnboardingReport,
    assess_candidate_onboarding,
)
from .candidate_inventory import CandidateImplementationCatalog
from .errors import QualificationError
from .qualification import (
    QualificationDecisionPolicy,
    QualificationPlanCatalog,
    QualificationStandard,
    _boolean,
    _canonical_json,
    _canonical_sha256,
    _exact_fields,
    _list,
    _load_json,
    _mapping,
    _text,
)
from .qualification_evaluation import (
    QualificationCandidateBinding,
    QualificationEvaluationSuite,
)
from .registry import ExpertRegistry
from .routing import CapabilityCatalog

SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
SUBMISSION_ID_PATTERN = re.compile(r"[a-z0-9]+(?:[.-][a-z0-9]+)*")
REPORT_ID_PATTERN = re.compile(r"PFR-[0-9A-F]{32}")
ONBOARDING_REPORT_ID_PATTERN = re.compile(r"ONR-[0-9A-F]{32}")
SUBMISSION_DOMAIN = "sunderkey.candidate-evaluation-submission.v1"
REPORT_DOMAIN = "sunderkey.candidate-evaluation-preflight-report.v1"
REPORT_SCHEMA_VERSION = 1


def _sha256(value: Any, label: str) -> str:
    digest = _text(value, label)
    if SHA256_PATTERN.fullmatch(digest) is None:
        raise QualificationError(f"{label} must be a SHA-256 digest")
    return digest


def _text_tuple(value: Any, label: str) -> tuple[str, ...]:
    result = tuple(
        _text(item, f"{label}[{index}]")
        for index, item in enumerate(_list(value, label))
    )
    if not result:
        raise QualificationError(f"{label} must not be empty")
    if len(result) != len(set(result)):
        raise QualificationError(f"{label} contains duplicate values")
    return result


def _artifact_binding(
    raw: Any,
    label: str,
    *,
    id_field: str = "id",
    include_version: bool = True,
    report_id: bool = False,
) -> dict[str, str]:
    value = _mapping(raw, label)
    required = {id_field, "sha256"}
    if include_version:
        required.add("version")
    _exact_fields(value, required, label)
    artifact_id = _text(value.get(id_field), f"{label}.{id_field}")
    if report_id and ONBOARDING_REPORT_ID_PATTERN.fullmatch(artifact_id) is None:
        raise QualificationError(f"{label}.{id_field} is invalid")
    result = {
        id_field: artifact_id,
        "sha256": _sha256(value.get("sha256"), f"{label}.sha256"),
    }
    if include_version:
        result["version"] = _text(
            value.get("version"), f"{label}.version"
        )
    return result


def compute_candidate_evaluation_submission_sha256(
    submission_body: dict[str, Any],
) -> str:
    """Compute the content identity of one closed submission body."""

    return _canonical_sha256(
        {
            "domain": SUBMISSION_DOMAIN,
            "submission": submission_body,
        }
    )


@dataclass(frozen=True)
class CandidateEvaluationSubmission:
    submission_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CandidateEvaluationSubmission:
        value = _mapping(raw, "candidate evaluation submission")
        _exact_fields(
            value,
            {
                "schema_version",
                "submission_id",
                "submission_version",
                "submission_mode",
                "advisory_only",
                "profile_id",
                "candidate",
                "candidate_blueprint_sha256",
                "candidate_component_catalog",
                "candidate_onboarding_report",
                "qualification_suite",
                "requested_gate_ids",
                "review_requirements",
                "reviewer_assignment_state",
                "evidence_manifest_state",
                "submission_sha256",
            },
            "candidate evaluation submission",
        )
        if value.get("schema_version") != 1:
            raise QualificationError(
                "Candidate evaluation submission schema_version must be 1"
            )
        submission_id = _text(value.get("submission_id"), "submission_id")
        if SUBMISSION_ID_PATTERN.fullmatch(submission_id) is None:
            raise QualificationError(
                "Candidate evaluation submission ID is invalid"
            )
        submission_mode = _text(
            value.get("submission_mode"), "submission_mode"
        )
        if submission_mode != "synthetic_contract_fixture":
            raise QualificationError(
                "Candidate evaluation submission mode must be "
                "synthetic_contract_fixture"
            )
        advisory_only = _boolean(
            value.get("advisory_only"), "advisory_only"
        )
        if not advisory_only:
            raise QualificationError(
                "Candidate evaluation submission must be advisory_only"
            )
        reviewer_state = _text(
            value.get("reviewer_assignment_state"),
            "reviewer_assignment_state",
        )
        if reviewer_state != "not_performed":
            raise QualificationError(
                "Candidate evaluation reviewer assignment state must be "
                "not_performed"
            )
        evidence_state = _text(
            value.get("evidence_manifest_state"),
            "evidence_manifest_state",
        )
        if evidence_state != "not_provided":
            raise QualificationError(
                "Candidate evaluation evidence manifest state must be "
                "not_provided"
            )
        body = {
            "schema_version": 1,
            "submission_id": submission_id,
            "submission_version": _text(
                value.get("submission_version"), "submission_version"
            ),
            "submission_mode": submission_mode,
            "advisory_only": advisory_only,
            "profile_id": _text(value.get("profile_id"), "profile_id"),
            "candidate": QualificationCandidateBinding.from_dict(
                value.get("candidate")
            ).to_dict(),
            "candidate_blueprint_sha256": _sha256(
                value.get("candidate_blueprint_sha256"),
                "candidate_blueprint_sha256",
            ),
            "candidate_component_catalog": _artifact_binding(
                value.get("candidate_component_catalog"),
                "candidate_component_catalog",
            ),
            "candidate_onboarding_report": _artifact_binding(
                value.get("candidate_onboarding_report"),
                "candidate_onboarding_report",
                id_field="report_id",
                include_version=False,
                report_id=True,
            ),
            "qualification_suite": _artifact_binding(
                value.get("qualification_suite"),
                "qualification_suite",
            ),
            "requested_gate_ids": list(
                _text_tuple(
                    value.get("requested_gate_ids"),
                    "requested_gate_ids",
                )
            ),
            "review_requirements": QualificationDecisionPolicy.from_dict(
                value.get("review_requirements")
            ).to_dict(),
            "reviewer_assignment_state": reviewer_state,
            "evidence_manifest_state": evidence_state,
        }
        submission_sha256 = _sha256(
            value.get("submission_sha256"), "submission_sha256"
        )
        if submission_sha256 != compute_candidate_evaluation_submission_sha256(
            body
        ):
            raise QualificationError(
                "Candidate evaluation submission hash is invalid"
            )
        return cls(
            submission_sha256=submission_sha256,
            document_json=_canonical_json(
                {**body, "submission_sha256": submission_sha256}
            ),
        )

    def revalidated(self) -> CandidateEvaluationSubmission:
        try:
            raw = self.to_dict()
        except (AttributeError, TypeError, ValueError) as exc:
            raise QualificationError(
                "Invalid directly constructed candidate evaluation "
                "submission"
            ) from exc
        return CandidateEvaluationSubmission.from_dict(raw)

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise QualificationError(
                "Candidate evaluation submission document is invalid"
            )
        return value


@dataclass(frozen=True)
class CandidateEvaluationPreflightReport:
    report_id: str
    report_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CandidateEvaluationPreflightReport:
        value = _mapping(raw, "candidate evaluation preflight report")
        _exact_fields(
            value,
            {
                "schema_version",
                "report_id",
                "report_sha256",
                "status",
                "preflight_effect",
                "authoritative_evaluation_eligible",
                "registry",
                "capability_catalog",
                "qualification_standard",
                "qualification_plan_catalog",
                "candidate_blueprint_catalog",
                "candidate_component_catalog",
                "candidate_catalog",
                "candidate_onboarding_report",
                "qualification_suite",
                "submission",
                "candidate",
                "summary",
                "checks",
                "authoritative_evaluation_blockers",
                "limitations",
            },
            "candidate evaluation preflight report",
        )
        if value.get("schema_version") != REPORT_SCHEMA_VERSION:
            raise QualificationError(
                "Candidate evaluation preflight report schema version is "
                "invalid"
            )
        report_id = value.get("report_id")
        report_sha256 = value.get("report_sha256")
        if (
            not isinstance(report_id, str)
            or REPORT_ID_PATTERN.fullmatch(report_id) is None
            or not isinstance(report_sha256, str)
        ):
            raise QualificationError(
                "Candidate evaluation preflight report identity is invalid"
            )
        body = {
            key: item
            for key, item in value.items()
            if key not in {"report_id", "report_sha256"}
        }
        expected_hash = _canonical_sha256(
            {"domain": REPORT_DOMAIN, "report": body}
        )
        expected_id = (
            "PFR-" + expected_hash.removeprefix("sha256:")[:32].upper()
        )
        if report_sha256 != expected_hash or report_id != expected_id:
            raise QualificationError(
                "Candidate evaluation preflight report hash is invalid"
            )
        return cls(
            report_id=report_id,
            report_sha256=report_sha256,
            document_json=_canonical_json(value),
        )

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise QualificationError(
                "Candidate evaluation preflight report document is invalid"
            )
        return value


def _require_exact_binding(
    actual: Any,
    expected: dict[str, Any],
    label: str,
) -> None:
    if actual != expected:
        raise QualificationError(f"{label} binding is invalid")


def assess_candidate_evaluation_preflight(
    registry: ExpertRegistry,
    capability_catalog: CapabilityCatalog,
    standard: QualificationStandard,
    plans: QualificationPlanCatalog,
    blueprints: CandidateBlueprintCatalog,
    components: CandidateComponentCatalog,
    candidates: CandidateImplementationCatalog,
    onboarding: CandidateOnboardingReport,
    suite: QualificationEvaluationSuite,
    submission: CandidateEvaluationSubmission,
) -> CandidateEvaluationPreflightReport:
    """Validate one unsigned fixture submission without evaluating it."""

    if not isinstance(registry, ExpertRegistry):
        raise QualificationError("registry must be an ExpertRegistry")
    if not isinstance(capability_catalog, CapabilityCatalog):
        raise QualificationError(
            "capability_catalog must be a CapabilityCatalog"
        )
    if not isinstance(standard, QualificationStandard):
        raise QualificationError("standard must be a QualificationStandard")
    if not isinstance(plans, QualificationPlanCatalog):
        raise QualificationError("plans must be a QualificationPlanCatalog")
    if not isinstance(blueprints, CandidateBlueprintCatalog):
        raise QualificationError(
            "blueprints must be a CandidateBlueprintCatalog"
        )
    if not isinstance(components, CandidateComponentCatalog):
        raise QualificationError(
            "components must be a CandidateComponentCatalog"
        )
    if not isinstance(candidates, CandidateImplementationCatalog):
        raise QualificationError(
            "candidates must be a CandidateImplementationCatalog"
        )
    if not isinstance(onboarding, CandidateOnboardingReport):
        raise QualificationError(
            "onboarding must be a CandidateOnboardingReport"
        )
    if not isinstance(suite, QualificationEvaluationSuite):
        raise QualificationError(
            "suite must be a QualificationEvaluationSuite"
        )
    if not isinstance(submission, CandidateEvaluationSubmission):
        raise QualificationError(
            "submission must be a CandidateEvaluationSubmission"
        )
    registry.validate()
    capability_catalog = capability_catalog.revalidated(registry)
    standard = standard.revalidated(registry, capability_catalog)
    plans = plans.revalidated(registry, capability_catalog, standard)
    blueprints = blueprints.revalidated(
        registry, capability_catalog, standard, plans
    )
    components = components.revalidated(blueprints)
    candidates = candidates.revalidated(
        registry, capability_catalog, standard, plans, blueprints
    )
    expected_onboarding = assess_candidate_onboarding(
        registry,
        capability_catalog,
        standard,
        plans,
        blueprints,
        components,
        candidates,
    )
    onboarding = CandidateOnboardingReport.from_dict(onboarding.to_dict())
    if onboarding != expected_onboarding:
        raise QualificationError(
            "Candidate onboarding report does not match current artifacts"
        )
    suite = suite.revalidated(
        registry, capability_catalog, standard, plans
    )
    submission = submission.revalidated()
    document = submission.to_dict()
    candidate_binding = document["candidate"]
    candidate = next(
        (
            item
            for item in candidates.candidates
            if item.candidate_id == candidate_binding["candidate_id"]
            and item.candidate_version
            == candidate_binding["candidate_version"]
        ),
        None,
    )
    if candidate is None:
        raise QualificationError(
            "Candidate evaluation submission candidate is not catalogued"
        )
    if candidate.lifecycle != "contract_fixture":
        raise QualificationError(
            "Synthetic contract fixture submission requires a fixture "
            "candidate"
        )
    _require_exact_binding(
        candidate_binding,
        {
            "candidate_id": candidate.candidate_id,
            "candidate_version": candidate.candidate_version,
            "candidate_artifact_sha256": (
                candidate.candidate_artifact_sha256
            ),
        },
        "Candidate evaluation candidate",
    )
    if (
        document["profile_id"] != candidate.profile_id
        or document["candidate_blueprint_sha256"]
        != candidate.candidate_blueprint_sha256
    ):
        raise QualificationError(
            "Candidate evaluation profile or blueprint binding is invalid"
        )
    _require_exact_binding(
        document["candidate_component_catalog"],
        {
            "id": components.component_catalog_id,
            "version": components.component_catalog_version,
            "sha256": components.canonical_sha256,
        },
        "Candidate component catalog",
    )
    _require_exact_binding(
        document["candidate_onboarding_report"],
        {
            "report_id": onboarding.report_id,
            "sha256": onboarding.report_sha256,
        },
        "Candidate onboarding report",
    )
    _require_exact_binding(
        document["qualification_suite"],
        {
            "id": suite.suite_id,
            "version": suite.suite_version,
            "sha256": suite.canonical_sha256,
        },
        "Qualification suite",
    )
    if (
        suite.profile_id != candidate.profile_id
        or suite.candidate.to_dict() != candidate_binding
    ):
        raise QualificationError(
            "Qualification suite candidate binding is invalid"
        )
    plan = plans.plans_by_profile_id[candidate.profile_id]
    if tuple(document["requested_gate_ids"]) != plan.required_gate_ids:
        raise QualificationError(
            "Candidate evaluation requested gate binding is invalid"
        )
    if document["review_requirements"] != standard.decision_policy.to_dict():
        raise QualificationError(
            "Candidate evaluation review requirements are invalid"
        )
    onboarding_candidate = next(
        item
        for item in onboarding.to_dict()["candidates"]
        if item["candidate_id"] == candidate.candidate_id
        and item["candidate_version"] == candidate.candidate_version
    )
    if not onboarding_candidate["component_binding_complete"]:
        raise QualificationError(
            "Candidate evaluation component binding is incomplete"
        )
    checks = [
        {"check_id": "submission-content-identity", "status": "passed"},
        {"check_id": "candidate-artifact-binding", "status": "passed"},
        {"check_id": "component-onboarding-binding", "status": "passed"},
        {"check_id": "synthetic-suite-binding", "status": "passed"},
        {"check_id": "qualification-gate-coverage", "status": "passed"},
        {"check_id": "review-requirements-binding", "status": "passed"},
    ]
    blockers = [
        "candidate_is_contract_fixture",
        "submission_is_unsigned",
        "reviewer_assignments_not_performed",
        "signed_evidence_manifest_not_provided",
        "qualification_suite_is_advisory_only",
        "qualification_decision_authority_pending_d008",
    ]
    body = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "status": "synthetic_fixture_preflight_complete",
        "preflight_effect": "none",
        "authoritative_evaluation_eligible": False,
        "registry": {
            "id": registry.catalog_id,
            "version": registry.catalog_version,
            "sha256": _canonical_sha256(registry.to_dict()),
        },
        "capability_catalog": {
            "id": capability_catalog.catalog_id,
            "version": capability_catalog.catalog_version,
            "sha256": capability_catalog.canonical_sha256,
        },
        "qualification_standard": {
            "id": standard.standard_id,
            "version": standard.standard_version,
            "sha256": standard.canonical_sha256,
        },
        "qualification_plan_catalog": {
            "id": plans.plan_catalog_id,
            "version": plans.plan_catalog_version,
            "sha256": plans.canonical_sha256,
        },
        "candidate_blueprint_catalog": {
            "id": blueprints.blueprint_catalog_id,
            "version": blueprints.blueprint_catalog_version,
            "sha256": blueprints.canonical_sha256,
        },
        "candidate_component_catalog": {
            "id": components.component_catalog_id,
            "version": components.component_catalog_version,
            "sha256": components.canonical_sha256,
        },
        "candidate_catalog": {
            "id": candidates.candidate_catalog_id,
            "version": candidates.candidate_catalog_version,
            "sha256": candidates.canonical_sha256,
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
        "submission": {
            "id": document["submission_id"],
            "version": document["submission_version"],
            "sha256": submission.submission_sha256,
        },
        "candidate": candidate_binding,
        "summary": {
            "requested_gate_count": len(document["requested_gate_ids"]),
            "suite_case_count": len(suite.cases),
            "component_artifact_count": len(
                onboarding_candidate["components"]
            ),
            "preflight_check_count": len(checks),
            "passed_preflight_check_count": len(checks),
            "authoritative_evaluation_blocker_count": len(blockers),
        },
        "checks": checks,
        "authoritative_evaluation_blockers": blockers,
        "limitations": [
            "Preflight completion proves contract consistency, not "
            "candidate competence or deployment.",
            "The submission and onboarding report are unsigned local "
            "fixture artifacts.",
            "No evaluator, Control reviewer, or Assurance reviewer has "
            "been assigned or performed review.",
            "This report cannot qualify a candidate or change registry or "
            "routing status.",
        ],
    }
    report_sha256 = _canonical_sha256(
        {"domain": REPORT_DOMAIN, "report": body}
    )
    document_out = {
        **body,
        "report_id": (
            "PFR-" + report_sha256.removeprefix("sha256:")[:32].upper()
        ),
        "report_sha256": report_sha256,
    }
    return CandidateEvaluationPreflightReport.from_dict(document_out)


def load_candidate_evaluation_submission(
    path: str | Path,
) -> CandidateEvaluationSubmission:
    return CandidateEvaluationSubmission.from_dict(
        _load_json(path, "candidate evaluation submission")
    )


def load_candidate_onboarding_report(
    path: str | Path,
) -> CandidateOnboardingReport:
    return CandidateOnboardingReport.from_dict(
        _load_json(path, "candidate onboarding report")
    )
