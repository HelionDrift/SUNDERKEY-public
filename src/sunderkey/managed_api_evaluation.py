"""Approved managed API architecture for specialist evaluation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import QualificationError
from .qualification import (
    _canonical_json,
    _canonical_sha256,
    _exact_fields,
    _mapping,
)
from .validation import loads_json_without_duplicate_keys

SCHEMA_VERSION = 1
DECISION_ID = "D010"
BOUNDARY_DOMAIN = "sunderkey.managed-api-evaluation-boundary.v1"
BOUNDARY_ID_PATTERN = re.compile(r"MAB-[0-9A-F]{32}")
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
PROFILE_ID = "AOE-GA-D01-S01"
CANDIDATE_ID = "development.passive-osint"
CANDIDATE_VERSION = "1.0.0"
SUITE_ID = "development.passive-osint.qualification"
SUITE_VERSION = "1.0.0"
SELECTED_ARCHITECTURE = "managed_model_api_isolated_evaluation_worker"

APPROVAL_BASIS = {
    "authority_role": "repository_owner",
    "approval_channel": "explicit_owner_decision",
    "recording_mechanism": "reviewed_versioned_repository_record",
}

DATA_BOUNDARY = {
    "allowed_data_classes": [
        "synthetic_evaluation_scenario",
        "reviewed_instruction_bundle",
    ],
    "target_data_allowed": False,
    "credential_data_allowed": False,
    "retrieval_allowed": False,
    "tool_calls_allowed": False,
    "unreviewed_context_allowed": False,
}

WORKER_BOUNDARY = {
    "process_isolation_required": True,
    "network_default": "deny",
    "provider_endpoint_allowlist": "unselected",
    "automatic_retries": 0,
    "maximum_parallel_requests": 1,
    "server_side_tools_allowed": False,
    "response_handling": "content_address_before_review",
    "raw_logging": "disabled",
}

RUNTIME_BINDING = {
    "provider_id": "unselected",
    "model_id": "unselected",
    "model_revision": "unselected",
    "api_protocol": "unselected",
    "hosting_region": "unselected",
    "retention_policy_id": "unselected",
    "credential_reference_id": "unselected",
}

MISSING_BINDINGS = (
    "provider_id",
    "model_id",
    "model_revision",
    "api_protocol",
    "hosting_region",
    "retention_policy_id",
    "credential_reference_id",
    "provider_endpoint_allowlist",
)

AUTHORIZED_NEXT_STEPS = (
    "select_exact_provider_model_and_revision",
    "review_region_and_retention_policy",
    "define_external_secret_reference",
    "define_provider_endpoint_allowlist",
    "implement_provider_adapter_behind_boundary",
    "run_synthetic_cases_after_independent_review",
)

PROHIBITED_EFFECTS = (
    "does_not_enable_network_access",
    "does_not_store_or_accept_api_credentials",
    "does_not_select_a_provider_model_endpoint_or_region",
    "does_not_enable_tools_retrieval_or_target_access",
    "does_not_run_the_candidate_or_evaluation_suite",
    "does_not_create_observations_results_or_evidence",
    "does_not_qualify_a_candidate_or_change_routing",
    "does_not_mutate_mission_work_or_sqlite_state",
)


def _require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise QualificationError(f"{label} must be a canonical SHA-256 digest")
    return value


def _require_exact(value: Any, expected: Any, label: str) -> Any:
    if value != expected:
        raise QualificationError(f"{label} does not match the approved contract")
    return value


def _require_exact_list(value: Any, expected: tuple[str, ...], label: str) -> None:
    if not isinstance(value, list) or tuple(value) != expected:
        raise QualificationError(f"{label} does not match the approved contract")


@dataclass(frozen=True)
class ManagedApiEvaluationBoundary:
    """Content-addressed D010 managed API architecture record."""

    boundary_id: str
    boundary_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> ManagedApiEvaluationBoundary:
        value = _mapping(raw, "managed API evaluation boundary")
        _exact_fields(
            value,
            {
                "schema_version",
                "boundary_id",
                "boundary_sha256",
                "decision_id",
                "decision_status",
                "decision_effect",
                "approval_basis",
                "selected_architecture",
                "candidate",
                "evaluation_suite",
                "data_boundary",
                "worker_boundary",
                "runtime_binding",
                "readiness",
                "authorized_next_steps",
                "prohibited_effects",
            },
            "managed API evaluation boundary",
        )
        if value.get("schema_version") != SCHEMA_VERSION:
            raise QualificationError("Managed API boundary schema version is invalid")
        boundary_id = value.get("boundary_id")
        if not isinstance(boundary_id, str) or BOUNDARY_ID_PATTERN.fullmatch(boundary_id) is None:
            raise QualificationError("Managed API boundary ID is invalid")
        boundary_sha256 = _require_sha256(value.get("boundary_sha256"), "boundary_sha256")
        _require_exact(value.get("decision_id"), DECISION_ID, "decision_id")
        _require_exact(value.get("decision_status"), "approved", "decision_status")
        _require_exact(
            value.get("decision_effect"),
            "contract_implementation_authorized",
            "decision_effect",
        )
        _require_exact(value.get("approval_basis"), APPROVAL_BASIS, "approval_basis")
        _require_exact(
            value.get("selected_architecture"),
            SELECTED_ARCHITECTURE,
            "selected_architecture",
        )
        cls._validate_candidate(value.get("candidate"))
        cls._validate_suite(value.get("evaluation_suite"), value.get("candidate"))
        _require_exact(value.get("data_boundary"), DATA_BOUNDARY, "data_boundary")
        _require_exact(value.get("worker_boundary"), WORKER_BOUNDARY, "worker_boundary")
        _require_exact(value.get("runtime_binding"), RUNTIME_BINDING, "runtime_binding")
        cls._validate_readiness(value.get("readiness"))
        _require_exact_list(
            value.get("authorized_next_steps"),
            AUTHORIZED_NEXT_STEPS,
            "authorized_next_steps",
        )
        _require_exact_list(
            value.get("prohibited_effects"),
            PROHIBITED_EFFECTS,
            "prohibited_effects",
        )
        body = {
            key: item
            for key, item in value.items()
            if key not in {"boundary_id", "boundary_sha256"}
        }
        expected_hash = _boundary_hash(body)
        if boundary_sha256 != expected_hash or boundary_id != _boundary_id(expected_hash):
            raise QualificationError("Managed API boundary hash is invalid")
        return cls(
            boundary_id=boundary_id,
            boundary_sha256=boundary_sha256,
            document_json=_canonical_json(value),
        )

    @staticmethod
    def _validate_candidate(raw: Any) -> None:
        value = _mapping(raw, "candidate")
        _exact_fields(
            value,
            {
                "candidate_id",
                "candidate_version",
                "candidate_artifact_sha256",
                "profile_id",
            },
            "candidate",
        )
        _require_exact(value.get("candidate_id"), CANDIDATE_ID, "candidate_id")
        _require_exact(value.get("candidate_version"), CANDIDATE_VERSION, "candidate_version")
        _require_exact(value.get("profile_id"), PROFILE_ID, "profile_id")
        _require_sha256(value.get("candidate_artifact_sha256"), "candidate_artifact_sha256")

    @staticmethod
    def _validate_suite(raw: Any, raw_candidate: Any) -> None:
        value = _mapping(raw, "evaluation_suite")
        _exact_fields(
            value,
            {
                "suite_id",
                "suite_version",
                "suite_sha256",
                "case_count",
                "candidate_artifact_sha256",
            },
            "evaluation_suite",
        )
        _require_exact(value.get("suite_id"), SUITE_ID, "suite_id")
        _require_exact(value.get("suite_version"), SUITE_VERSION, "suite_version")
        _require_sha256(value.get("suite_sha256"), "suite_sha256")
        _require_exact(value.get("case_count"), 29, "case_count")
        candidate = _mapping(raw_candidate, "candidate")
        if value.get("candidate_artifact_sha256") != candidate.get("candidate_artifact_sha256"):
            raise QualificationError("Evaluation suite candidate artifact binding is invalid")

    @staticmethod
    def _validate_readiness(raw: Any) -> None:
        value = _mapping(raw, "readiness")
        _exact_fields(
            value,
            {"status", "missing_bindings", "execution_enabled"},
            "readiness",
        )
        _require_exact(
            value.get("status"),
            "blocked_pending_exact_runtime_binding",
            "readiness.status",
        )
        _require_exact_list(
            value.get("missing_bindings"), MISSING_BINDINGS, "readiness.missing_bindings"
        )
        if value.get("execution_enabled") is not False:
            raise QualificationError("Managed API boundary execution must remain disabled")

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise QualificationError("Managed API evaluation boundary is invalid")
        return value


def build_managed_api_evaluation_boundary(
    candidate_catalog: dict[str, Any],
    evaluation_suite: dict[str, Any],
) -> ManagedApiEvaluationBoundary:
    """Record the selected architecture against the exact candidate and suite."""

    candidates = candidate_catalog.get("candidates")
    if not isinstance(candidates, list):
        raise QualificationError("Candidate catalog candidates must be a list")
    matches = [
        item
        for item in candidates
        if isinstance(item, dict) and item.get("candidate_id") == CANDIDATE_ID
    ]
    if len(matches) != 1:
        raise QualificationError("Passive OSINT candidate must exist exactly once")
    candidate = matches[0]
    candidate_binding = {
        "candidate_id": candidate.get("candidate_id"),
        "candidate_version": candidate.get("candidate_version"),
        "candidate_artifact_sha256": candidate.get("candidate_artifact_sha256"),
        "profile_id": candidate.get("profile_id"),
    }
    ManagedApiEvaluationBoundary._validate_candidate(candidate_binding)
    suite_candidate = _mapping(evaluation_suite.get("candidate"), "suite candidate")
    expected_suite_candidate = {
        key: candidate_binding[key]
        for key in (
            "candidate_id",
            "candidate_version",
            "candidate_artifact_sha256",
        )
    }
    if suite_candidate != expected_suite_candidate:
        raise QualificationError("Evaluation suite candidate binding is invalid")
    cases = evaluation_suite.get("cases")
    if not isinstance(cases, list) or len(cases) != 29:
        raise QualificationError("Evaluation suite must contain exactly 29 cases")
    suite_binding = {
        "suite_id": evaluation_suite.get("suite_id"),
        "suite_version": evaluation_suite.get("suite_version"),
        "suite_sha256": _canonical_sha256(evaluation_suite),
        "case_count": len(cases),
        "candidate_artifact_sha256": candidate_binding["candidate_artifact_sha256"],
    }
    body = {
        "schema_version": SCHEMA_VERSION,
        "decision_id": DECISION_ID,
        "decision_status": "approved",
        "decision_effect": "contract_implementation_authorized",
        "approval_basis": APPROVAL_BASIS,
        "selected_architecture": SELECTED_ARCHITECTURE,
        "candidate": candidate_binding,
        "evaluation_suite": suite_binding,
        "data_boundary": DATA_BOUNDARY,
        "worker_boundary": WORKER_BOUNDARY,
        "runtime_binding": RUNTIME_BINDING,
        "readiness": {
            "status": "blocked_pending_exact_runtime_binding",
            "missing_bindings": list(MISSING_BINDINGS),
            "execution_enabled": False,
        },
        "authorized_next_steps": list(AUTHORIZED_NEXT_STEPS),
        "prohibited_effects": list(PROHIBITED_EFFECTS),
    }
    boundary_hash = _boundary_hash(body)
    return ManagedApiEvaluationBoundary.from_dict(
        {
            **body,
            "boundary_id": _boundary_id(boundary_hash),
            "boundary_sha256": boundary_hash,
        }
    )


def load_managed_api_evaluation_boundary(
    path: str | Path,
) -> ManagedApiEvaluationBoundary:
    resolved = Path(path).resolve()
    try:
        raw = loads_json_without_duplicate_keys(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise QualificationError(
            f"Could not load managed API evaluation boundary: {resolved}"
        ) from exc
    return ManagedApiEvaluationBoundary.from_dict(raw)


def _boundary_hash(body: dict[str, Any]) -> str:
    return _canonical_sha256({"domain": BOUNDARY_DOMAIN, "boundary": body})


def _boundary_id(boundary_hash: str) -> str:
    return "MAB-" + boundary_hash.removeprefix("sha256:")[:32].upper()


__all__ = [
    "DECISION_ID",
    "MISSING_BINDINGS",
    "SELECTED_ARCHITECTURE",
    "ManagedApiEvaluationBoundary",
    "build_managed_api_evaluation_boundary",
    "load_managed_api_evaluation_boundary",
]
