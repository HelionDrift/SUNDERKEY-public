"""D011 checkpoint custody and append-only release ledger contracts."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .candidate_enrollment_activation_decision import (
    CandidateEnrollmentActivationDecisionRecord,
)
from .candidate_enrollment_deployment_verification import (
    CandidateEnrollmentDeploymentVerificationReceipt,
)
from .candidate_enrollment_verification import CandidateEnrollmentCatalogCheckpoint
from .errors import QualificationError
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .qualification_trust import _positive_integer
from .validation import loads_json_without_duplicate_keys

SCHEMA_VERSION = 1
POLICY_DOMAIN = "sunderkey.candidate-enrollment-release-policy.d011.v1"
CHECKPOINT_DOMAIN = "sunderkey.candidate-enrollment-checkpoint-record.v1"
LEDGER_DOMAIN = "sunderkey.candidate-enrollment-release-ledger-entry.v1"

SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
TIMESTAMP_PATTERN = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"
)
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")

EVENT_OUTCOMES = {
    "release_intent": "pending_checkpoint_commit",
    "checkpoint_committed": "pending_catalog_promotion",
    "catalog_promoted": "pending_release_completion",
    "release_completed": "completed",
    "release_failed": "failed_closed",
    "recovery_intent": "pending_recovery",
    "recovery_completed": "recovered",
}

AUTHORITY_APPROVAL_COUNTS = {
    "automatic_monotonic_advance": 0,
    "dual_control_initialization": 2,
    "dual_control_recovery": 2,
}

RELEASE_SEQUENCE = (
    "verify_catalog_and_phase72_receipt",
    "append_release_intent",
    "atomically_commit_local_checkpoint",
    "append_checkpoint_committed",
    "promote_content_addressed_catalog",
    "append_catalog_promoted",
    "append_release_completed",
)

FAIL_CLOSED_CONDITIONS = (
    "missing_checkpoint_after_initialization",
    "checkpoint_digest_mismatch",
    "checkpoint_version_decrease",
    "same_version_different_catalog_digest",
    "ledger_sequence_gap_or_fork",
    "ledger_digest_or_predecessor_mismatch",
    "receipt_binding_mismatch",
    "promotion_before_checkpoint_commit",
    "ambiguous_partial_release_state",
    "recovery_without_dual_control",
)

PROHIBITED_POLICY_EFFECTS = (
    "does_not_create_a_deployment_checkpoint_or_release_ledger",
    "does_not_write_or_promote_an_operational_catalog",
    "does_not_select_operational_paths_endpoints_or_credentials",
    "does_not_enroll_a_candidate_or_accept_evidence",
    "does_not_qualify_a_specialist_or_change_routing",
)


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise QualificationError(f"{label} must be a canonical SHA-256 digest")
    return value


def _identifier(value: Any, label: str, pattern: str | None = None) -> str:
    if not isinstance(value, str):
        raise QualificationError(f"{label} is invalid")
    expected = IDENTIFIER_PATTERN if pattern is None else re.compile(pattern)
    if expected.fullmatch(value) is None:
        raise QualificationError(f"{label} is invalid")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or TIMESTAMP_PATTERN.fullmatch(value) is None:
        raise QualificationError(f"{label} must be a canonical UTC timestamp")
    try:
        datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise QualificationError(f"{label} is not a valid timestamp") from exc
    return value


def _binding(raw: Any, label: str, id_field: str, pattern: str) -> dict[str, str]:
    value = _mapping(raw, label)
    _exact_fields(value, {id_field, "sha256"}, label)
    return {
        id_field: _identifier(value.get(id_field), f"{label}.{id_field}", pattern),
        "sha256": _sha256(value.get("sha256"), f"{label}.sha256"),
    }


def _sequenced_binding(
    raw: Any,
    label: str,
    id_field: str,
    pattern: str,
    sequence_field: str,
) -> dict[str, Any]:
    value = _mapping(raw, label)
    _exact_fields(value, {id_field, "sha256", sequence_field}, label)
    return {
        id_field: _identifier(value.get(id_field), f"{label}.{id_field}", pattern),
        "sha256": _sha256(value.get("sha256"), f"{label}.sha256"),
        sequence_field: _positive_integer(
            value.get(sequence_field), f"{label}.{sequence_field}", 2_147_483_647
        ),
    }


def _load_json(path: str | Path, label: str) -> Any:
    resolved = Path(path).resolve()
    try:
        return loads_json_without_duplicate_keys(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise QualificationError(f"Could not load {label}: {resolved}") from exc


@dataclass(frozen=True)
class CandidateEnrollmentReleasePolicy:
    """Content-addressed implementation contract derived from D011."""

    policy_id: str
    policy_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CandidateEnrollmentReleasePolicy:
        value = _mapping(raw, "candidate enrollment release policy")
        fields = {
            "schema_version",
            "policy_id",
            "policy_sha256",
            "d011_decision",
            "checkpoint_authority",
            "local_checkpoint_storage",
            "release_sequence",
            "authority_rules",
            "recovery_rules",
            "distribution",
            "initial_activation_scope",
            "retention",
            "fail_closed_conditions",
            "prohibited_effects",
            "implementation_effect",
            "qualification_effect",
            "registry_effect",
        }
        _exact_fields(value, fields, "candidate enrollment release policy")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise QualificationError("Candidate enrollment release policy schema is invalid")
        policy_id = _identifier(
            value.get("policy_id"), "policy_id", r"CRP-[0-9A-F]{32}"
        )
        policy_sha256 = _sha256(value.get("policy_sha256"), "policy_sha256")
        _binding(value.get("d011_decision"), "d011_decision", "record_id", r"CAR-[0-9A-F]{32}")
        expected = {
            "checkpoint_authority": "append_only_release_ledger_with_local_mirror",
            "local_checkpoint_storage": {
                "format": "canonical_json_versioned_file",
                "commit": "atomic_replace_after_fsync",
                "access": "deployment_service_identity_only",
                "backup": "previous_valid_checkpoint_preserved",
                "runtime_database_storage": False,
            },
            "release_sequence": list(RELEASE_SEQUENCE),
            "authority_rules": {
                "monotonic_advance": "automatic_after_complete_verification",
                "initialization": "deployment_owner_and_independent_control",
                "recovery": "deployment_owner_and_independent_control",
            },
            "recovery_rules": {
                "failure_mode": "fail_closed",
                "retry": "same_version_same_digest_only",
                "authority_source": "verified_append_only_release_ledger",
                "self_declared_current_catalog_trusted": False,
            },
            "distribution": "organization_content_addressed_artifact_repository",
            "initial_activation_scope": "single_candidate_canary",
            "retention": "deployment_lifetime_plus_audit_period",
            "fail_closed_conditions": list(FAIL_CLOSED_CONDITIONS),
            "prohibited_effects": list(PROHIBITED_POLICY_EFFECTS),
            "implementation_effect": "contracts_defined_no_operational_state",
            "qualification_effect": "none",
            "registry_effect": "none",
        }
        for field, expected_value in expected.items():
            if value.get(field) != expected_value:
                raise QualificationError(
                    f"Candidate enrollment release policy {field} is invalid"
                )
        body = {
            key: item
            for key, item in value.items()
            if key not in {"policy_id", "policy_sha256"}
        }
        expected_hash = _canonical_sha256({"domain": POLICY_DOMAIN, "policy": body})
        expected_id = "CRP-" + expected_hash.removeprefix("sha256:")[:32].upper()
        if policy_sha256 != expected_hash or policy_id != expected_id:
            raise QualificationError("Candidate enrollment release policy hash is invalid")
        return cls(policy_id, policy_sha256, _canonical_json(value))

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise QualificationError("Candidate enrollment release policy is invalid")
        return value


def build_candidate_enrollment_release_policy(
    decision: CandidateEnrollmentActivationDecisionRecord,
) -> CandidateEnrollmentReleasePolicy:
    """Derive the approved D011 record contracts without creating live state."""

    if not isinstance(decision, CandidateEnrollmentActivationDecisionRecord):
        raise QualificationError("decision must be an approved D011 decision record")
    decision = CandidateEnrollmentActivationDecisionRecord.from_dict(decision.to_dict())
    document = decision.to_dict()
    if (
        document["decision_status"] != "approved_operator_asserted_unsigned"
        or not document["recommendation_alignment"]["all_recommended_options_selected"]
    ):
        raise QualificationError("D011 decision does not authorize the release policy")
    body = {
        "schema_version": SCHEMA_VERSION,
        "d011_decision": {
            "record_id": decision.record_id,
            "sha256": decision.record_sha256,
        },
        "checkpoint_authority": "append_only_release_ledger_with_local_mirror",
        "local_checkpoint_storage": {
            "format": "canonical_json_versioned_file",
            "commit": "atomic_replace_after_fsync",
            "access": "deployment_service_identity_only",
            "backup": "previous_valid_checkpoint_preserved",
            "runtime_database_storage": False,
        },
        "release_sequence": list(RELEASE_SEQUENCE),
        "authority_rules": {
            "monotonic_advance": "automatic_after_complete_verification",
            "initialization": "deployment_owner_and_independent_control",
            "recovery": "deployment_owner_and_independent_control",
        },
        "recovery_rules": {
            "failure_mode": "fail_closed",
            "retry": "same_version_same_digest_only",
            "authority_source": "verified_append_only_release_ledger",
            "self_declared_current_catalog_trusted": False,
        },
        "distribution": "organization_content_addressed_artifact_repository",
        "initial_activation_scope": "single_candidate_canary",
        "retention": "deployment_lifetime_plus_audit_period",
        "fail_closed_conditions": list(FAIL_CLOSED_CONDITIONS),
        "prohibited_effects": list(PROHIBITED_POLICY_EFFECTS),
        "implementation_effect": "contracts_defined_no_operational_state",
        "qualification_effect": "none",
        "registry_effect": "none",
    }
    digest = _canonical_sha256({"domain": POLICY_DOMAIN, "policy": body})
    return CandidateEnrollmentReleasePolicy.from_dict(
        {
            **body,
            "policy_id": "CRP-" + digest.removeprefix("sha256:")[:32].upper(),
            "policy_sha256": digest,
        }
    )


def _approval_bindings(raw: Any, mode: str) -> list[dict[str, str]]:
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        raise QualificationError("authority.approval_bindings must be an array")
    approvals: list[dict[str, str]] = []
    for item in raw:
        value = _mapping(item, "authority approval")
        _exact_fields(value, {"approval_id", "sha256", "role"}, "authority approval")
        approvals.append(
            {
                "approval_id": _identifier(
                    value.get("approval_id"),
                    "authority approval.approval_id",
                    r"CRA-[0-9A-F]{32}",
                ),
                "sha256": _sha256(
                    value.get("sha256"), "authority approval.sha256"
                ),
                "role": str(value.get("role")),
            }
        )
    for item in approvals:
        if item["role"] not in {"deployment_owner", "independent_control"}:
            raise QualificationError("Release authority approval role is invalid")
    if len(approvals) != AUTHORITY_APPROVAL_COUNTS[mode]:
        raise QualificationError("Release authority approval count is invalid")
    if mode != "automatic_monotonic_advance" and {
        item["role"] for item in approvals
    } != {"deployment_owner", "independent_control"}:
        raise QualificationError("Release authority requires both dual-control roles")
    return approvals


def _event_artifact(
    raw: Any,
    expected_kind: str,
    identifier_pattern: str,
) -> dict[str, str]:
    value = _mapping(raw, "release event artifact")
    _exact_fields(
        value,
        {"artifact_kind", "artifact_id", "sha256"},
        "release event artifact",
    )
    if value.get("artifact_kind") != expected_kind:
        raise QualificationError("Release event artifact kind is invalid")
    return {
        "artifact_kind": expected_kind,
        "artifact_id": _identifier(
            value.get("artifact_id"),
            "release event artifact.artifact_id",
            identifier_pattern,
        ),
        "sha256": _sha256(value.get("sha256"), "release event artifact.sha256"),
    }


@dataclass(frozen=True)
class CandidateEnrollmentCheckpointRecord:
    """Content-addressed committed local mirror record."""

    checkpoint_id: str
    checkpoint_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CandidateEnrollmentCheckpointRecord:
        value = _mapping(raw, "candidate enrollment checkpoint record")
        fields = {
            "schema_version",
            "checkpoint_id",
            "checkpoint_sha256",
            "deployment_id",
            "checkpoint_sequence",
            "release_id",
            "catalog_checkpoint",
            "verification_receipt",
            "release_intent",
            "predecessor_checkpoint",
            "committed_at",
            "state",
            "custody_model",
            "contains_secret_material",
        }
        _exact_fields(value, fields, "candidate enrollment checkpoint record")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise QualificationError("Candidate enrollment checkpoint schema is invalid")
        checkpoint_id = _identifier(
            value.get("checkpoint_id"), "checkpoint_id", r"CPC-[0-9A-F]{32}"
        )
        checkpoint_sha256 = _sha256(
            value.get("checkpoint_sha256"), "checkpoint_sha256"
        )
        _identifier(value.get("deployment_id"), "deployment_id")
        sequence = _positive_integer(
            value.get("checkpoint_sequence"), "checkpoint_sequence", 2_147_483_647
        )
        _identifier(value.get("release_id"), "release_id", r"CRL-[0-9A-F]{32}")
        CandidateEnrollmentCatalogCheckpoint.from_dict(value.get("catalog_checkpoint"))
        _binding(
            value.get("verification_receipt"),
            "verification_receipt",
            "receipt_id",
            r"CVR-[0-9A-F]{32}",
        )
        _binding(
            value.get("release_intent"),
            "release_intent",
            "entry_id",
            r"CLE-[0-9A-F]{32}",
        )
        predecessor = value.get("predecessor_checkpoint")
        if sequence == 1:
            if predecessor is not None:
                raise QualificationError("Initial checkpoint cannot have a predecessor")
        else:
            binding = _sequenced_binding(
                predecessor,
                "predecessor_checkpoint",
                "checkpoint_id",
                r"CPC-[0-9A-F]{32}",
                "checkpoint_sequence",
            )
            if binding["checkpoint_sequence"] != sequence - 1:
                raise QualificationError("Checkpoint predecessor sequence is invalid")
        _timestamp(value.get("committed_at"), "committed_at")
        if (
            value.get("state") != "committed"
            or value.get("custody_model")
            != "atomic_versioned_file_with_protected_acl_and_backup"
            or value.get("contains_secret_material") is not False
        ):
            raise QualificationError("Candidate enrollment checkpoint boundary is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"checkpoint_id", "checkpoint_sha256"}
        }
        expected_hash = _canonical_sha256(
            {"domain": CHECKPOINT_DOMAIN, "checkpoint": body}
        )
        expected_id = "CPC-" + expected_hash.removeprefix("sha256:")[:32].upper()
        if checkpoint_sha256 != expected_hash or checkpoint_id != expected_id:
            raise QualificationError("Candidate enrollment checkpoint hash is invalid")
        return cls(checkpoint_id, checkpoint_sha256, _canonical_json(value))

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise QualificationError("Candidate enrollment checkpoint is invalid")
        return value


@dataclass(frozen=True)
class CandidateEnrollmentReleaseLedgerEntry:
    """One content-addressed append-only release ledger event."""

    entry_id: str
    entry_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CandidateEnrollmentReleaseLedgerEntry:
        value = _mapping(raw, "candidate enrollment release ledger entry")
        fields = {
            "schema_version",
            "entry_id",
            "entry_sha256",
            "deployment_id",
            "ledger_sequence",
            "previous_entry",
            "event_type",
            "release_id",
            "d011_decision",
            "verification_receipt",
            "catalog_checkpoint",
            "checkpoint_record",
            "event_artifact",
            "authority",
            "event_time",
            "outcome",
        }
        _exact_fields(value, fields, "candidate enrollment release ledger entry")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise QualificationError("Candidate enrollment release ledger schema is invalid")
        entry_id = _identifier(value.get("entry_id"), "entry_id", r"CLE-[0-9A-F]{32}")
        entry_sha256 = _sha256(value.get("entry_sha256"), "entry_sha256")
        _identifier(value.get("deployment_id"), "deployment_id")
        sequence = _positive_integer(
            value.get("ledger_sequence"), "ledger_sequence", 2_147_483_647
        )
        previous = value.get("previous_entry")
        if sequence == 1:
            if previous is not None:
                raise QualificationError("Initial ledger entry cannot have a predecessor")
        else:
            binding = _sequenced_binding(
                previous,
                "previous_entry",
                "entry_id",
                r"CLE-[0-9A-F]{32}",
                "ledger_sequence",
            )
            if binding["ledger_sequence"] != sequence - 1:
                raise QualificationError("Release ledger predecessor sequence is invalid")
        event_type = value.get("event_type")
        if event_type not in EVENT_OUTCOMES:
            raise QualificationError("Candidate enrollment release event type is invalid")
        _identifier(value.get("release_id"), "release_id", r"CRL-[0-9A-F]{32}")
        _binding(value.get("d011_decision"), "d011_decision", "record_id", r"CAR-[0-9A-F]{32}")
        _binding(
            value.get("verification_receipt"),
            "verification_receipt",
            "receipt_id",
            r"CVR-[0-9A-F]{32}",
        )
        CandidateEnrollmentCatalogCheckpoint.from_dict(value.get("catalog_checkpoint"))
        checkpoint = value.get("checkpoint_record")
        if event_type == "release_intent":
            if checkpoint is not None:
                raise QualificationError("Release intent cannot claim a committed checkpoint")
        elif event_type not in {"release_failed", "recovery_intent"}:
            _binding(
                checkpoint,
                "checkpoint_record",
                "checkpoint_id",
                r"CPC-[0-9A-F]{32}",
            )
        artifact = value.get("event_artifact")
        if event_type in {"release_intent", "recovery_intent"}:
            if artifact is not None:
                raise QualificationError(
                    "Release or recovery intent cannot bind an outcome artifact"
                )
        elif event_type == "checkpoint_committed":
            _event_artifact(artifact, "checkpoint_commit_receipt", r"CCR-[0-9A-F]{32}")
        elif event_type in {
            "catalog_promoted",
            "release_completed",
            "recovery_completed",
        }:
            _event_artifact(artifact, "catalog_promotion_receipt", r"CPR-[0-9A-F]{32}")
        authority = _mapping(value.get("authority"), "release authority")
        _exact_fields(authority, {"mode", "approval_bindings"}, "release authority")
        mode = authority.get("mode")
        if mode not in AUTHORITY_APPROVAL_COUNTS:
            raise QualificationError("Release authority mode is invalid")
        _approval_bindings(authority.get("approval_bindings"), str(mode))
        if event_type.startswith("recovery_") and mode != "dual_control_recovery":
            raise QualificationError("Recovery requires dual-control authority")
        if sequence == 1 and mode != "dual_control_initialization":
            raise QualificationError("Ledger initialization requires dual-control authority")
        _timestamp(value.get("event_time"), "event_time")
        if value.get("outcome") != EVENT_OUTCOMES[event_type]:
            raise QualificationError("Candidate enrollment release outcome is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"entry_id", "entry_sha256"}
        }
        expected_hash = _canonical_sha256({"domain": LEDGER_DOMAIN, "entry": body})
        expected_id = "CLE-" + expected_hash.removeprefix("sha256:")[:32].upper()
        if entry_sha256 != expected_hash or entry_id != expected_id:
            raise QualificationError("Candidate enrollment release ledger hash is invalid")
        return cls(entry_id, entry_sha256, _canonical_json(value))

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise QualificationError("Candidate enrollment release ledger entry is invalid")
        return value


def build_candidate_enrollment_release_ledger_entry(
    *,
    deployment_id: str,
    ledger_sequence: int,
    previous_entry: CandidateEnrollmentReleaseLedgerEntry | None,
    event_type: str,
    release_id: str,
    decision: CandidateEnrollmentActivationDecisionRecord,
    verification_receipt: CandidateEnrollmentDeploymentVerificationReceipt,
    catalog_checkpoint: CandidateEnrollmentCatalogCheckpoint,
    checkpoint_record: CandidateEnrollmentCheckpointRecord | None,
    event_artifact: Mapping[str, str] | None,
    authority_mode: str,
    approval_bindings: Sequence[Mapping[str, str]],
    event_time: str,
) -> CandidateEnrollmentReleaseLedgerEntry:
    """Construct one validated hash-chained ledger entry without persisting it."""

    if not isinstance(decision, CandidateEnrollmentActivationDecisionRecord):
        raise QualificationError("decision is invalid")
    decision = CandidateEnrollmentActivationDecisionRecord.from_dict(decision.to_dict())
    if not isinstance(
        verification_receipt, CandidateEnrollmentDeploymentVerificationReceipt
    ):
        raise QualificationError("verification_receipt is invalid")
    verification_receipt = CandidateEnrollmentDeploymentVerificationReceipt.from_dict(
        verification_receipt.to_dict()
    )
    if not isinstance(catalog_checkpoint, CandidateEnrollmentCatalogCheckpoint):
        raise QualificationError("catalog_checkpoint is invalid")
    catalog_checkpoint = CandidateEnrollmentCatalogCheckpoint.from_dict(
        catalog_checkpoint.to_dict()
    )
    receipt_document = verification_receipt.to_dict()
    if receipt_document["next_checkpoint"] != catalog_checkpoint.to_dict():
        raise QualificationError("Release checkpoint differs from verification receipt")
    sequence = _positive_integer(
        ledger_sequence, "ledger_sequence", 2_147_483_647
    )
    previous_binding: dict[str, Any] | None = None
    if previous_entry is not None:
        if not isinstance(previous_entry, CandidateEnrollmentReleaseLedgerEntry):
            raise QualificationError("previous_entry is invalid")
        previous_entry = CandidateEnrollmentReleaseLedgerEntry.from_dict(
            previous_entry.to_dict()
        )
        previous_document = previous_entry.to_dict()
        if previous_document["deployment_id"] != deployment_id:
            raise QualificationError("Release ledger deployment binding changed")
        previous_binding = {
            "entry_id": previous_entry.entry_id,
            "sha256": previous_entry.entry_sha256,
            "ledger_sequence": previous_document["ledger_sequence"],
        }
    checkpoint_binding: dict[str, str] | None = None
    if checkpoint_record is not None:
        if not isinstance(checkpoint_record, CandidateEnrollmentCheckpointRecord):
            raise QualificationError("checkpoint_record is invalid")
        checkpoint_record = CandidateEnrollmentCheckpointRecord.from_dict(
            checkpoint_record.to_dict()
        )
        checkpoint_document = checkpoint_record.to_dict()
        if (
            checkpoint_document["deployment_id"] != deployment_id
            or checkpoint_document["release_id"] != release_id
            or checkpoint_document["catalog_checkpoint"]
            != catalog_checkpoint.to_dict()
            or checkpoint_document["verification_receipt"]["receipt_id"]
            != verification_receipt.receipt_id
        ):
            raise QualificationError("Release ledger checkpoint binding is inconsistent")
        checkpoint_binding = {
            "checkpoint_id": checkpoint_record.checkpoint_id,
            "sha256": checkpoint_record.checkpoint_sha256,
        }
    body = {
        "schema_version": SCHEMA_VERSION,
        "deployment_id": deployment_id,
        "ledger_sequence": sequence,
        "previous_entry": previous_binding,
        "event_type": event_type,
        "release_id": release_id,
        "d011_decision": {
            "record_id": decision.record_id,
            "sha256": decision.record_sha256,
        },
        "verification_receipt": {
            "receipt_id": verification_receipt.receipt_id,
            "sha256": verification_receipt.receipt_sha256,
        },
        "catalog_checkpoint": catalog_checkpoint.to_dict(),
        "checkpoint_record": checkpoint_binding,
        "event_artifact": None if event_artifact is None else dict(event_artifact),
        "authority": {
            "mode": authority_mode,
            "approval_bindings": [dict(item) for item in approval_bindings],
        },
        "event_time": event_time,
        "outcome": EVENT_OUTCOMES.get(event_type),
    }
    digest = _canonical_sha256({"domain": LEDGER_DOMAIN, "entry": body})
    return CandidateEnrollmentReleaseLedgerEntry.from_dict(
        {
            **body,
            "entry_id": "CLE-" + digest.removeprefix("sha256:")[:32].upper(),
            "entry_sha256": digest,
        }
    )


def build_candidate_enrollment_checkpoint_record(
    *,
    deployment_id: str,
    checkpoint_sequence: int,
    release_id: str,
    catalog_checkpoint: CandidateEnrollmentCatalogCheckpoint,
    verification_receipt: CandidateEnrollmentDeploymentVerificationReceipt,
    release_intent: CandidateEnrollmentReleaseLedgerEntry,
    predecessor_checkpoint: CandidateEnrollmentCheckpointRecord | None,
    committed_at: str,
) -> CandidateEnrollmentCheckpointRecord:
    """Construct a validated committed mirror record without writing it."""

    if not isinstance(
        verification_receipt, CandidateEnrollmentDeploymentVerificationReceipt
    ):
        raise QualificationError("verification_receipt is invalid")
    verification_receipt = CandidateEnrollmentDeploymentVerificationReceipt.from_dict(
        verification_receipt.to_dict()
    )
    if not isinstance(catalog_checkpoint, CandidateEnrollmentCatalogCheckpoint):
        raise QualificationError("catalog_checkpoint is invalid")
    catalog_checkpoint = CandidateEnrollmentCatalogCheckpoint.from_dict(
        catalog_checkpoint.to_dict()
    )
    if verification_receipt.to_dict()["next_checkpoint"] != catalog_checkpoint.to_dict():
        raise QualificationError("Checkpoint differs from verification receipt")
    if not isinstance(release_intent, CandidateEnrollmentReleaseLedgerEntry):
        raise QualificationError("release_intent is invalid")
    release_intent = CandidateEnrollmentReleaseLedgerEntry.from_dict(
        release_intent.to_dict()
    )
    intent_document = release_intent.to_dict()
    if (
        intent_document["event_type"] != "release_intent"
        or intent_document["deployment_id"] != deployment_id
        or intent_document["release_id"] != release_id
        or intent_document["catalog_checkpoint"] != catalog_checkpoint.to_dict()
        or intent_document["verification_receipt"]["receipt_id"]
        != verification_receipt.receipt_id
    ):
        raise QualificationError("Checkpoint release intent binding is inconsistent")
    sequence = _positive_integer(
        checkpoint_sequence, "checkpoint_sequence", 2_147_483_647
    )
    predecessor_binding: dict[str, Any] | None = None
    if predecessor_checkpoint is not None:
        if not isinstance(predecessor_checkpoint, CandidateEnrollmentCheckpointRecord):
            raise QualificationError("predecessor_checkpoint is invalid")
        predecessor_checkpoint = CandidateEnrollmentCheckpointRecord.from_dict(
            predecessor_checkpoint.to_dict()
        )
        predecessor_document = predecessor_checkpoint.to_dict()
        if predecessor_document["deployment_id"] != deployment_id:
            raise QualificationError("Checkpoint deployment binding changed")
        previous_catalog = CandidateEnrollmentCatalogCheckpoint.from_dict(
            predecessor_document["catalog_checkpoint"]
        )
        if (
            previous_catalog.catalog_id != catalog_checkpoint.catalog_id
            or catalog_checkpoint.catalog_version
            != previous_catalog.catalog_version + 1
        ):
            raise QualificationError("Checkpoint catalog is not a monotonic advance")
        predecessor_binding = {
            "checkpoint_id": predecessor_checkpoint.checkpoint_id,
            "sha256": predecessor_checkpoint.checkpoint_sha256,
            "checkpoint_sequence": predecessor_document["checkpoint_sequence"],
        }
    body = {
        "schema_version": SCHEMA_VERSION,
        "deployment_id": deployment_id,
        "checkpoint_sequence": sequence,
        "release_id": release_id,
        "catalog_checkpoint": catalog_checkpoint.to_dict(),
        "verification_receipt": {
            "receipt_id": verification_receipt.receipt_id,
            "sha256": verification_receipt.receipt_sha256,
        },
        "release_intent": {
            "entry_id": release_intent.entry_id,
            "sha256": release_intent.entry_sha256,
        },
        "predecessor_checkpoint": predecessor_binding,
        "committed_at": committed_at,
        "state": "committed",
        "custody_model": "atomic_versioned_file_with_protected_acl_and_backup",
        "contains_secret_material": False,
    }
    digest = _canonical_sha256({"domain": CHECKPOINT_DOMAIN, "checkpoint": body})
    return CandidateEnrollmentCheckpointRecord.from_dict(
        {
            **body,
            "checkpoint_id": "CPC-" + digest.removeprefix("sha256:")[:32].upper(),
            "checkpoint_sha256": digest,
        }
    )


def load_candidate_enrollment_release_policy(
    path: str | Path,
) -> CandidateEnrollmentReleasePolicy:
    return CandidateEnrollmentReleasePolicy.from_dict(
        _load_json(path, "candidate enrollment release policy")
    )


def load_candidate_enrollment_checkpoint_record(
    path: str | Path,
) -> CandidateEnrollmentCheckpointRecord:
    return CandidateEnrollmentCheckpointRecord.from_dict(
        _load_json(path, "candidate enrollment checkpoint record")
    )


def load_candidate_enrollment_release_ledger_entry(
    path: str | Path,
) -> CandidateEnrollmentReleaseLedgerEntry:
    return CandidateEnrollmentReleaseLedgerEntry.from_dict(
        _load_json(path, "candidate enrollment release ledger entry")
    )


__all__ = [
    "CandidateEnrollmentCheckpointRecord",
    "CandidateEnrollmentReleaseLedgerEntry",
    "CandidateEnrollmentReleasePolicy",
    "build_candidate_enrollment_release_policy",
    "build_candidate_enrollment_checkpoint_record",
    "build_candidate_enrollment_release_ledger_entry",
    "load_candidate_enrollment_checkpoint_record",
    "load_candidate_enrollment_release_ledger_entry",
    "load_candidate_enrollment_release_policy",
]
