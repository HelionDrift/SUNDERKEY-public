"""Fail-closed recovery for interrupted D011 catalog releases."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .candidate_enrollment import CandidateEnrollmentCatalog
from .candidate_enrollment_activation_decision import (
    CandidateEnrollmentActivationDecisionRecord,
)
from .candidate_enrollment_checkpoint_store import (
    AtomicCandidateEnrollmentCheckpointStore,
)
from .candidate_enrollment_deployment_verification import (
    CandidateEnrollmentDeploymentVerificationReceipt,
)
from .candidate_enrollment_release_contract import (
    CandidateEnrollmentCheckpointRecord,
    CandidateEnrollmentReleaseLedgerEntry,
    build_candidate_enrollment_checkpoint_record,
    build_candidate_enrollment_release_ledger_entry,
)
from .candidate_enrollment_release_protocol import (
    CandidateEnrollmentCatalogPromoter,
    CandidateEnrollmentCatalogPromotionReceipt,
    CandidateEnrollmentReleaseLedger,
    CandidateEnrollmentReleaseVerificationGate,
    _append_verified,
    derive_candidate_enrollment_release_id,
)
from .candidate_enrollment_verification import CandidateEnrollmentCatalogCheckpoint
from .errors import QualificationError
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .qualification_trust import _clock_value, _format_timestamp

SCHEMA_VERSION = 1
ASSESSMENT_DOMAIN = "sunderkey.candidate-enrollment-release-recovery-assessment.v1"
RECOVERY_DOMAIN = "sunderkey.candidate-enrollment-release-recovery-receipt.v1"
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")

RECOVERABLE_STATES = {
    "intent_recorded_checkpoint_not_committed",
    "checkpoint_committed_ledger_not_updated",
    "checkpoint_committed_promotion_not_recorded",
    "promotion_recorded_completion_not_recorded",
    "recovery_intent_recorded_resume_required",
}


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise QualificationError(f"{label} must be a canonical SHA-256 digest")
    return value


def _binding(raw: Any, label: str, id_field: str, pattern: str) -> dict[str, str]:
    value = _mapping(raw, label)
    _exact_fields(value, {id_field, "sha256"}, label)
    identifier = value.get(id_field)
    if not isinstance(identifier, str) or re.fullmatch(pattern, identifier) is None:
        raise QualificationError(f"{label} is invalid")
    return {
        id_field: identifier,
        "sha256": _sha256(value.get("sha256"), f"{label}.sha256"),
    }


def _validate_chain(
    deployment_id: str,
    entries: Sequence[CandidateEnrollmentReleaseLedgerEntry],
) -> tuple[CandidateEnrollmentReleaseLedgerEntry, ...]:
    verified: list[CandidateEnrollmentReleaseLedgerEntry] = []
    for index, entry in enumerate(entries, start=1):
        if not isinstance(entry, CandidateEnrollmentReleaseLedgerEntry):
            raise QualificationError("Release recovery ledger contains an invalid entry")
        entry = CandidateEnrollmentReleaseLedgerEntry.from_dict(entry.to_dict())
        document = entry.to_dict()
        if document["deployment_id"] != deployment_id:
            raise QualificationError("Release recovery ledger deployment changed")
        if document["ledger_sequence"] != index:
            raise QualificationError("Release recovery ledger sequence has a gap")
        if index == 1:
            if document["previous_entry"] is not None:
                raise QualificationError("Release recovery ledger root is invalid")
        else:
            previous = verified[-1]
            expected = {
                "entry_id": previous.entry_id,
                "sha256": previous.entry_sha256,
                "ledger_sequence": index - 1,
            }
            if document["previous_entry"] != expected:
                raise QualificationError("Release recovery ledger chain is invalid")
        verified.append(entry)
    return tuple(verified)


@dataclass(frozen=True)
class CandidateEnrollmentReleaseRecoveryAssessment:
    """Content-addressed classification of one release and checkpoint state."""

    assessment_id: str
    assessment_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CandidateEnrollmentReleaseRecoveryAssessment:
        value = _mapping(raw, "candidate enrollment release recovery assessment")
        fields = {
            "schema_version",
            "assessment_id",
            "assessment_sha256",
            "deployment_id",
            "release_state",
            "checkpoint_status",
            "ledger_tail",
            "recovery_eligible",
            "required_authority",
            "permitted_action",
            "live_enrollment_allowed",
            "assessment_effect",
            "qualification_effect",
            "registry_effect",
        }
        _exact_fields(value, fields, "candidate enrollment release recovery assessment")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise QualificationError("Release recovery assessment schema is invalid")
        assessment_id = value.get("assessment_id")
        digest = value.get("assessment_sha256")
        if (
            not isinstance(assessment_id, str)
            or re.fullmatch(r"RRA-[0-9A-F]{32}", assessment_id) is None
            or not isinstance(digest, str)
            or SHA256_PATTERN.fullmatch(digest) is None
        ):
            raise QualificationError("Release recovery assessment identity is invalid")
        state = value.get("release_state")
        deployment_id = value.get("deployment_id")
        if (
            not isinstance(deployment_id, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", deployment_id)
            is None
        ):
            raise QualificationError("Release recovery deployment is invalid")
        if state not in RECOVERABLE_STATES | {
            "uninitialized",
            "release_complete",
            "ambiguous_fail_closed",
        }:
            raise QualificationError("Release recovery assessment state is invalid")
        eligible = state in RECOVERABLE_STATES
        if (
            value.get("recovery_eligible") is not eligible
            or value.get("required_authority")
            != ("deployment_owner_and_independent_control" if eligible else "none")
            or value.get("permitted_action")
            != ("same_digest_recovery_only" if eligible else "none")
            or value.get("live_enrollment_allowed") is not False
            or value.get("assessment_effect") != "none"
            or value.get("qualification_effect") != "none"
            or value.get("registry_effect") != "none"
        ):
            raise QualificationError("Release recovery assessment boundary is invalid")
        checkpoint_status = value.get("checkpoint_status")
        if checkpoint_status not in {"absent", "committed", "unavailable_fail_closed"}:
            raise QualificationError("Release recovery checkpoint status is invalid")
        tail = value.get("ledger_tail")
        if tail is not None:
            _binding(tail, "ledger_tail", "entry_id", r"CLE-[0-9A-F]{32}")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"assessment_id", "assessment_sha256"}
        }
        expected_hash = _canonical_sha256(
            {"domain": ASSESSMENT_DOMAIN, "assessment": body}
        )
        expected_id = "RRA-" + expected_hash.removeprefix("sha256:")[:32].upper()
        if digest != expected_hash or assessment_id != expected_id:
            raise QualificationError("Release recovery assessment hash is invalid")
        return cls(assessment_id, digest, _canonical_json(value))

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise QualificationError("Release recovery assessment is invalid")
        return value


def assess_candidate_enrollment_release_recovery(
    deployment_id: str,
    checkpoint_store: AtomicCandidateEnrollmentCheckpointStore,
    release_ledger: CandidateEnrollmentReleaseLedger,
) -> CandidateEnrollmentReleaseRecoveryAssessment:
    """Classify durable state without changing checkpoint or ledger data."""

    entries = _validate_chain(deployment_id, release_ledger.entries(deployment_id))
    try:
        checkpoint = checkpoint_store.load_for_release_initialization()
        checkpoint_status = "absent" if checkpoint is None else "committed"
    except QualificationError:
        checkpoint = None
        checkpoint_status = "unavailable_fail_closed"
    tail = None if not entries else entries[-1]
    if checkpoint_status == "unavailable_fail_closed":
        state = "ambiguous_fail_closed"
    elif tail is None and checkpoint is None:
        state = "uninitialized"
    elif tail is None:
        state = "ambiguous_fail_closed"
    elif checkpoint is None and not all(
        item.to_dict()["event_type"] in {"release_intent", "recovery_intent"}
        and item.to_dict()["release_id"] == entries[0].to_dict()["release_id"]
        for item in entries
    ):
        state = "ambiguous_fail_closed"
    else:
        tail_document = tail.to_dict()
        event_type = tail_document["event_type"]
        checkpoint_matches = checkpoint is not None and tail_document[
            "checkpoint_record"
        ] == {
            "checkpoint_id": checkpoint.checkpoint_id,
            "sha256": checkpoint.checkpoint_sha256,
        }
        intent_checkpoint_matches = checkpoint is not None and (
            checkpoint.to_dict()["release_id"] == tail_document["release_id"]
            and checkpoint.to_dict()["catalog_checkpoint"]
            == tail_document["catalog_checkpoint"]
        )
        if event_type == "release_intent" and checkpoint is None:
            state = "intent_recorded_checkpoint_not_committed"
        elif event_type == "release_intent" and intent_checkpoint_matches:
            state = "checkpoint_committed_ledger_not_updated"
        elif event_type == "checkpoint_committed" and checkpoint_matches:
            state = "checkpoint_committed_promotion_not_recorded"
        elif event_type == "catalog_promoted" and checkpoint_matches:
            state = "promotion_recorded_completion_not_recorded"
        elif event_type == "recovery_intent" and (
            checkpoint is None or intent_checkpoint_matches
        ):
            state = "recovery_intent_recorded_resume_required"
        elif event_type == "release_completed" and checkpoint_matches:
            state = "release_complete"
        else:
            state = "ambiguous_fail_closed"
    body = {
        "schema_version": SCHEMA_VERSION,
        "deployment_id": deployment_id,
        "release_state": state,
        "checkpoint_status": checkpoint_status,
        "ledger_tail": (
            None
            if tail is None
            else {"entry_id": tail.entry_id, "sha256": tail.entry_sha256}
        ),
        "recovery_eligible": state in RECOVERABLE_STATES,
        "required_authority": (
            "deployment_owner_and_independent_control"
            if state in RECOVERABLE_STATES
            else "none"
        ),
        "permitted_action": (
            "same_digest_recovery_only" if state in RECOVERABLE_STATES else "none"
        ),
        "live_enrollment_allowed": False,
        "assessment_effect": "none",
        "qualification_effect": "none",
        "registry_effect": "none",
    }
    digest = _canonical_sha256({"domain": ASSESSMENT_DOMAIN, "assessment": body})
    return CandidateEnrollmentReleaseRecoveryAssessment.from_dict(
        {
            **body,
            "assessment_id": "RRA-" + digest.removeprefix("sha256:")[:32].upper(),
            "assessment_sha256": digest,
        }
    )


@dataclass(frozen=True)
class CandidateEnrollmentReleaseRecoveryReceipt:
    """Terminal content-addressed proof of a same-digest recovery."""

    receipt_id: str
    receipt_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CandidateEnrollmentReleaseRecoveryReceipt:
        value = _mapping(raw, "candidate enrollment release recovery receipt")
        fields = {
            "schema_version",
            "receipt_id",
            "receipt_sha256",
            "deployment_id",
            "release_id",
            "source_assessment",
            "d011_decision",
            "verification_receipt",
            "catalog_checkpoint",
            "checkpoint_record",
            "catalog_promotion_receipt",
            "recovery_entries",
            "recovery_status",
            "readiness",
            "network_call_performed",
            "qualification_effect",
            "registry_effect",
        }
        _exact_fields(value, fields, "candidate enrollment release recovery receipt")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise QualificationError("Release recovery receipt schema is invalid")
        receipt_id = value.get("receipt_id")
        digest = value.get("receipt_sha256")
        if (
            not isinstance(receipt_id, str)
            or re.fullmatch(r"RRR-[0-9A-F]{32}", receipt_id) is None
            or not isinstance(digest, str)
            or SHA256_PATTERN.fullmatch(digest) is None
        ):
            raise QualificationError("Release recovery receipt identity is invalid")
        deployment_id = value.get("deployment_id")
        release_id = value.get("release_id")
        if (
            not isinstance(deployment_id, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", deployment_id)
            is None
            or not isinstance(release_id, str)
            or re.fullmatch(r"CRL-[0-9A-F]{32}", release_id) is None
        ):
            raise QualificationError("Release recovery scope is invalid")
        for field, id_field, pattern in (
            ("source_assessment", "assessment_id", r"RRA-[0-9A-F]{32}"),
            ("d011_decision", "record_id", r"CAR-[0-9A-F]{32}"),
            ("verification_receipt", "receipt_id", r"CVR-[0-9A-F]{32}"),
            ("checkpoint_record", "checkpoint_id", r"CPC-[0-9A-F]{32}"),
            ("catalog_promotion_receipt", "receipt_id", r"CPR-[0-9A-F]{32}"),
        ):
            _binding(value.get(field), field, id_field, pattern)
        CandidateEnrollmentCatalogCheckpoint.from_dict(value.get("catalog_checkpoint"))
        entries = _mapping(value.get("recovery_entries"), "recovery_entries")
        _exact_fields(
            entries,
            {
                "recovery_intent",
                "checkpoint_committed",
                "catalog_promoted",
                "recovery_completed",
                "release_completed",
            },
            "recovery_entries",
        )
        for name in entries:
            _binding(entries[name], f"recovery_entries.{name}", "entry_id", r"CLE-[0-9A-F]{32}")
        if (
            value.get("recovery_status") != "completed_same_digest"
            or value.get("readiness")
            != {
                "controlled_catalog_release_complete": True,
                "ready_for_live_enrollment": False,
                "next_action": "prepare_single_candidate_canary_activation_packet",
            }
            or not isinstance(value.get("network_call_performed"), bool)
            or value.get("qualification_effect") != "none"
            or value.get("registry_effect") != "none"
        ):
            raise QualificationError("Release recovery receipt boundary is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"receipt_id", "receipt_sha256"}
        }
        expected_hash = _canonical_sha256({"domain": RECOVERY_DOMAIN, "receipt": body})
        expected_id = "RRR-" + expected_hash.removeprefix("sha256:")[:32].upper()
        if digest != expected_hash or receipt_id != expected_id:
            raise QualificationError("Release recovery receipt hash is invalid")
        return cls(receipt_id, digest, _canonical_json(value))

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise QualificationError("Release recovery receipt is invalid")
        return value


def _original_intent(
    entries: Sequence[CandidateEnrollmentReleaseLedgerEntry],
    release_id: str,
) -> CandidateEnrollmentReleaseLedgerEntry:
    matches = [
        entry
        for entry in entries
        if entry.to_dict()["release_id"] == release_id
        and entry.to_dict()["event_type"] == "release_intent"
    ]
    if len(matches) != 1:
        raise QualificationError("Recovery requires one exact original release intent")
    return matches[0]


def recover_candidate_enrollment_controlled_release(
    *,
    deployment_id: str,
    assessment: CandidateEnrollmentReleaseRecoveryAssessment,
    decision: CandidateEnrollmentActivationDecisionRecord,
    verification_receipt: CandidateEnrollmentDeploymentVerificationReceipt,
    catalog: CandidateEnrollmentCatalog,
    verification_gate: CandidateEnrollmentReleaseVerificationGate,
    recovery_approval_bindings: Sequence[Mapping[str, str]],
    checkpoint_store: AtomicCandidateEnrollmentCheckpointStore,
    release_ledger: CandidateEnrollmentReleaseLedger,
    catalog_promoter: CandidateEnrollmentCatalogPromoter,
    clock: Callable[[], datetime],
) -> CandidateEnrollmentReleaseRecoveryReceipt:
    """Resume one eligible exact release under fresh dual-control authority."""

    assessment = CandidateEnrollmentReleaseRecoveryAssessment.from_dict(
        assessment.to_dict()
    )
    current_assessment = assess_candidate_enrollment_release_recovery(
        deployment_id, checkpoint_store, release_ledger
    )
    if assessment != current_assessment:
        raise QualificationError("Release recovery assessment is stale")
    if assessment.to_dict()["release_state"] not in RECOVERABLE_STATES:
        raise QualificationError("Release state is not eligible for automatic recovery")
    decision = CandidateEnrollmentActivationDecisionRecord.from_dict(decision.to_dict())
    verification_receipt = CandidateEnrollmentDeploymentVerificationReceipt.from_dict(
        verification_receipt.to_dict()
    )
    catalog = CandidateEnrollmentCatalog.from_dict(catalog.to_dict())
    verify_method = getattr(verification_gate, "verify", None)
    if not callable(verify_method):
        raise QualificationError("Release recovery verification gate is invalid")
    verified_receipt = verify_method(verification_receipt, catalog)
    if not isinstance(
        verified_receipt, CandidateEnrollmentDeploymentVerificationReceipt
    ):
        raise QualificationError("Release recovery gate returned an invalid result")
    verified_receipt = CandidateEnrollmentDeploymentVerificationReceipt.from_dict(
        verified_receipt.to_dict()
    )
    if verified_receipt != verification_receipt:
        raise QualificationError("Release recovery reverification failed")
    checkpoint = CandidateEnrollmentCatalogCheckpoint.from_dict(
        verification_receipt.to_dict()["next_checkpoint"]
    )
    if (
        checkpoint.catalog_id != catalog.catalog_id
        or checkpoint.catalog_version != catalog.catalog_version
        or checkpoint.catalog_sha256 != catalog.content_sha256
    ):
        raise QualificationError("Recovery catalog differs from verified receipt")
    release_id = derive_candidate_enrollment_release_id(
        deployment_id, decision, verification_receipt
    )
    entries = list(
        _validate_chain(deployment_id, release_ledger.entries(deployment_id))
    )
    intent = _original_intent(entries, release_id)
    intent_index = entries.index(intent)
    release_entries = entries[intent_index:]
    tail = entries[-1]
    tail_document = tail.to_dict()
    if any(item.to_dict()["release_id"] != release_id for item in release_entries):
        raise QualificationError("Recovery ledger contains another release")
    approvals = [dict(item) for item in recovery_approval_bindings]
    recovery_intent = build_candidate_enrollment_release_ledger_entry(
        deployment_id=deployment_id,
        ledger_sequence=tail_document["ledger_sequence"] + 1,
        previous_entry=tail,
        event_type="recovery_intent",
        release_id=release_id,
        decision=decision,
        verification_receipt=verification_receipt,
        catalog_checkpoint=checkpoint,
        checkpoint_record=None,
        event_artifact=None,
        authority_mode="dual_control_recovery",
        approval_bindings=approvals,
        event_time=_format_timestamp(_clock_value(clock)),
    )
    _append_verified(release_ledger, recovery_intent)
    current = checkpoint_store.load_for_release_initialization()
    if current is None:
        if any(
            item.to_dict()["event_type"] not in {"release_intent", "recovery_intent"}
            for item in release_entries
        ):
            raise QualificationError(
                "Missing established checkpoint requires external ledger restoration"
            )
        checkpoint_record = build_candidate_enrollment_checkpoint_record(
            deployment_id=deployment_id,
            checkpoint_sequence=1,
            release_id=release_id,
            catalog_checkpoint=checkpoint,
            verification_receipt=verification_receipt,
            release_intent=intent,
            predecessor_checkpoint=None,
            committed_at=_format_timestamp(_clock_value(clock)),
        )
    else:
        checkpoint_record = CandidateEnrollmentCheckpointRecord.from_dict(
            current.to_dict()
        )
        if (
            checkpoint_record.to_dict()["release_id"] != release_id
            or checkpoint_record.to_dict()["catalog_checkpoint"]
            != checkpoint.to_dict()
        ):
            raise QualificationError("Recovery checkpoint differs from exact release")
    commit_receipt = checkpoint_store.commit(checkpoint_record, intent)
    checkpoint_entry = build_candidate_enrollment_release_ledger_entry(
        deployment_id=deployment_id,
        ledger_sequence=recovery_intent.to_dict()["ledger_sequence"] + 1,
        previous_entry=recovery_intent,
        event_type="checkpoint_committed",
        release_id=release_id,
        decision=decision,
        verification_receipt=verification_receipt,
        catalog_checkpoint=checkpoint,
        checkpoint_record=checkpoint_record,
        event_artifact={
            "artifact_kind": "checkpoint_commit_receipt",
            "artifact_id": commit_receipt.receipt_id,
            "sha256": commit_receipt.receipt_sha256,
        },
        authority_mode="dual_control_recovery",
        approval_bindings=approvals,
        event_time=_format_timestamp(_clock_value(clock)),
    )
    _append_verified(release_ledger, checkpoint_entry)
    promotion = catalog_promoter.promote(
        deployment_id=deployment_id,
        release_id=release_id,
        catalog=catalog,
        verification_receipt=verification_receipt,
        promoted_at=_format_timestamp(_clock_value(clock)),
    )
    promotion = CandidateEnrollmentCatalogPromotionReceipt.from_dict(
        promotion.to_dict()
    )
    promotion_document = promotion.to_dict()
    if (
        promotion_document["deployment_id"] != deployment_id
        or promotion_document["release_id"] != release_id
        or promotion_document["catalog_checkpoint"] != checkpoint.to_dict()
        or promotion_document["verification_receipt"]["receipt_id"]
        != verification_receipt.receipt_id
    ):
        raise QualificationError("Recovery promoter returned a mismatched receipt")
    artifact = {
        "artifact_kind": "catalog_promotion_receipt",
        "artifact_id": promotion.receipt_id,
        "sha256": promotion.receipt_sha256,
    }
    promoted_entry = build_candidate_enrollment_release_ledger_entry(
        deployment_id=deployment_id,
        ledger_sequence=checkpoint_entry.to_dict()["ledger_sequence"] + 1,
        previous_entry=checkpoint_entry,
        event_type="catalog_promoted",
        release_id=release_id,
        decision=decision,
        verification_receipt=verification_receipt,
        catalog_checkpoint=checkpoint,
        checkpoint_record=checkpoint_record,
        event_artifact=artifact,
        authority_mode="dual_control_recovery",
        approval_bindings=approvals,
        event_time=_format_timestamp(_clock_value(clock)),
    )
    _append_verified(release_ledger, promoted_entry)
    recovered_entry = build_candidate_enrollment_release_ledger_entry(
        deployment_id=deployment_id,
        ledger_sequence=promoted_entry.to_dict()["ledger_sequence"] + 1,
        previous_entry=promoted_entry,
        event_type="recovery_completed",
        release_id=release_id,
        decision=decision,
        verification_receipt=verification_receipt,
        catalog_checkpoint=checkpoint,
        checkpoint_record=checkpoint_record,
        event_artifact=artifact,
        authority_mode="dual_control_recovery",
        approval_bindings=approvals,
        event_time=_format_timestamp(_clock_value(clock)),
    )
    _append_verified(release_ledger, recovered_entry)
    completed_entry = build_candidate_enrollment_release_ledger_entry(
        deployment_id=deployment_id,
        ledger_sequence=recovered_entry.to_dict()["ledger_sequence"] + 1,
        previous_entry=recovered_entry,
        event_type="release_completed",
        release_id=release_id,
        decision=decision,
        verification_receipt=verification_receipt,
        catalog_checkpoint=checkpoint,
        checkpoint_record=checkpoint_record,
        event_artifact=artifact,
        authority_mode="dual_control_recovery",
        approval_bindings=approvals,
        event_time=_format_timestamp(_clock_value(clock)),
    )
    _append_verified(release_ledger, completed_entry)
    body = {
        "schema_version": SCHEMA_VERSION,
        "deployment_id": deployment_id,
        "release_id": release_id,
        "source_assessment": {
            "assessment_id": assessment.assessment_id,
            "sha256": assessment.assessment_sha256,
        },
        "d011_decision": {
            "record_id": decision.record_id,
            "sha256": decision.record_sha256,
        },
        "verification_receipt": {
            "receipt_id": verification_receipt.receipt_id,
            "sha256": verification_receipt.receipt_sha256,
        },
        "catalog_checkpoint": checkpoint.to_dict(),
        "checkpoint_record": {
            "checkpoint_id": checkpoint_record.checkpoint_id,
            "sha256": checkpoint_record.checkpoint_sha256,
        },
        "catalog_promotion_receipt": {
            "receipt_id": promotion.receipt_id,
            "sha256": promotion.receipt_sha256,
        },
        "recovery_entries": {
            "recovery_intent": {
                "entry_id": recovery_intent.entry_id,
                "sha256": recovery_intent.entry_sha256,
            },
            "checkpoint_committed": {
                "entry_id": checkpoint_entry.entry_id,
                "sha256": checkpoint_entry.entry_sha256,
            },
            "catalog_promoted": {
                "entry_id": promoted_entry.entry_id,
                "sha256": promoted_entry.entry_sha256,
            },
            "recovery_completed": {
                "entry_id": recovered_entry.entry_id,
                "sha256": recovered_entry.entry_sha256,
            },
            "release_completed": {
                "entry_id": completed_entry.entry_id,
                "sha256": completed_entry.entry_sha256,
            },
        },
        "recovery_status": "completed_same_digest",
        "readiness": {
            "controlled_catalog_release_complete": True,
            "ready_for_live_enrollment": False,
            "next_action": "prepare_single_candidate_canary_activation_packet",
        },
        "network_call_performed": promotion_document["network_call_performed"],
        "qualification_effect": "none",
        "registry_effect": "none",
    }
    digest = _canonical_sha256({"domain": RECOVERY_DOMAIN, "receipt": body})
    return CandidateEnrollmentReleaseRecoveryReceipt.from_dict(
        {
            **body,
            "receipt_id": "RRR-" + digest.removeprefix("sha256:")[:32].upper(),
            "receipt_sha256": digest,
        }
    )


__all__ = [
    "CandidateEnrollmentReleaseRecoveryAssessment",
    "CandidateEnrollmentReleaseRecoveryReceipt",
    "assess_candidate_enrollment_release_recovery",
    "recover_candidate_enrollment_controlled_release",
]
