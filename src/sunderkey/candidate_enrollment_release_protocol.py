"""Controlled D011 release transaction orchestration."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

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
    CandidateEnrollmentReleaseLedgerEntry,
    build_candidate_enrollment_checkpoint_record,
    build_candidate_enrollment_release_ledger_entry,
)
from .candidate_enrollment_verification import CandidateEnrollmentCatalogCheckpoint
from .errors import QualificationError
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .qualification_trust import _clock_value, _format_timestamp

SCHEMA_VERSION = 1
PROMOTION_DOMAIN = "sunderkey.candidate-enrollment-catalog-promotion-receipt.v1"
COMPLETION_DOMAIN = "sunderkey.candidate-enrollment-release-completion-receipt.v1"
RELEASE_DOMAIN = "sunderkey.candidate-enrollment-controlled-release.v1"
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")


class CandidateEnrollmentReleaseLedger(Protocol):
    """Append-only ledger behavior required by the release protocol."""

    def tail(
        self, deployment_id: str
    ) -> CandidateEnrollmentReleaseLedgerEntry | None: ...

    def append(self, entry: CandidateEnrollmentReleaseLedgerEntry) -> None: ...

    def entries(
        self, deployment_id: str
    ) -> tuple[CandidateEnrollmentReleaseLedgerEntry, ...]: ...


class CandidateEnrollmentCatalogPromoter(Protocol):
    """Content-addressed catalog publication behavior required by the protocol."""

    def promote(
        self,
        *,
        deployment_id: str,
        release_id: str,
        catalog: CandidateEnrollmentCatalog,
        verification_receipt: CandidateEnrollmentDeploymentVerificationReceipt,
        promoted_at: str,
    ) -> CandidateEnrollmentCatalogPromotionReceipt: ...


class CandidateEnrollmentReleaseVerificationGate(Protocol):
    """Reverification boundary required before any release intent is appended."""

    def verify(
        self,
        receipt: CandidateEnrollmentDeploymentVerificationReceipt,
        catalog: CandidateEnrollmentCatalog,
    ) -> CandidateEnrollmentDeploymentVerificationReceipt: ...


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise QualificationError(f"{label} must be a canonical SHA-256 digest")
    return value


def _binding(raw: Any, label: str, id_field: str, pattern: str) -> dict[str, str]:
    value = _mapping(raw, label)
    _exact_fields(value, {id_field, "sha256"}, label)
    identifier = value.get(id_field)
    if not isinstance(identifier, str) or re.fullmatch(pattern, identifier) is None:
        raise QualificationError(f"{label}.{id_field} is invalid")
    return {
        id_field: identifier,
        "sha256": _sha256(value.get("sha256"), f"{label}.sha256"),
    }


def _catalog_checkpoint(raw: Any) -> CandidateEnrollmentCatalogCheckpoint:
    return CandidateEnrollmentCatalogCheckpoint.from_dict(raw)


@dataclass(frozen=True)
class CandidateEnrollmentCatalogPromotionReceipt:
    """Content-addressed result returned by a catalog repository adapter."""

    receipt_id: str
    receipt_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CandidateEnrollmentCatalogPromotionReceipt:
        value = _mapping(raw, "candidate enrollment catalog promotion receipt")
        fields = {
            "schema_version",
            "receipt_id",
            "receipt_sha256",
            "deployment_id",
            "release_id",
            "repository_id",
            "catalog_checkpoint",
            "verification_receipt",
            "content_address",
            "promotion_status",
            "promoted_at",
            "network_call_performed",
            "qualification_effect",
            "registry_effect",
        }
        _exact_fields(value, fields, "candidate enrollment catalog promotion receipt")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise QualificationError("Catalog promotion receipt schema is invalid")
        receipt_id = value.get("receipt_id")
        receipt_sha256 = value.get("receipt_sha256")
        if (
            not isinstance(receipt_id, str)
            or re.fullmatch(r"CPR-[0-9A-F]{32}", receipt_id) is None
            or not isinstance(receipt_sha256, str)
            or SHA256_PATTERN.fullmatch(receipt_sha256) is None
        ):
            raise QualificationError("Catalog promotion receipt identity is invalid")
        for field in ("deployment_id", "repository_id"):
            identifier = value.get(field)
            if (
                not isinstance(identifier, str)
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", identifier)
                is None
            ):
                raise QualificationError(f"Catalog promotion {field} is invalid")
        release_id = value.get("release_id")
        if not isinstance(release_id, str) or re.fullmatch(
            r"CRL-[0-9A-F]{32}", release_id
        ) is None:
            raise QualificationError("Catalog promotion release ID is invalid")
        checkpoint = _catalog_checkpoint(value.get("catalog_checkpoint"))
        _binding(
            value.get("verification_receipt"),
            "verification_receipt",
            "receipt_id",
            r"CVR-[0-9A-F]{32}",
        )
        if value.get("content_address") != checkpoint.catalog_sha256:
            raise QualificationError("Catalog promotion content address is invalid")
        if value.get("promotion_status") not in {
            "promoted",
            "already_promoted_same_digest",
        }:
            raise QualificationError("Catalog promotion status is invalid")
        promoted_at = value.get("promoted_at")
        if (
            not isinstance(promoted_at, str)
            or re.fullmatch(
                r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
                promoted_at,
            )
            is None
        ):
            raise QualificationError("Catalog promotion time is invalid")
        datetime.fromisoformat(promoted_at.removesuffix("Z") + "+00:00")
        if (
            not isinstance(value.get("network_call_performed"), bool)
            or value.get("qualification_effect") != "none"
            or value.get("registry_effect") != "none"
        ):
            raise QualificationError("Catalog promotion boundary is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"receipt_id", "receipt_sha256"}
        }
        expected_hash = _canonical_sha256(
            {"domain": PROMOTION_DOMAIN, "receipt": body}
        )
        expected_id = "CPR-" + expected_hash.removeprefix("sha256:")[:32].upper()
        if receipt_sha256 != expected_hash or receipt_id != expected_id:
            raise QualificationError("Catalog promotion receipt hash is invalid")
        return cls(receipt_id, receipt_sha256, _canonical_json(value))

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise QualificationError("Catalog promotion receipt is invalid")
        return value


@dataclass(frozen=True)
class CandidateEnrollmentReleaseCompletionReceipt:
    """Terminal proof of ordered checkpoint and catalog release completion."""

    receipt_id: str
    receipt_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CandidateEnrollmentReleaseCompletionReceipt:
        value = _mapping(raw, "candidate enrollment release completion receipt")
        fields = {
            "schema_version",
            "receipt_id",
            "receipt_sha256",
            "deployment_id",
            "release_id",
            "d011_decision",
            "verification_receipt",
            "catalog_checkpoint",
            "checkpoint_record",
            "checkpoint_commit_receipt",
            "catalog_promotion_receipt",
            "ledger_entries",
            "release_status",
            "readiness",
            "network_call_performed",
            "qualification_effect",
            "registry_effect",
        }
        _exact_fields(value, fields, "candidate enrollment release completion receipt")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise QualificationError("Release completion receipt schema is invalid")
        receipt_id = value.get("receipt_id")
        receipt_sha256 = value.get("receipt_sha256")
        if (
            not isinstance(receipt_id, str)
            or re.fullmatch(r"CRC-[0-9A-F]{32}", receipt_id) is None
            or not isinstance(receipt_sha256, str)
            or SHA256_PATTERN.fullmatch(receipt_sha256) is None
        ):
            raise QualificationError("Release completion receipt identity is invalid")
        deployment_id = value.get("deployment_id")
        release_id = value.get("release_id")
        if (
            not isinstance(deployment_id, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", deployment_id)
            is None
        ):
            raise QualificationError("Release completion deployment is invalid")
        if not isinstance(release_id, str) or re.fullmatch(
            r"CRL-[0-9A-F]{32}", release_id
        ) is None:
            raise QualificationError("Release completion release ID is invalid")
        _binding(value.get("d011_decision"), "d011_decision", "record_id", r"CAR-[0-9A-F]{32}")
        _binding(
            value.get("verification_receipt"),
            "verification_receipt",
            "receipt_id",
            r"CVR-[0-9A-F]{32}",
        )
        _catalog_checkpoint(value.get("catalog_checkpoint"))
        _binding(
            value.get("checkpoint_record"),
            "checkpoint_record",
            "checkpoint_id",
            r"CPC-[0-9A-F]{32}",
        )
        _binding(
            value.get("checkpoint_commit_receipt"),
            "checkpoint_commit_receipt",
            "receipt_id",
            r"CCR-[0-9A-F]{32}",
        )
        _binding(
            value.get("catalog_promotion_receipt"),
            "catalog_promotion_receipt",
            "receipt_id",
            r"CPR-[0-9A-F]{32}",
        )
        ledger = _mapping(value.get("ledger_entries"), "ledger_entries")
        _exact_fields(
            ledger,
            {"release_intent", "checkpoint_committed", "catalog_promoted", "release_completed"},
            "ledger_entries",
        )
        for name in ledger:
            _binding(ledger[name], f"ledger_entries.{name}", "entry_id", r"CLE-[0-9A-F]{32}")
        expected_readiness = {
            "controlled_catalog_release_complete": True,
            "ready_for_live_enrollment": False,
            "next_action": "prepare_single_candidate_canary_activation_packet",
        }
        if (
            value.get("release_status") != "completed"
            or value.get("readiness") != expected_readiness
            or not isinstance(value.get("network_call_performed"), bool)
            or value.get("qualification_effect") != "none"
            or value.get("registry_effect") != "none"
        ):
            raise QualificationError("Release completion boundary is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"receipt_id", "receipt_sha256"}
        }
        expected_hash = _canonical_sha256(
            {"domain": COMPLETION_DOMAIN, "receipt": body}
        )
        expected_id = "CRC-" + expected_hash.removeprefix("sha256:")[:32].upper()
        if receipt_sha256 != expected_hash or receipt_id != expected_id:
            raise QualificationError("Release completion receipt hash is invalid")
        return cls(receipt_id, receipt_sha256, _canonical_json(value))

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise QualificationError("Release completion receipt is invalid")
        return value


class InMemoryCandidateEnrollmentReleaseLedger:
    """Strict in-memory ledger adapter for tests and offline composition."""

    def __init__(self) -> None:
        self._entries: dict[str, list[CandidateEnrollmentReleaseLedgerEntry]] = {}

    def tail(self, deployment_id: str) -> CandidateEnrollmentReleaseLedgerEntry | None:
        entries = self._entries.get(deployment_id, [])
        return None if not entries else entries[-1]

    def append(self, entry: CandidateEnrollmentReleaseLedgerEntry) -> None:
        if not isinstance(entry, CandidateEnrollmentReleaseLedgerEntry):
            raise QualificationError("Release ledger entry is invalid")
        entry = CandidateEnrollmentReleaseLedgerEntry.from_dict(entry.to_dict())
        document = entry.to_dict()
        deployment_id = document["deployment_id"]
        entries = self._entries.setdefault(deployment_id, [])
        if entries and entries[-1] == entry:
            return
        expected_sequence = len(entries) + 1
        if document["ledger_sequence"] != expected_sequence:
            raise QualificationError("Release ledger append sequence is invalid")
        if not entries:
            if document["previous_entry"] is not None:
                raise QualificationError("Release ledger initial predecessor is invalid")
        else:
            previous = entries[-1]
            previous_document = previous.to_dict()
            expected = {
                "entry_id": previous.entry_id,
                "sha256": previous.entry_sha256,
                "ledger_sequence": previous_document["ledger_sequence"],
            }
            if document["previous_entry"] != expected:
                raise QualificationError("Release ledger predecessor does not match tail")
        entries.append(entry)

    def entries(self, deployment_id: str) -> tuple[CandidateEnrollmentReleaseLedgerEntry, ...]:
        return tuple(self._entries.get(deployment_id, []))


class InMemoryCandidateEnrollmentCatalogPromoter:
    """Content-addressed offline repository adapter used for contract testing."""

    def __init__(self, repository_id: str) -> None:
        if not isinstance(repository_id, str) or not repository_id:
            raise QualificationError("repository_id is invalid")
        self.repository_id = repository_id
        self._artifacts: dict[str, str] = {}
        self._receipts: dict[str, CandidateEnrollmentCatalogPromotionReceipt] = {}

    def promote(
        self,
        *,
        deployment_id: str,
        release_id: str,
        catalog: CandidateEnrollmentCatalog,
        verification_receipt: CandidateEnrollmentDeploymentVerificationReceipt,
        promoted_at: str,
    ) -> CandidateEnrollmentCatalogPromotionReceipt:
        catalog = CandidateEnrollmentCatalog.from_dict(catalog.to_dict())
        verification_receipt = CandidateEnrollmentDeploymentVerificationReceipt.from_dict(
            verification_receipt.to_dict()
        )
        checkpoint = CandidateEnrollmentCatalogCheckpoint.from_dict(
            verification_receipt.to_dict()["next_checkpoint"]
        )
        if (
            checkpoint.catalog_id != catalog.catalog_id
            or checkpoint.catalog_version != catalog.catalog_version
            or checkpoint.catalog_sha256 != catalog.content_sha256
        ):
            raise QualificationError("Promotion catalog differs from verified checkpoint")
        serialized = _canonical_json(catalog.to_dict())
        existing = self._artifacts.get(catalog.content_sha256)
        if existing is not None and existing != serialized:
            raise QualificationError("Content-addressed repository digest collision")
        status_value = "already_promoted_same_digest" if existing else "promoted"
        self._artifacts[catalog.content_sha256] = serialized
        body = {
            "schema_version": SCHEMA_VERSION,
            "deployment_id": deployment_id,
            "release_id": release_id,
            "repository_id": self.repository_id,
            "catalog_checkpoint": checkpoint.to_dict(),
            "verification_receipt": {
                "receipt_id": verification_receipt.receipt_id,
                "sha256": verification_receipt.receipt_sha256,
            },
            "content_address": catalog.content_sha256,
            "promotion_status": status_value,
            "promoted_at": promoted_at,
            "network_call_performed": False,
            "qualification_effect": "none",
            "registry_effect": "none",
        }
        digest = _canonical_sha256({"domain": PROMOTION_DOMAIN, "receipt": body})
        receipt = CandidateEnrollmentCatalogPromotionReceipt.from_dict(
            {
                **body,
                "receipt_id": "CPR-" + digest.removeprefix("sha256:")[:32].upper(),
                "receipt_sha256": digest,
            }
        )
        self._receipts[release_id] = receipt
        return receipt

    def receipt(self, release_id: str) -> CandidateEnrollmentCatalogPromotionReceipt:
        try:
            return self._receipts[release_id]
        except KeyError as exc:
            raise QualificationError("Catalog promotion receipt is unavailable") from exc


def derive_candidate_enrollment_release_id(
    deployment_id: str,
    decision: CandidateEnrollmentActivationDecisionRecord,
    receipt: CandidateEnrollmentDeploymentVerificationReceipt,
) -> str:
    material = {
        "deployment_id": deployment_id,
        "d011_decision": {
            "record_id": decision.record_id,
            "sha256": decision.record_sha256,
        },
        "verification_receipt": {
            "receipt_id": receipt.receipt_id,
            "sha256": receipt.receipt_sha256,
        },
    }
    digest = _canonical_sha256({"domain": RELEASE_DOMAIN, "release": material})
    return "CRL-" + digest.removeprefix("sha256:")[:32].upper()


def _append_verified(
    ledger: CandidateEnrollmentReleaseLedger,
    entry: CandidateEnrollmentReleaseLedgerEntry,
) -> None:
    ledger.append(entry)
    if ledger.tail(entry.to_dict()["deployment_id"]) != entry:
        raise QualificationError("Release ledger did not retain the appended entry")


def execute_candidate_enrollment_controlled_release(
    *,
    deployment_id: str,
    decision: CandidateEnrollmentActivationDecisionRecord,
    verification_receipt: CandidateEnrollmentDeploymentVerificationReceipt,
    catalog: CandidateEnrollmentCatalog,
    verification_gate: CandidateEnrollmentReleaseVerificationGate,
    initialization_approval_bindings: Sequence[Mapping[str, str]],
    checkpoint_store: AtomicCandidateEnrollmentCheckpointStore,
    release_ledger: CandidateEnrollmentReleaseLedger,
    catalog_promoter: CandidateEnrollmentCatalogPromoter,
    clock: Callable[[], datetime],
) -> CandidateEnrollmentReleaseCompletionReceipt:
    """Execute verify, intent, checkpoint, promote, and completion ordering."""

    decision = CandidateEnrollmentActivationDecisionRecord.from_dict(decision.to_dict())
    verification_receipt = CandidateEnrollmentDeploymentVerificationReceipt.from_dict(
        verification_receipt.to_dict()
    )
    catalog = CandidateEnrollmentCatalog.from_dict(catalog.to_dict())
    verify_method = getattr(verification_gate, "verify", None)
    if not callable(verify_method):
        raise QualificationError("Release verification gate is invalid")
    verified_receipt = verify_method(verification_receipt, catalog)
    if not isinstance(
        verified_receipt, CandidateEnrollmentDeploymentVerificationReceipt
    ):
        raise QualificationError("Release verification gate returned an invalid result")
    verified_receipt = CandidateEnrollmentDeploymentVerificationReceipt.from_dict(
        verified_receipt.to_dict()
    )
    if verified_receipt != verification_receipt:
        raise QualificationError("Release verification gate changed the receipt")
    checkpoint = CandidateEnrollmentCatalogCheckpoint.from_dict(
        verification_receipt.to_dict()["next_checkpoint"]
    )
    if (
        checkpoint.catalog_id != catalog.catalog_id
        or checkpoint.catalog_version != catalog.catalog_version
        or checkpoint.catalog_sha256 != catalog.content_sha256
    ):
        raise QualificationError("Release catalog differs from Phase 72 verification")
    current = checkpoint_store.load_for_release_initialization()
    tail = release_ledger.tail(deployment_id)
    if (current is None) != (tail is None):
        raise QualificationError("Checkpoint and release ledger initialization are ambiguous")
    if current is None:
        if len(catalog.enrollments) != 1:
            raise QualificationError("Initial activation must contain one candidate canary")
        authority_mode = "dual_control_initialization"
        approvals = [dict(item) for item in initialization_approval_bindings]
        checkpoint_sequence = 1
        ledger_sequence = 1
    else:
        if tail is None:
            raise QualificationError("Release ledger tail is missing")
        tail_document = tail.to_dict()
        if (
            tail_document["event_type"] != "release_completed"
            or tail_document["checkpoint_record"]
            != {
                "checkpoint_id": current.checkpoint_id,
                "sha256": current.checkpoint_sha256,
            }
        ):
            raise QualificationError("Prior release is not complete and unambiguous")
        authority_mode = "automatic_monotonic_advance"
        approvals = []
        checkpoint_sequence = current.to_dict()["checkpoint_sequence"] + 1
        ledger_sequence = tail_document["ledger_sequence"] + 1
    release_id = derive_candidate_enrollment_release_id(
        deployment_id, decision, verification_receipt
    )
    intent = build_candidate_enrollment_release_ledger_entry(
        deployment_id=deployment_id,
        ledger_sequence=ledger_sequence,
        previous_entry=tail,
        event_type="release_intent",
        release_id=release_id,
        decision=decision,
        verification_receipt=verification_receipt,
        catalog_checkpoint=checkpoint,
        checkpoint_record=None,
        event_artifact=None,
        authority_mode=authority_mode,
        approval_bindings=approvals,
        event_time=_format_timestamp(_clock_value(clock)),
    )
    _append_verified(release_ledger, intent)
    checkpoint_record = build_candidate_enrollment_checkpoint_record(
        deployment_id=deployment_id,
        checkpoint_sequence=checkpoint_sequence,
        release_id=release_id,
        catalog_checkpoint=checkpoint,
        verification_receipt=verification_receipt,
        release_intent=intent,
        predecessor_checkpoint=current,
        committed_at=_format_timestamp(_clock_value(clock)),
    )
    commit_receipt = checkpoint_store.commit(checkpoint_record, intent)
    checkpoint_entry = build_candidate_enrollment_release_ledger_entry(
        deployment_id=deployment_id,
        ledger_sequence=ledger_sequence + 1,
        previous_entry=intent,
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
        authority_mode=authority_mode,
        approval_bindings=approvals,
        event_time=_format_timestamp(_clock_value(clock)),
    )
    _append_verified(release_ledger, checkpoint_entry)
    promotion_receipt = catalog_promoter.promote(
        deployment_id=deployment_id,
        release_id=release_id,
        catalog=catalog,
        verification_receipt=verification_receipt,
        promoted_at=_format_timestamp(_clock_value(clock)),
    )
    promotion_receipt = CandidateEnrollmentCatalogPromotionReceipt.from_dict(
        promotion_receipt.to_dict()
    )
    promotion_document = promotion_receipt.to_dict()
    if (
        promotion_document["deployment_id"] != deployment_id
        or promotion_document["release_id"] != release_id
        or promotion_document["catalog_checkpoint"] != checkpoint.to_dict()
        or promotion_document["verification_receipt"]["receipt_id"]
        != verification_receipt.receipt_id
    ):
        raise QualificationError("Catalog promoter returned a mismatched receipt")
    promoted_entry = build_candidate_enrollment_release_ledger_entry(
        deployment_id=deployment_id,
        ledger_sequence=ledger_sequence + 2,
        previous_entry=checkpoint_entry,
        event_type="catalog_promoted",
        release_id=release_id,
        decision=decision,
        verification_receipt=verification_receipt,
        catalog_checkpoint=checkpoint,
        checkpoint_record=checkpoint_record,
        event_artifact={
            "artifact_kind": "catalog_promotion_receipt",
            "artifact_id": promotion_receipt.receipt_id,
            "sha256": promotion_receipt.receipt_sha256,
        },
        authority_mode=authority_mode,
        approval_bindings=approvals,
        event_time=_format_timestamp(_clock_value(clock)),
    )
    _append_verified(release_ledger, promoted_entry)
    completed_entry = build_candidate_enrollment_release_ledger_entry(
        deployment_id=deployment_id,
        ledger_sequence=ledger_sequence + 3,
        previous_entry=promoted_entry,
        event_type="release_completed",
        release_id=release_id,
        decision=decision,
        verification_receipt=verification_receipt,
        catalog_checkpoint=checkpoint,
        checkpoint_record=checkpoint_record,
        event_artifact={
            "artifact_kind": "catalog_promotion_receipt",
            "artifact_id": promotion_receipt.receipt_id,
            "sha256": promotion_receipt.receipt_sha256,
        },
        authority_mode=authority_mode,
        approval_bindings=approvals,
        event_time=_format_timestamp(_clock_value(clock)),
    )
    _append_verified(release_ledger, completed_entry)
    body = {
        "schema_version": SCHEMA_VERSION,
        "deployment_id": deployment_id,
        "release_id": release_id,
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
        "checkpoint_commit_receipt": {
            "receipt_id": commit_receipt.receipt_id,
            "sha256": commit_receipt.receipt_sha256,
        },
        "catalog_promotion_receipt": {
            "receipt_id": promotion_receipt.receipt_id,
            "sha256": promotion_receipt.receipt_sha256,
        },
        "ledger_entries": {
            "release_intent": {"entry_id": intent.entry_id, "sha256": intent.entry_sha256},
            "checkpoint_committed": {
                "entry_id": checkpoint_entry.entry_id,
                "sha256": checkpoint_entry.entry_sha256,
            },
            "catalog_promoted": {
                "entry_id": promoted_entry.entry_id,
                "sha256": promoted_entry.entry_sha256,
            },
            "release_completed": {
                "entry_id": completed_entry.entry_id,
                "sha256": completed_entry.entry_sha256,
            },
        },
        "release_status": "completed",
        "readiness": {
            "controlled_catalog_release_complete": True,
            "ready_for_live_enrollment": False,
            "next_action": "prepare_single_candidate_canary_activation_packet",
        },
        "network_call_performed": promotion_document["network_call_performed"],
        "qualification_effect": "none",
        "registry_effect": "none",
    }
    digest = _canonical_sha256({"domain": COMPLETION_DOMAIN, "receipt": body})
    return CandidateEnrollmentReleaseCompletionReceipt.from_dict(
        {
            **body,
            "receipt_id": "CRC-" + digest.removeprefix("sha256:")[:32].upper(),
            "receipt_sha256": digest,
        }
    )


__all__ = [
    "CandidateEnrollmentCatalogPromoter",
    "CandidateEnrollmentCatalogPromotionReceipt",
    "CandidateEnrollmentReleaseCompletionReceipt",
    "CandidateEnrollmentReleaseLedger",
    "CandidateEnrollmentReleaseVerificationGate",
    "InMemoryCandidateEnrollmentCatalogPromoter",
    "InMemoryCandidateEnrollmentReleaseLedger",
    "derive_candidate_enrollment_release_id",
    "execute_candidate_enrollment_controlled_release",
]
