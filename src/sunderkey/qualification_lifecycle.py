"""Signed qualification status lifecycle contracts."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from .errors import QualificationError
from .identity import (
    _decode_base64url,
    _identifier,
    _strict_ed25519_public_key,
    _timestamp,
    _verify_ed25519,
)
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .qualification_decisions import VerifiedQualificationDecision
from .qualification_evaluation import QualificationCandidateBinding
from .qualification_trust import (
    QualificationAuthorityKeyState,
    QualificationAuthorityKeyUse,
    QualificationReviewerCredential,
    QualificationReviewerRole,
    QualificationTrustPolicy,
    VerifiedQualificationReviewerCredential,
    VerifiedQualificationTrustPolicy,
    _auth_value,
    _clock_value,
    _format_timestamp,
    _parse_timestamp,
    _positive_integer,
    _qualification_failure,
    _sha256,
    _signature,
    _specialist_id,
)
from .validation import loads_json_without_duplicate_keys

QUALIFICATION_STATUS_TRANSITION_SIGNING_DOMAIN = (
    b"SUNDERKEY\x00QUALIFICATION-STATUS-TRANSITION\x00V1\x00"
)
_TRANSITION_ID_PATTERN = re.compile(r"QST-[0-9A-F]{32}")
_DECISION_ID_PATTERN = re.compile(r"QKD-[0-9A-F]{32}")
_CREDENTIAL_ID_PATTERN = re.compile(r"QRC-[0-9A-F]{32}")
_STATUS_EVENT_ID_PATTERN = re.compile(r"(?:QKD|QST)-[0-9A-F]{32}")
_VERIFICATION_PROOF_KEY = secrets.token_bytes(32)


class QualificationStatus(StrEnum):
    """Qualification statuses represented by the signed lifecycle."""

    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


class QualificationStatusTransitionKind(StrEnum):
    """Supported restrictive and restorative status transitions."""

    SUSPEND = "suspend"
    REVOKE = "revoke"
    RENEW = "renew"
    REINSTATE = "reinstate"


_RESULTING_STATUS = {
    QualificationStatusTransitionKind.SUSPEND: QualificationStatus.SUSPENDED,
    QualificationStatusTransitionKind.REVOKE: QualificationStatus.REVOKED,
    QualificationStatusTransitionKind.RENEW: QualificationStatus.ACTIVE,
    QualificationStatusTransitionKind.REINSTATE: QualificationStatus.ACTIVE,
}
_ALLOWED_PRIOR_STATUS = {
    QualificationStatusTransitionKind.SUSPEND: frozenset(
        {QualificationStatus.ACTIVE}
    ),
    QualificationStatusTransitionKind.REVOKE: frozenset(
        {QualificationStatus.ACTIVE, QualificationStatus.SUSPENDED}
    ),
    QualificationStatusTransitionKind.RENEW: frozenset(
        {QualificationStatus.ACTIVE}
    ),
    QualificationStatusTransitionKind.REINSTATE: frozenset(
        {QualificationStatus.SUSPENDED}
    ),
}
_ALLOWED_REASON_CODES = {
    QualificationStatusTransitionKind.SUSPEND: frozenset(
        {
            "evidence_integrity_concern",
            "key_compromise_suspected",
            "operational_safety",
            "policy_violation_investigation",
        }
    ),
    QualificationStatusTransitionKind.REVOKE: frozenset(
        {
            "confirmed_key_compromise",
            "fraudulent_evidence",
            "material_policy_violation",
            "qualification_withdrawn",
        }
    ),
    QualificationStatusTransitionKind.RENEW: frozenset(
        {"material_scope_change", "periodic_review"}
    ),
    QualificationStatusTransitionKind.REINSTATE: frozenset(
        {"corrective_review_complete", "incident_resolved"}
    ),
}
_RESTORATIVE_KINDS = frozenset(
    {
        QualificationStatusTransitionKind.RENEW,
        QualificationStatusTransitionKind.REINSTATE,
    }
)


def _transition_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or _TRANSITION_ID_PATTERN.fullmatch(value) is None:
        raise _qualification_failure(f"{label} is not a valid transition ID")
    return value


def _decision_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DECISION_ID_PATTERN.fullmatch(value) is None:
        raise _qualification_failure(f"{label} is not a valid decision ID")
    return value


def _status_event_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or _STATUS_EVENT_ID_PATTERN.fullmatch(value) is None:
        raise _qualification_failure(f"{label} is not a valid status event ID")
    return value


def _policy_binding(raw: Any, label: str) -> dict[str, Any]:
    value = _mapping(raw, label)
    _exact_fields(value, {"policy_id", "policy_version", "sha256"}, label)
    policy_id = value.get("policy_id")
    if (
        not isinstance(policy_id, str)
        or re.fullmatch(r"QTP-[0-9A-F]{32}", policy_id) is None
    ):
        raise _qualification_failure(f"{label}.policy_id is invalid")
    return {
        "policy_id": policy_id,
        "policy_version": _positive_integer(
            value.get("policy_version"),
            f"{label}.policy_version",
            2_147_483_647,
        ),
        "sha256": _sha256(value.get("sha256"), f"{label}.sha256"),
    }


def _event_binding(raw: Any, label: str) -> dict[str, str]:
    value = _mapping(raw, label)
    _exact_fields(value, {"id", "sha256"}, label)
    return {
        "id": _status_event_id(value.get("id"), f"{label}.id"),
        "sha256": _sha256(value.get("sha256"), f"{label}.sha256"),
    }


def _decision_binding(raw: Any, label: str) -> dict[str, str]:
    value = _mapping(raw, label)
    _exact_fields(value, {"id", "sha256"}, label)
    return {
        "id": _decision_id(value.get("id"), f"{label}.id"),
        "sha256": _sha256(value.get("sha256"), f"{label}.sha256"),
    }


def _credential_binding(raw: Any, label: str) -> dict[str, str]:
    value = _mapping(raw, label)
    _exact_fields(value, {"id", "sha256"}, label)
    credential_id = value.get("id")
    if (
        not isinstance(credential_id, str)
        or _CREDENTIAL_ID_PATTERN.fullmatch(credential_id) is None
    ):
        raise _qualification_failure(f"{label}.id is not a valid credential ID")
    return {
        "id": credential_id,
        "sha256": _sha256(value.get("sha256"), f"{label}.sha256"),
    }


@dataclass(frozen=True)
class QualificationStatusBinding:
    """Canonical prior-state binding used to form a linear event chain."""

    profile_id: str
    candidate: QualificationCandidateBinding
    sequence: int
    status: QualificationStatus
    source_event: dict[str, str]
    current_review_decision: dict[str, str]
    qualification_valid_until: str
    changed_at: str

    @classmethod
    def from_dict(cls, raw: Any, label: str) -> QualificationStatusBinding:
        value = _mapping(raw, label)
        _exact_fields(
            value,
            {
                "profile_id",
                "candidate",
                "sequence",
                "status",
                "source_event",
                "current_review_decision",
                "qualification_valid_until",
                "changed_at",
            },
            label,
        )
        try:
            status = QualificationStatus(value.get("status"))
        except (TypeError, ValueError) as exc:
            raise _qualification_failure(f"{label}.status is invalid") from exc
        changed_at = _auth_value(
            _timestamp,
            value.get("changed_at"),
            f"{label}.changed_at",
        )
        valid_until = _auth_value(
            _timestamp,
            value.get("qualification_valid_until"),
            f"{label}.qualification_valid_until",
        )
        if _parse_timestamp(changed_at, label) >= _parse_timestamp(
            valid_until,
            label,
        ):
            raise _qualification_failure(
                f"{label} must change before qualification expiry"
            )
        return cls(
            profile_id=_specialist_id(
                value.get("profile_id"),
                f"{label}.profile_id",
            ),
            candidate=QualificationCandidateBinding.from_dict(
                value.get("candidate"),
                f"{label}.candidate",
            ),
            sequence=_positive_integer(
                value.get("sequence"),
                f"{label}.sequence",
                2_147_483_647,
            ),
            status=status,
            source_event=_event_binding(
                value.get("source_event"),
                f"{label}.source_event",
            ),
            current_review_decision=_decision_binding(
                value.get("current_review_decision"),
                f"{label}.current_review_decision",
            ),
            qualification_valid_until=valid_until,
            changed_at=changed_at,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "candidate": self.candidate.to_dict(),
            "sequence": self.sequence,
            "status": self.status.value,
            "source_event": dict(self.source_event),
            "current_review_decision": dict(self.current_review_decision),
            "qualification_valid_until": self.qualification_valid_until,
            "changed_at": self.changed_at,
        }

    @property
    def content_sha256(self) -> str:
        return _canonical_sha256(self.to_dict())


def _status_proof(material: dict[str, Any]) -> bytes:
    payload = _canonical_json(
        {"kind": "verified_qualification_status", "material": material}
    ).encode("ascii")
    return hmac.new(_VERIFICATION_PROOF_KEY, payload, hashlib.sha256).digest()


@dataclass(frozen=True)
class VerifiedQualificationStatus:
    """Authenticated status checkpoint with a process-local tamper check."""

    binding: QualificationStatusBinding
    binding_sha256: str
    previous_binding_sha256: str | None
    verified_at: str
    _proof: bytes = field(repr=False, compare=False)

    def _material(self) -> dict[str, Any]:
        return {
            "binding": self.binding.to_dict(),
            "binding_sha256": self.binding_sha256,
            "previous_binding_sha256": self.previous_binding_sha256,
            "verified_at": self.verified_at,
        }

    def __post_init__(self) -> None:
        expected = _status_proof(self._material())
        if not isinstance(self._proof, bytes) or not hmac.compare_digest(
            self._proof,
            expected,
        ):
            raise TypeError(
                "VerifiedQualificationStatus can be created only by lifecycle "
                "verification"
            )


@dataclass(frozen=True)
class QualificationStatusTransition:
    """Authority-signed lifecycle transition with no direct registry effect."""

    schema_version: int
    transition_id: str
    transition_version: int
    transition_kind: QualificationStatusTransitionKind
    policy: dict[str, Any]
    prior_status: QualificationStatusBinding
    resulting_status: QualificationStatus
    reason_code: str
    reason_evidence_sha256: str
    supporting_decision: dict[str, str] | None
    issued_at: str
    effective_at: str
    signer_id: str
    authority_key_id: str | None
    reviewer_credential: dict[str, str] | None
    registry_effect: str
    signature: str

    @classmethod
    def from_dict(cls, raw: Any) -> QualificationStatusTransition:
        value = _mapping(raw, "qualification status transition")
        base_fields = {
            "schema_version",
            "transition_id",
            "transition_version",
            "transition_kind",
            "policy",
            "prior_status",
            "resulting_status",
            "reason_code",
            "reason_evidence_sha256",
            "issued_at",
            "effective_at",
            "signer_id",
            "registry_effect",
            "algorithm",
            "signature",
        }
        try:
            kind = QualificationStatusTransitionKind(value.get("transition_kind"))
        except (TypeError, ValueError) as exc:
            raise _qualification_failure(
                "Qualification status transition kind is invalid"
            ) from exc
        restorative = kind in _RESTORATIVE_KINDS
        expected_fields = base_fields | (
            {"reviewer_credential"}
            if kind is QualificationStatusTransitionKind.SUSPEND
            else {"authority_key_id"}
        )
        if restorative:
            expected_fields.add("supporting_decision")
        _exact_fields(value, expected_fields, "qualification status transition")
        if value.get("schema_version") != 1:
            raise _qualification_failure(
                "Qualification status transition schema_version must be 1"
            )
        if value.get("algorithm") != "Ed25519":
            raise _qualification_failure(
                "Qualification status transition algorithm must be Ed25519"
            )
        if value.get("registry_effect") != "none":
            raise _qualification_failure(
                "Qualification status transition registry_effect must be none"
            )
        try:
            resulting = QualificationStatus(value.get("resulting_status"))
        except (TypeError, ValueError) as exc:
            raise _qualification_failure(
                "Qualification status transition resulting_status is invalid"
            ) from exc
        if resulting is not _RESULTING_STATUS[kind]:
            raise _qualification_failure(
                "Qualification status transition resulting status is invalid"
            )
        reason_code = value.get("reason_code")
        if not isinstance(reason_code, str) or reason_code not in _ALLOWED_REASON_CODES[kind]:
            raise _qualification_failure(
                "Qualification status transition reason code is invalid"
            )
        issued_at = _auth_value(
            _timestamp,
            value.get("issued_at"),
            "qualification status transition.issued_at",
        )
        effective_at = _auth_value(
            _timestamp,
            value.get("effective_at"),
            "qualification status transition.effective_at",
        )
        if _parse_timestamp(issued_at, "qualification status transition") > _parse_timestamp(
            effective_at,
            "qualification status transition",
        ):
            raise _qualification_failure(
                "Qualification status transition cannot precede issuance"
            )
        return cls(
            schema_version=1,
            transition_id=_transition_id(
                value.get("transition_id"),
                "qualification status transition.transition_id",
            ),
            transition_version=_positive_integer(
                value.get("transition_version"),
                "qualification status transition.transition_version",
                2_147_483_647,
            ),
            transition_kind=kind,
            policy=_policy_binding(
                value.get("policy"),
                "qualification status transition.policy",
            ),
            prior_status=QualificationStatusBinding.from_dict(
                value.get("prior_status"),
                "qualification status transition.prior_status",
            ),
            resulting_status=resulting,
            reason_code=reason_code,
            reason_evidence_sha256=_sha256(
                value.get("reason_evidence_sha256"),
                "qualification status transition.reason_evidence_sha256",
            ),
            supporting_decision=(
                _decision_binding(
                    value.get("supporting_decision"),
                    "qualification status transition.supporting_decision",
                )
                if restorative
                else None
            ),
            issued_at=issued_at,
            effective_at=effective_at,
            signer_id=_auth_value(
                _identifier,
                value.get("signer_id"),
                "qualification status transition.signer_id",
            ),
            authority_key_id=(
                None
                if kind is QualificationStatusTransitionKind.SUSPEND
                else _auth_value(
                    _identifier,
                    value.get("authority_key_id"),
                    "qualification status transition.authority_key_id",
                )
            ),
            reviewer_credential=(
                _credential_binding(
                    value.get("reviewer_credential"),
                    "qualification status transition.reviewer_credential",
                )
                if kind is QualificationStatusTransitionKind.SUSPEND
                else None
            ),
            registry_effect="none",
            signature=_signature(
                value.get("signature"),
                "qualification status transition.signature",
            ),
        )

    def unsigned_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schema_version": self.schema_version,
            "transition_id": self.transition_id,
            "transition_version": self.transition_version,
            "transition_kind": self.transition_kind.value,
            "policy": dict(self.policy),
            "prior_status": self.prior_status.to_dict(),
            "resulting_status": self.resulting_status.value,
            "reason_code": self.reason_code,
            "reason_evidence_sha256": self.reason_evidence_sha256,
            "issued_at": self.issued_at,
            "effective_at": self.effective_at,
            "signer_id": self.signer_id,
            "registry_effect": self.registry_effect,
            "algorithm": "Ed25519",
        }
        if self.authority_key_id is not None:
            value["authority_key_id"] = self.authority_key_id
        if self.reviewer_credential is not None:
            value["reviewer_credential"] = dict(self.reviewer_credential)
        if self.supporting_decision is not None:
            value["supporting_decision"] = dict(self.supporting_decision)
        return value

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "signature": self.signature}

    def signing_bytes(self) -> bytes:
        return QUALIFICATION_STATUS_TRANSITION_SIGNING_DOMAIN + _canonical_json(
            self.unsigned_dict()
        ).encode("ascii")

    @property
    def content_sha256(self) -> str:
        return _canonical_sha256(self.to_dict())


def _validated_policy(
    verified_policy: VerifiedQualificationTrustPolicy,
) -> QualificationTrustPolicy:
    if type(verified_policy) is not VerifiedQualificationTrustPolicy:
        raise _qualification_failure(
            "verified_policy must be a VerifiedQualificationTrustPolicy"
        )
    try:
        VerifiedQualificationTrustPolicy.__post_init__(verified_policy)
    except TypeError as exc:
        raise _qualification_failure(
            "Verified qualification trust policy proof is invalid"
        ) from exc
    policy = QualificationTrustPolicy.from_dict(verified_policy.policy.to_dict())
    if policy.content_sha256 != verified_policy.policy_sha256:
        raise _qualification_failure(
            "Verified qualification trust policy digest is invalid"
        )
    return policy


def _validated_decision(
    verified_decision: VerifiedQualificationDecision,
) -> VerifiedQualificationDecision:
    if type(verified_decision) is not VerifiedQualificationDecision:
        raise _qualification_failure(
            "supporting_decision must be a VerifiedQualificationDecision"
        )
    try:
        VerifiedQualificationDecision.__post_init__(verified_decision)
    except TypeError as exc:
        raise _qualification_failure(
            "Verified qualification decision proof is invalid"
        ) from exc
    if verified_decision.decision.content_sha256 != verified_decision.decision_sha256:
        raise _qualification_failure(
            "Verified qualification decision digest is invalid"
        )
    return verified_decision


def _validated_control_credential(
    verified_credential: VerifiedQualificationReviewerCredential,
) -> QualificationReviewerCredential:
    if type(verified_credential) is not VerifiedQualificationReviewerCredential:
        raise _qualification_failure(
            "control_credential must be a VerifiedQualificationReviewerCredential"
        )
    try:
        VerifiedQualificationReviewerCredential.__post_init__(verified_credential)
    except TypeError as exc:
        raise _qualification_failure(
            "Verified qualification reviewer credential proof is invalid"
        ) from exc
    credential = QualificationReviewerCredential.from_dict(
        verified_credential.credential.to_dict()
    )
    if credential.content_sha256 != verified_credential.credential_sha256:
        raise _qualification_failure(
            "Verified qualification reviewer credential digest is invalid"
        )
    return credential


def _validated_status(
    verified_status: VerifiedQualificationStatus,
) -> QualificationStatusBinding:
    if type(verified_status) is not VerifiedQualificationStatus:
        raise _qualification_failure(
            "previous_status must be a VerifiedQualificationStatus"
        )
    try:
        VerifiedQualificationStatus.__post_init__(verified_status)
    except TypeError as exc:
        raise _qualification_failure(
            "Verified qualification status proof is invalid"
        ) from exc
    binding = QualificationStatusBinding.from_dict(
        verified_status.binding.to_dict(),
        "verified qualification status",
    )
    if binding.content_sha256 != verified_status.binding_sha256:
        raise _qualification_failure(
            "Verified qualification status digest is invalid"
        )
    return binding


def _verified_status(
    binding: QualificationStatusBinding,
    verified_at: str,
    previous_binding_sha256: str | None,
) -> VerifiedQualificationStatus:
    material = {
        "binding": binding.to_dict(),
        "binding_sha256": binding.content_sha256,
        "previous_binding_sha256": previous_binding_sha256,
        "verified_at": verified_at,
    }
    return VerifiedQualificationStatus(
        binding=binding,
        binding_sha256=binding.content_sha256,
        previous_binding_sha256=previous_binding_sha256,
        verified_at=verified_at,
        _proof=_status_proof(material),
    )


def qualification_status_from_initial_decision(
    verified_decision: VerifiedQualificationDecision,
    *,
    clock: Callable[[], datetime],
) -> VerifiedQualificationStatus:
    """Create the first active checkpoint from a verified initial decision."""

    verified = _validated_decision(verified_decision)
    decision = verified.decision
    now = _clock_value(clock)
    starts = _parse_timestamp(decision.valid_from, "qualification decision")
    expires = _parse_timestamp(decision.valid_until, "qualification decision")
    if now < starts or now >= expires:
        raise _qualification_failure(
            "Initial qualification decision is not active"
        )
    binding = QualificationStatusBinding(
        profile_id=decision.profile_id,
        candidate=decision.candidate,
        sequence=1,
        status=QualificationStatus.ACTIVE,
        source_event={
            "id": decision.decision_id,
            "sha256": verified.decision_sha256,
        },
        current_review_decision={
            "id": decision.decision_id,
            "sha256": verified.decision_sha256,
        },
        qualification_valid_until=decision.valid_until,
        changed_at=decision.valid_from,
    )
    binding = QualificationStatusBinding.from_dict(
        binding.to_dict(),
        "initial qualification status",
    )
    return _verified_status(binding, _format_timestamp(now), None)


def verify_qualification_status_transition(
    transition: QualificationStatusTransition,
    previous_status: VerifiedQualificationStatus,
    verified_policy: VerifiedQualificationTrustPolicy,
    *,
    clock: Callable[[], datetime],
    supporting_decision: VerifiedQualificationDecision | None = None,
    control_credential: VerifiedQualificationReviewerCredential | None = None,
) -> VerifiedQualificationStatus:
    """Authenticate one exact lifecycle event and return its new checkpoint."""

    if not isinstance(transition, QualificationStatusTransition):
        raise _qualification_failure(
            "transition must be a QualificationStatusTransition"
        )
    transition = QualificationStatusTransition.from_dict(transition.to_dict())
    previous = _validated_status(previous_status)
    policy = _validated_policy(verified_policy)
    if transition.prior_status != previous:
        raise _qualification_failure(
            "Qualification status transition prior-state binding is stale"
        )
    kind = transition.transition_kind
    if previous.status is QualificationStatus.REVOKED:
        raise _qualification_failure(
            "Revoked qualification status is terminal"
        )
    if previous.status not in _ALLOWED_PRIOR_STATUS[kind]:
        raise _qualification_failure(
            "Qualification status transition is invalid from the prior status"
        )
    if transition.policy != {
        "policy_id": policy.policy_id,
        "policy_version": policy.policy_version,
        "sha256": verified_policy.policy_sha256,
    }:
        raise _qualification_failure(
            "Qualification status transition policy binding is stale"
        )
    if previous.profile_id not in policy.allowed_profile_ids:
        raise _qualification_failure(
            "Qualification status transition profile is outside policy scope"
        )
    issued = _parse_timestamp(transition.issued_at, "qualification status transition")
    effective = _parse_timestamp(
        transition.effective_at,
        "qualification status transition",
    )
    now = _clock_value(clock)
    if effective > now:
        raise _qualification_failure(
            "Qualification status transition is not effective yet"
        )
    previous_change = _parse_timestamp(previous.changed_at, "qualification status")
    previous_expiry = _parse_timestamp(
        previous.qualification_valid_until,
        "qualification status",
    )
    if issued < previous_change:
        raise _qualification_failure(
            "Qualification status transition predates the prior status"
        )
    if effective >= previous_expiry:
        raise _qualification_failure(
            "Qualification status transition follows qualification expiry"
        )
    policy_start = _parse_timestamp(policy.not_before, "qualification trust policy")
    policy_end = _parse_timestamp(policy.expires_at, "qualification trust policy")
    if issued < policy_start or effective >= policy_end or now >= policy_end:
        raise _qualification_failure(
            "Qualification status transition is outside the policy window"
        )
    if kind is QualificationStatusTransitionKind.SUSPEND:
        if control_credential is None:
            raise _qualification_failure(
                "Qualification suspension requires an independent Control credential"
            )
        credential = _validated_control_credential(control_credential)
        if credential.reviewer_role is not QualificationReviewerRole.INDEPENDENT_CONTROL:
            raise _qualification_failure(
                "Qualification suspension signer is not independent Control"
            )
        if (
            control_credential.policy_sha256 != verified_policy.policy_sha256
            or credential.policy_sha256 != verified_policy.policy_sha256
        ):
            raise _qualification_failure(
                "Qualification suspension credential policy is stale"
            )
        if (
            control_credential.verified_profile_id != previous.profile_id
            or previous.profile_id not in credential.allowed_profile_ids
        ):
            raise _qualification_failure(
                "Qualification suspension credential profile scope is stale"
            )
        if transition.signer_id != credential.reviewer_id:
            raise _qualification_failure(
                "Qualification suspension signer identity is stale"
            )
        if transition.reviewer_credential != {
            "id": credential.credential_id,
            "sha256": control_credential.credential_sha256,
        }:
            raise _qualification_failure(
                "Qualification suspension credential binding is stale"
            )
        credential_start = _parse_timestamp(
            credential.not_before,
            "qualification suspension credential",
        )
        credential_end = _parse_timestamp(
            credential.expires_at,
            "qualification suspension credential",
        )
        if issued < credential_start or effective >= credential_end:
            raise _qualification_failure(
                "Qualification suspension is outside the credential window"
            )
        signer_public_bytes = _decode_base64url(credential.public_key)
        signer_label = f"independent Control reviewer {credential.reviewer_id}"
    else:
        if control_credential is not None:
            raise _qualification_failure(
                "Authority qualification transition cannot use a reviewer credential"
            )
        if transition.signer_id != policy.issuer:
            raise _qualification_failure(
                "Qualification status transition signer does not match policy issuer"
            )
        if transition.authority_key_id is None:
            raise _qualification_failure(
                "Qualification status transition authority key is missing"
            )
        signer = policy.key(transition.authority_key_id)
        expected_key_use = (
            QualificationAuthorityKeyUse.QUALIFICATION_REVOCATION
            if kind is QualificationStatusTransitionKind.REVOKE
            else QualificationAuthorityKeyUse.QUALIFICATION_DECISION
        )
        if signer.key_use is not expected_key_use:
            raise _qualification_failure(
                "Qualification status transition signer key use is not authorized"
            )
        if previous.profile_id not in signer.allowed_profile_ids:
            raise _qualification_failure(
                "Qualification status transition signer profile scope is stale"
            )
        if signer.state is QualificationAuthorityKeyState.REVOKED:
            raise _qualification_failure(
                "Qualification status transition signer key is revoked"
            )
        key_start = _parse_timestamp(signer.not_before, signer.key_id)
        key_end = _parse_timestamp(signer.not_after, signer.key_id)
        if issued < key_start or issued >= key_end:
            raise _qualification_failure(
                "Qualification status transition issuance is outside the signer key window"
            )
        if signer.state is QualificationAuthorityKeyState.RETIRING and (
            signer.retire_at is None
            or issued >= _parse_timestamp(signer.retire_at, signer.key_id)
        ):
            raise _qualification_failure(
                "Qualification status transition was issued after key retirement"
            )
        signer_public_bytes = _decode_base64url(signer.public_key)
        signer_label = f"qualification authority key {signer.key_id}"
    supporting = None
    if kind in _RESTORATIVE_KINDS:
        if supporting_decision is None:
            raise _qualification_failure(
                "Restorative qualification transition requires a supporting decision"
            )
        supporting = _validated_decision(supporting_decision)
        decision = supporting.decision
        expected_binding = {
            "id": decision.decision_id,
            "sha256": supporting.decision_sha256,
        }
        if transition.supporting_decision != expected_binding:
            raise _qualification_failure(
                "Qualification status transition supporting decision is stale"
            )
        if (
            decision.profile_id != previous.profile_id
            or decision.candidate != previous.candidate
        ):
            raise _qualification_failure(
                "Qualification status transition candidate binding is stale"
            )
        if supporting.policy_sha256 != verified_policy.policy_sha256:
            raise _qualification_failure(
                "Qualification status transition decision policy is stale"
            )
        decision_issued = _parse_timestamp(
            decision.issued_at,
            "supporting qualification decision",
        )
        manifest_created = _parse_timestamp(
            supporting.manifest_created_at,
            "supporting qualification evidence manifest",
        )
        reviewed_ats = tuple(
            _parse_timestamp(value, "supporting reviewer attestation")
            for value in supporting.reviewer_reviewed_ats
        )
        decision_expiry = _parse_timestamp(
            decision.valid_until,
            "supporting qualification decision",
        )
        decision_start = _parse_timestamp(
            decision.valid_from,
            "supporting qualification decision",
        )
        if decision_issued < previous_change or decision_issued > issued:
            raise _qualification_failure(
                "Supporting qualification decision is not fresh for this transition"
            )
        if effective < decision_start:
            raise _qualification_failure(
                "Qualification status transition predates its supporting decision window"
            )
        if (
            manifest_created <= previous_change
            or len(reviewed_ats) != len(decision.attestations)
            or any(
                reviewed_at <= previous_change
                or reviewed_at < manifest_created
                or reviewed_at > decision_issued
                for reviewed_at in reviewed_ats
            )
        ):
            raise _qualification_failure(
                "Restorative qualification transition requires fresh evidence and review"
            )
        if supporting.decision_sha256 == previous.current_review_decision["sha256"]:
            raise _qualification_failure(
                "Restorative qualification transition requires a fresh decision"
            )
        if now >= decision_expiry:
            raise _qualification_failure(
                "Supporting qualification decision has expired"
            )
        if (
            kind is QualificationStatusTransitionKind.RENEW
            and decision_expiry <= previous_expiry
        ):
            raise _qualification_failure(
                "Qualification renewal must extend the validity window"
            )
    elif supporting_decision is not None:
        raise _qualification_failure(
            "Restrictive qualification transition cannot include a supporting decision"
        )
    signer_public_key = _auth_value(
        _strict_ed25519_public_key,
        signer_public_bytes,
        signer_label,
    )
    _auth_value(
        _verify_ed25519,
        signer_public_key,
        transition.signature,
        transition.signing_bytes(),
        "Qualification status transition",
    )
    if supporting is None:
        review_binding = previous.current_review_decision
        valid_until = previous.qualification_valid_until
    else:
        review_binding = {
            "id": supporting.decision.decision_id,
            "sha256": supporting.decision_sha256,
        }
        valid_until = supporting.decision.valid_until
    next_binding = QualificationStatusBinding(
        profile_id=previous.profile_id,
        candidate=previous.candidate,
        sequence=previous.sequence + 1,
        status=transition.resulting_status,
        source_event={
            "id": transition.transition_id,
            "sha256": transition.content_sha256,
        },
        current_review_decision=review_binding,
        qualification_valid_until=valid_until,
        changed_at=transition.effective_at,
    )
    next_binding = QualificationStatusBinding.from_dict(
        next_binding.to_dict(),
        "resulting qualification status",
    )
    return _verified_status(
        next_binding,
        _format_timestamp(now),
        previous.content_sha256,
    )


def load_qualification_status_transition(
    path: str | Path,
) -> QualificationStatusTransition:
    resolved = Path(path)
    try:
        raw = loads_json_without_duplicate_keys(
            resolved.read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise QualificationError(
            f"Could not load qualification status transition: {resolved}"
        ) from exc
    return QualificationStatusTransition.from_dict(raw)


__all__ = [
    "QUALIFICATION_STATUS_TRANSITION_SIGNING_DOMAIN",
    "QualificationStatus",
    "QualificationStatusBinding",
    "QualificationStatusTransition",
    "QualificationStatusTransitionKind",
    "VerifiedQualificationStatus",
    "load_qualification_status_transition",
    "qualification_status_from_initial_decision",
    "verify_qualification_status_transition",
]
