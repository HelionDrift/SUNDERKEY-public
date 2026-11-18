"""Signed continuous custody for authorized target-health receipts.

The collector performs no target interaction. It signs already verified health
receipts and emits non-authoritative pause proposals for adverse observations.
"""

from __future__ import annotations

import base64
import hmac
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, ClassVar, Protocol

from .authorized_target_health_runtime import (
    HealthSignalState,
    TargetHealthReceipt,
    TargetHealthStatus,
    verify_target_health_receipt,
)
from .target_adapter_conformance import AdapterStopState, canonical_json, canonical_sha256

SCHEMA_VERSION = 1
NO_BUILTIN_IO = True
AUTHORITY_EFFECT = "none"
QUALIFICATION_EFFECT = "none"

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{1,255}\Z")
_CODE = re.compile(r"[a-z][a-z0-9_.-]{1,63}\Z")
_SIGNATURE = re.compile(r"[A-Za-z0-9_-]{16,8192}\Z")
SUPPORTED_SIGNATURE_ALGORITHMS = frozenset(
    {"ecdsa_p256_sha256", "ed25519", "hmac_sha256_test_only", "rsa_pss_sha256"}
)


class TargetHealthCollectorError(ValueError):
    """Raised when health custody or signature evidence fails closed."""


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise TargetHealthCollectorError(f"{label} must be a sha256 digest")
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise TargetHealthCollectorError(f"{label} is invalid")
    return value


def _code(value: Any, label: str) -> str:
    if not isinstance(value, str) or _CODE.fullmatch(value) is None:
        raise TargetHealthCollectorError(f"{label} is invalid")
    return value


def _identity(prefix: str, kind: str, body: dict[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"body": body, "kind": kind})
    return f"{prefix}-{digest[7:39].upper()}", digest


@dataclass(frozen=True, slots=True)
class HealthSignatureMaterial:
    """Detached signature metadata returned by an injected signer."""

    algorithm: str
    key_id: str
    public_key_sha256: str
    signature: str

    def __post_init__(self) -> None:
        _code(self.algorithm, "signature algorithm")
        if self.algorithm not in SUPPORTED_SIGNATURE_ALGORITHMS:
            raise TargetHealthCollectorError("signature algorithm is unsupported")
        _identifier(self.key_id, "signature key_id")
        _digest(self.public_key_sha256, "signature public_key_sha256")
        if not isinstance(self.signature, str) or _SIGNATURE.fullmatch(self.signature) is None:
            raise TargetHealthCollectorError("signature is invalid")
        try:
            base64.urlsafe_b64decode(self.signature + "=" * (-len(self.signature) % 4))
        except (ValueError, TypeError) as exc:
            raise TargetHealthCollectorError("signature is not base64url") from exc

    def to_dict(self) -> dict[str, str]:
        return {
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "public_key_sha256": self.public_key_sha256,
            "signature": self.signature,
        }


class HealthObservationSigner(Protocol):
    """Injected signing boundary. The collector never receives key material."""

    def sign(self, payload: bytes) -> HealthSignatureMaterial: ...


class HealthObservationVerifier(Protocol):
    """Injected verification boundary for one detached signature."""

    def verify(self, payload: bytes, signature: HealthSignatureMaterial) -> bool: ...


@dataclass(frozen=True, slots=True)
class SignedTargetHealthObservation:
    """One chain-linked authorized health receipt and detached signature."""

    collector_id: str
    sequence: int
    previous_observation_sha256: str | None
    health_receipt: TargetHealthReceipt
    signing_payload_sha256: str
    signature: HealthSignatureMaterial
    authority_effect: str = AUTHORITY_EFFECT
    qualification_effect: str = QUALIFICATION_EFFECT
    network_call_performed: bool = False
    observation_id: str = ""
    observation_sha256: str = ""

    KIND: ClassVar[str] = "signed_target_health_observation"

    def __post_init__(self) -> None:
        _identifier(self.collector_id, "collector_id")
        if (
            isinstance(self.sequence, bool)
            or not isinstance(self.sequence, int)
            or self.sequence < 1
        ):
            raise TargetHealthCollectorError("sequence is invalid")
        if self.sequence == 1:
            if self.previous_observation_sha256 is not None:
                raise TargetHealthCollectorError("first observation cannot have a predecessor")
        else:
            _digest(self.previous_observation_sha256, "previous_observation_sha256")
        if not isinstance(self.health_receipt, TargetHealthReceipt):
            raise TargetHealthCollectorError("health_receipt is invalid")
        verify_target_health_receipt(self.health_receipt.to_dict())
        _digest(self.signing_payload_sha256, "signing_payload_sha256")
        expected_payload = canonical_sha256(self.signing_payload())
        if not hmac.compare_digest(self.signing_payload_sha256, expected_payload):
            raise TargetHealthCollectorError("signing payload digest does not match content")
        if not isinstance(self.signature, HealthSignatureMaterial):
            raise TargetHealthCollectorError("signature material is invalid")
        if self.authority_effect != AUTHORITY_EFFECT:
            raise TargetHealthCollectorError("signed health cannot grant authority")
        if self.qualification_effect != QUALIFICATION_EFFECT:
            raise TargetHealthCollectorError("signed health cannot grant qualification")
        if self.network_call_performed is not False:
            raise TargetHealthCollectorError("collector cannot claim a network call")
        identity, digest = _identity("SHO", self.KIND, self.body())
        if self.observation_id and self.observation_id != identity:
            raise TargetHealthCollectorError("observation_id does not match content")
        if self.observation_sha256 and not hmac.compare_digest(
            self.observation_sha256, digest
        ):
            raise TargetHealthCollectorError("observation_sha256 does not match content")
        object.__setattr__(self, "observation_id", identity)
        object.__setattr__(self, "observation_sha256", digest)

    def signing_payload(self) -> dict[str, Any]:
        return {
            "collector_id": self.collector_id,
            "health_receipt_id": self.health_receipt.receipt_id,
            "health_receipt_sha256": self.health_receipt.receipt_sha256,
            "previous_observation_sha256": self.previous_observation_sha256,
            "sequence": self.sequence,
        }

    def body(self) -> dict[str, Any]:
        return {
            "authority_effect": self.authority_effect,
            "collector_id": self.collector_id,
            "health_receipt": self.health_receipt.to_dict(),
            "network_call_performed": self.network_call_performed,
            "previous_observation_sha256": self.previous_observation_sha256,
            "qualification_effect": self.qualification_effect,
            "sequence": self.sequence,
            "signature": self.signature.to_dict(),
            "signing_payload_sha256": self.signing_payload_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "kind": self.KIND,
            "observation_id": self.observation_id,
            "observation_sha256": self.observation_sha256,
            "schema_version": SCHEMA_VERSION,
        }


@dataclass(frozen=True, slots=True)
class TargetPauseProposal:
    """Non-authoritative proposal that requires a separate control action."""

    collector_id: str
    signed_observation_id: str
    signed_observation_sha256: str
    target_id: str
    session_id: str
    reason: str
    requested_control_action: str = "pause_target_execution"
    authority_effect: str = AUTHORITY_EFFECT
    qualification_effect: str = QUALIFICATION_EFFECT
    proposal_id: str = ""
    proposal_sha256: str = ""

    KIND: ClassVar[str] = "target_pause_proposal"

    def __post_init__(self) -> None:
        for value, label in (
            (self.collector_id, "collector_id"),
            (self.signed_observation_id, "signed_observation_id"),
            (self.target_id, "target_id"),
            (self.session_id, "session_id"),
        ):
            _identifier(value, label)
        _digest(self.signed_observation_sha256, "signed_observation_sha256")
        _code(self.reason, "proposal reason")
        if self.requested_control_action != "pause_target_execution":
            raise TargetHealthCollectorError("requested control action is invalid")
        if self.authority_effect != AUTHORITY_EFFECT:
            raise TargetHealthCollectorError("pause proposal cannot grant authority")
        if self.qualification_effect != QUALIFICATION_EFFECT:
            raise TargetHealthCollectorError("pause proposal cannot grant qualification")
        identity, digest = _identity("TPP", self.KIND, self.body())
        if self.proposal_id and self.proposal_id != identity:
            raise TargetHealthCollectorError("proposal_id does not match content")
        if self.proposal_sha256 and not hmac.compare_digest(self.proposal_sha256, digest):
            raise TargetHealthCollectorError("proposal_sha256 does not match content")
        object.__setattr__(self, "proposal_id", identity)
        object.__setattr__(self, "proposal_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "authority_effect": self.authority_effect,
            "collector_id": self.collector_id,
            "qualification_effect": self.qualification_effect,
            "reason": self.reason,
            "requested_control_action": self.requested_control_action,
            "session_id": self.session_id,
            "signed_observation_id": self.signed_observation_id,
            "signed_observation_sha256": self.signed_observation_sha256,
            "target_id": self.target_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "kind": self.KIND,
            "proposal_id": self.proposal_id,
            "proposal_sha256": self.proposal_sha256,
            "schema_version": SCHEMA_VERSION,
        }


class TargetHealthCollector:
    """Stateful chain builder over already authorized health receipts."""

    def __init__(
        self,
        *,
        collector_id: str,
        signer: HealthObservationSigner,
        stop_state: AdapterStopState,
    ) -> None:
        _identifier(collector_id, "collector_id")
        self.collector_id = collector_id
        self.signer = signer
        self.stop_state = stop_state
        self._sequence = 0
        self._previous: str | None = None
        self._binding_sha256: str | None = None

    def collect(
        self, receipt: TargetHealthReceipt
    ) -> tuple[SignedTargetHealthObservation, TargetPauseProposal | None]:
        if not isinstance(receipt, TargetHealthReceipt):
            raise TargetHealthCollectorError("receipt is invalid")
        verify_target_health_receipt(receipt.to_dict())
        if self._binding_sha256 is None:
            self._binding_sha256 = receipt.binding_sha256
        elif not hmac.compare_digest(self._binding_sha256, receipt.binding_sha256):
            raise TargetHealthCollectorError("collector binding substitution detected")
        sequence = self._sequence + 1
        payload = {
            "collector_id": self.collector_id,
            "health_receipt_id": receipt.receipt_id,
            "health_receipt_sha256": receipt.receipt_sha256,
            "previous_observation_sha256": self._previous,
            "sequence": sequence,
        }
        payload_bytes = canonical_json(payload).encode("ascii")
        signature = self.signer.sign(payload_bytes)
        if not isinstance(signature, HealthSignatureMaterial):
            raise TargetHealthCollectorError("signer returned invalid material")
        signed = SignedTargetHealthObservation(
            collector_id=self.collector_id,
            sequence=sequence,
            previous_observation_sha256=self._previous,
            health_receipt=receipt,
            signing_payload_sha256=canonical_sha256(payload),
            signature=signature,
        )
        reason = self._pause_reason(receipt)
        proposal = (
            None
            if reason is None
            else TargetPauseProposal(
                collector_id=self.collector_id,
                signed_observation_id=signed.observation_id,
                signed_observation_sha256=signed.observation_sha256,
                target_id=receipt.binding.target_id,
                session_id=receipt.binding.session_id,
                reason=reason,
            )
        )
        self._sequence = sequence
        self._previous = signed.observation_sha256
        return signed, proposal

    def _pause_reason(self, receipt: TargetHealthReceipt) -> str | None:
        if self.stop_state.code is not None:
            return self.stop_state.code
        if receipt.status is TargetHealthStatus.REJECTED:
            return "health_evidence_rejected"
        if receipt.overall_health is HealthSignalState.DEGRADED:
            return "target_health_degraded"
        if receipt.overall_health is HealthSignalState.UNHEALTHY:
            return "target_health_unhealthy"
        return None


def verify_signed_target_health_observation(
    observation: SignedTargetHealthObservation,
    verifier: HealthObservationVerifier,
) -> MappingProxyType:
    """Verify content, embedded receipt, chain fields, and detached signature."""

    if not isinstance(observation, SignedTargetHealthObservation):
        raise TargetHealthCollectorError("signed observation is invalid")
    verify_target_health_receipt(observation.health_receipt.to_dict())
    expected_id, expected_sha = _identity(
        "SHO", SignedTargetHealthObservation.KIND, observation.body()
    )
    if (
        observation.observation_id != expected_id
        or not hmac.compare_digest(observation.observation_sha256, expected_sha)
    ):
        raise TargetHealthCollectorError("signed observation content address is invalid")
    payload = canonical_json(observation.signing_payload()).encode("ascii")
    if not verifier.verify(payload, observation.signature):
        raise TargetHealthCollectorError("health signature verification failed")
    return MappingProxyType(observation.to_dict())


__all__ = [
    "AUTHORITY_EFFECT",
    "NO_BUILTIN_IO",
    "QUALIFICATION_EFFECT",
    "HealthObservationSigner",
    "HealthObservationVerifier",
    "HealthSignatureMaterial",
    "SignedTargetHealthObservation",
    "SUPPORTED_SIGNATURE_ALGORITHMS",
    "TargetHealthCollector",
    "TargetHealthCollectorError",
    "TargetPauseProposal",
    "verify_signed_target_health_observation",
]
