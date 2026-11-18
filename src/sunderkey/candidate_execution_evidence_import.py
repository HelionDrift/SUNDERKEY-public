"""Challenge-bound import for signed candidate execution evidence."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .candidate_adapter_evidence import CandidateEvidencePacket
from .candidate_adapter_runner import (
    ContainmentBackendAttestation,
    ContainmentExecutionPlan,
    ContainmentExecutionReceipt,
)
from .candidate_adapter_sdk import AdapterInvocation, AdapterManifest, AdapterResult
from .candidate_backend_conformance import (
    BackendAdmissionReceipt,
    BackendConformanceReport,
    ContainmentConformanceSuiteCatalog,
)
from .errors import QualificationError
from .identity import _base64url, _verify_ed25519
from .qualification import _canonical_json, _canonical_sha256

CHALLENGE_DOMAIN = "sunderkey.candidate-execution-evidence-challenge.v1"
SUBMISSION_DOMAIN = "sunderkey.candidate-execution-evidence-submission.v1"
SIGNING_DOMAIN = b"SUNDERKEY\x00CANDIDATE-EXECUTION-EVIDENCE\x00V1\x00"
CHALLENGE_ID_PATTERN = re.compile(r"CEC-[0-9A-F]{32}")
SUBMISSION_ID_PATTERN = re.compile(r"CES-[0-9A-F]{32}")
IDENTIFIER_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{2,127}")
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
MAX_CHALLENGE_LIFETIME_SECONDS = 900
_VERIFICATION_PROOF_KEY = secrets.token_bytes(32)


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or not value.isascii():
        raise QualificationError(f"{label} must be nonempty ASCII text")
    return value


def _identifier(value: Any, label: str) -> str:
    text = _text(value, label)
    if IDENTIFIER_PATTERN.fullmatch(text) is None:
        raise QualificationError(f"{label} is invalid")
    return text


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise QualificationError(f"{label} must be a SHA-256 digest")
    return value


def _utc(value: Any, label: str) -> datetime:
    text = _text(value, label)
    if not text.endswith("Z"):
        raise QualificationError(f"{label} must use UTC Z notation")
    try:
        parsed = datetime.fromisoformat(text.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise QualificationError(f"{label} is invalid") from exc
    if parsed.tzinfo != UTC or parsed.microsecond:
        raise QualificationError(f"{label} must be whole-second UTC")
    return parsed


def _positive_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 2**63 - 1:
        raise QualificationError(f"{label} must be a positive integer")
    return value


def _canonical_inputs(
    *,
    manifest: AdapterManifest,
    attestation: ContainmentBackendAttestation,
    conformance_catalog: ContainmentConformanceSuiteCatalog,
    conformance_report: BackendConformanceReport,
    backend_admission: BackendAdmissionReceipt,
) -> None:
    if (
        AdapterManifest.from_dict(manifest.to_dict()) != manifest
        or ContainmentBackendAttestation.from_dict(attestation.to_dict()) != attestation
        or ContainmentConformanceSuiteCatalog.from_dict(conformance_catalog.to_dict())
        != conformance_catalog
        or BackendConformanceReport.from_dict(
            conformance_report.to_dict(), attestation, conformance_catalog
        )
        != conformance_report
        or BackendAdmissionReceipt.from_dict(
            backend_admission.to_dict(),
            conformance_report,
            attestation,
            manifest,
            conformance_catalog,
        )
        != backend_admission
    ):
        raise QualificationError("Candidate execution evidence inputs are not canonical")


@dataclass(frozen=True)
class CandidateExecutionEvidenceChallenge:
    challenge_id: str
    challenge_sha256: str
    expires_at: str
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        *,
        manifest: AdapterManifest,
        attestation: ContainmentBackendAttestation,
        conformance_catalog: ContainmentConformanceSuiteCatalog,
        conformance_report: BackendConformanceReport,
        backend_admission: BackendAdmissionReceipt,
    ) -> CandidateExecutionEvidenceChallenge:
        expected_fields = {
            "schema_version",
            "challenge_id",
            "challenge_sha256",
            "adapter_id",
            "profile_id",
            "vector_id",
            "manifest_sha256",
            "backend_id",
            "backend_attestation_sha256",
            "conformance_report_id",
            "conformance_report_sha256",
            "backend_admission_id",
            "backend_admission_sha256",
            "collector_id",
            "key_id",
            "public_key_sha256",
            "nonce",
            "sequence_number",
            "issued_at",
            "expires_at",
            "execution_scope",
            "qualification_effect",
            "routing_effect",
            "deployment_effect",
            "target_authority_effect",
        }
        if not isinstance(raw, dict) or set(raw) != expected_fields:
            raise QualificationError("Candidate execution evidence challenge fields are invalid")
        _canonical_inputs(
            manifest=manifest,
            attestation=attestation,
            conformance_catalog=conformance_catalog,
            conformance_report=conformance_report,
            backend_admission=backend_admission,
        )
        admission_raw = backend_admission.to_dict()
        bindings = {
            "adapter_id": manifest.adapter_id,
            "profile_id": manifest.profile_id,
            "vector_id": manifest.vector_id,
            "manifest_sha256": manifest.manifest_sha256,
            "backend_id": attestation.backend_id,
            "backend_attestation_sha256": attestation.attestation_sha256,
            "conformance_report_id": conformance_report.report_id,
            "conformance_report_sha256": conformance_report.report_sha256,
            "backend_admission_id": admission_raw["admission_id"],
            "backend_admission_sha256": admission_raw["admission_sha256"],
            "execution_scope": "phase157_synthetic_candidate_evidence",
        }
        if (
            raw.get("schema_version") != 1
            or any(raw.get(key) != value for key, value in bindings.items())
            or any(
                raw.get(field) != "none"
                for field in (
                    "qualification_effect",
                    "routing_effect",
                    "deployment_effect",
                    "target_authority_effect",
                )
            )
        ):
            raise QualificationError("Candidate execution evidence challenge binding is invalid")
        _identifier(raw.get("collector_id"), "candidate evidence collector ID")
        _identifier(raw.get("key_id"), "candidate evidence key ID")
        _sha(raw.get("public_key_sha256"), "candidate evidence public key hash")
        _base64url(raw.get("nonce"), "candidate evidence challenge nonce", decoded_length=32)
        _positive_integer(raw.get("sequence_number"), "candidate evidence sequence number")
        issued_at = _utc(raw.get("issued_at"), "candidate evidence challenge issued_at")
        expires_at = _utc(raw.get("expires_at"), "candidate evidence challenge expires_at")
        lifetime = int((expires_at - issued_at).total_seconds())
        if not 1 <= lifetime <= MAX_CHALLENGE_LIFETIME_SECONDS:
            raise QualificationError("Candidate evidence challenge lifetime is invalid")
        challenge_sha256 = _sha(raw.get("challenge_sha256"), "candidate evidence challenge hash")
        challenge_id = _text(raw.get("challenge_id"), "candidate evidence challenge ID")
        if CHALLENGE_ID_PATTERN.fullmatch(challenge_id) is None:
            raise QualificationError("Candidate evidence challenge ID is invalid")
        body = {
            key: value
            for key, value in raw.items()
            if key not in {"challenge_id", "challenge_sha256"}
        }
        expected_sha256 = _canonical_sha256({"domain": CHALLENGE_DOMAIN, "challenge": body})
        expected_id = f"CEC-{expected_sha256.removeprefix('sha256:')[:32].upper()}"
        if challenge_sha256 != expected_sha256 or challenge_id != expected_id:
            raise QualificationError("Candidate evidence challenge identity does not match content")
        return cls(challenge_id, challenge_sha256, raw["expires_at"], _canonical_json(raw))


def build_candidate_execution_evidence_challenge(
    *,
    manifest: AdapterManifest,
    attestation: ContainmentBackendAttestation,
    conformance_catalog: ContainmentConformanceSuiteCatalog,
    conformance_report: BackendConformanceReport,
    backend_admission: BackendAdmissionReceipt,
    collector_id: str,
    key_id: str,
    public_key_sha256: str,
    nonce: str,
    sequence_number: int,
    issued_at: str,
    expires_at: str,
) -> CandidateExecutionEvidenceChallenge:
    admission_raw = backend_admission.to_dict()
    body = {
        "schema_version": 1,
        "adapter_id": manifest.adapter_id,
        "profile_id": manifest.profile_id,
        "vector_id": manifest.vector_id,
        "manifest_sha256": manifest.manifest_sha256,
        "backend_id": attestation.backend_id,
        "backend_attestation_sha256": attestation.attestation_sha256,
        "conformance_report_id": conformance_report.report_id,
        "conformance_report_sha256": conformance_report.report_sha256,
        "backend_admission_id": admission_raw["admission_id"],
        "backend_admission_sha256": admission_raw["admission_sha256"],
        "collector_id": collector_id,
        "key_id": key_id,
        "public_key_sha256": public_key_sha256,
        "nonce": nonce,
        "sequence_number": sequence_number,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "execution_scope": "phase157_synthetic_candidate_evidence",
        "qualification_effect": "none",
        "routing_effect": "none",
        "deployment_effect": "none",
        "target_authority_effect": "none",
    }
    digest = _canonical_sha256({"domain": CHALLENGE_DOMAIN, "challenge": body})
    return CandidateExecutionEvidenceChallenge.from_dict(
        {
            **body,
            "challenge_id": f"CEC-{digest.removeprefix('sha256:')[:32].upper()}",
            "challenge_sha256": digest,
        },
        manifest=manifest,
        attestation=attestation,
        conformance_catalog=conformance_catalog,
        conformance_report=conformance_report,
        backend_admission=backend_admission,
    )


@dataclass(frozen=True)
class UnsignedCandidateExecutionEvidenceSubmission:
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    def signing_bytes(self) -> bytes:
        return SIGNING_DOMAIN + self.document_json.encode("ascii")


@dataclass(frozen=True)
class SignedCandidateExecutionEvidenceSubmission:
    submission_id: str
    submission_sha256: str
    challenge_id: str
    packet_id: str
    packet_sha256: str
    collected_at: str
    sequence_number: int
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    def unsigned_dict(self) -> dict[str, Any]:
        return {key: value for key, value in self.to_dict().items() if key != "signature"}

    def signing_bytes(self) -> bytes:
        return SIGNING_DOMAIN + _canonical_json(self.unsigned_dict()).encode("ascii")

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        *,
        challenge: CandidateExecutionEvidenceChallenge,
        packet: CandidateEvidencePacket,
    ) -> SignedCandidateExecutionEvidenceSubmission:
        expected_fields = {
            "schema_version",
            "submission_id",
            "submission_sha256",
            "challenge_id",
            "challenge_sha256",
            "adapter_id",
            "profile_id",
            "vector_id",
            "manifest_sha256",
            "backend_attestation_sha256",
            "backend_admission_id",
            "backend_admission_sha256",
            "collector_id",
            "key_id",
            "public_key_sha256",
            "nonce",
            "sequence_number",
            "packet_id",
            "packet_sha256",
            "execution_plan_id",
            "execution_plan_sha256",
            "execution_receipt_id",
            "execution_receipt_sha256",
            "result_sha256",
            "collected_at",
            "execution_scope",
            "qualification_effect",
            "routing_effect",
            "deployment_effect",
            "target_authority_effect",
            "signature_algorithm",
            "signature",
        }
        if not isinstance(raw, dict) or set(raw) != expected_fields:
            raise QualificationError("Signed candidate evidence submission fields are invalid")
        challenge_raw = challenge.to_dict()
        packet_raw = packet.manifest
        bindings = {
            "challenge_id": challenge.challenge_id,
            "challenge_sha256": challenge.challenge_sha256,
            "adapter_id": challenge_raw["adapter_id"],
            "profile_id": challenge_raw["profile_id"],
            "vector_id": challenge_raw["vector_id"],
            "manifest_sha256": challenge_raw["manifest_sha256"],
            "backend_attestation_sha256": challenge_raw["backend_attestation_sha256"],
            "backend_admission_id": challenge_raw["backend_admission_id"],
            "backend_admission_sha256": challenge_raw["backend_admission_sha256"],
            "collector_id": challenge_raw["collector_id"],
            "key_id": challenge_raw["key_id"],
            "public_key_sha256": challenge_raw["public_key_sha256"],
            "nonce": challenge_raw["nonce"],
            "sequence_number": challenge_raw["sequence_number"],
            "packet_id": packet.packet_id,
            "packet_sha256": packet.packet_sha256,
            "execution_plan_id": packet_raw["plan_id"],
            "execution_plan_sha256": packet_raw["plan_sha256"],
            "execution_receipt_id": packet_raw["receipt_id"],
            "execution_receipt_sha256": packet_raw["receipt_sha256"],
            "result_sha256": packet_raw["result_sha256"],
            "execution_scope": "phase157_synthetic_candidate_evidence",
        }
        if (
            raw.get("schema_version") != 1
            or any(raw.get(key) != value for key, value in bindings.items())
            or raw.get("signature_algorithm") != "Ed25519"
            or any(
                raw.get(field) != "none"
                for field in (
                    "qualification_effect",
                    "routing_effect",
                    "deployment_effect",
                    "target_authority_effect",
                )
            )
        ):
            raise QualificationError("Signed candidate evidence submission binding is invalid")
        _base64url(raw.get("signature"), "candidate evidence signature", decoded_length=64)
        collected_at = _utc(raw.get("collected_at"), "candidate evidence collected_at")
        issued_at = _utc(challenge_raw["issued_at"], "candidate evidence challenge issued_at")
        expires_at = _utc(challenge_raw["expires_at"], "candidate evidence challenge expires_at")
        packet_created_at = _utc(
            packet_raw.get("created_at"), "candidate evidence packet created_at"
        )
        if not issued_at <= packet_created_at <= collected_at < expires_at:
            raise QualificationError("Candidate evidence collection time is outside the challenge")
        submission_sha256 = _sha(raw.get("submission_sha256"), "candidate evidence submission hash")
        submission_id = _text(raw.get("submission_id"), "candidate evidence submission ID")
        if SUBMISSION_ID_PATTERN.fullmatch(submission_id) is None:
            raise QualificationError("Candidate evidence submission ID is invalid")
        body = {
            key: value
            for key, value in raw.items()
            if key not in {"submission_id", "submission_sha256", "signature"}
        }
        expected_sha256 = _canonical_sha256({"domain": SUBMISSION_DOMAIN, "submission": body})
        expected_id = f"CES-{expected_sha256.removeprefix('sha256:')[:32].upper()}"
        if submission_sha256 != expected_sha256 or submission_id != expected_id:
            raise QualificationError(
                "Candidate evidence submission identity does not match content"
            )
        return cls(
            submission_id,
            submission_sha256,
            challenge.challenge_id,
            packet.packet_id,
            packet.packet_sha256,
            raw["collected_at"],
            raw["sequence_number"],
            _canonical_json(raw),
        )


def prepare_candidate_execution_evidence_submission(
    *,
    challenge: CandidateExecutionEvidenceChallenge,
    packet: CandidateEvidencePacket,
    collected_at: str,
) -> UnsignedCandidateExecutionEvidenceSubmission:
    challenge_raw = challenge.to_dict()
    packet_raw = packet.manifest
    body = {
        "schema_version": 1,
        "challenge_id": challenge.challenge_id,
        "challenge_sha256": challenge.challenge_sha256,
        "adapter_id": challenge_raw["adapter_id"],
        "profile_id": challenge_raw["profile_id"],
        "vector_id": challenge_raw["vector_id"],
        "manifest_sha256": challenge_raw["manifest_sha256"],
        "backend_attestation_sha256": challenge_raw["backend_attestation_sha256"],
        "backend_admission_id": challenge_raw["backend_admission_id"],
        "backend_admission_sha256": challenge_raw["backend_admission_sha256"],
        "collector_id": challenge_raw["collector_id"],
        "key_id": challenge_raw["key_id"],
        "public_key_sha256": challenge_raw["public_key_sha256"],
        "nonce": challenge_raw["nonce"],
        "sequence_number": challenge_raw["sequence_number"],
        "packet_id": packet.packet_id,
        "packet_sha256": packet.packet_sha256,
        "execution_plan_id": packet_raw["plan_id"],
        "execution_plan_sha256": packet_raw["plan_sha256"],
        "execution_receipt_id": packet_raw["receipt_id"],
        "execution_receipt_sha256": packet_raw["receipt_sha256"],
        "result_sha256": packet_raw["result_sha256"],
        "collected_at": collected_at,
        "execution_scope": "phase157_synthetic_candidate_evidence",
        "qualification_effect": "none",
        "routing_effect": "none",
        "deployment_effect": "none",
        "target_authority_effect": "none",
        "signature_algorithm": "Ed25519",
    }
    digest = _canonical_sha256({"domain": SUBMISSION_DOMAIN, "submission": body})
    document = {
        **body,
        "submission_id": f"CES-{digest.removeprefix('sha256:')[:32].upper()}",
        "submission_sha256": digest,
    }
    unsigned = UnsignedCandidateExecutionEvidenceSubmission(_canonical_json(document))
    SignedCandidateExecutionEvidenceSubmission.from_dict(
        {**document, "signature": "A" * 86}, challenge=challenge, packet=packet
    )
    return unsigned


def finalize_candidate_execution_evidence_submission(
    unsigned: UnsignedCandidateExecutionEvidenceSubmission,
    signature: str,
    *,
    challenge: CandidateExecutionEvidenceChallenge,
    packet: CandidateEvidencePacket,
) -> SignedCandidateExecutionEvidenceSubmission:
    return SignedCandidateExecutionEvidenceSubmission.from_dict(
        {**unsigned.to_dict(), "signature": signature}, challenge=challenge, packet=packet
    )


@dataclass(frozen=True)
class VerifiedCandidateExecutionEvidence:
    submission: SignedCandidateExecutionEvidenceSubmission
    packet: CandidateEvidencePacket
    plan: ContainmentExecutionPlan
    receipt: ContainmentExecutionReceipt
    result: AdapterResult
    challenge_sha256: str
    backend_admission_sha256: str
    collector_id: str
    key_id: str
    proof: bytes = field(repr=False)

    def __post_init__(self) -> None:
        expected = _verification_proof(
            self.submission.submission_sha256,
            self.packet.packet_sha256,
            self.challenge_sha256,
            self.backend_admission_sha256,
            self.collector_id,
            self.key_id,
        )
        if not hmac.compare_digest(self.proof, expected):
            raise QualificationError("Verified candidate execution evidence proof is invalid")


def _verification_proof(*values: str) -> bytes:
    return hmac.new(
        _VERIFICATION_PROOF_KEY,
        "\x00".join(values).encode("ascii"),
        hashlib.sha256,
    ).digest()


def _public_key_bytes(value: bytes | Ed25519PublicKey) -> bytes:
    if isinstance(value, bytes):
        if len(value) != 32:
            raise QualificationError("Candidate evidence collector public key must be 32 bytes")
        try:
            key = Ed25519PublicKey.from_public_bytes(value)
        except ValueError as exc:
            raise QualificationError("Candidate evidence collector public key is invalid") from exc
    elif isinstance(value, Ed25519PublicKey):
        key = value
    else:
        raise QualificationError("Candidate evidence collector public key type is invalid")
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _load_exact_evidence_packet(source: str | Path) -> CandidateEvidencePacket:
    return CandidateEvidencePacket.from_directory(source)


def _load_packet_objects(
    *,
    packet: CandidateEvidencePacket,
    manifest: AdapterManifest,
    invocation: AdapterInvocation,
    attestation: ContainmentBackendAttestation,
) -> tuple[ContainmentExecutionPlan, ContainmentExecutionReceipt, AdapterResult]:
    files = dict(packet.files)
    try:
        packet_attestation = ContainmentBackendAttestation.from_dict(
            json.loads(files["backend-attestation.json"])
        )
        plan = ContainmentExecutionPlan.from_dict(
            json.loads(files["execution-plan.json"]), manifest, invocation, attestation
        )
        receipt = ContainmentExecutionReceipt.from_dict(
            json.loads(files["execution-receipt.json"]), plan
        )
        result = AdapterResult.from_dict(json.loads(files["adapter-result.json"]))
    except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise QualificationError("Candidate evidence packet content is incomplete") from exc
    if packet_attestation != attestation:
        raise QualificationError("Candidate evidence packet attestation does not match")
    receipt_raw = receipt.to_dict()
    if (
        receipt.result_sha256 != result.result_sha256
        or receipt_raw["result_status"] != result.status
        or receipt_raw["result_disposition"] != result.disposition
        or receipt_raw["restoration_status"] != result.restoration_status
        or receipt_raw["residual_effects"] != list(result.residual_effects)
    ):
        raise QualificationError("Candidate evidence receipt and result do not match")
    try:
        created_at = packet.manifest["created_at"]
    except KeyError as exc:
        raise QualificationError("Candidate evidence packet content is incomplete") from exc
    expected_packet = CandidateEvidencePacket.build(
        manifest=manifest,
        attestation=attestation,
        plan=plan,
        receipt=receipt,
        result=result,
        created_at=created_at,
    )
    if expected_packet != packet:
        raise QualificationError("Candidate evidence packet does not match its source artifacts")
    return plan, receipt, result


def verify_candidate_execution_evidence_submission(
    *,
    submission: SignedCandidateExecutionEvidenceSubmission,
    challenge: CandidateExecutionEvidenceChallenge,
    manifest: AdapterManifest,
    invocation: AdapterInvocation,
    attestation: ContainmentBackendAttestation,
    conformance_catalog: ContainmentConformanceSuiteCatalog,
    conformance_report: BackendConformanceReport,
    backend_admission: BackendAdmissionReceipt,
    evidence_root: str | Path,
    collector_public_key: bytes | Ed25519PublicKey,
    observed_at: str,
) -> VerifiedCandidateExecutionEvidence:
    _canonical_inputs(
        manifest=manifest,
        attestation=attestation,
        conformance_catalog=conformance_catalog,
        conformance_report=conformance_report,
        backend_admission=backend_admission,
    )
    verified_challenge = CandidateExecutionEvidenceChallenge.from_dict(
        challenge.to_dict(),
        manifest=manifest,
        attestation=attestation,
        conformance_catalog=conformance_catalog,
        conformance_report=conformance_report,
        backend_admission=backend_admission,
    )
    if verified_challenge != challenge:
        raise QualificationError("Candidate execution evidence challenge is not canonical")
    packet = _load_exact_evidence_packet(evidence_root)
    plan, receipt, result = _load_packet_objects(
        packet=packet,
        manifest=manifest,
        invocation=invocation,
        attestation=attestation,
    )
    verified_submission = SignedCandidateExecutionEvidenceSubmission.from_dict(
        submission.to_dict(), challenge=challenge, packet=packet
    )
    if verified_submission != submission:
        raise QualificationError("Signed candidate evidence submission is not canonical")
    now = _utc(observed_at, "candidate evidence verification observed_at")
    challenge_raw = challenge.to_dict()
    issued_at = _utc(challenge_raw["issued_at"], "candidate evidence challenge issued_at")
    expires_at = _utc(challenge_raw["expires_at"], "candidate evidence challenge expires_at")
    collected_at = _utc(submission.collected_at, "candidate evidence collected_at")
    if not issued_at <= collected_at <= now < expires_at:
        raise QualificationError("Candidate evidence or challenge is outside its validity window")
    public_bytes = _public_key_bytes(collector_public_key)
    public_digest = f"sha256:{hashlib.sha256(public_bytes).hexdigest()}"
    if not hmac.compare_digest(public_digest, challenge_raw["public_key_sha256"]):
        raise QualificationError("Candidate evidence collector public key does not match")
    _verify_ed25519(
        public_bytes,
        submission.to_dict()["signature"],
        submission.signing_bytes(),
        "Candidate execution evidence submission",
    )
    receipt_raw = receipt.to_dict()
    if (
        receipt.run_status != "completed_nonqualifying"
        or receipt_raw["timed_out"]
        or receipt_raw["cancelled"]
        or result.status != "completed"
        or result.restoration_status not in {"not_required", "verified"}
        or result.residual_effects
    ):
        raise QualificationError("Candidate execution evidence did not complete cleanly")
    collector_id = challenge_raw["collector_id"]
    key_id = challenge_raw["key_id"]
    admission_sha256 = backend_admission.admission_sha256
    return VerifiedCandidateExecutionEvidence(
        submission,
        packet,
        plan,
        receipt,
        result,
        challenge.challenge_sha256,
        admission_sha256,
        collector_id,
        key_id,
        _verification_proof(
            submission.submission_sha256,
            packet.packet_sha256,
            challenge.challenge_sha256,
            admission_sha256,
            collector_id,
            key_id,
        ),
    )


__all__ = [
    "CandidateExecutionEvidenceChallenge",
    "SignedCandidateExecutionEvidenceSubmission",
    "UnsignedCandidateExecutionEvidenceSubmission",
    "VerifiedCandidateExecutionEvidence",
    "build_candidate_execution_evidence_challenge",
    "finalize_candidate_execution_evidence_submission",
    "prepare_candidate_execution_evidence_submission",
    "verify_candidate_execution_evidence_submission",
]
