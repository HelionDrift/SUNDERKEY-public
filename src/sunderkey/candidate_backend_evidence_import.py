"""Signed, challenge-bound import for external containment conformance evidence."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .candidate_adapter_runner import ContainmentBackendAttestation
from .candidate_backend_conformance import (
    BackendConformanceReport,
    ContainmentConformanceSuiteCatalog,
    build_backend_conformance_report,
    build_conformance_observation,
)
from .errors import QualificationError
from .identity import _base64url, _verify_ed25519
from .qualification import _canonical_json, _canonical_sha256

CHALLENGE_DOMAIN = "sunderkey.containment-conformance-challenge.v1"
BATCH_DOMAIN = "sunderkey.containment-conformance-observation-batch.v1"
SIGNING_DOMAIN = b"SUNDERKEY\x00CONTAINMENT-CONFORMANCE-OBSERVATION-BATCH\x00V1\x00"
CHALLENGE_ID_PATTERN = re.compile(r"BCC-[0-9A-F]{32}")
BATCH_ID_PATTERN = re.compile(r"BCB-[0-9A-F]{32}")
IDENTIFIER_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{2,127}")
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
MEDIA_TYPES = {
    "application/json",
    "application/octet-stream",
    "text/plain",
}
MAX_CHALLENGE_LIFETIME_SECONDS = 900
MAX_EVIDENCE_FILE_BYTES = 16_777_216
MAX_EVIDENCE_TOTAL_BYTES = 67_108_864
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
    if parsed.tzinfo != timezone.utc or parsed.microsecond:
        raise QualificationError(f"{label} must be whole-second UTC")
    return parsed


def _positive_integer(value: Any, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise QualificationError(f"{label} must be an integer from 1 through {maximum}")
    return value


def _relative_path(value: Any, label: str) -> str:
    text = _text(value, label)
    if "\\" in text or ":" in text:
        raise QualificationError(f"{label} must use a portable relative path")
    path = PurePosixPath(text)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise QualificationError(f"{label} must be a safe relative path")
    return path.as_posix()


def _canonical_inputs(
    catalog: ContainmentConformanceSuiteCatalog,
    attestation: ContainmentBackendAttestation,
) -> None:
    if (
        ContainmentConformanceSuiteCatalog.from_dict(catalog.to_dict()) != catalog
        or ContainmentBackendAttestation.from_dict(attestation.to_dict()) != attestation
    ):
        raise QualificationError("Conformance evidence inputs are not canonical")


def _suite(
    catalog: ContainmentConformanceSuiteCatalog,
    isolation_class: str,
) -> dict[str, Any]:
    result = next(
        (item for item in catalog.suites if item["isolation_class"] == isolation_class),
        None,
    )
    if result is None:
        raise QualificationError("Conformance evidence suite is unavailable")
    return result


@dataclass(frozen=True)
class ConformanceProbeChallenge:
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
        catalog: ContainmentConformanceSuiteCatalog,
        attestation: ContainmentBackendAttestation,
    ) -> ConformanceProbeChallenge:
        expected_fields = {
            "schema_version",
            "challenge_id",
            "challenge_sha256",
            "suite_catalog_sha256",
            "suite_id",
            "suite_version",
            "backend_id",
            "backend_attestation_sha256",
            "isolation_class",
            "collector_id",
            "key_id",
            "public_key_sha256",
            "nonce",
            "sequence_number",
            "issued_at",
            "expires_at",
            "probe_ids",
            "execution_scope",
            "qualification_effect",
            "routing_effect",
            "deployment_effect",
            "target_authority_effect",
        }
        if not isinstance(raw, dict) or set(raw) != expected_fields:
            raise QualificationError("Conformance probe challenge fields are invalid")
        _canonical_inputs(catalog, attestation)
        suite = _suite(catalog, attestation.isolation_class)
        if (
            raw.get("schema_version") != 1
            or raw.get("suite_catalog_sha256") != catalog.catalog_sha256
            or raw.get("suite_id") != suite["suite_id"]
            or raw.get("suite_version") != suite["suite_version"]
            or raw.get("backend_id") != attestation.backend_id
            or raw.get("backend_attestation_sha256") != attestation.attestation_sha256
            or raw.get("isolation_class") != attestation.isolation_class
            or raw.get("probe_ids") != suite["probe_ids"]
            or raw.get("execution_scope") != "external_synthetic_conformance_only"
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
            raise QualificationError("Conformance probe challenge binding is invalid")
        _identifier(raw.get("collector_id"), "conformance collector ID")
        _identifier(raw.get("key_id"), "conformance collector key ID")
        _sha(raw.get("public_key_sha256"), "conformance collector public key hash")
        _base64url(raw.get("nonce"), "conformance challenge nonce", decoded_length=32)
        _positive_integer(raw.get("sequence_number"), "conformance sequence number", 2**63 - 1)
        issued_at = _utc(raw.get("issued_at"), "conformance challenge issued_at")
        expires_at = _utc(raw.get("expires_at"), "conformance challenge expires_at")
        lifetime = int((expires_at - issued_at).total_seconds())
        if not 1 <= lifetime <= MAX_CHALLENGE_LIFETIME_SECONDS:
            raise QualificationError("Conformance challenge lifetime is invalid")
        challenge_sha256 = _sha(
            raw.get("challenge_sha256"), "conformance challenge hash"
        )
        challenge_id = _text(raw.get("challenge_id"), "conformance challenge ID")
        if CHALLENGE_ID_PATTERN.fullmatch(challenge_id) is None:
            raise QualificationError("Conformance challenge ID is invalid")
        body = {
            key: value
            for key, value in raw.items()
            if key not in {"challenge_id", "challenge_sha256"}
        }
        expected_sha256 = _canonical_sha256({"domain": CHALLENGE_DOMAIN, "challenge": body})
        expected_id = f"BCC-{expected_sha256.removeprefix('sha256:')[:32].upper()}"
        if challenge_sha256 != expected_sha256 or challenge_id != expected_id:
            raise QualificationError("Conformance challenge identity does not match content")
        return cls(challenge_id, challenge_sha256, raw["expires_at"], _canonical_json(raw))


def build_conformance_probe_challenge(
    *,
    catalog: ContainmentConformanceSuiteCatalog,
    attestation: ContainmentBackendAttestation,
    collector_id: str,
    key_id: str,
    public_key_sha256: str,
    nonce: str,
    sequence_number: int,
    issued_at: str,
    expires_at: str,
) -> ConformanceProbeChallenge:
    _canonical_inputs(catalog, attestation)
    suite = _suite(catalog, attestation.isolation_class)
    body = {
        "schema_version": 1,
        "suite_catalog_sha256": catalog.catalog_sha256,
        "suite_id": suite["suite_id"],
        "suite_version": suite["suite_version"],
        "backend_id": attestation.backend_id,
        "backend_attestation_sha256": attestation.attestation_sha256,
        "isolation_class": attestation.isolation_class,
        "collector_id": collector_id,
        "key_id": key_id,
        "public_key_sha256": public_key_sha256,
        "nonce": nonce,
        "sequence_number": sequence_number,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "probe_ids": suite["probe_ids"],
        "execution_scope": "external_synthetic_conformance_only",
        "qualification_effect": "none",
        "routing_effect": "none",
        "deployment_effect": "none",
        "target_authority_effect": "none",
    }
    digest = _canonical_sha256({"domain": CHALLENGE_DOMAIN, "challenge": body})
    return ConformanceProbeChallenge.from_dict(
        {
            **body,
            "challenge_id": f"BCC-{digest.removeprefix('sha256:')[:32].upper()}",
            "challenge_sha256": digest,
        },
        catalog,
        attestation,
    )


def _validate_evidence_files(raw: Any) -> tuple[dict[str, Any], ...]:
    if not isinstance(raw, list) or not raw:
        raise QualificationError("Conformance evidence file manifest is incomplete")
    entries: list[dict[str, Any]] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict) or set(item) != {
            "path",
            "sha256",
            "size_bytes",
            "media_type",
        }:
            raise QualificationError("Conformance evidence file fields are invalid")
        path = _relative_path(item.get("path"), f"conformance evidence path {index}")
        digest = _sha(item.get("sha256"), f"conformance evidence hash {index}")
        size_bytes = _positive_integer(
            item.get("size_bytes"),
            f"conformance evidence size {index}",
            MAX_EVIDENCE_FILE_BYTES,
        )
        media_type = _text(item.get("media_type"), f"conformance evidence media type {index}")
        if media_type not in MEDIA_TYPES:
            raise QualificationError("Conformance evidence media type is not allowed")
        entries.append(
            {
                "path": path,
                "sha256": digest,
                "size_bytes": size_bytes,
                "media_type": media_type,
            }
        )
    if entries != sorted(entries, key=lambda item: item["path"]):
        raise QualificationError("Conformance evidence files must use path order")
    if len({item["path"] for item in entries}) != len(entries):
        raise QualificationError("Conformance evidence file paths are duplicated")
    if len({item["sha256"] for item in entries}) != len(entries):
        raise QualificationError("Conformance evidence file hashes are duplicated")
    if sum(item["size_bytes"] for item in entries) > MAX_EVIDENCE_TOTAL_BYTES:
        raise QualificationError("Conformance evidence total size exceeds the limit")
    return tuple(entries)


def _validate_observations(raw: Any, probe_ids: list[str]) -> tuple[dict[str, Any], ...]:
    if not isinstance(raw, list) or len(raw) != len(probe_ids):
        raise QualificationError("Signed conformance observations are incomplete")
    result: list[dict[str, Any]] = []
    for item, probe_id in zip(raw, probe_ids, strict=True):
        if not isinstance(item, dict) or item.get("probe_id") != probe_id:
            raise QualificationError("Signed conformance observations are unordered")
        rebuilt = build_conformance_observation(
            probe_id=probe_id,
            status=item.get("status"),
            evidence_sha256=tuple(item.get("evidence_sha256", [])),
            measurement=item.get("measurement"),
        )
        if rebuilt != item:
            raise QualificationError("Signed conformance observation is invalid")
        result.append(rebuilt)
    return tuple(result)


@dataclass(frozen=True)
class UnsignedConformanceObservationBatch:
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    def signing_bytes(self) -> bytes:
        return SIGNING_DOMAIN + self.document_json.encode("ascii")


@dataclass(frozen=True)
class SignedConformanceObservationBatch:
    batch_id: str
    batch_sha256: str
    challenge_id: str
    collected_at: str
    sequence_number: int
    observations: tuple[dict[str, Any], ...]
    evidence_files: tuple[dict[str, Any], ...]
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
        challenge: ConformanceProbeChallenge,
        catalog: ContainmentConformanceSuiteCatalog,
        attestation: ContainmentBackendAttestation,
    ) -> SignedConformanceObservationBatch:
        expected_fields = {
            "schema_version",
            "batch_id",
            "batch_sha256",
            "challenge_id",
            "challenge_sha256",
            "suite_catalog_sha256",
            "backend_attestation_sha256",
            "collector_id",
            "key_id",
            "public_key_sha256",
            "nonce",
            "sequence_number",
            "collected_at",
            "observations",
            "evidence_files",
            "execution_scope",
            "qualification_effect",
            "routing_effect",
            "deployment_effect",
            "target_authority_effect",
            "signature_algorithm",
            "signature",
        }
        if not isinstance(raw, dict) or set(raw) != expected_fields:
            raise QualificationError("Signed conformance batch fields are invalid")
        _canonical_inputs(catalog, attestation)
        verified_challenge = ConformanceProbeChallenge.from_dict(
            challenge.to_dict(), catalog, attestation
        )
        if verified_challenge != challenge:
            raise QualificationError("Conformance challenge is not canonical")
        challenge_raw = challenge.to_dict()
        binding_fields = {
            "challenge_id": challenge.challenge_id,
            "challenge_sha256": challenge.challenge_sha256,
            "suite_catalog_sha256": catalog.catalog_sha256,
            "backend_attestation_sha256": attestation.attestation_sha256,
            "collector_id": challenge_raw["collector_id"],
            "key_id": challenge_raw["key_id"],
            "public_key_sha256": challenge_raw["public_key_sha256"],
            "nonce": challenge_raw["nonce"],
            "sequence_number": challenge_raw["sequence_number"],
            "execution_scope": "external_synthetic_conformance_only",
        }
        if (
            raw.get("schema_version") != 1
            or any(raw.get(key) != value for key, value in binding_fields.items())
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
            raise QualificationError("Signed conformance batch binding is invalid")
        _base64url(raw.get("signature"), "conformance batch signature", decoded_length=64)
        collected_at = _utc(raw.get("collected_at"), "conformance batch collected_at")
        issued_at = _utc(challenge_raw["issued_at"], "conformance challenge issued_at")
        expires_at = _utc(challenge_raw["expires_at"], "conformance challenge expires_at")
        if not issued_at <= collected_at < expires_at:
            raise QualificationError("Conformance batch collection time is outside the challenge")
        suite = _suite(catalog, attestation.isolation_class)
        parsed_observations = _validate_observations(raw.get("observations"), suite["probe_ids"])
        parsed_evidence = _validate_evidence_files(raw.get("evidence_files"))
        referenced = {
            digest
            for observation in parsed_observations
            for digest in observation["evidence_sha256"]
        }
        manifested = {item["sha256"] for item in parsed_evidence}
        if referenced != manifested:
            raise QualificationError("Conformance evidence references do not match the manifest")
        batch_sha256 = _sha(raw.get("batch_sha256"), "conformance batch hash")
        batch_id = _text(raw.get("batch_id"), "conformance batch ID")
        if BATCH_ID_PATTERN.fullmatch(batch_id) is None:
            raise QualificationError("Conformance batch ID is invalid")
        body = {
            key: value
            for key, value in raw.items()
            if key not in {"batch_id", "batch_sha256", "signature"}
        }
        expected_sha256 = _canonical_sha256({"domain": BATCH_DOMAIN, "batch": body})
        expected_id = f"BCB-{expected_sha256.removeprefix('sha256:')[:32].upper()}"
        if batch_sha256 != expected_sha256 or batch_id != expected_id:
            raise QualificationError("Conformance batch identity does not match content")
        return cls(
            batch_id,
            batch_sha256,
            challenge.challenge_id,
            raw["collected_at"],
            raw["sequence_number"],
            parsed_observations,
            parsed_evidence,
            _canonical_json(raw),
        )


def prepare_conformance_observation_batch(
    *,
    challenge: ConformanceProbeChallenge,
    catalog: ContainmentConformanceSuiteCatalog,
    attestation: ContainmentBackendAttestation,
    collected_at: str,
    observations: list[dict[str, Any]],
    evidence_files: list[dict[str, Any]],
) -> UnsignedConformanceObservationBatch:
    challenge_raw = challenge.to_dict()
    body = {
        "schema_version": 1,
        "challenge_id": challenge.challenge_id,
        "challenge_sha256": challenge.challenge_sha256,
        "suite_catalog_sha256": catalog.catalog_sha256,
        "backend_attestation_sha256": attestation.attestation_sha256,
        "collector_id": challenge_raw["collector_id"],
        "key_id": challenge_raw["key_id"],
        "public_key_sha256": challenge_raw["public_key_sha256"],
        "nonce": challenge_raw["nonce"],
        "sequence_number": challenge_raw["sequence_number"],
        "collected_at": collected_at,
        "observations": observations,
        "evidence_files": evidence_files,
        "execution_scope": "external_synthetic_conformance_only",
        "qualification_effect": "none",
        "routing_effect": "none",
        "deployment_effect": "none",
        "target_authority_effect": "none",
        "signature_algorithm": "Ed25519",
    }
    digest = _canonical_sha256({"domain": BATCH_DOMAIN, "batch": body})
    document = {
        **body,
        "batch_id": f"BCB-{digest.removeprefix('sha256:')[:32].upper()}",
        "batch_sha256": digest,
    }
    unsigned = UnsignedConformanceObservationBatch(_canonical_json(document))
    placeholder = "A" * 86
    SignedConformanceObservationBatch.from_dict(
        {**document, "signature": placeholder},
        challenge,
        catalog,
        attestation,
    )
    return unsigned


def finalize_conformance_observation_batch(
    unsigned: UnsignedConformanceObservationBatch,
    signature: str,
    challenge: ConformanceProbeChallenge,
    catalog: ContainmentConformanceSuiteCatalog,
    attestation: ContainmentBackendAttestation,
) -> SignedConformanceObservationBatch:
    return SignedConformanceObservationBatch.from_dict(
        {**unsigned.to_dict(), "signature": signature},
        challenge,
        catalog,
        attestation,
    )


@dataclass(frozen=True)
class VerifiedConformanceObservationBatch:
    batch: SignedConformanceObservationBatch
    challenge_sha256: str
    backend_attestation_sha256: str
    collector_id: str
    key_id: str
    proof: bytes = field(repr=False)

    def __post_init__(self) -> None:
        expected = _verification_proof(
            self.batch.batch_sha256,
            self.challenge_sha256,
            self.backend_attestation_sha256,
            self.collector_id,
            self.key_id,
        )
        if not hmac.compare_digest(self.proof, expected):
            raise QualificationError("Verified conformance batch proof is invalid")


def _verification_proof(*values: str) -> bytes:
    return hmac.new(
        _VERIFICATION_PROOF_KEY,
        "\x00".join(values).encode("ascii"),
        hashlib.sha256,
    ).digest()


def _public_key_bytes(value: bytes | Ed25519PublicKey) -> bytes:
    if isinstance(value, bytes):
        if len(value) != 32:
            raise QualificationError("Conformance collector public key must be 32 bytes")
        try:
            key = Ed25519PublicKey.from_public_bytes(value)
        except ValueError as exc:
            raise QualificationError("Conformance collector public key is invalid") from exc
    elif isinstance(value, Ed25519PublicKey):
        key = value
    else:
        raise QualificationError("Conformance collector public key type is invalid")
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _verify_evidence_directory(
    evidence_root: str | Path,
    evidence_files: tuple[dict[str, Any], ...],
) -> None:
    root = Path(evidence_root).resolve(strict=True)
    if not root.is_dir():
        raise QualificationError("Conformance evidence root must be a directory")
    for entry in evidence_files:
        candidate = root.joinpath(*PurePosixPath(entry["path"]).parts)
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(root)
        except (OSError, ValueError) as exc:
            raise QualificationError("Conformance evidence path escapes the evidence root") from exc
        if candidate.is_symlink() or not resolved.is_file():
            raise QualificationError("Conformance evidence file must be a regular file")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(resolved, flags)
        except OSError as exc:
            raise QualificationError(
                "Conformance evidence file could not be opened safely"
            ) from exc
        try:
            file_status = os.fstat(descriptor)
            if not stat.S_ISREG(file_status.st_mode):
                raise QualificationError("Conformance evidence file must be a regular file")
            if file_status.st_size != entry["size_bytes"]:
                raise QualificationError(
                    "Conformance evidence file size does not match the manifest"
                )
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                content = stream.read(entry["size_bytes"] + 1)
            if len(content) != entry["size_bytes"]:
                raise QualificationError("Conformance evidence file size changed during reading")
            digest = f"sha256:{hashlib.sha256(content).hexdigest()}"
        finally:
            os.close(descriptor)
        if not hmac.compare_digest(digest, entry["sha256"]):
            raise QualificationError("Conformance evidence file hash does not match the manifest")


def verify_conformance_observation_batch(
    *,
    batch: SignedConformanceObservationBatch,
    challenge: ConformanceProbeChallenge,
    catalog: ContainmentConformanceSuiteCatalog,
    attestation: ContainmentBackendAttestation,
    collector_public_key: bytes | Ed25519PublicKey,
    evidence_root: str | Path,
    observed_at: str,
) -> VerifiedConformanceObservationBatch:
    verified_batch = SignedConformanceObservationBatch.from_dict(
        batch.to_dict(), challenge, catalog, attestation
    )
    if verified_batch != batch:
        raise QualificationError("Signed conformance batch is not canonical")
    now = _utc(observed_at, "conformance verification observed_at")
    challenge_raw = challenge.to_dict()
    issued_at = _utc(challenge_raw["issued_at"], "conformance challenge issued_at")
    expires_at = _utc(challenge_raw["expires_at"], "conformance challenge expires_at")
    collected_at = _utc(batch.collected_at, "conformance batch collected_at")
    if not issued_at <= collected_at <= now < expires_at:
        raise QualificationError("Conformance batch or challenge is outside its validity window")
    public_bytes = _public_key_bytes(collector_public_key)
    public_digest = f"sha256:{hashlib.sha256(public_bytes).hexdigest()}"
    if not hmac.compare_digest(public_digest, challenge_raw["public_key_sha256"]):
        raise QualificationError("Conformance collector public key does not match the challenge")
    _verify_ed25519(
        public_bytes,
        batch.to_dict()["signature"],
        batch.signing_bytes(),
        "Conformance observation batch",
    )
    _verify_evidence_directory(evidence_root, batch.evidence_files)
    collector_id = challenge_raw["collector_id"]
    key_id = challenge_raw["key_id"]
    return VerifiedConformanceObservationBatch(
        batch,
        challenge.challenge_sha256,
        attestation.attestation_sha256,
        collector_id,
        key_id,
        _verification_proof(
            batch.batch_sha256,
            challenge.challenge_sha256,
            attestation.attestation_sha256,
            collector_id,
            key_id,
        ),
    )


def build_report_from_verified_conformance_batch(
    *,
    verified: VerifiedConformanceObservationBatch,
    catalog: ContainmentConformanceSuiteCatalog,
    attestation: ContainmentBackendAttestation,
) -> BackendConformanceReport:
    VerifiedConformanceObservationBatch.__post_init__(verified)
    if verified.backend_attestation_sha256 != attestation.attestation_sha256:
        raise QualificationError("Verified conformance batch attestation does not match")
    return build_backend_conformance_report(
        attestation=attestation,
        catalog=catalog,
        observations=list(verified.batch.observations),
        tested_at=verified.batch.collected_at,
        verifier_id=f"signed-collector:{verified.collector_id}:{verified.key_id}",
    )


__all__ = [
    "ConformanceProbeChallenge",
    "SignedConformanceObservationBatch",
    "UnsignedConformanceObservationBatch",
    "VerifiedConformanceObservationBatch",
    "build_conformance_probe_challenge",
    "build_report_from_verified_conformance_batch",
    "finalize_conformance_observation_batch",
    "prepare_conformance_observation_batch",
    "verify_conformance_observation_batch",
]
