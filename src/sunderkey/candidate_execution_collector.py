"""Host-side packaging for challenge-bound candidate execution evidence."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .candidate_adapter_evidence import (
    MAX_PACKET_ARTIFACT_BYTES,
    MAX_PACKET_ARTIFACTS,
    MAX_PACKET_MANIFEST_BYTES,
    MAX_PACKET_TOTAL_BYTES,
    CandidateEvidencePacket,
    _read_bounded_regular_file,
)
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
from .candidate_backend_host_preflight import (
    ContainmentBackendDeploymentBinding,
    ContainmentHostPreflightReport,
    ContainmentHostSnapshot,
)
from .candidate_execution_evidence_import import (
    CandidateExecutionEvidenceChallenge,
    SignedCandidateExecutionEvidenceSubmission,
    VerifiedCandidateExecutionEvidence,
    finalize_candidate_execution_evidence_submission,
    prepare_candidate_execution_evidence_submission,
    verify_candidate_execution_evidence_submission,
)
from .errors import QualificationError
from .identity import _verify_ed25519
from .qualification import _canonical_json, _canonical_sha256
from .validation import loads_json_without_duplicate_keys

COLLECTOR_PLAN_DOMAIN = "sunderkey.candidate-execution-collector-plan.v1"
COLLECTION_DOMAIN = "sunderkey.candidate-execution-collection.v1"
PLAN_ID_PATTERN = re.compile(r"CECPL-[0-9A-F]{32}")
COLLECTION_ID_PATTERN = re.compile(r"CECL-[0-9A-F]{32}")
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
PLAN_FILENAME = "collector-plan.json"
SUBMISSION_FILENAME = "signed-submission.json"
MANIFEST_FILENAME = "collection-manifest.json"
PACKET_DIRECTORY = "packet"
MAX_COLLECTION_CONTROL_BYTES = 1_000_000
MAX_COLLECTION_ARTIFACTS = MAX_PACKET_ARTIFACTS + 3
MAX_COLLECTION_TOTAL_ARTIFACT_BYTES = MAX_PACKET_TOTAL_BYTES + 2 * MAX_COLLECTION_CONTROL_BYTES


def _sha256_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise QualificationError(f"{label} must be a SHA-256 digest")
    return value


def _utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise QualificationError(f"{label} must use UTC Z notation")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise QualificationError(f"{label} is invalid") from exc
    if parsed.tzinfo != UTC or parsed.microsecond:
        raise QualificationError(f"{label} must be whole-second UTC")
    return parsed


def _canonical_inputs(
    *,
    manifest: AdapterManifest,
    invocation: AdapterInvocation,
    attestation: ContainmentBackendAttestation,
    catalog: ContainmentConformanceSuiteCatalog,
    conformance_report: BackendConformanceReport,
    backend_admission: BackendAdmissionReceipt,
    binding: ContainmentBackendDeploymentBinding,
    snapshot: ContainmentHostSnapshot,
    preflight: ContainmentHostPreflightReport,
    challenge: CandidateExecutionEvidenceChallenge,
    execution_plan: ContainmentExecutionPlan,
) -> None:
    if AdapterManifest.from_dict(manifest.to_dict()) != manifest:
        raise QualificationError("Candidate collector manifest is not canonical")
    if ContainmentBackendAttestation.from_dict(attestation.to_dict()) != attestation:
        raise QualificationError("Candidate collector backend attestation is not canonical")
    if ContainmentConformanceSuiteCatalog.from_dict(catalog.to_dict()) != catalog:
        raise QualificationError("Candidate collector conformance catalog is not canonical")
    if (
        BackendConformanceReport.from_dict(conformance_report.to_dict(), attestation, catalog)
        != conformance_report
    ):
        raise QualificationError("Candidate collector conformance report is not canonical")
    if (
        BackendAdmissionReceipt.from_dict(
            backend_admission.to_dict(),
            conformance_report,
            attestation,
            manifest,
            catalog,
        )
        != backend_admission
    ):
        raise QualificationError("Candidate collector backend admission is not canonical")
    if backend_admission.status != "admitted_for_phase157_synthetic_only":
        raise QualificationError("Candidate collector requires an admitted backend")
    if (
        ContainmentBackendDeploymentBinding.from_dict(binding.to_dict(), catalog, attestation)
        != binding
    ):
        raise QualificationError("Candidate collector deployment binding is not canonical")
    if ContainmentHostSnapshot.from_dict(snapshot.to_dict()) != snapshot:
        raise QualificationError("Candidate collector host snapshot is not canonical")
    if (
        ContainmentHostPreflightReport.from_dict(
            preflight.to_dict(), binding, snapshot, catalog, attestation
        )
        != preflight
    ):
        raise QualificationError("Candidate collector host preflight is not canonical")
    if preflight.status != "ready_for_dynamic_conformance_nonqualifying":
        raise QualificationError("Candidate collector requires a passing host preflight")
    if (
        CandidateExecutionEvidenceChallenge.from_dict(
            challenge.to_dict(),
            manifest=manifest,
            attestation=attestation,
            conformance_catalog=catalog,
            conformance_report=conformance_report,
            backend_admission=backend_admission,
        )
        != challenge
    ):
        raise QualificationError("Candidate collector challenge is not canonical")
    if (
        ContainmentExecutionPlan.from_dict(
            execution_plan.to_dict(), manifest, invocation, attestation
        )
        != execution_plan
    ):
        raise QualificationError("Candidate collector execution plan is not canonical")
    binding_raw = binding.to_dict()
    challenge_raw = challenge.to_dict()
    if (
        binding_raw["host_id"] != snapshot.to_dict()["host_id"]
        or challenge_raw["manifest_sha256"] != manifest.manifest_sha256
        or challenge_raw["backend_attestation_sha256"] != attestation.attestation_sha256
        or challenge_raw["backend_admission_sha256"] != backend_admission.admission_sha256
    ):
        raise QualificationError("Candidate collector inputs are not bound to one execution")


@dataclass(frozen=True)
class CandidateExecutionCollectorPlan:
    plan_id: str
    plan_sha256: str
    adapter_id: str
    challenge_id: str
    execution_plan_id: str
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        *,
        manifest: AdapterManifest,
        invocation: AdapterInvocation,
        attestation: ContainmentBackendAttestation,
        catalog: ContainmentConformanceSuiteCatalog,
        conformance_report: BackendConformanceReport,
        backend_admission: BackendAdmissionReceipt,
        binding: ContainmentBackendDeploymentBinding,
        snapshot: ContainmentHostSnapshot,
        preflight: ContainmentHostPreflightReport,
        challenge: CandidateExecutionEvidenceChallenge,
        execution_plan: ContainmentExecutionPlan,
    ) -> CandidateExecutionCollectorPlan:
        expected_fields = {
            "schema_version",
            "plan_id",
            "plan_sha256",
            "adapter_id",
            "profile_id",
            "vector_id",
            "manifest_sha256",
            "backend_attestation_sha256",
            "conformance_report_sha256",
            "backend_admission_id",
            "backend_admission_sha256",
            "binding_id",
            "binding_sha256",
            "snapshot_id",
            "snapshot_sha256",
            "preflight_report_id",
            "preflight_report_sha256",
            "challenge_id",
            "challenge_sha256",
            "collector_id",
            "key_id",
            "sequence_number",
            "execution_plan_id",
            "execution_plan_sha256",
            "publication_contract",
            "status",
            "qualification_effect",
            "routing_effect",
            "deployment_effect",
            "target_authority_effect",
        }
        if not isinstance(raw, dict) or set(raw) != expected_fields:
            raise QualificationError("Candidate execution collector plan fields are invalid")
        _canonical_inputs(
            manifest=manifest,
            invocation=invocation,
            attestation=attestation,
            catalog=catalog,
            conformance_report=conformance_report,
            backend_admission=backend_admission,
            binding=binding,
            snapshot=snapshot,
            preflight=preflight,
            challenge=challenge,
            execution_plan=execution_plan,
        )
        challenge_raw = challenge.to_dict()
        preflight_raw = preflight.to_dict()
        expected_bindings = {
            "adapter_id": manifest.adapter_id,
            "profile_id": manifest.profile_id,
            "vector_id": manifest.vector_id,
            "manifest_sha256": manifest.manifest_sha256,
            "backend_attestation_sha256": attestation.attestation_sha256,
            "conformance_report_sha256": conformance_report.report_sha256,
            "backend_admission_id": backend_admission.admission_id,
            "backend_admission_sha256": backend_admission.admission_sha256,
            "binding_id": binding.binding_id,
            "binding_sha256": binding.binding_sha256,
            "snapshot_id": snapshot.snapshot_id,
            "snapshot_sha256": snapshot.snapshot_sha256,
            "preflight_report_id": preflight_raw["report_id"],
            "preflight_report_sha256": preflight_raw["report_sha256"],
            "challenge_id": challenge.challenge_id,
            "challenge_sha256": challenge.challenge_sha256,
            "collector_id": challenge_raw["collector_id"],
            "key_id": challenge_raw["key_id"],
            "sequence_number": challenge_raw["sequence_number"],
            "execution_plan_id": execution_plan.plan_id,
            "execution_plan_sha256": execution_plan.plan_sha256,
        }
        expected_contract = {
            "plan_file": PLAN_FILENAME,
            "submission_file": SUBMISSION_FILENAME,
            "manifest_file": MANIFEST_FILENAME,
            "packet_directory": PACKET_DIRECTORY,
            "collision_policy": "refuse_existing_output",
            "promotion_policy": "same_parent_atomic_rename",
            "failure_policy": "publish_signed_nonconforming",
            "readiness_policy": "clean_execution_only",
            "private_key_storage": "prohibited",
            "inventory_policy": "exact_no_extra_files",
        }
        if (
            raw.get("schema_version") != 1
            or any(raw.get(key) != value for key, value in expected_bindings.items())
            or raw.get("publication_contract") != expected_contract
            or raw.get("status") != "ready_for_external_execution_collection_nonqualifying"
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
            raise QualificationError("Candidate execution collector plan binding is invalid")
        plan_sha256 = _sha(raw.get("plan_sha256"), "candidate collector plan hash")
        plan_id = raw.get("plan_id")
        if not isinstance(plan_id, str) or PLAN_ID_PATTERN.fullmatch(plan_id) is None:
            raise QualificationError("Candidate execution collector plan ID is invalid")
        body = {key: value for key, value in raw.items() if key not in {"plan_id", "plan_sha256"}}
        expected_sha256 = _canonical_sha256({"domain": COLLECTOR_PLAN_DOMAIN, "plan": body})
        expected_id = f"CECPL-{expected_sha256.removeprefix('sha256:')[:32].upper()}"
        if plan_sha256 != expected_sha256 or plan_id != expected_id:
            raise QualificationError("Candidate execution collector plan identity is invalid")
        return cls(
            plan_id,
            plan_sha256,
            manifest.adapter_id,
            challenge.challenge_id,
            execution_plan.plan_id,
            _canonical_json(raw),
        )


def build_candidate_execution_collector_plan(
    *,
    manifest: AdapterManifest,
    invocation: AdapterInvocation,
    attestation: ContainmentBackendAttestation,
    catalog: ContainmentConformanceSuiteCatalog,
    conformance_report: BackendConformanceReport,
    backend_admission: BackendAdmissionReceipt,
    binding: ContainmentBackendDeploymentBinding,
    snapshot: ContainmentHostSnapshot,
    preflight: ContainmentHostPreflightReport,
    challenge: CandidateExecutionEvidenceChallenge,
    execution_plan: ContainmentExecutionPlan,
) -> CandidateExecutionCollectorPlan:
    challenge_raw = challenge.to_dict()
    preflight_raw = preflight.to_dict()
    body = {
        "schema_version": 1,
        "adapter_id": manifest.adapter_id,
        "profile_id": manifest.profile_id,
        "vector_id": manifest.vector_id,
        "manifest_sha256": manifest.manifest_sha256,
        "backend_attestation_sha256": attestation.attestation_sha256,
        "conformance_report_sha256": conformance_report.report_sha256,
        "backend_admission_id": backend_admission.admission_id,
        "backend_admission_sha256": backend_admission.admission_sha256,
        "binding_id": binding.binding_id,
        "binding_sha256": binding.binding_sha256,
        "snapshot_id": snapshot.snapshot_id,
        "snapshot_sha256": snapshot.snapshot_sha256,
        "preflight_report_id": preflight_raw["report_id"],
        "preflight_report_sha256": preflight_raw["report_sha256"],
        "challenge_id": challenge.challenge_id,
        "challenge_sha256": challenge.challenge_sha256,
        "collector_id": challenge_raw["collector_id"],
        "key_id": challenge_raw["key_id"],
        "sequence_number": challenge_raw["sequence_number"],
        "execution_plan_id": execution_plan.plan_id,
        "execution_plan_sha256": execution_plan.plan_sha256,
        "publication_contract": {
            "plan_file": PLAN_FILENAME,
            "submission_file": SUBMISSION_FILENAME,
            "manifest_file": MANIFEST_FILENAME,
            "packet_directory": PACKET_DIRECTORY,
            "collision_policy": "refuse_existing_output",
            "promotion_policy": "same_parent_atomic_rename",
            "failure_policy": "publish_signed_nonconforming",
            "readiness_policy": "clean_execution_only",
            "private_key_storage": "prohibited",
            "inventory_policy": "exact_no_extra_files",
        },
        "status": "ready_for_external_execution_collection_nonqualifying",
        "qualification_effect": "none",
        "routing_effect": "none",
        "deployment_effect": "none",
        "target_authority_effect": "none",
    }
    digest = _canonical_sha256({"domain": COLLECTOR_PLAN_DOMAIN, "plan": body})
    return CandidateExecutionCollectorPlan.from_dict(
        {
            **body,
            "plan_id": f"CECPL-{digest.removeprefix('sha256:')[:32].upper()}",
            "plan_sha256": digest,
        },
        manifest=manifest,
        invocation=invocation,
        attestation=attestation,
        catalog=catalog,
        conformance_report=conformance_report,
        backend_admission=backend_admission,
        binding=binding,
        snapshot=snapshot,
        preflight=preflight,
        challenge=challenge,
        execution_plan=execution_plan,
    )


@dataclass(frozen=True)
class PublishedCandidateExecutionCollection:
    output_directory: Path
    collection_id: str
    collection_sha256: str
    readiness_status: str
    failure_reasons: tuple[str, ...]
    plan: CandidateExecutionCollectorPlan
    packet: CandidateEvidencePacket
    submission: SignedCandidateExecutionEvidenceSubmission
    receipt: ContainmentExecutionReceipt
    result: AdapterResult
    verified_evidence: VerifiedCandidateExecutionEvidence | None


def _execution_outcome(
    receipt: ContainmentExecutionReceipt,
    result: AdapterResult,
) -> tuple[str, tuple[str, ...]]:
    receipt_raw = receipt.to_dict()
    reasons: list[str] = []
    if receipt.run_status != "completed_nonqualifying":
        reasons.append("receipt_not_completed")
    if receipt_raw["timed_out"]:
        reasons.append("execution_timed_out")
    if receipt_raw["cancelled"]:
        reasons.append("execution_cancelled")
    if result.status != "completed":
        reasons.append("result_not_completed")
    if result.restoration_status not in {"not_required", "verified"}:
        reasons.append("restoration_not_verified")
    if result.residual_effects:
        reasons.append("residual_effects_present")
    if reasons:
        return "published_signed_nonconforming", tuple(reasons)
    return "published_signed_import_ready", ()


def _packet_artifacts(packet: CandidateEvidencePacket) -> list[tuple[str, bytes]]:
    return [(f"{PACKET_DIRECTORY}/{path}", content) for path, content in packet.files]


def _artifact_records(files: list[tuple[str, bytes]]) -> list[dict[str, Any]]:
    return [
        {
            "path": path,
            "media_type": "application/json",
            "byte_size": len(content),
            "sha256": _sha256_bytes(content),
        }
        for path, content in sorted(files)
    ]


def _collection_manifest(
    *,
    plan: CandidateExecutionCollectorPlan,
    packet: CandidateEvidencePacket,
    submission: SignedCandidateExecutionEvidenceSubmission,
    receipt: ContainmentExecutionReceipt,
    result: AdapterResult,
    artifacts: list[dict[str, Any]],
) -> dict[str, Any]:
    readiness_status, reasons = _execution_outcome(receipt, result)
    body = {
        "schema_version": 1,
        "collector_plan_id": plan.plan_id,
        "collector_plan_sha256": plan.plan_sha256,
        "challenge_id": submission.challenge_id,
        "submission_id": submission.submission_id,
        "submission_sha256": submission.submission_sha256,
        "packet_id": packet.packet_id,
        "packet_sha256": packet.packet_sha256,
        "receipt_id": receipt.receipt_id,
        "receipt_sha256": receipt.receipt_sha256,
        "result_sha256": result.result_sha256,
        "artifacts": artifacts,
        "artifact_count": len(artifacts),
        "readiness_status": readiness_status,
        "failure_reasons": list(reasons),
        "qualification_effect": "none",
        "routing_effect": "none",
        "deployment_effect": "none",
        "target_authority_effect": "none",
    }
    digest = _canonical_sha256({"domain": COLLECTION_DOMAIN, "collection": body})
    return {
        **body,
        "collection_id": f"CECL-{digest.removeprefix('sha256:')[:32].upper()}",
        "collection_sha256": digest,
    }


def _validate_collection_manifest(
    raw: Any,
    *,
    plan: CandidateExecutionCollectorPlan,
    packet: CandidateEvidencePacket,
    submission: SignedCandidateExecutionEvidenceSubmission,
    receipt: ContainmentExecutionReceipt,
    result: AdapterResult,
    artifacts: list[dict[str, Any]],
) -> tuple[str, str, str, tuple[str, ...]]:
    expected = _collection_manifest(
        plan=plan,
        packet=packet,
        submission=submission,
        receipt=receipt,
        result=result,
        artifacts=artifacts,
    )
    if raw != expected:
        raise QualificationError("Candidate execution collection manifest is invalid")
    collection_id = raw.get("collection_id")
    if not isinstance(collection_id, str) or COLLECTION_ID_PATTERN.fullmatch(collection_id) is None:
        raise QualificationError("Candidate execution collection ID is invalid")
    return (
        collection_id,
        _sha(raw.get("collection_sha256"), "candidate execution collection hash"),
        raw["readiness_status"],
        tuple(raw["failure_reasons"]),
    )


def _safe_collection_path(relative: Any) -> PurePosixPath:
    if not isinstance(relative, str) or not relative or "\\" in relative or ":" in relative:
        raise QualificationError("Candidate execution collection path is unsafe")
    path = PurePosixPath(relative)
    if (
        not path.parts
        or path.is_absolute()
        or path.as_posix() != relative
        or any(part in {"", ".", ".."} for part in path.parts)
        or "\x00" in relative
    ):
        raise QualificationError("Candidate execution collection path is unsafe")
    return path


def _write_file(root: Path, relative: str, content: bytes) -> None:
    path = _safe_collection_path(relative)
    target = root.joinpath(*path.parts)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("xb") as stream:
        stream.write(content)


def _verify_inventory(root: Path, artifacts: list[dict[str, Any]]) -> None:
    if len(artifacts) > MAX_COLLECTION_ARTIFACTS:
        raise QualificationError("Candidate execution collection has too many artifacts")
    expected_fields = {"path", "media_type", "byte_size", "sha256"}
    total_bytes = 0
    for item in artifacts:
        if not isinstance(item, dict) or set(item) != expected_fields:
            raise QualificationError("Candidate execution collection artifact is invalid")
        relative = item.get("path")
        _safe_collection_path(relative)
        if item.get("media_type") != "application/json":
            raise QualificationError("Candidate execution collection artifact is invalid")
        limit = (
            MAX_COLLECTION_CONTROL_BYTES
            if relative in {PLAN_FILENAME, SUBMISSION_FILENAME}
            else MAX_PACKET_MANIFEST_BYTES
            if relative == f"{PACKET_DIRECTORY}/packet-manifest.json"
            else MAX_PACKET_ARTIFACT_BYTES
        )
        if (
            isinstance(item.get("byte_size"), bool)
            or not isinstance(item.get("byte_size"), int)
            or not 1 <= item["byte_size"] <= limit
        ):
            raise QualificationError("Candidate execution collection artifact is invalid")
        total_bytes += item["byte_size"]
        if total_bytes > MAX_COLLECTION_TOTAL_ARTIFACT_BYTES:
            raise QualificationError("Candidate execution collection artifacts exceed hard limits")
        _sha(item.get("sha256"), "candidate execution collection artifact hash")
    recorded_paths = [item.get("path") for item in artifacts]
    if len(recorded_paths) != len(set(recorded_paths)):
        raise QualificationError("Candidate execution collection artifact paths are duplicated")
    expected = {MANIFEST_FILENAME, *(item["path"] for item in artifacts)}
    expected_directories = {
        parent.as_posix()
        for relative in expected
        for parent in PurePosixPath(relative).parents
        if parent.as_posix() != "."
    }
    actual: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise QualificationError("Candidate execution collection cannot contain symlinks")
        relative = path.relative_to(root).as_posix()
        if path.is_file():
            if relative not in expected:
                raise QualificationError("Candidate execution collection inventory is not exact")
            actual.add(relative)
        elif path.is_dir():
            if relative not in expected_directories:
                raise QualificationError("Candidate execution collection inventory is not exact")
        else:
            raise QualificationError("Candidate execution collection contains a non-regular entry")
    if actual != expected:
        raise QualificationError("Candidate execution collection inventory is not exact")
    for item in artifacts:
        relative = item.get("path")
        path = root.joinpath(*_safe_collection_path(relative).parts)
        try:
            content = _read_bounded_regular_file(path, item["byte_size"])
        except OSError as exc:
            raise QualificationError(
                "Candidate execution collection artifact could not be loaded"
            ) from exc
        if len(content) != item.get("byte_size") or not hmac.compare_digest(
            _sha256_bytes(content), item.get("sha256", "")
        ):
            raise QualificationError("Candidate execution collection artifact integrity failed")


def _load_control_document(root: Path, filename: str) -> dict[str, Any]:
    path = root / filename
    if path.is_symlink():
        raise QualificationError("Candidate execution collection cannot contain symlinks")
    try:
        content = _read_bounded_regular_file(path, MAX_COLLECTION_CONTROL_BYTES)
    except OSError as exc:
        raise QualificationError("Candidate execution collection could not be loaded") from exc
    if not content or len(content) > MAX_COLLECTION_CONTROL_BYTES:
        raise QualificationError("Candidate execution collection control file exceeds hard limits")
    try:
        value = loads_json_without_duplicate_keys(content.decode("ascii"))
        if not isinstance(value, dict) or _canonical_json(value).encode("ascii") != content:
            raise QualificationError("Candidate execution collection control file is not canonical")
    except QualificationError:
        raise
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise QualificationError("Candidate execution collection could not be loaded") from exc
    return value


def _public_key_bytes(value: bytes | Ed25519PublicKey) -> bytes:
    if isinstance(value, bytes):
        if len(value) != 32:
            raise QualificationError("Candidate collector public key must be 32 bytes")
        try:
            key = Ed25519PublicKey.from_public_bytes(value)
        except ValueError as exc:
            raise QualificationError("Candidate collector public key is invalid") from exc
    elif isinstance(value, Ed25519PublicKey):
        key = value
    else:
        raise QualificationError("Candidate collector public key type is invalid")
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _verify_submission_signature(
    *,
    submission: SignedCandidateExecutionEvidenceSubmission,
    challenge: CandidateExecutionEvidenceChallenge,
    collector_public_key: bytes | Ed25519PublicKey,
    observed_at: str,
) -> None:
    challenge_raw = challenge.to_dict()
    public_bytes = _public_key_bytes(collector_public_key)
    if not hmac.compare_digest(_sha256_bytes(public_bytes), challenge_raw["public_key_sha256"]):
        raise QualificationError("Candidate collector public key does not match")
    collected_at = _utc(submission.collected_at, "candidate collection collected_at")
    issued_at = _utc(challenge_raw["issued_at"], "candidate collection issued_at")
    expires_at = _utc(challenge_raw["expires_at"], "candidate collection expires_at")
    observed = _utc(observed_at, "candidate collection observed_at")
    if not issued_at <= collected_at <= observed < expires_at:
        raise QualificationError("Candidate collection is outside the challenge validity window")
    _verify_ed25519(
        public_bytes,
        submission.to_dict()["signature"],
        submission.signing_bytes(),
        "Candidate execution evidence submission",
    )


def _load_packet_objects(
    *,
    packet_root: Path,
    packet: CandidateEvidencePacket,
    manifest: AdapterManifest,
    invocation: AdapterInvocation,
    attestation: ContainmentBackendAttestation,
    execution_plan: ContainmentExecutionPlan,
) -> tuple[ContainmentExecutionReceipt, AdapterResult]:
    files = dict(packet.files)
    try:
        packet_attestation = ContainmentBackendAttestation.from_dict(
            json.loads(files["backend-attestation.json"])
        )
        loaded_execution_plan = ContainmentExecutionPlan.from_dict(
            json.loads(files["execution-plan.json"]), manifest, invocation, attestation
        )
        receipt = ContainmentExecutionReceipt.from_dict(
            json.loads(files["execution-receipt.json"]), execution_plan
        )
        result = AdapterResult.from_dict(json.loads(files["adapter-result.json"]))
    except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise QualificationError("Candidate execution packet content is incomplete") from exc
    if packet_attestation != attestation or loaded_execution_plan != execution_plan:
        raise QualificationError("Candidate execution packet source binding is invalid")
    receipt_raw = receipt.to_dict()
    if (
        receipt.result_sha256 != result.result_sha256
        or receipt_raw["result_status"] != result.status
        or receipt_raw["result_disposition"] != result.disposition
        or receipt_raw["restoration_status"] != result.restoration_status
        or receipt_raw["residual_effects"] != list(result.residual_effects)
    ):
        raise QualificationError("Candidate execution receipt and result do not match")
    try:
        created_at = packet.manifest["created_at"]
    except KeyError as exc:
        raise QualificationError("Candidate execution packet content is incomplete") from exc
    expected_packet = CandidateEvidencePacket.build(
        manifest=manifest,
        attestation=attestation,
        plan=execution_plan,
        receipt=receipt,
        result=result,
        created_at=created_at,
    )
    if expected_packet != packet:
        raise QualificationError("Candidate execution packet does not match source artifacts")
    expected_packet_files = {path for path, _ in packet.files}
    actual_packet_files = {
        path.relative_to(packet_root).as_posix()
        for path in packet_root.rglob("*")
        if path.is_file()
    }
    if actual_packet_files != expected_packet_files:
        raise QualificationError("Candidate execution packet inventory is not exact")
    return receipt, result


def publish_signed_candidate_execution_collection(
    *,
    output_directory: str | Path,
    plan: CandidateExecutionCollectorPlan,
    manifest: AdapterManifest,
    invocation: AdapterInvocation,
    attestation: ContainmentBackendAttestation,
    catalog: ContainmentConformanceSuiteCatalog,
    conformance_report: BackendConformanceReport,
    backend_admission: BackendAdmissionReceipt,
    binding: ContainmentBackendDeploymentBinding,
    snapshot: ContainmentHostSnapshot,
    preflight: ContainmentHostPreflightReport,
    challenge: CandidateExecutionEvidenceChallenge,
    execution_plan: ContainmentExecutionPlan,
    receipt: ContainmentExecutionReceipt,
    result: AdapterResult,
    collected_at: str,
    signer: Callable[[bytes], bytes],
    collector_public_key: bytes | Ed25519PublicKey,
) -> PublishedCandidateExecutionCollection:
    verified_plan = CandidateExecutionCollectorPlan.from_dict(
        plan.to_dict(),
        manifest=manifest,
        invocation=invocation,
        attestation=attestation,
        catalog=catalog,
        conformance_report=conformance_report,
        backend_admission=backend_admission,
        binding=binding,
        snapshot=snapshot,
        preflight=preflight,
        challenge=challenge,
        execution_plan=execution_plan,
    )
    if verified_plan != plan:
        raise QualificationError("Candidate execution collector plan is not canonical")
    verified_receipt = ContainmentExecutionReceipt.from_dict(receipt.to_dict(), execution_plan)
    verified_result = AdapterResult.from_dict(result.to_dict())
    if verified_receipt != receipt or verified_result != result:
        raise QualificationError("Candidate execution outcome is not canonical")
    if not callable(signer):
        raise QualificationError("Candidate execution collector signer is not callable")
    packet = CandidateEvidencePacket.build(
        manifest=manifest,
        attestation=attestation,
        plan=execution_plan,
        receipt=receipt,
        result=result,
        created_at=collected_at,
    )
    unsigned = prepare_candidate_execution_evidence_submission(
        challenge=challenge,
        packet=packet,
        collected_at=collected_at,
    )
    signature_bytes = signer(unsigned.signing_bytes())
    if not isinstance(signature_bytes, bytes) or len(signature_bytes) != 64:
        raise QualificationError("Candidate execution signer must return 64 signature bytes")
    signature = base64.urlsafe_b64encode(signature_bytes).rstrip(b"=").decode("ascii")
    submission = finalize_candidate_execution_evidence_submission(
        unsigned,
        signature,
        challenge=challenge,
        packet=packet,
    )
    files = [
        (PLAN_FILENAME, plan.document_json.encode("ascii")),
        (SUBMISSION_FILENAME, submission.document_json.encode("ascii")),
        *_packet_artifacts(packet),
    ]
    artifacts = _artifact_records(files)
    collection_manifest = _collection_manifest(
        plan=plan,
        packet=packet,
        submission=submission,
        receipt=receipt,
        result=result,
        artifacts=artifacts,
    )
    output = Path(output_directory)
    if output.exists() or output.is_symlink():
        raise QualificationError("Candidate execution collection output already exists")
    try:
        parent = output.parent.resolve(strict=True)
    except OSError as exc:
        raise QualificationError("Candidate execution collection parent is unavailable") from exc
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=parent))
    try:
        for relative, content in files:
            _write_file(temporary, relative, content)
        _write_file(
            temporary,
            MANIFEST_FILENAME,
            _canonical_json(collection_manifest).encode("ascii"),
        )
        published = verify_published_candidate_execution_collection(
            directory=temporary,
            expected_plan=plan,
            manifest=manifest,
            invocation=invocation,
            attestation=attestation,
            catalog=catalog,
            conformance_report=conformance_report,
            backend_admission=backend_admission,
            binding=binding,
            snapshot=snapshot,
            preflight=preflight,
            challenge=challenge,
            execution_plan=execution_plan,
            collector_public_key=collector_public_key,
            observed_at=collected_at,
        )
        os.replace(temporary, output)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return PublishedCandidateExecutionCollection(
        output,
        published.collection_id,
        published.collection_sha256,
        published.readiness_status,
        published.failure_reasons,
        published.plan,
        published.packet,
        published.submission,
        published.receipt,
        published.result,
        published.verified_evidence,
    )


def verify_published_candidate_execution_collection(
    *,
    directory: str | Path,
    expected_plan: CandidateExecutionCollectorPlan,
    manifest: AdapterManifest,
    invocation: AdapterInvocation,
    attestation: ContainmentBackendAttestation,
    catalog: ContainmentConformanceSuiteCatalog,
    conformance_report: BackendConformanceReport,
    backend_admission: BackendAdmissionReceipt,
    binding: ContainmentBackendDeploymentBinding,
    snapshot: ContainmentHostSnapshot,
    preflight: ContainmentHostPreflightReport,
    challenge: CandidateExecutionEvidenceChallenge,
    execution_plan: ContainmentExecutionPlan,
    collector_public_key: bytes | Ed25519PublicKey,
    observed_at: str,
) -> PublishedCandidateExecutionCollection:
    source = Path(directory)
    if source.is_symlink():
        raise QualificationError("Candidate execution collection root cannot be a symlink")
    try:
        root = source.resolve(strict=True)
    except OSError as exc:
        raise QualificationError("Candidate execution collection is unavailable") from exc
    if not root.is_dir():
        raise QualificationError("Candidate execution collection must be a directory")
    plan_raw = _load_control_document(root, PLAN_FILENAME)
    submission_raw = _load_control_document(root, SUBMISSION_FILENAME)
    collection_raw = _load_control_document(root, MANIFEST_FILENAME)
    plan = CandidateExecutionCollectorPlan.from_dict(
        plan_raw,
        manifest=manifest,
        invocation=invocation,
        attestation=attestation,
        catalog=catalog,
        conformance_report=conformance_report,
        backend_admission=backend_admission,
        binding=binding,
        snapshot=snapshot,
        preflight=preflight,
        challenge=challenge,
        execution_plan=execution_plan,
    )
    if plan != expected_plan:
        raise QualificationError("Candidate execution collection plan does not match")
    artifacts = collection_raw.get("artifacts")
    if not isinstance(artifacts, list):
        raise QualificationError("Candidate execution collection artifacts are invalid")
    _verify_inventory(root, artifacts)
    packet_root = root / PACKET_DIRECTORY
    packet = CandidateEvidencePacket.from_directory(packet_root)
    receipt, result = _load_packet_objects(
        packet_root=packet_root,
        packet=packet,
        manifest=manifest,
        invocation=invocation,
        attestation=attestation,
        execution_plan=execution_plan,
    )
    submission = SignedCandidateExecutionEvidenceSubmission.from_dict(
        submission_raw,
        challenge=challenge,
        packet=packet,
    )
    _verify_submission_signature(
        submission=submission,
        challenge=challenge,
        collector_public_key=collector_public_key,
        observed_at=observed_at,
    )
    expected_artifacts = _artifact_records(
        [
            (PLAN_FILENAME, plan.document_json.encode("ascii")),
            (SUBMISSION_FILENAME, submission.document_json.encode("ascii")),
            *_packet_artifacts(packet),
        ]
    )
    collection_id, collection_sha256, readiness_status, reasons = _validate_collection_manifest(
        collection_raw,
        plan=plan,
        packet=packet,
        submission=submission,
        receipt=receipt,
        result=result,
        artifacts=expected_artifacts,
    )
    verified_evidence: VerifiedCandidateExecutionEvidence | None = None
    if readiness_status == "published_signed_import_ready":
        verified_evidence = verify_candidate_execution_evidence_submission(
            submission=submission,
            challenge=challenge,
            manifest=manifest,
            invocation=invocation,
            attestation=attestation,
            conformance_catalog=catalog,
            conformance_report=conformance_report,
            backend_admission=backend_admission,
            evidence_root=packet_root,
            collector_public_key=collector_public_key,
            observed_at=observed_at,
        )
    elif readiness_status != "published_signed_nonconforming" or not reasons:
        raise QualificationError("Candidate execution collection readiness is invalid")
    return PublishedCandidateExecutionCollection(
        root,
        collection_id,
        collection_sha256,
        readiness_status,
        reasons,
        plan,
        packet,
        submission,
        receipt,
        result,
        verified_evidence,
    )


__all__ = [
    "CandidateExecutionCollectorPlan",
    "PublishedCandidateExecutionCollection",
    "build_candidate_execution_collector_plan",
    "publish_signed_candidate_execution_collection",
    "verify_published_candidate_execution_collection",
]
