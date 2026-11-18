"""Immutable evidence packets and Phase 157 development-gate records."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from .candidate_adapter_runner import (
    ContainmentBackendAttestation,
    ContainmentExecutionPlan,
    ContainmentExecutionReceipt,
)
from .candidate_adapter_sdk import AdapterManifest, AdapterResult, CandidateAdapterCatalog
from .errors import QualificationError
from .qualification import _canonical_json, _canonical_sha256
from .validation import loads_json_without_duplicate_keys

PACKET_DOMAIN = "sunderkey.candidate-evidence-packet.v1"
GATE_DOMAIN = "sunderkey.candidate-development-gate.v1"
GATE_CATALOG_DOMAIN = "sunderkey.candidate-development-gate-catalog.v1"
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
PACKET_ID_PATTERN = re.compile(r"CEPK-[0-9A-F]{32}")
MAX_PACKET_MANIFEST_BYTES = 1_000_000
MAX_PACKET_ARTIFACT_BYTES = 8_000_000
MAX_PACKET_TOTAL_BYTES = 64_000_000
MAX_PACKET_ARTIFACTS = 256
GATE_STAGES = (
    "static_analysis",
    "unit",
    "integration",
    "containment",
    "evidence",
    "restoration",
)
PASS_STATUS = "passed_reference_nonqualifying"
BLOCKED_STATUS = "blocked_pending_backend_conformance"
SOURCE_FILES = {
    "sdk": "src/sunderkey/candidate_adapter_sdk.py",
    "adapter": "src/sunderkey/reference_adapters.py",
    "runner": "src/sunderkey/candidate_adapter_runner.py",
    "evidence": "src/sunderkey/candidate_adapter_evidence.py",
    "sdk_tests": "tests/agents/test_candidate_adapter_sdk_phase157.py",
    "runner_tests": "tests/agents/test_candidate_adapter_runner_phase157.py",
    "evidence_tests": "tests/agents/test_candidate_adapter_evidence_phase157.py",
}


def _bytes_sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _utc(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise QualificationError(f"{label} must use UTC Z notation")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise QualificationError(f"{label} is invalid") from exc
    if parsed.tzinfo != timezone.utc or parsed.microsecond:
        raise QualificationError(f"{label} must be whole-second UTC")
    return value


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    return (_canonical_json(dict(value)) + "\n").encode("utf-8")


def _strict_packet_json(content: bytes, label: str) -> dict[str, Any]:
    try:
        value = loads_json_without_duplicate_keys(content.decode("utf-8"))
        if not isinstance(value, dict) or _json_bytes(value) != content:
            raise QualificationError(f"{label} is not canonical JSON")
        return value
    except QualificationError:
        raise
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise QualificationError(f"{label} could not be loaded") from exc


def _read_bounded_regular_file(path: Path, maximum_bytes: int) -> bytes:
    """Read no more than the limit plus one byte without opening a pipe blocking."""
    if not stat.S_ISREG(path.lstat().st_mode):
        raise OSError("Evidence source is not a regular file")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError("Evidence source is not a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            return stream.read(maximum_bytes + 1)
    finally:
        os.close(descriptor)


@dataclass(frozen=True)
class CandidateEvidencePacket:
    packet_id: str
    packet_sha256: str
    manifest_json: str
    files: tuple[tuple[str, bytes], ...]

    @property
    def manifest(self) -> dict[str, Any]:
        return json.loads(self.manifest_json)

    @classmethod
    def build(
        cls,
        *,
        manifest: AdapterManifest,
        attestation: ContainmentBackendAttestation,
        plan: ContainmentExecutionPlan,
        receipt: ContainmentExecutionReceipt,
        result: AdapterResult,
        created_at: str,
    ) -> CandidateEvidencePacket:
        _utc(created_at, "evidence packet created_at")
        receipt_document = receipt.to_dict()
        ContainmentExecutionReceipt.from_dict(receipt_document, plan)
        if datetime.fromisoformat(receipt_document["finished_at"].removesuffix("Z") + "+00:00") > (
            datetime.fromisoformat(created_at.removesuffix("Z") + "+00:00")
        ):
            raise QualificationError("Evidence packet creation predates completed execution")
        if (
            plan.adapter_id != manifest.adapter_id
            or plan.manifest_sha256 != manifest.manifest_sha256
            or plan.backend_attestation_sha256 != attestation.attestation_sha256
            or receipt.plan_id != plan.plan_id
            or receipt.result_sha256 != result.result_sha256
        ):
            raise QualificationError("Evidence packet source bindings are inconsistent")
        payloads: dict[str, bytes] = {
            "backend-attestation.json": _json_bytes(attestation.to_dict()),
            "execution-plan.json": _json_bytes(plan.to_dict()),
            "execution-receipt.json": _json_bytes(receipt_document),
            "adapter-result.json": _json_bytes(result.to_dict()),
        }
        for index, evidence in enumerate(result.evidence):
            payloads[f"evidence/{index:03d}.json"] = _json_bytes(evidence.to_dict())
        if (
            len(payloads) > MAX_PACKET_ARTIFACTS
            or any(len(content) > MAX_PACKET_ARTIFACT_BYTES for content in payloads.values())
            or sum(len(content) for content in payloads.values()) > MAX_PACKET_TOTAL_BYTES
        ):
            raise QualificationError("Evidence packet artifacts exceed hard limits")
        artifacts = [
            {
                "path": path,
                "media_type": "application/json",
                "byte_size": len(content),
                "sha256": _bytes_sha256(content),
            }
            for path, content in sorted(payloads.items())
        ]
        body = {
            "schema_version": 1,
            "adapter_id": manifest.adapter_id,
            "adapter_version": manifest.adapter_version,
            "profile_id": manifest.profile_id,
            "vector_id": manifest.vector_id,
            "manifest_sha256": manifest.manifest_sha256,
            "backend_attestation_sha256": attestation.attestation_sha256,
            "plan_id": plan.plan_id,
            "plan_sha256": plan.plan_sha256,
            "receipt_id": receipt.receipt_id,
            "receipt_sha256": receipt.receipt_sha256,
            "result_sha256": result.result_sha256,
            "evidence_sha256": [item.content_sha256 for item in result.evidence],
            "created_at": created_at,
            "artifacts": artifacts,
            "custody_status": "local_untrusted_development",
            "qualification_effect": "none",
            "routing_effect": "none",
            "deployment_effect": "none",
            "target_authority_effect": "none",
        }
        digest = _canonical_sha256({"domain": PACKET_DOMAIN, "packet": body})
        packet_id = f"CEPK-{digest.removeprefix('sha256:')[:32].upper()}"
        packet_manifest = {**body, "packet_id": packet_id, "packet_sha256": digest}
        all_files = {**payloads, "packet-manifest.json": _json_bytes(packet_manifest)}
        if (
            len(all_files["packet-manifest.json"]) > MAX_PACKET_MANIFEST_BYTES
            or sum(len(content) for content in all_files.values()) > MAX_PACKET_TOTAL_BYTES
        ):
            raise QualificationError("Evidence packet manifest exceeds hard limits")
        return cls(
            packet_id,
            digest,
            _canonical_json(packet_manifest),
            tuple(sorted(all_files.items())),
        )

    @classmethod
    def from_directory(cls, source: str | Path) -> CandidateEvidencePacket:
        source_path = Path(source)
        if source_path.is_symlink():
            raise QualificationError("Evidence packet root cannot be a symlink")
        try:
            root = source_path.resolve(strict=True)
            if not root.is_dir():
                raise QualificationError("Evidence packet root must be a directory")
            manifest_path = root / "packet-manifest.json"
            if manifest_path.is_symlink():
                raise QualificationError("Evidence packet manifest cannot be a symlink")
            manifest_bytes = _read_bounded_regular_file(manifest_path, MAX_PACKET_MANIFEST_BYTES)
        except QualificationError:
            raise
        except OSError as exc:
            raise QualificationError(f"Could not load evidence packet: {source_path}") from exc
        if not manifest_bytes or len(manifest_bytes) > MAX_PACKET_MANIFEST_BYTES:
            raise QualificationError("Evidence packet manifest exceeds hard limits")
        manifest = _strict_packet_json(manifest_bytes, "Evidence packet manifest")
        packet_id = manifest.get("packet_id")
        packet_sha256 = manifest.get("packet_sha256")
        if not isinstance(packet_id, str) or PACKET_ID_PATTERN.fullmatch(packet_id) is None:
            raise QualificationError("Evidence packet ID is invalid")
        if not isinstance(packet_sha256, str) or SHA256_PATTERN.fullmatch(packet_sha256) is None:
            raise QualificationError("Evidence packet hash is invalid")
        body = {
            key: value
            for key, value in manifest.items()
            if key not in {"packet_id", "packet_sha256"}
        }
        expected_sha256 = _canonical_sha256({"domain": PACKET_DOMAIN, "packet": body})
        expected_id = f"CEPK-{expected_sha256.removeprefix('sha256:')[:32].upper()}"
        if packet_sha256 != expected_sha256 or packet_id != expected_id:
            raise QualificationError("Evidence packet identity does not match content")
        artifacts = manifest.get("artifacts")
        if not isinstance(artifacts, list) or len(artifacts) > MAX_PACKET_ARTIFACTS:
            raise QualificationError("Evidence packet artifacts must be a bounded list")
        files: dict[str, bytes] = {}
        total_bytes = len(manifest_bytes)
        for item in artifacts:
            if not isinstance(item, dict) or set(item) != {
                "path",
                "media_type",
                "byte_size",
                "sha256",
            }:
                raise QualificationError("Evidence packet artifact record is invalid")
            relative = item.get("path")
            if not isinstance(relative, str):
                raise QualificationError("Evidence packet artifact path or type is invalid")
            relative_path = PurePosixPath(relative)
            if (
                relative == "packet-manifest.json"
                or relative_path.is_absolute()
                or relative_path.as_posix() != relative
                or any(part in {"", ".", ".."} for part in relative_path.parts)
                or "\\" in relative
                or ":" in relative
                or item.get("media_type") != "application/json"
            ):
                raise QualificationError("Evidence packet artifact path or type is invalid")
            byte_size = item.get("byte_size")
            if (
                isinstance(byte_size, bool)
                or not isinstance(byte_size, int)
                or not 1 <= byte_size <= MAX_PACKET_ARTIFACT_BYTES
                or total_bytes + byte_size > MAX_PACKET_TOTAL_BYTES
                or relative in files
            ):
                raise QualificationError("Evidence packet artifact exceeds hard limits")
            total_bytes += byte_size
            path = root.joinpath(*relative_path.parts)
            if path.is_symlink():
                raise QualificationError("Evidence packet artifact cannot be a symlink")
            try:
                content = _read_bounded_regular_file(path, byte_size)
            except OSError as exc:
                raise QualificationError(f"Could not load evidence artifact: {relative}") from exc
            if len(content) != byte_size or _bytes_sha256(content) != item.get("sha256"):
                raise QualificationError(f"Evidence artifact integrity failed: {relative}")
            _strict_packet_json(content, f"Evidence artifact {relative}")
            files[relative] = content
        expected_files = {*files, "packet-manifest.json"}
        expected_directories = {
            parent.as_posix()
            for relative in expected_files
            for parent in PurePosixPath(relative).parents
            if parent.as_posix() != "."
        }
        actual = set()
        for path in root.rglob("*"):
            if path.is_symlink():
                raise QualificationError("Evidence packet cannot contain symlinks")
            relative = path.relative_to(root).as_posix()
            if path.is_file():
                if relative not in expected_files:
                    raise QualificationError("Evidence packet inventory is not exact")
                actual.add(relative)
            elif path.is_dir():
                if relative not in expected_directories:
                    raise QualificationError("Evidence packet inventory is not exact")
            else:
                raise QualificationError("Evidence packet contains a non-regular entry")
        if actual != expected_files:
            raise QualificationError("Evidence packet inventory is not exact")
        files["packet-manifest.json"] = manifest_bytes
        return cls(
            packet_id,
            packet_sha256,
            _canonical_json(manifest),
            tuple(sorted(files.items())),
        )

    def publish(self, output_directory: str | Path) -> Path:
        if not 1 <= len(self.files) <= MAX_PACKET_ARTIFACTS + 1:
            raise QualificationError("Evidence packet file count exceeds hard limits")
        prepared: dict[str, bytes] = {}
        total_bytes = 0
        for relative, content in self.files:
            if not isinstance(relative, str) or not isinstance(content, bytes):
                raise QualificationError("Evidence packet file entry is invalid")
            relative_path = PurePosixPath(relative)
            if (
                not relative_path.parts
                or relative_path.is_absolute()
                or relative_path.as_posix() != relative
                or any(part in {"", ".", ".."} for part in relative_path.parts)
                or "\\" in relative
                or ":" in relative
                or relative in prepared
            ):
                raise QualificationError("Evidence packet file path is invalid")
            limit = (
                MAX_PACKET_MANIFEST_BYTES
                if relative == "packet-manifest.json"
                else MAX_PACKET_ARTIFACT_BYTES
            )
            if not content or len(content) > limit:
                raise QualificationError("Evidence packet file exceeds hard limits")
            total_bytes += len(content)
            if total_bytes > MAX_PACKET_TOTAL_BYTES:
                raise QualificationError("Evidence packet files exceed hard limits")
            prepared[relative] = content
        if "packet-manifest.json" not in prepared or not isinstance(self.manifest_json, str):
            raise QualificationError("Evidence packet manifest is missing")
        try:
            declared_manifest = (self.manifest_json + "\n").encode("utf-8")
        except UnicodeError as exc:
            raise QualificationError("Evidence packet manifest is invalid") from exc
        if prepared["packet-manifest.json"] != declared_manifest:
            raise QualificationError("Evidence packet manifest does not match published files")
        destination = Path(output_directory)
        if destination.exists() or destination.is_symlink():
            raise QualificationError(f"Evidence packet output already exists: {destination}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix=f".{destination.name}.", dir=destination.parent
        ) as temporary_name:
            temporary = Path(temporary_name)
            for relative, content in prepared.items():
                target = temporary / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
            loaded = CandidateEvidencePacket.from_directory(temporary)
            if (
                loaded.packet_id != self.packet_id
                or loaded.packet_sha256 != self.packet_sha256
                or loaded.files != tuple(sorted(self.files))
            ):
                raise QualificationError("Evidence packet publication source is inconsistent")
            if destination.exists() or destination.is_symlink():
                raise QualificationError(f"Evidence packet output already exists: {destination}")
            os.replace(temporary, destination)
        return destination


@dataclass(frozen=True)
class CandidateDevelopmentGateCatalog:
    catalog_sha256: str
    gate_records: tuple[dict[str, Any], ...]
    document_json: str

    @property
    def records_by_profile_id(self) -> dict[str, tuple[dict[str, Any], ...]]:
        result: dict[str, list[dict[str, Any]]] = {}
        for record in self.gate_records:
            result.setdefault(record["profile_id"], []).append(dict(record))
        return {key: tuple(value) for key, value in result.items()}

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        adapters: CandidateAdapterCatalog,
    ) -> CandidateDevelopmentGateCatalog:
        expected_fields = {
            "schema_version",
            "catalog_id",
            "catalog_version",
            "catalog_sha256",
            "adapter_catalog_sha256",
            "required_stages",
            "gate_records",
            "candidate_summaries",
            "coverage_summary",
            "phase158_admission_status",
            "qualification_effect",
            "routing_effect",
            "deployment_effect",
            "limitations",
        }
        if not isinstance(raw, dict) or set(raw) != expected_fields:
            raise QualificationError("Development gate catalog fields are invalid")
        if (
            raw.get("schema_version") != 1
            or raw.get("catalog_id") != "sunderkey-candidate-development-gates-v1"
            or raw.get("catalog_version") != "0.1.0"
            or raw.get("adapter_catalog_sha256") != adapters.catalog_sha256
            or raw.get("required_stages") != list(GATE_STAGES)
            or raw.get("phase158_admission_status") != "blocked"
            or any(
                raw.get(field) != "none"
                for field in ("qualification_effect", "routing_effect", "deployment_effect")
            )
        ):
            raise QualificationError("Development gate catalog binding is invalid")
        records = raw.get("gate_records")
        if not isinstance(records, list) or len(records) != len(adapters.manifests) * 6:
            raise QualificationError("Development gate records are incomplete")
        parsed: list[dict[str, Any]] = []
        expected_pairs = [
            (manifest.profile_id, stage) for manifest in adapters.manifests for stage in GATE_STAGES
        ]
        for record, expected_pair in zip(records, expected_pairs, strict=True):
            if not isinstance(record, dict) or set(record) != {
                "profile_id",
                "adapter_id",
                "manifest_sha256",
                "stage",
                "status",
                "evidence_sha256",
                "blockers",
                "gate_sha256",
            }:
                raise QualificationError("Development gate record fields are invalid")
            if (record.get("profile_id"), record.get("stage")) != expected_pair:
                raise QualificationError("Development gate records are unordered or misbound")
            if record.get("stage") == "containment":
                if record.get("status") != BLOCKED_STATUS or record.get("blockers") != [
                    "external_backend_not_installed",
                    "backend_conformance_receipt_missing",
                ]:
                    raise QualificationError("Containment gate must remain blocked")
            elif record.get("status") != PASS_STATUS or record.get("blockers") != []:
                raise QualificationError("Reference development gate status is invalid")
            evidence = record.get("evidence_sha256")
            if (
                not isinstance(evidence, list)
                or not evidence
                or any(
                    not isinstance(item, str) or SHA256_PATTERN.fullmatch(item) is None
                    for item in evidence
                )
            ):
                raise QualificationError("Development gate evidence is invalid")
            body = {key: value for key, value in record.items() if key != "gate_sha256"}
            if record.get("gate_sha256") != _canonical_sha256(
                {"domain": GATE_DOMAIN, "gate": body}
            ):
                raise QualificationError("Development gate hash does not match content")
            parsed.append(dict(record))
        summaries = raw.get("candidate_summaries")
        expected_summaries = [
            {
                "profile_id": manifest.profile_id,
                "adapter_id": manifest.adapter_id,
                "passed_gate_count": 5,
                "blocked_gate_count": 1,
                "phase158_admission": "blocked",
            }
            for manifest in adapters.manifests
        ]
        if summaries != expected_summaries or raw.get("coverage_summary") != {
            "candidate_count": 6,
            "gate_record_count": 36,
            "passed_reference_gate_count": 30,
            "blocked_gate_count": 6,
            "phase158_ready_candidate_count": 0,
        }:
            raise QualificationError("Development gate coverage summary is invalid")
        limitations = raw.get("limitations")
        if not isinstance(limitations, list) or len(limitations) < 4:
            raise QualificationError("Development gate limitations are incomplete")
        body = {key: value for key, value in raw.items() if key != "catalog_sha256"}
        digest = _canonical_sha256({"domain": GATE_CATALOG_DOMAIN, "catalog": body})
        if raw.get("catalog_sha256") != digest:
            raise QualificationError("Development gate catalog hash does not match content")
        return cls(digest, tuple(parsed), _canonical_json(raw))


def build_candidate_development_gate_catalog(
    adapters: CandidateAdapterCatalog,
    source_root: str | Path,
) -> CandidateDevelopmentGateCatalog:
    root = Path(source_root)
    source_digests = {
        name: _bytes_sha256((root / relative).read_bytes())
        for name, relative in SOURCE_FILES.items()
    }
    evidence_by_stage = {
        "static_analysis": [
            source_digests["sdk"],
            source_digests["adapter"],
            source_digests["runner"],
        ],
        "unit": [source_digests["sdk_tests"], source_digests["runner_tests"]],
        "integration": [source_digests["sdk_tests"], source_digests["runner_tests"]],
        "containment": [source_digests["runner"], source_digests["runner_tests"]],
        "evidence": [source_digests["evidence"], source_digests["evidence_tests"]],
        "restoration": [source_digests["adapter"], source_digests["sdk_tests"]],
    }
    records: list[dict[str, Any]] = []
    for manifest in adapters.manifests:
        for stage in GATE_STAGES:
            body = {
                "profile_id": manifest.profile_id,
                "adapter_id": manifest.adapter_id,
                "manifest_sha256": manifest.manifest_sha256,
                "stage": stage,
                "status": BLOCKED_STATUS if stage == "containment" else PASS_STATUS,
                "evidence_sha256": evidence_by_stage[stage],
                "blockers": [
                    "external_backend_not_installed",
                    "backend_conformance_receipt_missing",
                ]
                if stage == "containment"
                else [],
            }
            records.append(
                {
                    **body,
                    "gate_sha256": _canonical_sha256({"domain": GATE_DOMAIN, "gate": body}),
                }
            )
    body = {
        "schema_version": 1,
        "catalog_id": "sunderkey-candidate-development-gates-v1",
        "catalog_version": "0.1.0",
        "adapter_catalog_sha256": adapters.catalog_sha256,
        "required_stages": list(GATE_STAGES),
        "gate_records": records,
        "candidate_summaries": [
            {
                "profile_id": manifest.profile_id,
                "adapter_id": manifest.adapter_id,
                "passed_gate_count": 5,
                "blocked_gate_count": 1,
                "phase158_admission": "blocked",
            }
            for manifest in adapters.manifests
        ],
        "coverage_summary": {
            "candidate_count": 6,
            "gate_record_count": 36,
            "passed_reference_gate_count": 30,
            "blocked_gate_count": 6,
            "phase158_ready_candidate_count": 0,
        },
        "phase158_admission_status": "blocked",
        "qualification_effect": "none",
        "routing_effect": "none",
        "deployment_effect": "none",
        "limitations": [
            "Reference gate passes are development evidence, not qualification decisions.",
            "Containment remains blocked until a concrete backend passes conformance.",
            "No gate record grants mission, target, routing, or deployment authority.",
            "The remaining 385 specialist candidates are outside this reference slice.",
        ],
    }
    digest = _canonical_sha256({"domain": GATE_CATALOG_DOMAIN, "catalog": body})
    return CandidateDevelopmentGateCatalog.from_dict({**body, "catalog_sha256": digest}, adapters)


def load_candidate_development_gate_catalog(
    source: str | Path,
    adapters: CandidateAdapterCatalog,
) -> CandidateDevelopmentGateCatalog:
    try:
        raw = json.loads(Path(source).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise QualificationError(f"Could not load development gate catalog: {source}") from exc
    return CandidateDevelopmentGateCatalog.from_dict(raw, adapters)


__all__ = [
    "BLOCKED_STATUS",
    "CandidateDevelopmentGateCatalog",
    "CandidateEvidencePacket",
    "GATE_STAGES",
    "PASS_STATUS",
    "build_candidate_development_gate_catalog",
    "load_candidate_development_gate_catalog",
]
