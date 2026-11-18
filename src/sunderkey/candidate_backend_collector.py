"""Fail-closed host collector packaging for Phase 157 conformance evidence."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .candidate_adapter_evidence import _read_bounded_regular_file
from .candidate_adapter_runner import ContainmentBackendAttestation
from .candidate_backend_conformance import (
    BackendConformanceReport,
    ContainmentConformanceSuiteCatalog,
    build_conformance_observation,
)
from .candidate_backend_evidence_import import (
    ConformanceProbeChallenge,
    SignedConformanceObservationBatch,
    VerifiedConformanceObservationBatch,
    finalize_conformance_observation_batch,
    prepare_conformance_observation_batch,
    verify_conformance_observation_batch,
)
from .candidate_backend_host_preflight import (
    ContainmentBackendDeploymentBinding,
    ContainmentHostPreflightReport,
    ContainmentHostSnapshot,
)
from .errors import QualificationError
from .qualification import _canonical_json, _canonical_sha256
from .validation import loads_json_without_duplicate_keys

COLLECTOR_PLAN_DOMAIN = "sunderkey.containment-conformance-collector-plan.v1"
COLLECTION_MANIFEST_DOMAIN = "sunderkey.containment-conformance-collection.v1"
PLAN_ID_PATTERN = re.compile(r"BCP-[0-9A-F]{32}")
COLLECTION_ID_PATTERN = re.compile(r"BCL-[0-9A-F]{32}")
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
MAX_PROBE_EVIDENCE_BYTES = 1_048_576
MAX_PROBE_MEASUREMENT_BYTES = 65_536
MAX_COLLECTION_METADATA_BYTES = 4_000_000
PROBE_TIMEOUT_SECONDS = 120
PLAN_FILENAME = "collector-plan.json"
BATCH_FILENAME = "observation-batch.json"
MANIFEST_FILENAME = "collection-manifest.json"


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise QualificationError(f"{label} must be a SHA-256 digest")
    return value


def _safe_relative_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or not value.isascii():
        raise QualificationError(f"{label} must be nonempty ASCII text")
    if "\\" in value or ":" in value or "\x00" in value:
        raise QualificationError(f"{label} must use a portable relative path")
    path = PurePosixPath(value)
    if (
        not path.parts
        or path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise QualificationError(f"{label} must be a safe relative path")
    return path.as_posix()


def _suite(
    catalog: ContainmentConformanceSuiteCatalog,
    isolation_class: str,
) -> dict[str, Any]:
    suite = next(
        (item for item in catalog.suites if item["isolation_class"] == isolation_class),
        None,
    )
    if suite is None:
        raise QualificationError("Collector conformance suite is unavailable")
    return suite


def _canonical_inputs(
    *,
    catalog: ContainmentConformanceSuiteCatalog,
    attestation: ContainmentBackendAttestation,
    binding: ContainmentBackendDeploymentBinding,
    snapshot: ContainmentHostSnapshot,
    preflight: ContainmentHostPreflightReport,
    challenge: ConformanceProbeChallenge,
) -> None:
    if ContainmentConformanceSuiteCatalog.from_dict(catalog.to_dict()) != catalog:
        raise QualificationError("Collector suite catalog is not canonical")
    if ContainmentBackendAttestation.from_dict(attestation.to_dict()) != attestation:
        raise QualificationError("Collector backend attestation is not canonical")
    if (
        ContainmentBackendDeploymentBinding.from_dict(binding.to_dict(), catalog, attestation)
        != binding
    ):
        raise QualificationError("Collector deployment binding is not canonical")
    if ContainmentHostSnapshot.from_dict(snapshot.to_dict()) != snapshot:
        raise QualificationError("Collector host snapshot is not canonical")
    if (
        ContainmentHostPreflightReport.from_dict(
            preflight.to_dict(), binding, snapshot, catalog, attestation
        )
        != preflight
    ):
        raise QualificationError("Collector host preflight is not canonical")
    if preflight.status != "ready_for_dynamic_conformance_nonqualifying":
        raise QualificationError("Collector requires a passing host preflight")
    if ConformanceProbeChallenge.from_dict(challenge.to_dict(), catalog, attestation) != challenge:
        raise QualificationError("Collector challenge is not canonical")


def _probe_steps(probe_ids: list[str]) -> list[dict[str, Any]]:
    return [
        {
            "sequence": index,
            "probe_id": probe_id,
            "evidence_path": f"evidence/{index:02d}-{probe_id}.json",
            "media_type": "application/json",
            "maximum_evidence_bytes": MAX_PROBE_EVIDENCE_BYTES,
            "timeout_seconds": PROBE_TIMEOUT_SECONDS,
            "failure_policy": "record_failure_and_continue",
        }
        for index, probe_id in enumerate(probe_ids, start=1)
    ]


@dataclass(frozen=True)
class ConformanceCollectorPlan:
    plan_id: str
    plan_sha256: str
    isolation_class: str
    probe_count: int
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        *,
        catalog: ContainmentConformanceSuiteCatalog,
        attestation: ContainmentBackendAttestation,
        binding: ContainmentBackendDeploymentBinding,
        snapshot: ContainmentHostSnapshot,
        preflight: ContainmentHostPreflightReport,
        challenge: ConformanceProbeChallenge,
    ) -> ConformanceCollectorPlan:
        expected_fields = {
            "schema_version",
            "plan_id",
            "plan_sha256",
            "suite_catalog_sha256",
            "backend_attestation_sha256",
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
            "isolation_class",
            "host_id",
            "service_identity_id",
            "probe_steps",
            "publication_contract",
            "status",
            "qualification_effect",
            "routing_effect",
            "deployment_effect",
            "target_authority_effect",
        }
        if not isinstance(raw, dict) or set(raw) != expected_fields:
            raise QualificationError("Conformance collector plan fields are invalid")
        _canonical_inputs(
            catalog=catalog,
            attestation=attestation,
            binding=binding,
            snapshot=snapshot,
            preflight=preflight,
            challenge=challenge,
        )
        suite = _suite(catalog, attestation.isolation_class)
        binding_raw = binding.to_dict()
        preflight_raw = preflight.to_dict()
        challenge_raw = challenge.to_dict()
        expected_steps = _probe_steps(suite["probe_ids"])
        expected_publication = {
            "plan_file": PLAN_FILENAME,
            "batch_file": BATCH_FILENAME,
            "manifest_file": MANIFEST_FILENAME,
            "collision_policy": "refuse_existing_output",
            "promotion_policy": "same_parent_atomic_rename",
            "private_key_storage": "prohibited",
            "evidence_inventory": "exact_no_extra_files",
        }
        if (
            raw.get("schema_version") != 1
            or raw.get("suite_catalog_sha256") != catalog.catalog_sha256
            or raw.get("backend_attestation_sha256") != attestation.attestation_sha256
            or raw.get("binding_id") != binding.binding_id
            or raw.get("binding_sha256") != binding.binding_sha256
            or raw.get("snapshot_id") != snapshot.snapshot_id
            or raw.get("snapshot_sha256") != snapshot.snapshot_sha256
            or raw.get("preflight_report_id") != preflight_raw["report_id"]
            or raw.get("preflight_report_sha256") != preflight_raw["report_sha256"]
            or raw.get("challenge_id") != challenge.challenge_id
            or raw.get("challenge_sha256") != challenge.challenge_sha256
            or raw.get("collector_id") != challenge_raw["collector_id"]
            or raw.get("key_id") != challenge_raw["key_id"]
            or raw.get("sequence_number") != challenge_raw["sequence_number"]
            or raw.get("isolation_class") != attestation.isolation_class
            or raw.get("host_id") != binding_raw["host_id"]
            or raw.get("service_identity_id") != binding_raw["service_identity_id"]
            or raw.get("probe_steps") != expected_steps
            or raw.get("publication_contract") != expected_publication
            or raw.get("status") != "ready_for_external_host_collection_nonqualifying"
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
            raise QualificationError("Conformance collector plan binding is invalid")
        plan_sha256 = _sha(raw.get("plan_sha256"), "collector plan hash")
        plan_id = raw.get("plan_id")
        if not isinstance(plan_id, str) or PLAN_ID_PATTERN.fullmatch(plan_id) is None:
            raise QualificationError("Conformance collector plan ID is invalid")
        body = {key: value for key, value in raw.items() if key not in {"plan_id", "plan_sha256"}}
        expected_sha256 = _canonical_sha256({"domain": COLLECTOR_PLAN_DOMAIN, "plan": body})
        expected_id = f"BCP-{expected_sha256.removeprefix('sha256:')[:32].upper()}"
        if plan_sha256 != expected_sha256 or plan_id != expected_id:
            raise QualificationError("Conformance collector plan identity is invalid")
        return cls(
            plan_id,
            plan_sha256,
            attestation.isolation_class,
            len(expected_steps),
            _canonical_json(raw),
        )


def build_conformance_collector_plan(
    *,
    catalog: ContainmentConformanceSuiteCatalog,
    attestation: ContainmentBackendAttestation,
    binding: ContainmentBackendDeploymentBinding,
    snapshot: ContainmentHostSnapshot,
    preflight: ContainmentHostPreflightReport,
    challenge: ConformanceProbeChallenge,
) -> ConformanceCollectorPlan:
    _canonical_inputs(
        catalog=catalog,
        attestation=attestation,
        binding=binding,
        snapshot=snapshot,
        preflight=preflight,
        challenge=challenge,
    )
    suite = _suite(catalog, attestation.isolation_class)
    binding_raw = binding.to_dict()
    preflight_raw = preflight.to_dict()
    challenge_raw = challenge.to_dict()
    body = {
        "schema_version": 1,
        "suite_catalog_sha256": catalog.catalog_sha256,
        "backend_attestation_sha256": attestation.attestation_sha256,
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
        "isolation_class": attestation.isolation_class,
        "host_id": binding_raw["host_id"],
        "service_identity_id": binding_raw["service_identity_id"],
        "probe_steps": _probe_steps(suite["probe_ids"]),
        "publication_contract": {
            "plan_file": PLAN_FILENAME,
            "batch_file": BATCH_FILENAME,
            "manifest_file": MANIFEST_FILENAME,
            "collision_policy": "refuse_existing_output",
            "promotion_policy": "same_parent_atomic_rename",
            "private_key_storage": "prohibited",
            "evidence_inventory": "exact_no_extra_files",
        },
        "status": "ready_for_external_host_collection_nonqualifying",
        "qualification_effect": "none",
        "routing_effect": "none",
        "deployment_effect": "none",
        "target_authority_effect": "none",
    }
    digest = _canonical_sha256({"domain": COLLECTOR_PLAN_DOMAIN, "plan": body})
    return ConformanceCollectorPlan.from_dict(
        {
            **body,
            "plan_id": f"BCP-{digest.removeprefix('sha256:')[:32].upper()}",
            "plan_sha256": digest,
        },
        catalog=catalog,
        attestation=attestation,
        binding=binding,
        snapshot=snapshot,
        preflight=preflight,
        challenge=challenge,
    )


@dataclass(frozen=True)
class ProbeCapture:
    probe_id: str
    status: str
    measurement: Mapping[str, Any]
    evidence: bytes
    media_type: str = "application/json"


@dataclass(frozen=True)
class PublishedConformanceCollection:
    output_directory: Path
    collection_id: str
    collection_sha256: str
    plan: ConformanceCollectorPlan
    batch: SignedConformanceObservationBatch
    report: BackendConformanceReport


def _capture_artifacts(
    plan: ConformanceCollectorPlan,
    captures: list[ProbeCapture],
) -> tuple[list[dict[str, Any]], list[tuple[str, bytes]], list[dict[str, Any]]]:
    steps = plan.to_dict()["probe_steps"]
    if len(captures) != len(steps):
        raise QualificationError("Collector probe captures are incomplete")
    observations: list[dict[str, Any]] = []
    artifacts: list[tuple[str, bytes]] = []
    evidence_files: list[dict[str, Any]] = []
    for capture, step in zip(captures, steps, strict=True):
        if capture.probe_id != step["probe_id"]:
            raise QualificationError("Collector probe captures are unordered")
        if capture.status not in {"passed", "failed", "error"}:
            raise QualificationError("Collector probe capture status is invalid")
        if capture.media_type != step["media_type"]:
            raise QualificationError("Collector probe evidence media type is invalid")
        if not isinstance(capture.evidence, bytes) or not capture.evidence:
            raise QualificationError("Collector probe evidence must be nonempty bytes")
        if len(capture.evidence) > step["maximum_evidence_bytes"]:
            raise QualificationError("Collector probe evidence exceeds the plan limit")
        try:
            measurement_json = _canonical_json(dict(capture.measurement))
            if len(measurement_json) > MAX_PROBE_MEASUREMENT_BYTES:
                raise QualificationError("Collector probe measurement exceeds its hard limit")
            measurement = json.loads(measurement_json)
        except QualificationError:
            raise
        except (TypeError, ValueError) as exc:
            raise QualificationError("Collector probe measurement is invalid") from exc
        if not measurement:
            raise QualificationError("Collector probe measurement is incomplete")
        path = _safe_relative_path(step["evidence_path"], "collector evidence path")
        digest = f"sha256:{hashlib.sha256(capture.evidence).hexdigest()}"
        artifacts.append((path, capture.evidence))
        evidence_files.append(
            {
                "path": path,
                "sha256": digest,
                "size_bytes": len(capture.evidence),
                "media_type": capture.media_type,
            }
        )
        observations.append(
            build_conformance_observation(
                probe_id=capture.probe_id,
                status=capture.status,
                evidence_sha256=(digest,),
                measurement=measurement,
            )
        )
    if len({item["sha256"] for item in evidence_files}) != len(evidence_files):
        raise QualificationError("Collector probe evidence must be unique per probe")
    return observations, artifacts, evidence_files


def _encode_signature(value: bytes) -> str:
    if not isinstance(value, bytes) or len(value) != 64:
        raise QualificationError("Collector signer must return a 64-byte Ed25519 signature")
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _write_file(root: Path, relative_path: str, content: bytes) -> None:
    destination = root.joinpath(*PurePosixPath(relative_path).parts)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as stream:
        stream.write(content)


def _collection_metadata_bytes(
    *,
    plan: ConformanceCollectorPlan,
    batch: SignedConformanceObservationBatch,
    manifest: dict[str, Any],
) -> dict[str, bytes]:
    files = {
        PLAN_FILENAME: plan.document_json.encode("ascii"),
        BATCH_FILENAME: batch.document_json.encode("ascii"),
        MANIFEST_FILENAME: _canonical_json(manifest).encode("ascii"),
    }
    if any(
        not content or len(content) > MAX_COLLECTION_METADATA_BYTES
        for content in files.values()
    ):
        raise QualificationError("Collector metadata file exceeds its hard limit")
    return files


def _read_canonical_collection_metadata(path: Path) -> Any:
    try:
        if path.is_symlink():
            raise QualificationError("Collector metadata file must not be a symlink")
        data = _read_bounded_regular_file(path, MAX_COLLECTION_METADATA_BYTES)
        if not data or len(data) > MAX_COLLECTION_METADATA_BYTES:
            raise QualificationError("Collector metadata file exceeds its hard limit")
        value = loads_json_without_duplicate_keys(data.decode("ascii"))
        if _canonical_json(value).encode("ascii") != data:
            raise QualificationError("Collector metadata file is not canonical JSON")
        return value
    except QualificationError:
        raise
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        raise QualificationError("Collector metadata file could not be loaded") from exc


def _collection_manifest(
    *,
    plan: ConformanceCollectorPlan,
    batch: SignedConformanceObservationBatch,
) -> dict[str, Any]:
    body = {
        "schema_version": 1,
        "collector_plan_id": plan.plan_id,
        "collector_plan_sha256": plan.plan_sha256,
        "observation_batch_id": batch.batch_id,
        "observation_batch_sha256": batch.batch_sha256,
        "challenge_id": batch.challenge_id,
        "sequence_number": batch.sequence_number,
        "evidence_files": list(batch.evidence_files),
        "evidence_file_count": len(batch.evidence_files),
        "evidence_total_bytes": sum(item["size_bytes"] for item in batch.evidence_files),
        "status": "published_signed_pending_import",
        "qualification_effect": "none",
        "routing_effect": "none",
        "deployment_effect": "none",
        "target_authority_effect": "none",
    }
    digest = _canonical_sha256({"domain": COLLECTION_MANIFEST_DOMAIN, "collection": body})
    return {
        **body,
        "collection_id": f"BCL-{digest.removeprefix('sha256:')[:32].upper()}",
        "collection_sha256": digest,
    }


def _validate_collection_manifest(
    raw: Any,
    *,
    plan: ConformanceCollectorPlan,
    batch: SignedConformanceObservationBatch,
) -> tuple[str, str]:
    expected = _collection_manifest(plan=plan, batch=batch)
    if raw != expected:
        raise QualificationError("Collector collection manifest is invalid")
    collection_id = raw.get("collection_id")
    if not isinstance(collection_id, str) or COLLECTION_ID_PATTERN.fullmatch(collection_id) is None:
        raise QualificationError("Collector collection ID is invalid")
    return collection_id, _sha(raw.get("collection_sha256"), "collector collection hash")


def _expected_inventory(batch: SignedConformanceObservationBatch) -> set[str]:
    return {
        PLAN_FILENAME,
        BATCH_FILENAME,
        MANIFEST_FILENAME,
        *(item["path"] for item in batch.evidence_files),
    }


def _verify_exact_inventory(root: Path, expected: set[str]) -> None:
    actual: set[str] = set()
    entry_count = 0
    for path in root.rglob("*"):
        entry_count += 1
        if entry_count > 4 * len(expected) + 32:
            raise QualificationError("Collector output inventory exceeds hard limits")
        if path.is_symlink():
            raise QualificationError("Collector output must not contain symlinks")
        if path.is_file():
            actual.add(path.relative_to(root).as_posix())
            if len(actual) > len(expected):
                raise QualificationError("Collector output inventory is not exact")
        elif not path.is_dir():
            raise QualificationError("Collector output contains a non-regular entry")
    if actual != expected:
        raise QualificationError("Collector output inventory is not exact")


def publish_signed_conformance_collection(
    *,
    output_directory: str | Path,
    plan: ConformanceCollectorPlan,
    catalog: ContainmentConformanceSuiteCatalog,
    attestation: ContainmentBackendAttestation,
    binding: ContainmentBackendDeploymentBinding,
    snapshot: ContainmentHostSnapshot,
    preflight: ContainmentHostPreflightReport,
    challenge: ConformanceProbeChallenge,
    captures: list[ProbeCapture],
    collected_at: str,
    signer: Callable[[bytes], bytes],
    collector_public_key: bytes | Ed25519PublicKey,
) -> PublishedConformanceCollection:
    verified_plan = ConformanceCollectorPlan.from_dict(
        plan.to_dict(),
        catalog=catalog,
        attestation=attestation,
        binding=binding,
        snapshot=snapshot,
        preflight=preflight,
        challenge=challenge,
    )
    if verified_plan != plan:
        raise QualificationError("Collector plan is not canonical")
    if not callable(signer):
        raise QualificationError("Collector signer is not callable")
    observations, artifacts, evidence_files = _capture_artifacts(plan, captures)
    unsigned = prepare_conformance_observation_batch(
        challenge=challenge,
        catalog=catalog,
        attestation=attestation,
        collected_at=collected_at,
        observations=observations,
        evidence_files=evidence_files,
    )
    signature = _encode_signature(signer(unsigned.signing_bytes()))
    batch = finalize_conformance_observation_batch(
        unsigned,
        signature,
        challenge,
        catalog,
        attestation,
    )
    manifest = _collection_manifest(plan=plan, batch=batch)
    collection_id, collection_sha256 = _validate_collection_manifest(
        manifest, plan=plan, batch=batch
    )
    metadata_files = _collection_metadata_bytes(plan=plan, batch=batch, manifest=manifest)
    output = Path(output_directory)
    if output.exists() or output.is_symlink():
        raise QualificationError("Collector output directory already exists")
    parent = output.parent.resolve(strict=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=parent))
    try:
        for relative_path, content in artifacts:
            _write_file(temporary, relative_path, content)
        for name, content in metadata_files.items():
            _write_file(temporary, name, content)
        _verify_exact_inventory(temporary, _expected_inventory(batch))
        verified = verify_conformance_observation_batch(
            batch=batch,
            challenge=challenge,
            catalog=catalog,
            attestation=attestation,
            collector_public_key=collector_public_key,
            evidence_root=temporary,
            observed_at=collected_at,
        )
        report = _report_from_verified(verified, catalog, attestation)
        os.replace(temporary, output)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return PublishedConformanceCollection(
        output,
        collection_id,
        collection_sha256,
        plan,
        batch,
        report,
    )


def _report_from_verified(
    verified: VerifiedConformanceObservationBatch,
    catalog: ContainmentConformanceSuiteCatalog,
    attestation: ContainmentBackendAttestation,
) -> BackendConformanceReport:
    from .candidate_backend_evidence_import import (
        build_report_from_verified_conformance_batch,
    )

    return build_report_from_verified_conformance_batch(
        verified=verified,
        catalog=catalog,
        attestation=attestation,
    )


def verify_published_conformance_collection(
    *,
    directory: str | Path,
    expected_plan: ConformanceCollectorPlan,
    catalog: ContainmentConformanceSuiteCatalog,
    attestation: ContainmentBackendAttestation,
    binding: ContainmentBackendDeploymentBinding,
    snapshot: ContainmentHostSnapshot,
    preflight: ContainmentHostPreflightReport,
    challenge: ConformanceProbeChallenge,
    collector_public_key: bytes | Ed25519PublicKey,
    observed_at: str,
) -> PublishedConformanceCollection:
    source = Path(directory)
    if source.is_symlink():
        raise QualificationError("Collector output root cannot be a symlink")
    try:
        root = source.resolve(strict=True)
    except OSError as exc:
        raise QualificationError("Collector output could not be loaded") from exc
    if not root.is_dir():
        raise QualificationError("Collector output must be a directory")
    plan_raw = _read_canonical_collection_metadata(root / PLAN_FILENAME)
    batch_raw = _read_canonical_collection_metadata(root / BATCH_FILENAME)
    manifest_raw = _read_canonical_collection_metadata(root / MANIFEST_FILENAME)
    plan = ConformanceCollectorPlan.from_dict(
        plan_raw,
        catalog=catalog,
        attestation=attestation,
        binding=binding,
        snapshot=snapshot,
        preflight=preflight,
        challenge=challenge,
    )
    if plan != expected_plan:
        raise QualificationError("Collector output plan does not match the expected plan")
    batch = SignedConformanceObservationBatch.from_dict(batch_raw, challenge, catalog, attestation)
    collection_id, collection_sha256 = _validate_collection_manifest(
        manifest_raw, plan=plan, batch=batch
    )
    _verify_exact_inventory(root, _expected_inventory(batch))
    verified = verify_conformance_observation_batch(
        batch=batch,
        challenge=challenge,
        catalog=catalog,
        attestation=attestation,
        collector_public_key=collector_public_key,
        evidence_root=root,
        observed_at=observed_at,
    )
    report = _report_from_verified(verified, catalog, attestation)
    return PublishedConformanceCollection(
        root,
        collection_id,
        collection_sha256,
        plan,
        batch,
        report,
    )


__all__ = [
    "ConformanceCollectorPlan",
    "ProbeCapture",
    "PublishedConformanceCollection",
    "build_conformance_collector_plan",
    "publish_signed_conformance_collection",
    "verify_published_conformance_collection",
]
