"""Atomic local checkpoint mirror with fail-closed access verification."""

from __future__ import annotations

import json
import os
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Protocol
from uuid import uuid4

from .candidate_enrollment_release_contract import (
    CandidateEnrollmentCheckpointRecord,
    CandidateEnrollmentReleaseLedgerEntry,
)
from .errors import QualificationError
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .validation import loads_json_without_duplicate_keys

SCHEMA_VERSION = 1
COMMIT_DOMAIN = "sunderkey.candidate-enrollment-checkpoint-commit-receipt.v1"
MAX_CHECKPOINT_BYTES = 262_144
CURRENT_FILENAME = "checkpoint.json"
BACKUP_FILENAME = "checkpoint.previous.json"
LOCK_DIRECTORY_NAME = ".checkpoint.lock"


class CheckpointAccessController(Protocol):
    """Platform custody operations required by the atomic store."""

    def protect_directory(self, path: Path) -> None: ...

    def verify_directory(self, path: Path) -> None: ...

    def protect_file(self, path: Path) -> None: ...

    def verify_file(self, path: Path) -> None: ...

    def sync_directory(self, path: Path) -> None: ...


class PosixOwnerOnlyCheckpointAccess:
    """Owner-only POSIX custody implementation using mode and ownership checks."""

    def _require_posix(self) -> None:
        if os.name != "posix" or not hasattr(os, "getuid"):
            raise QualificationError(
                "POSIX checkpoint access control is unavailable on this platform"
            )

    def protect_directory(self, path: Path) -> None:
        self._require_posix()
        os.chmod(path, 0o700, follow_symlinks=False)

    def verify_directory(self, path: Path) -> None:
        self._verify(path, directory=True)

    def protect_file(self, path: Path) -> None:
        self._require_posix()
        os.chmod(path, 0o600, follow_symlinks=False)

    def verify_file(self, path: Path) -> None:
        self._verify(path, directory=False)

    def sync_directory(self, path: Path) -> None:
        self._require_posix()
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _verify(self, path: Path, *, directory: bool) -> None:
        self._require_posix()
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise QualificationError("Checkpoint custody path cannot be a symbolic link")
        if directory and not stat.S_ISDIR(metadata.st_mode):
            raise QualificationError("Checkpoint custody directory is invalid")
        if not directory and not stat.S_ISREG(metadata.st_mode):
            raise QualificationError("Checkpoint custody file is invalid")
        expected_mode = 0o700 if directory else 0o600
        if stat.S_IMODE(metadata.st_mode) != expected_mode:
            raise QualificationError("Checkpoint custody permissions are not owner-only")
        if metadata.st_uid != os.getuid():
            raise QualificationError("Checkpoint custody ownership is invalid")


def _require_controller(controller: Any) -> CheckpointAccessController:
    for method in (
        "protect_directory",
        "verify_directory",
        "protect_file",
        "verify_file",
        "sync_directory",
    ):
        if not callable(getattr(controller, method, None)):
            raise QualificationError("Checkpoint access controller is incomplete")
    return controller


def _write_all(handle: Any, payload: bytes) -> None:
    written = handle.write(payload)
    if written != len(payload):
        raise QualificationError("Checkpoint write was incomplete")
    handle.flush()
    os.fsync(handle.fileno())


def _file_state(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


@dataclass(frozen=True)
class CandidateEnrollmentCheckpointCommitReceipt:
    """Content-addressed outcome of one local atomic commit attempt."""

    receipt_id: str
    receipt_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CandidateEnrollmentCheckpointCommitReceipt:
        value = _mapping(raw, "candidate enrollment checkpoint commit receipt")
        fields = {
            "schema_version",
            "receipt_id",
            "receipt_sha256",
            "deployment_id",
            "checkpoint",
            "commit_status",
            "atomic_replace_performed",
            "backup_status",
            "access_verification_status",
            "sqlite_mutation_performed",
            "network_call_performed",
            "qualification_effect",
            "registry_effect",
        }
        _exact_fields(value, fields, "candidate enrollment checkpoint commit receipt")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise QualificationError("Checkpoint commit receipt schema is invalid")
        receipt_id = value.get("receipt_id")
        receipt_sha256 = value.get("receipt_sha256")
        if (
            not isinstance(receipt_id, str)
            or len(receipt_id) != 36
            or not receipt_id.startswith("CCR-")
            or not isinstance(receipt_sha256, str)
            or len(receipt_sha256) != 71
            or not receipt_sha256.startswith("sha256:")
        ):
            raise QualificationError("Checkpoint commit receipt identity is invalid")
        deployment_id = value.get("deployment_id")
        if not isinstance(deployment_id, str) or not deployment_id:
            raise QualificationError("Checkpoint commit deployment is invalid")
        checkpoint = _mapping(value.get("checkpoint"), "checkpoint binding")
        _exact_fields(
            checkpoint,
            {"checkpoint_id", "sha256", "checkpoint_sequence"},
            "checkpoint binding",
        )
        status_value = value.get("commit_status")
        if status_value not in {"committed", "already_committed_same_digest"}:
            raise QualificationError("Checkpoint commit status is invalid")
        if (
            value.get("atomic_replace_performed") is not (status_value == "committed")
            or value.get("backup_status")
            not in {"not_applicable_initial_commit", "preserved", "unchanged"}
            or value.get("access_verification_status") != "verified"
            or value.get("sqlite_mutation_performed") is not False
            or value.get("network_call_performed") is not False
            or value.get("qualification_effect") != "none"
            or value.get("registry_effect") != "none"
        ):
            raise QualificationError("Checkpoint commit receipt boundary is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"receipt_id", "receipt_sha256"}
        }
        expected_hash = _canonical_sha256({"domain": COMMIT_DOMAIN, "receipt": body})
        expected_id = "CCR-" + expected_hash.removeprefix("sha256:")[:32].upper()
        if receipt_sha256 != expected_hash or receipt_id != expected_id:
            raise QualificationError("Checkpoint commit receipt hash is invalid")
        return cls(receipt_id, receipt_sha256, _canonical_json(value))

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise QualificationError("Checkpoint commit receipt is invalid")
        return value


class AtomicCandidateEnrollmentCheckpointStore:
    """Atomic file-backed checkpoint mirror with an explicit ACL boundary."""

    def __init__(
        self,
        directory: str | Path,
        access_controller: CheckpointAccessController,
    ) -> None:
        self.directory = Path(directory).resolve()
        self.access_controller = _require_controller(access_controller)
        self.current_path = self.directory / CURRENT_FILENAME
        self.backup_path = self.directory / BACKUP_FILENAME
        self.lock_path = self.directory / LOCK_DIRECTORY_NAME

    def initialize_directory(self) -> None:
        """Create and verify an empty protected custody directory."""

        self.directory.mkdir(parents=True, exist_ok=True)
        if self.directory.is_symlink():
            raise QualificationError("Checkpoint custody directory cannot be a symbolic link")
        self.access_controller.protect_directory(self.directory)
        self.access_controller.verify_directory(self.directory)

    def _verify_directory(self) -> None:
        if not self.directory.exists() or self.directory.is_symlink():
            raise QualificationError("Checkpoint custody directory is missing or ambiguous")
        self.access_controller.verify_directory(self.directory)

    def _read_record(self, path: Path, label: str) -> CandidateEnrollmentCheckpointRecord:
        try:
            before = path.lstat()
        except OSError as exc:
            raise QualificationError(f"Could not inspect {label}") from exc
        if not stat.S_ISREG(before.st_mode):
            raise QualificationError(f"{label} is missing, non-regular, or ambiguous")
        if before.st_size <= 0 or before.st_size > MAX_CHECKPOINT_BYTES:
            raise QualificationError(f"{label} size is invalid")
        self.access_controller.verify_file(path)
        try:
            flags = (
                os.O_RDONLY
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NONBLOCK", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(path, flags)
            try:
                opened = os.fstat(descriptor)
                if not stat.S_ISREG(opened.st_mode) or _file_state(opened) != _file_state(before):
                    raise QualificationError(f"{label} changed while opening")
                with os.fdopen(descriptor, "rb", closefd=False) as stream:
                    payload = stream.read(MAX_CHECKPOINT_BYTES + 1)
                after_open = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            after_path = path.lstat()
        except OSError as exc:
            raise QualificationError(f"Could not read {label}") from exc
        if not payload or len(payload) > MAX_CHECKPOINT_BYTES:
            raise QualificationError(f"{label} size is invalid")
        if (
            len(payload) != opened.st_size
            or not stat.S_ISREG(after_path.st_mode)
            or _file_state(after_open) != _file_state(opened)
            or _file_state(after_path) != _file_state(opened)
        ):
            raise QualificationError(f"{label} changed while reading")
        try:
            raw = loads_json_without_duplicate_keys(payload.decode("ascii"))
        except (UnicodeError, ValueError) as exc:
            raise QualificationError(f"{label} is corrupt") from exc
        return CandidateEnrollmentCheckpointRecord.from_dict(raw)

    def load_required(self) -> CandidateEnrollmentCheckpointRecord:
        """Load current state and fail closed on missing or ambiguous custody."""

        self._verify_directory()
        if not self.current_path.exists():
            if self.backup_path.exists():
                raise QualificationError("Checkpoint current state is missing but backup exists")
            raise QualificationError("Checkpoint current state is not initialized")
        current = self._read_record(self.current_path, "current checkpoint")
        if self.backup_path.exists():
            backup = self._read_record(self.backup_path, "checkpoint backup")
            current_document = current.to_dict()
            backup_document = backup.to_dict()
            if (
                backup_document["deployment_id"] != current_document["deployment_id"]
                or backup_document["checkpoint_sequence"]
                != current_document["checkpoint_sequence"] - 1
            ):
                raise QualificationError("Checkpoint backup chain is ambiguous")
        return current

    def load_for_release_initialization(
        self,
    ) -> CandidateEnrollmentCheckpointRecord | None:
        """Return empty state only when both current and backup are absent."""

        self._verify_directory()
        if not self.current_path.exists():
            if self.backup_path.exists():
                raise QualificationError("Checkpoint state is ambiguous before initialization")
            return None
        return self.load_required()

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        try:
            self.lock_path.mkdir()
        except FileExistsError as exc:
            raise QualificationError("Checkpoint store is already locked") from exc
        except OSError as exc:
            raise QualificationError("Could not acquire checkpoint store lock") from exc
        try:
            self.access_controller.protect_directory(self.lock_path)
            self.access_controller.verify_directory(self.lock_path)
            yield
        finally:
            try:
                self.lock_path.rmdir()
            except OSError as exc:
                raise QualificationError("Could not release checkpoint store lock") from exc

    def _write_replacement(self, target: Path, payload: bytes) -> None:
        temporary = self.directory / f".{target.name}.{uuid4().hex}.tmp"
        try:
            with temporary.open("xb") as handle:
                _write_all(handle, payload)
            self.access_controller.protect_file(temporary)
            self.access_controller.verify_file(temporary)
            os.replace(temporary, target)
            self.access_controller.verify_file(target)
            self.access_controller.sync_directory(self.directory)
        except Exception:
            if temporary.exists() and not temporary.is_symlink():
                try:
                    temporary.unlink()
                except OSError:
                    pass
            raise

    def commit(
        self,
        record: CandidateEnrollmentCheckpointRecord,
        release_intent: CandidateEnrollmentReleaseLedgerEntry,
    ) -> CandidateEnrollmentCheckpointCommitReceipt:
        """Atomically commit one monotonic checkpoint or return an exact retry."""

        if not isinstance(record, CandidateEnrollmentCheckpointRecord):
            raise QualificationError("record must be a checkpoint record")
        record = CandidateEnrollmentCheckpointRecord.from_dict(record.to_dict())
        if not isinstance(release_intent, CandidateEnrollmentReleaseLedgerEntry):
            raise QualificationError("release_intent must be a release ledger entry")
        release_intent = CandidateEnrollmentReleaseLedgerEntry.from_dict(
            release_intent.to_dict()
        )
        document = record.to_dict()
        if document["release_intent"] != {
            "entry_id": release_intent.entry_id,
            "sha256": release_intent.entry_sha256,
        }:
            raise QualificationError("Checkpoint release intent binding is invalid")
        intent_document = release_intent.to_dict()
        if (
            intent_document["event_type"] != "release_intent"
            or intent_document["deployment_id"] != document["deployment_id"]
            or intent_document["release_id"] != document["release_id"]
            or intent_document["catalog_checkpoint"]
            != document["catalog_checkpoint"]
            or intent_document["verification_receipt"]
            != document["verification_receipt"]
        ):
            raise QualificationError("Checkpoint release intent content is inconsistent")
        self._verify_directory()
        with self._exclusive_lock():
            current: CandidateEnrollmentCheckpointRecord | None = None
            if self.current_path.exists():
                current = self.load_required()
            elif self.backup_path.exists():
                raise QualificationError("Checkpoint state is ambiguous before initialization")
            if current == record:
                return _commit_receipt(
                    record,
                    "already_committed_same_digest",
                    False,
                    "unchanged",
                )
            if current is None:
                if (
                    document["checkpoint_sequence"] != 1
                    or document["predecessor_checkpoint"] is not None
                ):
                    raise QualificationError("Checkpoint initialization sequence is invalid")
                if (
                    release_intent.to_dict()["authority"]["mode"]
                    != "dual_control_initialization"
                ):
                    raise QualificationError(
                        "Checkpoint initialization requires dual-control intent"
                    )
                backup_status = "not_applicable_initial_commit"
            else:
                current_document = current.to_dict()
                if document["deployment_id"] != current_document["deployment_id"]:
                    raise QualificationError("Checkpoint deployment binding changed")
                if document["checkpoint_sequence"] != (
                    current_document["checkpoint_sequence"] + 1
                ):
                    raise QualificationError("Checkpoint sequence did not advance by one")
                predecessor = document["predecessor_checkpoint"]
                expected_predecessor = {
                    "checkpoint_id": current.checkpoint_id,
                    "sha256": current.checkpoint_sha256,
                    "checkpoint_sequence": current_document["checkpoint_sequence"],
                }
                if predecessor != expected_predecessor:
                    raise QualificationError("Checkpoint predecessor does not match current state")
                current_catalog = current_document["catalog_checkpoint"]
                next_catalog = document["catalog_checkpoint"]
                if (
                    next_catalog["catalog_id"] != current_catalog["catalog_id"]
                    or next_catalog["catalog_version"]
                    != current_catalog["catalog_version"] + 1
                ):
                    raise QualificationError(
                        "Checkpoint catalog is not a monotonic one-version advance"
                    )
                current_payload = (current.document_json + "\n").encode("ascii")
                self._write_replacement(self.backup_path, current_payload)
                backup_status = "preserved"
            payload = (record.document_json + "\n").encode("ascii")
            if len(payload) > MAX_CHECKPOINT_BYTES:
                raise QualificationError("Checkpoint payload exceeds the size limit")
            self._write_replacement(self.current_path, payload)
            persisted = self._read_record(self.current_path, "committed checkpoint")
            if persisted != record:
                raise QualificationError("Committed checkpoint verification failed")
            return _commit_receipt(record, "committed", True, backup_status)
def _commit_receipt(
    record: CandidateEnrollmentCheckpointRecord,
    status_value: str,
    replaced: bool,
    backup_status: str,
) -> CandidateEnrollmentCheckpointCommitReceipt:
    document = record.to_dict()
    body = {
        "schema_version": SCHEMA_VERSION,
        "deployment_id": document["deployment_id"],
        "checkpoint": {
            "checkpoint_id": record.checkpoint_id,
            "sha256": record.checkpoint_sha256,
            "checkpoint_sequence": document["checkpoint_sequence"],
        },
        "commit_status": status_value,
        "atomic_replace_performed": replaced,
        "backup_status": backup_status,
        "access_verification_status": "verified",
        "sqlite_mutation_performed": False,
        "network_call_performed": False,
        "qualification_effect": "none",
        "registry_effect": "none",
    }
    digest = _canonical_sha256({"domain": COMMIT_DOMAIN, "receipt": body})
    return CandidateEnrollmentCheckpointCommitReceipt.from_dict(
        {
            **body,
            "receipt_id": "CCR-" + digest.removeprefix("sha256:")[:32].upper(),
            "receipt_sha256": digest,
        }
    )


__all__ = [
    "AtomicCandidateEnrollmentCheckpointStore",
    "CandidateEnrollmentCheckpointCommitReceipt",
    "CheckpointAccessController",
    "PosixOwnerOnlyCheckpointAccess",
]
