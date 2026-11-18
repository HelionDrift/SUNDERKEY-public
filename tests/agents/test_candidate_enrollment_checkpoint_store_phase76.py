"""Phase 76 atomic local checkpoint store coverage."""

from __future__ import annotations

import ast
import copy
import json
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

import sunderkey.candidate_enrollment_checkpoint_store as checkpoint_store_module
from sunderkey.candidate_enrollment_checkpoint_store import (
    BACKUP_FILENAME,
    CURRENT_FILENAME,
    LOCK_DIRECTORY_NAME,
    AtomicCandidateEnrollmentCheckpointStore,
)
from sunderkey.candidate_enrollment_deployment_verification import (
    RECEIPT_DOMAIN,
    CandidateEnrollmentDeploymentVerificationReceipt,
)
from sunderkey.candidate_enrollment_release_contract import (
    build_candidate_enrollment_checkpoint_record,
    build_candidate_enrollment_release_ledger_entry,
)
from sunderkey.candidate_enrollment_verification import (
    CandidateEnrollmentCatalogCheckpoint,
)
from sunderkey.errors import QualificationError
from sunderkey.qualification import _canonical_sha256
from tests.agents import test_candidate_enrollment_release_contract_phase75

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = (
    ROOT
    / "registry"
    / "schemas"
    / "candidate-enrollment-checkpoint-commit-receipt-v1.schema.json"
)


class TestCheckpointAccessController:
    """Test-only controller that records every required custody operation."""

    __test__ = False

    def __init__(self) -> None:
        self.protected_directories: list[Path] = []
        self.verified_directories: list[Path] = []
        self.protected_files: list[Path] = []
        self.verified_files: list[Path] = []
        self.synced_directories: list[Path] = []

    def protect_directory(self, path: Path) -> None:
        self.protected_directories.append(path)

    def verify_directory(self, path: Path) -> None:
        if not path.is_dir() or path.is_symlink():
            raise QualificationError("Test custody directory verification failed")
        self.verified_directories.append(path)

    def protect_file(self, path: Path) -> None:
        self.protected_files.append(path)

    def verify_file(self, path: Path) -> None:
        if not path.is_file() or path.is_symlink():
            raise QualificationError("Test custody file verification failed")
        self.verified_files.append(path)

    def sync_directory(self, path: Path) -> None:
        if not path.is_dir():
            raise QualificationError("Test custody directory sync failed")
        self.synced_directories.append(path)


class CandidateEnrollmentCheckpointStorePhase76Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        phase75 = test_candidate_enrollment_release_contract_phase75
        phase75.CandidateEnrollmentReleaseContractPhase75Tests.setUpClass()
        cls.fixture = phase75.CandidateEnrollmentReleaseContractPhase75Tests(
            methodName="test_checkpoint_binds_intent_and_precedes_promotion"
        )
        cls.intent1 = cls.fixture.intent()
        cls.checkpoint1 = cls.fixture.checkpoint()

    def store(self, directory: Path):
        controller = TestCheckpointAccessController()
        store = AtomicCandidateEnrollmentCheckpointStore(directory, controller)
        store.initialize_directory()
        return store, controller

    def second_release(self):
        receipt_document = copy.deepcopy(self.fixture.receipt.to_dict())
        receipt_document["sources"]["catalog"]["sha256"] = "sha256:" + "e" * 64
        receipt_document["next_checkpoint"]["catalog_version"] = 2
        receipt_document["next_checkpoint"]["catalog_sha256"] = "sha256:" + "e" * 64
        body = {
            key: value
            for key, value in receipt_document.items()
            if key not in {"receipt_id", "receipt_sha256"}
        }
        digest = _canonical_sha256({"domain": RECEIPT_DOMAIN, "receipt": body})
        receipt_document["receipt_id"] = (
            "CVR-" + digest.removeprefix("sha256:")[:32].upper()
        )
        receipt_document["receipt_sha256"] = digest
        receipt = CandidateEnrollmentDeploymentVerificationReceipt.from_dict(
            receipt_document
        )
        checkpoint = CandidateEnrollmentCatalogCheckpoint.from_dict(
            receipt_document["next_checkpoint"]
        )
        release_id = "CRL-" + "2" * 32
        intent = build_candidate_enrollment_release_ledger_entry(
            deployment_id="deployment.phase75",
            ledger_sequence=2,
            previous_entry=self.intent1,
            event_type="release_intent",
            release_id=release_id,
            decision=self.fixture.decision,
            verification_receipt=receipt,
            catalog_checkpoint=checkpoint,
            checkpoint_record=None,
            event_artifact=None,
            authority_mode="automatic_monotonic_advance",
            approval_bindings=[],
            event_time="2026-08-02T20:40:00Z",
        )
        record = build_candidate_enrollment_checkpoint_record(
            deployment_id="deployment.phase75",
            checkpoint_sequence=2,
            release_id=release_id,
            catalog_checkpoint=checkpoint,
            verification_receipt=receipt,
            release_intent=intent,
            predecessor_checkpoint=self.checkpoint1,
            committed_at="2026-08-02T20:41:00Z",
        )
        return intent, record

    def test_initial_commit_is_atomic_verified_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "checkpoint-store"
            store, controller = self.store(directory)
            receipt = store.commit(self.checkpoint1, self.intent1)
            self.assertEqual(receipt.to_dict()["commit_status"], "committed")
            self.assertTrue(receipt.to_dict()["atomic_replace_performed"])
            self.assertEqual(store.load_required(), self.checkpoint1)
            self.assertTrue((directory / CURRENT_FILENAME).is_file())
            self.assertFalse((directory / BACKUP_FILENAME).exists())
            self.assertGreaterEqual(len(controller.protected_files), 1)
            self.assertGreaterEqual(len(controller.synced_directories), 1)
            retry = store.commit(self.checkpoint1, self.intent1)
            self.assertEqual(
                retry.to_dict()["commit_status"],
                "already_committed_same_digest",
            )
            self.assertFalse(retry.to_dict()["atomic_replace_performed"])

    def test_monotonic_advance_preserves_verified_backup(self) -> None:
        intent2, checkpoint2 = self.second_release()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "checkpoint-store"
            store, _ = self.store(directory)
            store.commit(self.checkpoint1, self.intent1)
            receipt = store.commit(checkpoint2, intent2)
            self.assertEqual(receipt.to_dict()["backup_status"], "preserved")
            self.assertEqual(store.load_required(), checkpoint2)
            backup = json.loads(
                (directory / BACKUP_FILENAME).read_text(encoding="ascii")
            )
            self.assertEqual(backup["checkpoint_id"], self.checkpoint1.checkpoint_id)
            with self.assertRaisesRegex(QualificationError, "sequence"):
                store.commit(self.checkpoint1, self.intent1)

    def test_corruption_missing_current_and_lock_contention_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "checkpoint-store"
            store, _ = self.store(directory)
            with self.assertRaisesRegex(QualificationError, "not initialized"):
                store.load_required()
            store.commit(self.checkpoint1, self.intent1)
            (directory / CURRENT_FILENAME).write_text("{", encoding="ascii")
            with self.assertRaisesRegex(QualificationError, "corrupt"):
                store.load_required()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "checkpoint-store"
            store, _ = self.store(directory)
            (directory / LOCK_DIRECTORY_NAME).mkdir()
            with self.assertRaisesRegex(QualificationError, "already locked"):
                store.commit(self.checkpoint1, self.intent1)

    def test_read_rejects_nonregular_and_replaced_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store, _ = self.store(Path(temporary) / "checkpoint-store")
            store.commit(self.checkpoint1, self.intent1)
            current = store.current_path
            replacement = current.with_name("replacement.json")
            replacement.write_bytes(current.read_bytes())

            with patch.object(
                Path,
                "lstat",
                return_value=SimpleNamespace(st_mode=stat.S_IFIFO, st_size=0),
            ):
                with self.assertRaisesRegex(QualificationError, "non-regular"):
                    store._read_record(current, "current checkpoint")

            original_open = checkpoint_store_module.os.open
            flags_seen: list[int] = []

            def open_replacement(path, flags, *args, **kwargs):
                flags_seen.append(flags)
                if Path(path) == current:
                    return original_open(replacement, flags, *args, **kwargs)
                return original_open(path, flags, *args, **kwargs)

            with patch.object(checkpoint_store_module.os, "open", side_effect=open_replacement):
                with self.assertRaisesRegex(QualificationError, "changed while opening"):
                    store._read_record(current, "current checkpoint")
            if getattr(checkpoint_store_module.os, "O_NONBLOCK", 0):
                self.assertTrue(flags_seen[0] & checkpoint_store_module.os.O_NONBLOCK)
            if getattr(checkpoint_store_module.os, "O_NOFOLLOW", 0):
                self.assertTrue(flags_seen[0] & checkpoint_store_module.os.O_NOFOLLOW)

    def test_read_bounds_growth_after_open(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store, _ = self.store(Path(temporary) / "checkpoint-store")
            store.commit(self.checkpoint1, self.intent1)
            current = store.current_path
            limit = current.stat().st_size + 8
            original_fdopen = checkpoint_store_module.os.fdopen

            with patch.object(checkpoint_store_module, "MAX_CHECKPOINT_BYTES", 1):
                with patch.object(checkpoint_store_module.os, "open", side_effect=AssertionError):
                    with self.assertRaisesRegex(QualificationError, "size is invalid"):
                        store._read_record(current, "current checkpoint")

            def grow_before_read(descriptor, *args, **kwargs):
                with current.open("ab") as stream:
                    stream.write(b"x" * 40)
                return original_fdopen(descriptor, *args, **kwargs)

            with patch.object(checkpoint_store_module, "MAX_CHECKPOINT_BYTES", limit):
                with patch.object(
                    checkpoint_store_module.os,
                    "fdopen",
                    side_effect=grow_before_read,
                ):
                    with self.assertRaisesRegex(QualificationError, "size is invalid"):
                        store._read_record(current, "current checkpoint")

    def test_read_rejects_path_change_after_open(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store, controller = self.store(Path(temporary) / "checkpoint-store")
            store.commit(self.checkpoint1, self.intent1)
            current = store.current_path
            original_lstat = Path.lstat
            inspections = 0

            def changed_metadata(path, *args, **kwargs):
                nonlocal inspections
                metadata = original_lstat(path, *args, **kwargs)
                if Path(path) != current:
                    return metadata
                inspections += 1
                if inspections == 2:
                    return SimpleNamespace(
                        st_mode=metadata.st_mode,
                        st_dev=metadata.st_dev,
                        st_ino=metadata.st_ino,
                        st_size=metadata.st_size,
                        st_mtime_ns=metadata.st_mtime_ns + 1,
                    )
                return metadata

            with patch.object(controller, "verify_file", return_value=None):
                with patch.object(Path, "lstat", side_effect=changed_metadata, autospec=True):
                    with self.assertRaisesRegex(QualificationError, "changed while reading"):
                        store._read_record(current, "current checkpoint")

    def test_access_controller_is_mandatory_and_incomplete_one_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(QualificationError, "incomplete"):
                AtomicCandidateEnrollmentCheckpointStore(temporary, object())

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_commit_receipt_matches_published_schema(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store, _ = self.store(Path(temporary) / "checkpoint-store")
            receipt = store.commit(self.checkpoint1, self.intent1)
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(receipt.to_dict())

    def test_store_has_no_network_database_or_subprocess_imports(self) -> None:
        path = ROOT / "src" / "sunderkey" / "candidate_enrollment_checkpoint_store.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        prohibited = {
            "asyncio",
            "http",
            "requests",
            "socket",
            "sqlite3",
            "subprocess",
            "urllib",
        }
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported.update(
            str(node.module).split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        )
        self.assertFalse(imported & prohibited)


if __name__ == "__main__":
    unittest.main()
