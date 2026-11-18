"""Phase 157 durable challenge replay custody tests."""

from __future__ import annotations

import base64
import os
import sqlite3
import stat
import tempfile
import threading
import unittest
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sunderkey.challenge_replay_store import (
    APPLICATION_ID,
    CANDIDATE_EXECUTION_CONTEXT,
    CONFORMANCE_CONTEXT,
    ChallengeExpiredError,
    ChallengeReplayConflictError,
    ChallengeReplayStore,
    PosixOwnerOnlyChallengeReplayAccess,
)
from sunderkey.errors import StoreError, StoreIntegrityError
from sunderkey.qualification import _canonical_sha256


class TestAccessController:
    """Test custody controller that verifies paths without changing host ACLs."""

    __test__ = False

    def __init__(self) -> None:
        self.protected_directories: list[Path] = []
        self.verified_directories: list[Path] = []
        self.protected_files: list[Path] = []
        self.verified_files: list[Path] = []
        self.synced_directories: list[Path] = []
        self.fail_verification = False

    def protect_directory(self, path: Path) -> None:
        self.protected_directories.append(path)

    def verify_directory(self, path: Path) -> None:
        if self.fail_verification or path.is_symlink() or not path.is_dir():
            raise StoreIntegrityError("Test directory custody failed")
        self.verified_directories.append(path)

    def protect_file(self, path: Path) -> None:
        self.protected_files.append(path)

    def verify_file(self, path: Path) -> None:
        if self.fail_verification or path.is_symlink() or not path.is_file():
            raise StoreIntegrityError("Test file custody failed")
        self.verified_files.append(path)

    def sync_directory(self, path: Path) -> None:
        if self.fail_verification or not path.is_dir():
            raise StoreIntegrityError("Test directory sync failed")
        self.synced_directories.append(path)


class MutableClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


class ChallengeReplayStorePhase157Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name) / "challenge-custody"
        self.controller = TestAccessController()
        self.clock = MutableClock(datetime(2026, 9, 19, 12, 0, tzinfo=UTC))
        self.store = ChallengeReplayStore(
            self.directory,
            self.controller,
            clock=self.clock,
        )
        self.store.initialize()
        self.public_key_sha256 = "sha256:" + "a" * 64

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def reserve(self, *, context: str = CONFORMANCE_CONTEXT):
        return self.store.reserve_sequence(
            context=context,
            collector_id="collector.phase157",
            key_id="collector-key.1",
            public_key_sha256=self.public_key_sha256,
        )

    def challenge(self, reservation, *, lifetime_seconds: int = 300):
        issued_at = datetime.fromisoformat(reservation.reserved_at.removesuffix("Z") + "+00:00")
        if reservation.context == CONFORMANCE_CONTEXT:
            domain = "sunderkey.containment-conformance-challenge.v1"
            prefix = "BCC-"
            scope = "external_synthetic_conformance_only"
            context_bindings = {
                "suite_catalog_sha256": "sha256:" + "b" * 64,
                "suite_id": "sunderkey-containment-oci_container-v1",
                "suite_version": "1.0.0",
                "backend_id": "backend.phase157",
                "backend_attestation_sha256": "sha256:" + "c" * 64,
                "isolation_class": "oci_container",
                "probe_ids": ["network_deny_verified"],
            }
        else:
            domain = "sunderkey.candidate-execution-evidence-challenge.v1"
            prefix = "CEC-"
            scope = "phase157_synthetic_candidate_evidence"
            context_bindings = {
                "adapter_id": "candidate.phase157",
                "profile_id": "expert.phase157",
                "vector_id": "vector.phase157",
                "manifest_sha256": "sha256:" + "b" * 64,
                "backend_id": "backend.phase157",
                "backend_attestation_sha256": "sha256:" + "c" * 64,
                "conformance_report_id": "BCR-" + "1" * 32,
                "conformance_report_sha256": "sha256:" + "d" * 64,
                "backend_admission_id": "BAR-" + "2" * 32,
                "backend_admission_sha256": "sha256:" + "e" * 64,
            }
        body = {
            "schema_version": 1,
            **context_bindings,
            "collector_id": reservation.collector_id,
            "key_id": reservation.key_id,
            "public_key_sha256": reservation.public_key_sha256,
            "nonce": reservation.nonce,
            "sequence_number": reservation.sequence_number,
            "issued_at": reservation.reserved_at,
            "expires_at": (issued_at + timedelta(seconds=lifetime_seconds))
            .isoformat()
            .replace("+00:00", "Z"),
            "execution_scope": scope,
            "qualification_effect": "none",
            "routing_effect": "none",
            "deployment_effect": "none",
            "target_authority_effect": "none",
        }
        digest = _canonical_sha256({"domain": domain, "challenge": body})
        return {
            **body,
            "challenge_id": prefix + digest.removeprefix("sha256:")[:32].upper(),
            "challenge_sha256": digest,
        }

    @staticmethod
    def nonce(byte: int) -> str:
        return base64.urlsafe_b64encode(bytes([byte]) * 32).rstrip(b"=").decode()

    def test_atomic_reservation_rejects_duplicate_gap_and_rollback(self) -> None:
        first = self.reserve()
        second = self.reserve()
        self.assertEqual((first.sequence_number, second.sequence_number), (1, 2))
        self.assertEqual(
            len(base64.urlsafe_b64decode(first.nonce + "=")),
            32,
        )
        with self.assertRaisesRegex(ChallengeReplayConflictError, "rollback"):
            self.store.register_sequence(
                context=CONFORMANCE_CONTEXT,
                collector_id=first.collector_id,
                key_id=first.key_id,
                public_key_sha256=first.public_key_sha256,
                nonce=self.nonce(21),
                sequence_number=1,
            )
        with self.assertRaisesRegex(ChallengeReplayConflictError, "gap"):
            self.store.register_sequence(
                context=CONFORMANCE_CONTEXT,
                collector_id=first.collector_id,
                key_id=first.key_id,
                public_key_sha256=first.public_key_sha256,
                nonce=self.nonce(22),
                sequence_number=4,
            )
        with self.assertRaisesRegex(ChallengeReplayConflictError, "nonce"):
            self.store.register_sequence(
                context=CONFORMANCE_CONTEXT,
                collector_id=first.collector_id,
                key_id=first.key_id,
                public_key_sha256=first.public_key_sha256,
                nonce=first.nonce,
                sequence_number=3,
            )
        third = self.store.register_sequence(
            context=CONFORMANCE_CONTEXT,
            collector_id=first.collector_id,
            key_id=first.key_id,
            public_key_sha256=first.public_key_sha256,
            nonce=self.nonce(23),
            sequence_number=3,
        )
        self.assertEqual(third.sequence_number, 3)

    def test_context_collector_and_key_scopes_have_separate_heads(self) -> None:
        conformance = self.reserve()
        candidate = self.reserve(context=CANDIDATE_EXECUTION_CONTEXT)
        other_collector = self.store.reserve_sequence(
            context=CONFORMANCE_CONTEXT,
            collector_id="collector.other",
            key_id=conformance.key_id,
            public_key_sha256=conformance.public_key_sha256,
        )
        other_key = self.store.reserve_sequence(
            context=CONFORMANCE_CONTEXT,
            collector_id=conformance.collector_id,
            key_id="collector-key.2",
            public_key_sha256="sha256:" + "c" * 64,
        )
        self.assertEqual(
            [
                conformance.sequence_number,
                candidate.sequence_number,
                other_collector.sequence_number,
                other_key.sequence_number,
            ],
            [1, 1, 1, 1],
        )
        with self.assertRaisesRegex(ChallengeReplayConflictError, "another"):
            self.store.reserve_sequence(
                context=CONFORMANCE_CONTEXT,
                collector_id=conformance.collector_id,
                key_id=conformance.key_id,
                public_key_sha256="sha256:" + "d" * 64,
            )

    def test_issue_binds_exact_challenge_and_consume_is_one_time(self) -> None:
        reservation = self.reserve()
        challenge = self.challenge(reservation)
        issued = self.store.issue_challenge(reservation, challenge)
        self.assertEqual(issued.status, "issued")
        self.assertEqual(issued.challenge_sha256, challenge["challenge_sha256"])
        with self.assertRaisesRegex(ChallengeReplayConflictError, "already"):
            self.store.issue_challenge(reservation, challenge)

        consumed = self.store.consume_challenge(
            context=CONFORMANCE_CONTEXT,
            challenge=challenge,
            evidence_id="BCB-" + "1" * 32,
            evidence_sha256="sha256:" + "e" * 64,
        )
        self.assertEqual(consumed.status, "consumed")
        self.assertIsNotNone(consumed.consumed_at)
        with self.assertRaisesRegex(ChallengeReplayConflictError, "already consumed"):
            self.store.consume_challenge(
                context=CONFORMANCE_CONTEXT,
                challenge=challenge,
                evidence_id="BCB-" + "1" * 32,
                evidence_sha256="sha256:" + "e" * 64,
            )

    def test_issue_rejects_binding_drift_sensitive_material_and_expiry(self) -> None:
        reservation = self.reserve()
        changed = self.challenge(reservation)
        changed["collector_id"] = "collector.changed"
        with self.assertRaisesRegex(ChallengeReplayConflictError, "does not match"):
            self.store.issue_challenge(reservation, changed)
        sensitive = self.challenge(reservation)
        sensitive["private_key"] = "must-not-persist"
        with self.assertRaisesRegex(StoreError, "prohibited"):
            self.store.issue_challenge(reservation, sensitive)

        challenge = self.challenge(reservation, lifetime_seconds=60)
        self.store.issue_challenge(reservation, challenge)
        self.clock.value += timedelta(seconds=60)
        selected = self.store.get_challenge(
            context=CONFORMANCE_CONTEXT,
            challenge_id=challenge["challenge_id"],
        )
        self.assertIsNotNone(selected)
        assert selected is not None
        self.assertEqual(selected.status, "expired")
        with self.assertRaises(ChallengeExpiredError):
            self.store.consume_challenge(
                context=CONFORMANCE_CONTEXT,
                challenge=challenge,
                evidence_id="BCB-" + "2" * 32,
                evidence_sha256="sha256:" + "f" * 64,
            )

    def test_duplicate_evidence_rejection_rolls_back_consumption(self) -> None:
        first_reservation = self.reserve()
        first_challenge = self.challenge(first_reservation)
        self.store.issue_challenge(first_reservation, first_challenge)
        self.store.consume_challenge(
            context=CONFORMANCE_CONTEXT,
            challenge=first_challenge,
            evidence_id="BCB-" + "3" * 32,
            evidence_sha256="sha256:" + "1" * 64,
        )
        second_reservation = self.reserve()
        second_challenge = self.challenge(second_reservation)
        self.store.issue_challenge(second_reservation, second_challenge)
        with self.assertRaisesRegex(ChallengeReplayConflictError, "already"):
            self.store.consume_challenge(
                context=CONFORMANCE_CONTEXT,
                challenge=second_challenge,
                evidence_id="BCB-" + "4" * 32,
                evidence_sha256="sha256:" + "1" * 64,
            )
        selected = self.store.get_challenge(
            context=CONFORMANCE_CONTEXT,
            challenge_id=second_challenge["challenge_id"],
        )
        self.assertIsNotNone(selected)
        assert selected is not None
        self.assertEqual(selected.status, "issued")

    def test_reopen_preserves_consumption_and_monotonic_sequence(self) -> None:
        reservation = self.reserve(context=CANDIDATE_EXECUTION_CONTEXT)
        challenge = self.challenge(reservation)
        self.store.issue_challenge(reservation, challenge)
        self.store.consume_challenge(
            context=CANDIDATE_EXECUTION_CONTEXT,
            challenge=challenge,
            evidence_id="CES-" + "5" * 32,
            evidence_sha256="sha256:" + "2" * 64,
        )
        reopened = ChallengeReplayStore(
            self.directory,
            self.controller,
            clock=self.clock,
        )
        reopened.initialize()
        record = reopened.get_challenge(
            context=CANDIDATE_EXECUTION_CONTEXT,
            challenge_id=challenge["challenge_id"],
        )
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(record.status, "consumed")
        next_reservation = reopened.reserve_sequence(
            context=CANDIDATE_EXECUTION_CONTEXT,
            collector_id=reservation.collector_id,
            key_id=reservation.key_id,
            public_key_sha256=reservation.public_key_sha256,
        )
        self.assertEqual(next_reservation.sequence_number, 2)

    def test_concurrent_consumers_commit_exactly_one_winner(self) -> None:
        reservation = self.reserve()
        challenge = self.challenge(reservation)
        self.store.issue_challenge(reservation, challenge)
        second_store = ChallengeReplayStore(
            self.directory,
            self.controller,
            clock=self.clock,
        )
        second_store.initialize()
        barrier = threading.Barrier(3)
        results: list[str] = []
        result_lock = threading.Lock()

        def consume(store: ChallengeReplayStore, evidence_digit: str) -> None:
            barrier.wait()
            try:
                store.consume_challenge(
                    context=CONFORMANCE_CONTEXT,
                    challenge=challenge,
                    evidence_id="BCB-" + evidence_digit * 32,
                    evidence_sha256="sha256:" + evidence_digit * 64,
                )
            except ChallengeReplayConflictError:
                result = "rejected"
            else:
                result = "consumed"
            with result_lock:
                results.append(result)

        threads = [
            threading.Thread(target=consume, args=(self.store, "6")),
            threading.Thread(target=consume, args=(second_store, "7")),
        ]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
        self.assertCountEqual(results, ["consumed", "rejected"])

    def test_schema_is_narrow_append_only_and_has_no_authority_columns(self) -> None:
        with closing(sqlite3.connect(self.store.path)) as connection:
            application_id = connection.execute("PRAGMA application_id").fetchone()[0]
            columns = {
                row[1]
                for table in (
                    "challenge_sequence_heads",
                    "challenge_reservations",
                )
                for row in connection.execute(f"PRAGMA table_info({table})")
            }
            self.assertEqual(application_id, APPLICATION_ID)
            self.assertFalse(
                columns
                & {
                    "private_key",
                    "qualification_grant",
                    "routing_authority",
                    "deployment_authority",
                    "target_authority",
                }
            )
            reservation = self.reserve()
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "DELETE FROM challenge_reservations WHERE reservation_id = ?",
                    (reservation.reservation_id,),
                )

    def test_access_control_and_clock_fail_closed(self) -> None:
        with self.assertRaisesRegex(StoreIntegrityError, "incomplete"):
            ChallengeReplayStore(self.directory / "incomplete", object())
        failing = TestAccessController()
        failing.fail_verification = True
        blocked = ChallengeReplayStore(self.directory / "blocked", failing)
        with self.assertRaisesRegex(StoreIntegrityError, "custody"):
            blocked.initialize()
        naive = ChallengeReplayStore(
            self.directory,
            self.controller,
            clock=lambda: datetime(2026, 9, 19, 12, 0),
        )
        with self.assertRaisesRegex(StoreError, "timezone-aware"):
            naive.reserve_sequence(
                context=CONFORMANCE_CONTEXT,
                collector_id="collector.naive",
                key_id="collector-key.naive",
                public_key_sha256=self.public_key_sha256,
            )

    @unittest.skipUnless(os.name == "posix", "POSIX permission check")
    def test_posix_controller_enforces_owner_only_modes(self) -> None:
        directory = Path(self.temporary.name) / "posix-custody"
        store = ChallengeReplayStore(
            directory,
            PosixOwnerOnlyChallengeReplayAccess(),
            clock=self.clock,
        )
        store.initialize()
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(store.path.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
