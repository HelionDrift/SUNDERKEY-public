"""Focused tests for authenticated Phase 13 mission creation."""

from __future__ import annotations

import ast
import hashlib
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from sunderkey.authenticated_missions import (
    AuthenticatedMissionCreationReceipt,
    AuthenticatedMissionCreationService,
)
from sunderkey.errors import (
    PrincipalAuthenticationError,
    StoreConflictError,
)
from sunderkey.identity import (
    PrincipalOperation,
    compute_operation_intent_hash,
)
from sunderkey.mission import MissionRequest
from sunderkey.registry import load_registry
from sunderkey.store import MissionStore, canonical_json, sha256_text
from sunderkey.trust import TrustProvisioningService

from .test_identity_phase4 import (
    ASSERTION_ID,
    AUDIENCE,
    PROFILE_ID,
    ROOT_KEY_ID,
    SCOPE_DOCUMENT_HASH,
    SCOPE_REFERENCE,
    CredentialFactory,
    b64url,
    public_bytes,
)
from .test_store import REGISTRY_PATH, mission_data

MISSION_ID = "MISSION-PHASE13-CREATE"
POLICY_VERSION = 13
ROOT = Path(__file__).resolve().parents[2]


class AuthenticatedMissionCreationPhase13Tests(
    unittest.TestCase
):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = (
            Path(temporary.name)
            / "authenticated-mission-creation.sqlite3"
        )
        self.now = datetime(
            2026,
            7,
            30,
            10,
            5,
            tzinfo=UTC,
        )
        self.store = MissionStore(
            self.path,
            clock=lambda: self.now,
        )
        self.store.initialize()
        raw_mission = mission_data()
        raw_mission.update(
            {
                "mission_id": MISSION_ID,
                "scope_reference": SCOPE_REFERENCE,
                "scope_document_hash": SCOPE_DOCUMENT_HASH,
            }
        )
        self.mission = MissionRequest.from_dict(raw_mission)
        self.context = self.store._build_context(
            self.registry,
            self.mission,
        )
        self.context_hash = sha256_text(
            canonical_json(self.context)
        )

        self.factory = CredentialFactory()
        trust = TrustProvisioningService(self.store)
        self.store_id = trust.status().store_id
        root_public_key = public_bytes(
            self.factory.root_private
        )
        trust.pin_root(
            ROOT_KEY_ID,
            AUDIENCE,
            b64url(root_public_key),
            "sha256:"
            + hashlib.sha256(root_public_key).hexdigest(),
        )
        self.policy = self.factory.policy(
            policy_version=POLICY_VERSION,
            store_id=self.store_id,
            allowed_profiles=[PROFILE_ID],
            allowed_operations=[
                PrincipalOperation.MISSION_CREATE.value
            ],
        )
        trust.apply_policy(self.policy)
        self.grant = self.factory.grant(
            profile_id=PROFILE_ID,
            store_id=self.store_id,
            mission_id=MISSION_ID,
            mission_context_hash=self.context_hash,
            scope_reference=SCOPE_REFERENCE,
            scope_document_hash=SCOPE_DOCUMENT_HASH,
            environment=self.mission.environment.value,
            max_action_tier=self.mission.max_action_tier.value,
            constraints_hash=sha256_text(
                canonical_json(
                    self.mission.to_dict()["constraints"]
                )
            ),
            operations=[
                PrincipalOperation.MISSION_CREATE.value
            ],
            issued_at="2026-07-30T10:05:00Z",
            not_before="2026-07-30T10:05:00Z",
            expires_at="2026-07-30T10:30:00Z",
            policy_version=POLICY_VERSION,
        )
        intent_hash = compute_operation_intent_hash(
            PrincipalOperation.MISSION_CREATE,
            {
                "mission_context_sha256": self.context_hash,
                "mission_id": MISSION_ID,
                "principal_profile_id": PROFILE_ID,
            },
        )
        self.assertion = self.factory.assertion(
            grant=self.grant,
            assertion_id=ASSERTION_ID,
            policy_version=POLICY_VERSION,
            scope_grant_id=self.grant.grant_id,
            subject=self.grant.subject,
            profile_id=PROFILE_ID,
            audience=AUDIENCE,
            store_id=self.store_id,
            mission_id=MISSION_ID,
            operation=PrincipalOperation.MISSION_CREATE,
            operation_intent_sha256=intent_hash,
            issued_at="2026-07-30T10:05:00Z",
            not_before="2026-07-30T10:05:00Z",
            expires_at="2026-07-30T10:09:00Z",
        )
        self.service = AuthenticatedMissionCreationService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        )

    def test_create_commits_mission_scope_and_provenance(
        self,
    ) -> None:
        receipt = self.service.create(
            self.assertion,
            self.grant,
            self.mission,
        )

        self.assertEqual(
            receipt.mission.context_hash,
            self.context_hash,
        )
        self.assertEqual(
            receipt.principal_profile_id,
            PROFILE_ID,
        )
        self.assertEqual(
            receipt.operation_intent_sha256,
            self.assertion.operation_intent_sha256,
        )
        self.assertEqual(
            receipt.consumed_at,
            "2026-07-30T10:05:00Z",
        )
        with closing(sqlite3.connect(self.path)) as connection:
            counts = {
                table: int(
                    connection.execute(
                        f"SELECT COUNT(*) FROM {table}"
                    ).fetchone()[0]
                )
                for table in (
                    "missions",
                    "mission_scope_grants",
                    "principal_assertion_uses",
                    "principal_assertion_effects",
                    "mission_creation_provenance",
                )
            }
            ledger = connection.execute(
                """
                SELECT assertion_count, effect_count
                FROM mission_principal_ledgers
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
        self.assertEqual(set(counts.values()), {1})
        self.assertEqual(ledger, (1, 1))
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_exact_replay_precedes_current_credential_state(
        self,
    ) -> None:
        first = self.service.create(
            self.assertion,
            self.grant,
            self.mission,
        )
        self.now = datetime(
            2026,
            7,
            30,
            11,
            0,
            tzinfo=UTC,
        )

        replay = self.service.create(
            self.assertion,
            self.grant,
            self.mission,
        )

        self.assertEqual(replay.to_dict(), first.to_dict())

    def test_direct_new_and_exact_retry_are_blocked_after_policy(
        self,
    ) -> None:
        with self.assertRaisesRegex(
            StoreConflictError,
            "mission-create-authenticated",
        ):
            self.store.create_mission(
                self.registry,
                self.mission,
            )

        self.service.create(
            self.assertion,
            self.grant,
            self.mission,
        )
        with self.assertRaisesRegex(
            StoreConflictError,
            "mission-create-authenticated",
        ):
            self.store.create_mission(
                self.registry,
                self.mission,
            )

    def test_concurrent_competing_assertions_commit_one_creation(
        self,
    ) -> None:
        second = self.factory.assertion(
            grant=self.grant,
            assertion_id="PAS-" + "D" * 32,
            policy_version=POLICY_VERSION,
            scope_grant_id=self.grant.grant_id,
            subject=self.grant.subject,
            profile_id=PROFILE_ID,
            audience=AUDIENCE,
            store_id=self.store_id,
            mission_id=MISSION_ID,
            operation=PrincipalOperation.MISSION_CREATE,
            operation_intent_sha256=(
                self.assertion.operation_intent_sha256
            ),
            issued_at="2026-07-30T10:05:00Z",
            not_before="2026-07-30T10:05:00Z",
            expires_at="2026-07-30T10:09:00Z",
        )
        barrier = threading.Barrier(2)

        def run(assertion):
            service = AuthenticatedMissionCreationService(
                self.store,
                self.registry,
                clock=lambda: self.now,
            )
            barrier.wait()
            try:
                return service.create(
                    assertion,
                    self.grant,
                    self.mission,
                )
            except Exception as exc:
                return exc

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = tuple(
                executor.map(
                    run,
                    (self.assertion, second),
                )
            )

        receipts = [
            result
            for result in results
            if isinstance(
                result,
                AuthenticatedMissionCreationReceipt,
            )
        ]
        failures = [
            result
            for result in results
            if isinstance(result, Exception)
        ]
        self.assertEqual(len(receipts), 1)
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(
            failures[0],
            (StoreConflictError, PrincipalAuthenticationError),
        )
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM mission_creation_provenance
                    """
                ).fetchone()[0],
                1,
            )

    def test_wrong_signed_intent_rolls_back_everything(
        self,
    ) -> None:
        wrong_assertion = self.factory.assertion(
            grant=self.grant,
            assertion_id=ASSERTION_ID,
            policy_version=POLICY_VERSION,
            scope_grant_id=self.grant.grant_id,
            subject=self.grant.subject,
            profile_id=PROFILE_ID,
            audience=AUDIENCE,
            store_id=self.store_id,
            mission_id=MISSION_ID,
            operation=PrincipalOperation.MISSION_CREATE,
            operation_intent_sha256=(
                "sha256:" + "0" * 64
            ),
            issued_at="2026-07-30T10:05:00Z",
            not_before="2026-07-30T10:05:00Z",
            expires_at="2026-07-30T10:09:00Z",
        )

        with self.assertRaises(PrincipalAuthenticationError):
            self.service.create(
                wrong_assertion,
                self.grant,
                self.mission,
            )

        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM missions"
                ).fetchone()[0],
                0,
            )

    def test_authenticated_module_has_no_execution_surface(
        self,
    ) -> None:
        source_path = (
            ROOT / "src" / "sunderkey" / "authenticated_missions.py"
        )
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        forbidden_imports = {
            "http",
            "requests",
            "socket",
            "subprocess",
            "urllib",
        }
        forbidden_calls = {
            "__import__",
            "compile",
            "eval",
            "exec",
        }
        imported = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        called = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
        }
        self.assertFalse(imported & forbidden_imports)
        self.assertFalse(called & forbidden_calls)


if __name__ == "__main__":
    unittest.main()
