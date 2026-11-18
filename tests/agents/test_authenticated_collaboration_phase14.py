"""Focused tests for authenticated Phase 14 plan activation."""

from __future__ import annotations

import ast
import hashlib
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sunderkey.authenticated_collaboration import (
    AuthenticatedCollaborationActivationReceipt,
    AuthenticatedCollaborationActivationService,
)
from sunderkey.collaboration import build_collaboration_plan
from sunderkey.errors import (
    CollaborationPlanError,
    PrincipalAuthenticationError,
    StoreConflictError,
)
from sunderkey.identity import (
    PrincipalOperation,
    compute_operation_intent_hash,
)
from sunderkey.mission import MissionRequest
from sunderkey.registry import load_registry
from sunderkey.scope import ScopeGrantAcceptanceService
from sunderkey.store import MissionStore, canonical_json, sha256_text
from sunderkey.trust import TrustProvisioningService

from .test_identity_phase4 import (
    ASSERTION_ID,
    AUDIENCE,
    OTHER_PROFILE_ID,
    ROOT_KEY_ID,
    SCOPE_DOCUMENT_HASH,
    SCOPE_REFERENCE,
    CredentialFactory,
    b64url,
    public_bytes,
)
from .test_store import REGISTRY_PATH, mission_data

MISSION_ID = "MISSION-PHASE14-COLLABORATION"
ACTIVATOR_ID = "AOE-HQ-08"
POLICY_VERSION = 14
ROOT = Path(__file__).resolve().parents[2]


class AuthenticatedCollaborationPhase14Tests(
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
            / "authenticated-collaboration.sqlite3"
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
        self.stored = self.store.create_mission(
            self.registry,
            self.mission,
        )
        self.plan = build_collaboration_plan(
            self.registry,
            self.mission,
        )

        self.factory = CredentialFactory()
        self.trust = TrustProvisioningService(self.store)
        self.store_id = self.trust.status().store_id
        root_public_key = public_bytes(
            self.factory.root_private
        )
        self.trust.pin_root(
            ROOT_KEY_ID,
            AUDIENCE,
            b64url(root_public_key),
            "sha256:"
            + hashlib.sha256(root_public_key).hexdigest(),
        )
        self.policy = self.factory.policy(
            policy_version=POLICY_VERSION,
            store_id=self.store_id,
            allowed_profiles=[
                ACTIVATOR_ID,
                OTHER_PROFILE_ID,
            ],
            allowed_operations=[
                PrincipalOperation.COLLABORATION_ACTIVATE.value
            ],
        )
        self.trust.apply_policy(self.policy)
        self.grant = self.factory.grant(
            profile_id=ACTIVATOR_ID,
            store_id=self.store_id,
            mission_id=MISSION_ID,
            mission_context_hash=self.stored.context_hash,
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
                PrincipalOperation.COLLABORATION_ACTIVATE.value
            ],
            issued_at="2026-07-30T10:05:00Z",
            not_before="2026-07-30T10:05:00Z",
            expires_at="2026-07-30T10:30:00Z",
            policy_version=POLICY_VERSION,
        )
        ScopeGrantAcceptanceService(
            self.store,
            self.registry,
        ).accept(self.grant)
        intent_hash = compute_operation_intent_hash(
            PrincipalOperation.COLLABORATION_ACTIVATE,
            {
                "mission_id": MISSION_ID,
                "plan_content_sha256": (
                    self.plan.content_sha256
                ),
                "plan_id": self.plan.plan_id,
                "principal_profile_id": ACTIVATOR_ID,
            },
        )
        self.assertion = self.factory.assertion(
            grant=self.grant,
            assertion_id=ASSERTION_ID,
            policy_version=POLICY_VERSION,
            scope_grant_id=self.grant.grant_id,
            subject=self.grant.subject,
            profile_id=ACTIVATOR_ID,
            audience=AUDIENCE,
            store_id=self.store_id,
            mission_id=MISSION_ID,
            operation=(
                PrincipalOperation.COLLABORATION_ACTIVATE
            ),
            operation_intent_sha256=intent_hash,
            issued_at="2026-07-30T10:05:00Z",
            not_before="2026-07-30T10:05:00Z",
            expires_at="2026-07-30T10:09:00Z",
        )
        self.service = (
            AuthenticatedCollaborationActivationService(
                self.store,
                self.registry,
                clock=lambda: self.now,
            )
        )

    def test_activation_commits_plan_and_provenance_atomically(
        self,
    ) -> None:
        receipt = self.service.activate(
            self.assertion,
            self.plan,
        )

        self.assertEqual(receipt.plan, self.plan)
        self.assertEqual(
            receipt.principal_profile_id,
            ACTIVATOR_ID,
        )
        self.assertEqual(
            receipt.activated_at,
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
                    "collaboration_plan_activations",
                    "principal_assertion_uses",
                    "principal_assertion_effects",
                )
            }
            mission_state = connection.execute(
                """
                SELECT revision
                FROM missions
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
            event_count = int(
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM mission_events
                    WHERE mission_id = ?
                    """,
                    (MISSION_ID,),
                ).fetchone()[0]
            )
        self.assertEqual(set(counts.values()), {1})
        self.assertEqual(mission_state, (0,))
        self.assertEqual(event_count, 0)
        self.assertEqual(
            self.service.get(MISSION_ID).to_dict(),
            receipt.to_dict(),
        )
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_exact_replay_survives_expiry_and_policy_advancement(
        self,
    ) -> None:
        first = self.service.activate(
            self.assertion,
            self.plan,
        )
        self.now += timedelta(minutes=10)
        self.trust.apply_policy(
            self.factory.policy(
                policy_version=POLICY_VERSION + 1,
                store_id=self.store_id,
                allowed_profiles=[
                    ACTIVATOR_ID,
                    OTHER_PROFILE_ID,
                ],
                allowed_operations=[
                    PrincipalOperation.COLLABORATION_ACTIVATE.value
                ],
            )
        )

        replay = self.service.activate(
            self.assertion,
            self.plan,
        )

        self.assertEqual(replay.to_dict(), first.to_dict())

    def test_readiness_owner_is_mandatory(self) -> None:
        wrong = self.factory.assertion(
            grant=self.grant,
            assertion_id="PAS-" + "B" * 32,
            policy_version=POLICY_VERSION,
            scope_grant_id=self.grant.grant_id,
            subject=self.grant.subject,
            profile_id=OTHER_PROFILE_ID,
            audience=AUDIENCE,
            store_id=self.store_id,
            mission_id=MISSION_ID,
            operation=(
                PrincipalOperation.COLLABORATION_ACTIVATE
            ),
            operation_intent_sha256=(
                self.assertion.operation_intent_sha256
            ),
            issued_at="2026-07-30T10:05:00Z",
            not_before="2026-07-30T10:05:00Z",
            expires_at="2026-07-30T10:09:00Z",
        )

        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "readiness owner",
        ):
            self.service.activate(wrong, self.plan)

        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM collaboration_plan_activations
                    """
                ).fetchone()[0],
                0,
            )

    def test_tampered_plan_rolls_back_without_assertion_use(
        self,
    ) -> None:
        tampered = replace(
            self.plan,
            mission_objective="Changed objective",
        )

        with self.assertRaises(CollaborationPlanError):
            self.service.activate(self.assertion, tampered)

        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM principal_assertion_uses
                    """
                ).fetchone()[0],
                0,
            )

    def test_concurrent_competing_assertions_commit_one_plan(
        self,
    ) -> None:
        second = self.factory.assertion(
            grant=self.grant,
            assertion_id="PAS-" + "C" * 32,
            policy_version=POLICY_VERSION,
            scope_grant_id=self.grant.grant_id,
            subject=self.grant.subject,
            profile_id=ACTIVATOR_ID,
            audience=AUDIENCE,
            store_id=self.store_id,
            mission_id=MISSION_ID,
            operation=(
                PrincipalOperation.COLLABORATION_ACTIVATE
            ),
            operation_intent_sha256=(
                self.assertion.operation_intent_sha256
            ),
            issued_at="2026-07-30T10:05:00Z",
            not_before="2026-07-30T10:05:00Z",
            expires_at="2026-07-30T10:09:00Z",
        )
        barrier = threading.Barrier(2)

        def run(assertion):
            service = AuthenticatedCollaborationActivationService(
                self.store,
                self.registry,
                clock=lambda: self.now,
            )
            barrier.wait()
            try:
                return service.activate(assertion, self.plan)
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
                AuthenticatedCollaborationActivationReceipt,
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
            StoreConflictError,
        )

    def test_authenticated_module_has_no_execution_surface(
        self,
    ) -> None:
        source_path = (
            ROOT
            / "src"
            / "sunderkey"
            / "authenticated_collaboration.py"
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
