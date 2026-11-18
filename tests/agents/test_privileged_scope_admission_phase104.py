"""Phase 104 privileged ownership scope-admission coverage."""

from __future__ import annotations

import tomllib
import unittest
from datetime import timedelta
from pathlib import Path

from sunderkey.errors import PrincipalAuthenticationError
from sunderkey.identity import PrincipalOperation
from sunderkey.scope import ScopeGrantAcceptanceService
from sunderkey.store import canonical_json, sha256_text
from sunderkey.types import ProfileKind

from . import test_collaboration_ownership_preflight_phase90 as phase90
from . import (
    test_collaboration_ownership_privileged_reassignment_preflight_phase101 as phase101,
)

EXTERNAL_PROPOSED_ID = "AOE-HQ-01"
EXTERNAL_CONTROL_ID = "AOE-HQ-13"
EXTERNAL_SECOND_AUTHORITY_ID = "AOE-HQ-14"
ROOT = Path(__file__).resolve().parents[2]


class PrivilegedScopeAdmissionPhase104Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        phase101.CollaborationOwnershipPrivilegedReassignmentPreflightPhase101Tests.setUpClass()

    def setUp(self) -> None:
        base = phase101.CollaborationOwnershipPrivilegedReassignmentPreflightPhase101Tests(
            methodName="runTest"
        )
        base.setUp()
        self.addCleanup(base.doCleanups)
        self.base = base
        self.fixture = base.fixture
        self.fixture.now += timedelta(minutes=1)
        self.policy_version = base.base.trust_policy_version + 1
        self.operations = (
            PrincipalOperation.COLLABORATION_OWNERSHIP_CURRENT_OWNER_AUTHORIZE,
            PrincipalOperation.COLLABORATION_OWNERSHIP_PROPOSED_OWNER_ACCEPT,
            PrincipalOperation.COLLABORATION_OWNERSHIP_CONTROL_APPROVE,
            PrincipalOperation.COLLABORATION_OWNERSHIP_SECOND_AUTHORITY_APPROVE,
        )
        self.external_profiles = (
            EXTERNAL_PROPOSED_ID,
            EXTERNAL_CONTROL_ID,
            EXTERNAL_SECOND_AUTHORITY_ID,
        )
        self._apply_scope_policy(self.fixture, self.policy_version)
        self.acceptance = ScopeGrantAcceptanceService(
            self.fixture.store,
            self.fixture.registry,
        )

    def _apply_scope_policy(self, fixture, policy_version: int) -> None:
        allowed_operations = sorted(
            {
                *(operation.value for operation in fixture.policy.allowed_operations),
                *(operation.value for operation in self.operations),
                PrincipalOperation.WORK_CLAIM.value,
            }
        )
        trust_policy = fixture.factory.policy(
            policy_version=policy_version,
            store_id=fixture.store_id,
            allowed_profiles=sorted(
                {
                    *fixture.stored.allowed_profile_ids,
                    *self.external_profiles,
                }
            ),
            allowed_operations=allowed_operations,
        )
        fixture.trust.apply_policy(trust_policy)

    def _grant(
        self,
        profile_id: str,
        operations: list[PrincipalOperation],
        marker: str,
        *,
        fixture=None,
        policy_version: int | None = None,
    ):
        target = fixture or self.fixture
        return target.factory.grant(
            grant_id=(
                "SGR-"
                + sha256_text("phase104-scope-" + marker)[7:39].upper()
            ),
            profile_id=profile_id,
            store_id=target.store_id,
            mission_id=phase90.MISSION_ID,
            mission_context_hash=target.stored.context_hash,
            scope_reference=target.mission.scope_reference,
            scope_document_hash=target.mission.scope_document_hash,
            environment=target.mission.environment.value,
            max_action_tier=target.mission.max_action_tier.value,
            constraints_hash=sha256_text(
                canonical_json(target.mission.to_dict()["constraints"])
            ),
            operations=[operation.value for operation in operations],
            policy_version=policy_version or self.policy_version,
        )

    def test_external_privileged_participants_receive_only_ownership_scopes(
        self,
    ) -> None:
        proposed = self.acceptance.accept(
            self._grant(
                EXTERNAL_PROPOSED_ID,
                [
                    PrincipalOperation.COLLABORATION_OWNERSHIP_PROPOSED_OWNER_ACCEPT
                ],
                "A",
            )
        )
        control = self.acceptance.accept(
            self._grant(
                EXTERNAL_CONTROL_ID,
                [PrincipalOperation.COLLABORATION_OWNERSHIP_CONTROL_APPROVE],
                "B",
            )
        )
        second = self.acceptance.accept(
            self._grant(
                EXTERNAL_SECOND_AUTHORITY_ID,
                [
                    PrincipalOperation.COLLABORATION_OWNERSHIP_SECOND_AUTHORITY_APPROVE
                ],
                "C",
            )
        )
        self.assertNotIn(
            EXTERNAL_PROPOSED_ID,
            self.fixture.stored.allowed_profile_ids,
        )
        self.assertFalse(proposed.idempotent)
        self.assertFalse(control.idempotent)
        self.assertFalse(second.idempotent)
        self.fixture.store.verify_store(self.fixture.registry)

    def test_external_profile_cannot_receive_work_or_mixed_scope(self) -> None:
        for marker, operations in (
            ("D", [PrincipalOperation.WORK_CLAIM]),
            (
                "E",
                [
                    PrincipalOperation.COLLABORATION_OWNERSHIP_PROPOSED_OWNER_ACCEPT,
                    PrincipalOperation.WORK_CLAIM,
                ],
            ),
        ):
            with self.subTest(operations=operations), self.assertRaisesRegex(
                PrincipalAuthenticationError,
                "not assigned",
            ):
                self.acceptance.accept(
                    self._grant(
                        EXTERNAL_PROPOSED_ID,
                        operations,
                        marker,
                    )
                )

    def test_external_current_owner_scope_requires_effective_ownership(self) -> None:
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "not assigned",
        ):
            self.acceptance.accept(
                self._grant(
                    EXTERNAL_PROPOSED_ID,
                    [
                        PrincipalOperation.COLLABORATION_OWNERSHIP_CURRENT_OWNER_AUTHORIZE
                    ],
                    "F",
                )
            )

    def test_control_scope_requires_independent_control_profile(self) -> None:
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "not assigned",
        ):
            self.acceptance.accept(
                self._grant(
                    EXTERNAL_PROPOSED_ID,
                    [PrincipalOperation.COLLABORATION_OWNERSHIP_CONTROL_APPROVE],
                    "G",
                )
            )

    def test_specialist_cannot_enter_privileged_admission_path(self) -> None:
        specialist = next(
            profile
            for profile in self.fixture.registry.profiles
            if profile.kind is ProfileKind.SPECIALIST
            and profile.id not in self.fixture.stored.allowed_profile_ids
        )
        policy_version = self.policy_version + 1
        self.fixture.now += timedelta(minutes=1)
        policy = self.fixture.factory.policy(
            policy_version=policy_version,
            store_id=self.fixture.store_id,
            allowed_profiles=sorted(
                {
                    *self.fixture.stored.allowed_profile_ids,
                    *self.external_profiles,
                    specialist.id,
                }
            ),
            allowed_operations=sorted(
                {
                    *(operation.value for operation in self.fixture.policy.allowed_operations),
                    *(operation.value for operation in self.operations),
                    PrincipalOperation.WORK_CLAIM.value,
                }
            ),
        )
        self.fixture.trust.apply_policy(policy)
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "not assigned",
        ):
            self.acceptance.accept(
                self._grant(
                    specialist.id,
                    [
                        PrincipalOperation.COLLABORATION_OWNERSHIP_PROPOSED_OWNER_ACCEPT
                    ],
                    "H",
                    policy_version=policy_version,
                )
            )

    def test_disabled_d001_policy_rejects_external_ownership_scope(self) -> None:
        base = phase90.CollaborationOwnershipPreflightPhase90Tests(
            methodName="runTest"
        )
        base.setUp()
        self.addCleanup(base.doCleanups)
        base.fixture.now += timedelta(minutes=1)
        policy_version = base.trust_policy_version + 1
        self._apply_scope_policy(base.fixture, policy_version)
        acceptance = ScopeGrantAcceptanceService(
            base.fixture.store,
            base.fixture.registry,
        )
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "not assigned",
        ):
            acceptance.accept(
                self._grant(
                    EXTERNAL_PROPOSED_ID,
                    [
                        PrincipalOperation.COLLABORATION_OWNERSHIP_PROPOSED_OWNER_ACCEPT
                    ],
                    "I",
                    fixture=base.fixture,
                    policy_version=policy_version,
                )
            )

    def test_project_version_is_0_107(self) -> None:
        with (ROOT / "pyproject.toml").open("rb") as handle:
            project = tomllib.load(handle)
        self.assertEqual(project["project"]["version"], "0.1.0")


if __name__ == "__main__":
    unittest.main()
