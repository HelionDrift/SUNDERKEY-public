"""Focused tests for authenticated Phase 15 owner-only leases."""

from __future__ import annotations

import ast
import hashlib
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sunderkey.authenticated import (
    AuthenticatedMissionControlService,
)
from sunderkey.authenticated_collaboration import (
    AuthenticatedCollaborationActivationService,
)
from sunderkey.authenticated_work import (
    AuthenticatedWorkItemLeaseService,
    AuthenticatedWorkItemTransitionReceipt,
    WorkItemRuntimeState,
)
from sunderkey.collaboration import (
    WorkItemKind,
    build_collaboration_plan,
)
from sunderkey.errors import (
    MissionStoppedError,
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
from sunderkey.store import (
    MissionStore,
    canonical_json,
    format_timestamp,
    sha256_text,
)
from sunderkey.trust import TrustProvisioningService

from .test_identity_phase4 import (
    AUDIENCE,
    ROOT_KEY_ID,
    SCOPE_DOCUMENT_HASH,
    SCOPE_REFERENCE,
    CredentialFactory,
    b64url,
    public_bytes,
)
from .test_store import REGISTRY_PATH, mission_data

MISSION_ID = "MISSION-PHASE15-WORK"
OWNER_ID = "AOE-HQ-08"
CONTROL_ID = "AOE-HQ-12"
POLICY_VERSION = 15
OPERATIONS = [
    PrincipalOperation.COLLABORATION_ACTIVATE.value,
    PrincipalOperation.MISSION_STOP.value,
    PrincipalOperation.WORK_CLAIM.value,
    PrincipalOperation.WORK_COMPLETE.value,
    PrincipalOperation.WORK_RELEASE.value,
    PrincipalOperation.WORK_RENEW.value,
    PrincipalOperation.WORK_RECOVERY_REQUEST.value,
    PrincipalOperation.WORK_RECOVERY_APPROVE.value,
    PrincipalOperation.WORK_RECOVERY_DENY.value,
    PrincipalOperation.WORK_CANCEL.value,
    PrincipalOperation.WORK_HANDOFF_AUTHORIZE.value,
    PrincipalOperation.WORK_HANDOFF_ACCEPT.value,
]
ROOT = Path(__file__).resolve().parents[2]


class AuthenticatedWorkPhase15Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = (
            Path(temporary.name)
            / "authenticated-work.sqlite3"
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
        self.readiness = next(
            item
            for item in self.plan.work_items
            if item.kind is WorkItemKind.READINESS
        )
        self.specialist = next(
            item
            for item in self.plan.work_items
            if item.kind is WorkItemKind.SPECIALIST_ANALYSIS
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
                OWNER_ID,
                CONTROL_ID,
                self.specialist.owner_profile_id,
            ],
            allowed_operations=OPERATIONS,
        )
        self.trust.apply_policy(self.policy)
        constraints_hash = sha256_text(
            canonical_json(
                self.mission.to_dict()["constraints"]
            )
        )
        grant_arguments = {
            "store_id": self.store_id,
            "mission_id": MISSION_ID,
            "mission_context_hash": self.stored.context_hash,
            "scope_reference": SCOPE_REFERENCE,
            "scope_document_hash": SCOPE_DOCUMENT_HASH,
            "environment": self.mission.environment.value,
            "max_action_tier": (
                self.mission.max_action_tier.value
            ),
            "constraints_hash": constraints_hash,
            "operations": OPERATIONS,
            "issued_at": "2026-07-30T10:05:00Z",
            "not_before": "2026-07-30T10:05:00Z",
            "expires_at": "2026-07-30T10:55:00Z",
            "policy_version": POLICY_VERSION,
        }
        self.owner_grant = self.factory.grant(
            grant_id="SGR-" + "A" * 32,
            profile_id=OWNER_ID,
            **grant_arguments,
        )
        self.specialist_grant = self.factory.grant(
            grant_id="SGR-" + "B" * 32,
            profile_id=self.specialist.owner_profile_id,
            **grant_arguments,
        )
        self.control_grant = self.factory.grant(
            grant_id="SGR-" + "C" * 32,
            profile_id=CONTROL_ID,
            **grant_arguments,
        )
        acceptance = ScopeGrantAcceptanceService(
            self.store,
            self.registry,
        )
        acceptance.accept(self.owner_grant)
        acceptance.accept(self.specialist_grant)
        acceptance.accept(self.control_grant)

        activation_intent = {
            "mission_id": MISSION_ID,
            "plan_content_sha256": self.plan.content_sha256,
            "plan_id": self.plan.plan_id,
            "principal_profile_id": OWNER_ID,
        }
        activation_assertion = self._assertion(
            PrincipalOperation.COLLABORATION_ACTIVATE,
            activation_intent,
            "A",
            OWNER_ID,
            self.owner_grant,
        )
        AuthenticatedCollaborationActivationService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        ).activate(
            activation_assertion,
            self.plan,
        )
        self.service = AuthenticatedWorkItemLeaseService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        )

    def _assertion(
        self,
        operation: PrincipalOperation,
        intent: dict,
        token: str,
        profile_id: str,
        grant,
    ):
        issued_at = format_timestamp(self.now)
        expires_at = format_timestamp(
            self.now + timedelta(minutes=4)
        )
        return self.factory.assertion(
            grant=grant,
            assertion_id="PAS-" + token * 32,
            policy_version=POLICY_VERSION,
            scope_grant_id=grant.grant_id,
            subject=grant.subject,
            profile_id=profile_id,
            audience=AUDIENCE,
            store_id=self.store_id,
            mission_id=MISSION_ID,
            operation=operation,
            operation_intent_sha256=(
                compute_operation_intent_hash(
                    operation,
                    intent,
                )
            ),
            issued_at=issued_at,
            not_before=issued_at,
            expires_at=expires_at,
        )

    def _claim_intent(
        self,
        item,
        expected_generation: int,
    ) -> dict:
        return {
            "expected_generation": expected_generation,
            "mission_id": MISSION_ID,
            "plan_content_sha256": self.plan.content_sha256,
            "plan_id": self.plan.plan_id,
            "principal_profile_id": item.owner_profile_id,
            "work_item_id": item.work_item_id,
        }

    def _claim(
        self,
        token: str = "B",
        *,
        expected_generation: int = 0,
        item=None,
        grant=None,
    ):
        target = item or self.readiness
        credential = grant or self.owner_grant
        assertion = self._assertion(
            PrincipalOperation.WORK_CLAIM,
            self._claim_intent(
                target,
                expected_generation,
            ),
            token,
            target.owner_profile_id,
            credential,
        )
        return (
            assertion,
            self.service.claim(
                assertion,
                MISSION_ID,
                target.work_item_id,
                expected_generation=expected_generation,
            ),
        )

    def _active_intent(
        self,
        operation: PrincipalOperation,
        receipt,
        *,
        extra: dict | None = None,
    ) -> dict:
        value = {
            "claim_generation": receipt.generation,
            "expected_lease_expires_at": (
                receipt.lease_expires_at
            ),
            "mission_id": MISSION_ID,
            "plan_content_sha256": self.plan.content_sha256,
            "plan_id": self.plan.plan_id,
            "previous_transition_id": receipt.transition_id,
            "principal_profile_id": (
                receipt.owner_profile_id
            ),
            "work_item_id": receipt.work_item_id,
        }
        if extra:
            value.update(extra)
        return value

    def test_initial_claim_is_owner_only_and_fenced(self) -> None:
        initial = self.service.status(MISSION_ID)
        by_id = {
            item.work_item_id: item
            for item in initial.work_items
        }
        self.assertEqual(
            by_id[self.readiness.work_item_id].state,
            WorkItemRuntimeState.READY,
        )
        self.assertEqual(
            by_id[self.specialist.work_item_id].state,
            WorkItemRuntimeState.BLOCKED,
        )

        _, receipt = self._claim()

        self.assertEqual(receipt.generation, 1)
        self.assertEqual(
            receipt.lease_expires_at,
            "2026-07-30T10:20:00Z",
        )
        self.assertRegex(
            receipt.transition_id,
            r"^WLT-[0-9A-F]{32}$",
        )
        status = self.service.status(
            MISSION_ID,
            work_item_id=self.readiness.work_item_id,
        )
        self.assertEqual(
            status.work_items[0].state,
            WorkItemRuntimeState.LEASED,
        )
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM collaboration_work_item_transitions
                    """
                ).fetchone()[0],
                1,
            )
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_supporter_or_other_profile_cannot_claim(self) -> None:
        intent = self._claim_intent(self.readiness, 0)
        wrong = self._assertion(
            PrincipalOperation.WORK_CLAIM,
            intent,
            "C",
            self.specialist.owner_profile_id,
            self.specialist_grant,
        )

        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "planned owner",
        ):
            self.service.claim(
                wrong,
                MISSION_ID,
                self.readiness.work_item_id,
                expected_generation=0,
            )

    def test_competing_owner_claims_commit_one_generation(
        self,
    ) -> None:
        assertions = tuple(
            self._assertion(
                PrincipalOperation.WORK_CLAIM,
                self._claim_intent(self.readiness, 0),
                token,
                OWNER_ID,
                self.owner_grant,
            )
            for token in ("D", "E")
        )
        barrier = threading.Barrier(2)

        def run(assertion):
            service = AuthenticatedWorkItemLeaseService(
                self.store,
                self.registry,
                clock=lambda: self.now,
            )
            barrier.wait()
            try:
                return service.claim(
                    assertion,
                    MISSION_ID,
                    self.readiness.work_item_id,
                    expected_generation=0,
                )
            except Exception as exc:
                return exc

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = tuple(executor.map(run, assertions))

        self.assertEqual(
            sum(
                isinstance(
                    result,
                    AuthenticatedWorkItemTransitionReceipt,
                )
                for result in results
            ),
            1,
        )
        self.assertEqual(
            sum(
                isinstance(result, StoreConflictError)
                for result in results
            ),
            1,
        )

    def test_renewal_advances_fence_and_exact_replay_survives(
        self,
    ) -> None:
        _, claim = self._claim(token="F")
        self.now += timedelta(minutes=5)
        intent = self._active_intent(
            PrincipalOperation.WORK_RENEW,
            claim,
        )
        assertion = self._assertion(
            PrincipalOperation.WORK_RENEW,
            intent,
            "1",
            OWNER_ID,
            self.owner_grant,
        )
        renewed = self.service.renew(
            assertion,
            MISSION_ID,
            self.readiness.work_item_id,
            claim_generation=claim.generation,
            previous_transition_id=claim.transition_id,
            expected_lease_expires_at=(
                claim.lease_expires_at
            ),
        )

        self.assertEqual(renewed.generation, 1)
        self.assertEqual(
            renewed.lease_expires_at,
            "2026-07-30T10:25:00Z",
        )
        stale_intent = self._active_intent(
            PrincipalOperation.WORK_COMPLETE,
            claim,
            extra={
                "evidence_manifest_sha256": (
                    "sha256:" + "6" * 64
                ),
                "result_id": "RES-STALE",
                "result_sha256": "sha256:" + "7" * 64,
            },
        )
        stale = self._assertion(
            PrincipalOperation.WORK_COMPLETE,
            stale_intent,
            "2",
            OWNER_ID,
            self.owner_grant,
        )
        with self.assertRaisesRegex(
            StoreConflictError,
            "fence changed",
        ):
            self.service.complete(
                stale,
                MISSION_ID,
                self.readiness.work_item_id,
                claim_generation=claim.generation,
                previous_transition_id=claim.transition_id,
                expected_lease_expires_at=(
                    claim.lease_expires_at
                ),
                result_id="RES-STALE",
                result_sha256="sha256:" + "7" * 64,
                evidence_manifest_sha256=(
                    "sha256:" + "6" * 64
                ),
            )

        self.now += timedelta(minutes=20)
        replay = self.service.renew(
            assertion,
            MISSION_ID,
            self.readiness.work_item_id,
            claim_generation=claim.generation,
            previous_transition_id=claim.transition_id,
            expected_lease_expires_at=(
                claim.lease_expires_at
            ),
        )
        self.assertEqual(replay.to_dict(), renewed.to_dict())

    def test_expiry_reacquires_with_next_generation(self) -> None:
        assertion, first = self._claim(token="3")
        self.now += timedelta(minutes=16)
        status = self.service.status(
            MISSION_ID,
            work_item_id=self.readiness.work_item_id,
        )
        self.assertEqual(
            status.work_items[0].state,
            WorkItemRuntimeState.READY,
        )

        _, second = self._claim(
            token="4",
            expected_generation=1,
        )

        self.assertEqual(second.generation, 2)
        replay = self.service.claim(
            assertion,
            MISSION_ID,
            self.readiness.work_item_id,
            expected_generation=0,
        )
        self.assertEqual(replay.to_dict(), first.to_dict())

    def test_three_released_attempts_require_review(self) -> None:
        current = None
        for generation, claim_token, release_token in (
            (1, "5", "6"),
            (2, "7", "8"),
            (3, "9", "0"),
        ):
            _, current = self._claim(
                token=claim_token,
                expected_generation=generation - 1,
            )
            intent = self._active_intent(
                PrincipalOperation.WORK_RELEASE,
                current,
                extra={
                    "reason": "Owner cannot continue",
                    "reason_code": "owner_release",
                },
            )
            assertion = self._assertion(
                PrincipalOperation.WORK_RELEASE,
                intent,
                release_token,
                OWNER_ID,
                self.owner_grant,
            )
            self.service.release(
                assertion,
                MISSION_ID,
                self.readiness.work_item_id,
                claim_generation=current.generation,
                previous_transition_id=(
                    current.transition_id
                ),
                expected_lease_expires_at=(
                    current.lease_expires_at
                ),
                reason_code="owner_release",
                reason="Owner cannot continue",
            )

        status = self.service.status(
            MISSION_ID,
            work_item_id=self.readiness.work_item_id,
        )
        self.assertEqual(
            status.work_items[0].state,
            WorkItemRuntimeState.NEEDS_REVIEW,
        )
        blocked = self._assertion(
            PrincipalOperation.WORK_CLAIM,
            self._claim_intent(self.readiness, 3),
            "B",
            OWNER_ID,
            self.owner_grant,
        )
        with self.assertRaisesRegex(
            StoreConflictError,
            "require review",
        ):
            self.service.claim(
                blocked,
                MISSION_ID,
                self.readiness.work_item_id,
                expected_generation=3,
            )

    def test_evidence_bound_completion_unblocks_dependency(
        self,
    ) -> None:
        _, claim = self._claim(token="C")
        self.now += timedelta(minutes=1)
        completion_values = {
            "evidence_manifest_sha256": "sha256:" + "6" * 64,
            "result_id": "RES-READINESS-001",
            "result_sha256": "sha256:" + "7" * 64,
        }
        intent = self._active_intent(
            PrincipalOperation.WORK_COMPLETE,
            claim,
            extra=completion_values,
        )
        assertion = self._assertion(
            PrincipalOperation.WORK_COMPLETE,
            intent,
            "D",
            OWNER_ID,
            self.owner_grant,
        )
        completed = self.service.complete(
            assertion,
            MISSION_ID,
            self.readiness.work_item_id,
            claim_generation=claim.generation,
            previous_transition_id=claim.transition_id,
            expected_lease_expires_at=(
                claim.lease_expires_at
            ),
            **completion_values,
        )

        self.assertEqual(
            completed.result_id,
            "RES-READINESS-001",
        )
        statuses = self.service.status(MISSION_ID)
        by_id = {
            item.work_item_id: item
            for item in statuses.work_items
        }
        self.assertEqual(
            by_id[self.readiness.work_item_id].state,
            WorkItemRuntimeState.COMPLETED,
        )
        self.assertEqual(
            by_id[self.specialist.work_item_id].state,
            WorkItemRuntimeState.READY,
        )
        _, specialist_claim = self._claim(
            token="E",
            item=self.specialist,
            grant=self.specialist_grant,
        )
        self.assertEqual(
            specialist_claim.owner_profile_id,
            self.specialist.owner_profile_id,
        )
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_mission_stop_blocks_new_mutations_but_not_replay(
        self,
    ) -> None:
        claim_assertion, claim = self._claim(token="F")
        stop_values = {
            "decision_owner": "range-control",
            "expected_version": 1,
            "mission_id": MISSION_ID,
            "principal_profile_id": CONTROL_ID,
            "reason": "Operator stopped the mission",
            "reason_code": "operator_request",
            "risk": "Further work is outside the decision",
        }
        stop_intent = {
            **stop_values,
            "idempotency_key_sha256": sha256_text(
                "phase15-stop"
            ),
        }
        stop_assertion = self._assertion(
            PrincipalOperation.MISSION_STOP,
            stop_intent,
            "0",
            CONTROL_ID,
            self.control_grant,
        )
        AuthenticatedMissionControlService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        ).stop(
            stop_assertion,
            MISSION_ID,
            reason_code=stop_values["reason_code"],
            reason=stop_values["reason"],
            risk=stop_values["risk"],
            decision_owner=stop_values["decision_owner"],
            idempotency_key="phase15-stop",
            expected_version=stop_values["expected_version"],
        )

        status = self.service.status(
            MISSION_ID,
            work_item_id=self.readiness.work_item_id,
        )
        self.assertEqual(
            status.work_items[0].state,
            WorkItemRuntimeState.STOPPED,
        )
        replay = self.service.claim(
            claim_assertion,
            MISSION_ID,
            self.readiness.work_item_id,
            expected_generation=0,
        )
        self.assertEqual(replay.to_dict(), claim.to_dict())

        renew_intent = self._active_intent(
            PrincipalOperation.WORK_RENEW,
            claim,
        )
        renew_assertion = self._assertion(
            PrincipalOperation.WORK_RENEW,
            renew_intent,
            "1",
            OWNER_ID,
            self.owner_grant,
        )
        with self.assertRaises(MissionStoppedError):
            self.service.renew(
                renew_assertion,
                MISSION_ID,
                self.readiness.work_item_id,
                claim_generation=claim.generation,
                previous_transition_id=claim.transition_id,
                expected_lease_expires_at=(
                    claim.lease_expires_at
                ),
            )

    def test_authenticated_work_module_has_no_execution_surface(
        self,
    ) -> None:
        source_path = (
            ROOT
            / "src"
            / "sunderkey"
            / "authenticated_work.py"
        )
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        forbidden_imports = {
            "http",
            "requests",
            "socket",
            "subprocess",
            "urllib",
        }
        imported = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported.update(
            node.module.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            and node.module is not None
        )
        self.assertFalse(imported & forbidden_imports)


if __name__ == "__main__":
    unittest.main()
