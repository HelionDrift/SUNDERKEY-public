"""Phase 18 authenticated specialist work handoff coverage."""

from __future__ import annotations

import ast
import hashlib
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
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
)
from sunderkey.authenticated_work_cancellations import (
    AuthenticatedWorkCancellationService,
)
from sunderkey.authenticated_work_handoffs import (
    HANDOFF_SCOPE,
    QUALIFICATION_BASIS,
    AuthenticatedWorkHandoffService,
)
from sunderkey.authenticated_work_recovery import (
    AuthenticatedWorkRecoveryService,
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

from .test_authenticated_work_phase15 import (
    CONTROL_ID,
    OPERATIONS,
    OWNER_ID,
    POLICY_VERSION,
)
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

MISSION_ID = "MISSION-PHASE18-HANDOFF"
SOURCE_ID = "AOE-GB-D06-S09"
CANDIDATE_ID = "AOE-GB-D06-S10"
WRONG_COMMAND_ID = "AOE-GB-D07-S01"
ISSUER = "identity-provider"
ROOT = Path(__file__).resolve().parents[2]


class AuthenticatedWorkHandoffPhase18Tests(unittest.TestCase):
    """Exercise atomic authorization, acceptance, and owner projection."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "work-handoff.sqlite3"
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
                "requested_specialist_ids": [
                    SOURCE_ID,
                    CANDIDATE_ID,
                    WRONG_COMMAND_ID,
                ],
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
        self.source = next(
            item
            for item in self.plan.work_items
            if item.owner_profile_id == SOURCE_ID
        )
        self.candidate_item = next(
            item
            for item in self.plan.work_items
            if item.owner_profile_id == CANDIDATE_ID
        )
        self.wrong_candidate_item = next(
            item
            for item in self.plan.work_items
            if item.owner_profile_id == WRONG_COMMAND_ID
        )
        self.candidate_profile = self.registry.profile(CANDIDATE_ID)

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
        allowed_profiles = [
            OWNER_ID,
            CONTROL_ID,
            SOURCE_ID,
            CANDIDATE_ID,
            WRONG_COMMAND_ID,
        ]
        self.policy = self.factory.policy(
            policy_version=POLICY_VERSION,
            store_id=self.store_id,
            allowed_profiles=allowed_profiles,
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
        profiles = [
            (OWNER_ID, "A"),
            (CONTROL_ID, "B"),
            (SOURCE_ID, "C"),
            (CANDIDATE_ID, "D"),
            (WRONG_COMMAND_ID, "E"),
        ]
        self.grants = {
            profile_id: self.factory.grant(
                grant_id="SGR-" + token * 32,
                profile_id=profile_id,
                **grant_arguments,
            )
            for profile_id, token in profiles
        }
        acceptance = ScopeGrantAcceptanceService(
            self.store,
            self.registry,
        )
        for grant in self.grants.values():
            acceptance.accept(grant)

        activation_intent = {
            "mission_id": MISSION_ID,
            "plan_content_sha256": self.plan.content_sha256,
            "plan_id": self.plan.plan_id,
            "principal_profile_id": OWNER_ID,
        }
        activation_assertion = self._assertion(
            PrincipalOperation.COLLABORATION_ACTIVATE,
            activation_intent,
            "F",
            OWNER_ID,
        )
        AuthenticatedCollaborationActivationService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        ).activate(
            activation_assertion,
            self.plan,
        )
        self.work = AuthenticatedWorkItemLeaseService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        )
        self.handoffs = AuthenticatedWorkHandoffService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        )
        self.recovery = AuthenticatedWorkRecoveryService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        )
        self.cancellations = AuthenticatedWorkCancellationService(
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
    ):
        grant = self.grants[profile_id]
        issued_at = format_timestamp(self.now)
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
            expires_at=format_timestamp(
                self.now + timedelta(minutes=4)
            ),
        )

    def _handoff_intent(
        self,
        principal_profile_id: str,
        owner_token: str,
        candidate_token: str,
        *,
        candidate_id: str = CANDIDATE_ID,
        item=None,
        generation: int = 0,
        previous=None,
        reason: str = "Balance the assigned specialist workload",
    ) -> dict:
        target = item or self.source
        candidate = self.registry.profile(candidate_id)
        return {
            "candidate_assertion_id": (
                "PAS-" + candidate_token * 32
            ),
            "candidate_issuer": ISSUER,
            "candidate_profile_id": candidate_id,
            "candidate_profile_version": candidate.version,
            "candidate_registry_status": candidate.status,
            "expected_generation": generation,
            "expected_lease_expires_at": (
                None
                if previous is None
                else previous.lease_expires_at
            ),
            "handoff_scope": HANDOFF_SCOPE,
            "mission_id": MISSION_ID,
            "owner_assertion_id": "PAS-" + owner_token * 32,
            "owner_issuer": ISSUER,
            "plan_content_sha256": self.plan.content_sha256,
            "plan_id": self.plan.plan_id,
            "planned_owner_profile_id": (
                target.owner_profile_id
            ),
            "previous_transition_id": (
                None
                if previous is None
                else previous.transition_id
            ),
            "principal_profile_id": principal_profile_id,
            "qualification_basis": QUALIFICATION_BASIS,
            "qualification_command_id": target.command_id,
            "reason": reason,
            "reason_code": "load_balance",
            "work_item_id": target.work_item_id,
            "work_item_kind": target.kind.value,
        }

    def _handoff_pair(
        self,
        owner_token: str = "1",
        candidate_token: str = "2",
        *,
        candidate_id: str = CANDIDATE_ID,
        item=None,
        generation: int = 0,
        previous=None,
        reason: str = "Balance the assigned specialist workload",
    ):
        target = item or self.source
        owner_intent = self._handoff_intent(
            target.owner_profile_id,
            owner_token,
            candidate_token,
            candidate_id=candidate_id,
            item=target,
            generation=generation,
            previous=previous,
            reason=reason,
        )
        candidate_intent = {
            **owner_intent,
            "principal_profile_id": candidate_id,
        }
        owner_assertion = self._assertion(
            PrincipalOperation.WORK_HANDOFF_AUTHORIZE,
            owner_intent,
            owner_token,
            target.owner_profile_id,
        )
        candidate_assertion = self._assertion(
            PrincipalOperation.WORK_HANDOFF_ACCEPT,
            candidate_intent,
            candidate_token,
            candidate_id,
        )
        return owner_assertion, candidate_assertion

    def _handoff(
        self,
        owner_token: str = "1",
        candidate_token: str = "2",
        *,
        candidate_id: str = CANDIDATE_ID,
        item=None,
        generation: int = 0,
        previous=None,
        reason: str = "Balance the assigned specialist workload",
    ):
        target = item or self.source
        pair = self._handoff_pair(
            owner_token,
            candidate_token,
            candidate_id=candidate_id,
            item=target,
            generation=generation,
            previous=previous,
            reason=reason,
        )
        receipt = self.handoffs.handoff(
            *pair,
            MISSION_ID,
            target.work_item_id,
            expected_generation=generation,
            previous_transition_id=(
                None
                if previous is None
                else previous.transition_id
            ),
            expected_lease_expires_at=(
                None
                if previous is None
                else previous.lease_expires_at
            ),
            reason_code="load_balance",
            reason=reason,
        )
        return pair, receipt

    def _claim(
        self,
        item,
        profile_id: str,
        token: str,
        expected_generation: int,
    ):
        intent = {
            "expected_generation": expected_generation,
            "mission_id": MISSION_ID,
            "plan_content_sha256": self.plan.content_sha256,
            "plan_id": self.plan.plan_id,
            "principal_profile_id": profile_id,
            "work_item_id": item.work_item_id,
        }
        assertion = self._assertion(
            PrincipalOperation.WORK_CLAIM,
            intent,
            token,
            profile_id,
        )
        return self.work.claim(
            assertion,
            MISSION_ID,
            item.work_item_id,
            expected_generation=expected_generation,
        )

    def _release(
        self,
        receipt,
        profile_id: str,
        token: str,
    ):
        intent = {
            "claim_generation": receipt.generation,
            "expected_lease_expires_at": (
                receipt.lease_expires_at
            ),
            "mission_id": MISSION_ID,
            "plan_content_sha256": self.plan.content_sha256,
            "plan_id": self.plan.plan_id,
            "previous_transition_id": receipt.transition_id,
            "principal_profile_id": profile_id,
            "reason": "Attempt incomplete",
            "reason_code": "attempt_incomplete",
            "work_item_id": receipt.work_item_id,
        }
        assertion = self._assertion(
            PrincipalOperation.WORK_RELEASE,
            intent,
            token,
            profile_id,
        )
        return self.work.release(
            assertion,
            MISSION_ID,
            receipt.work_item_id,
            claim_generation=receipt.generation,
            previous_transition_id=receipt.transition_id,
            expected_lease_expires_at=receipt.lease_expires_at,
            reason_code="attempt_incomplete",
            reason="Attempt incomplete",
        )

    def _complete_readiness(self) -> None:
        claim = self._claim(
            self.readiness,
            OWNER_ID,
            "A",
            0,
        )
        intent = {
            "claim_generation": 1,
            "evidence_manifest_sha256": "sha256:" + "6" * 64,
            "expected_lease_expires_at": claim.lease_expires_at,
            "mission_id": MISSION_ID,
            "plan_content_sha256": self.plan.content_sha256,
            "plan_id": self.plan.plan_id,
            "previous_transition_id": claim.transition_id,
            "principal_profile_id": OWNER_ID,
            "result_id": "RES-PHASE18-READINESS",
            "result_sha256": "sha256:" + "7" * 64,
            "work_item_id": self.readiness.work_item_id,
        }
        assertion = self._assertion(
            PrincipalOperation.WORK_COMPLETE,
            intent,
            "B",
            OWNER_ID,
        )
        self.work.complete(
            assertion,
            MISSION_ID,
            self.readiness.work_item_id,
            claim_generation=1,
            previous_transition_id=claim.transition_id,
            expected_lease_expires_at=claim.lease_expires_at,
            result_id="RES-PHASE18-READINESS",
            result_sha256="sha256:" + "7" * 64,
            evidence_manifest_sha256="sha256:" + "6" * 64,
        )

    def test_unclaimed_handoff_projects_owner_and_replays(self) -> None:
        pair, receipt = self._handoff()
        replay = self.handoffs.handoff(
            *pair,
            MISSION_ID,
            self.source.work_item_id,
            expected_generation=0,
            previous_transition_id=None,
            expected_lease_expires_at=None,
            reason_code="load_balance",
            reason="Balance the assigned specialist workload",
        )
        self.assertEqual(replay, receipt)
        self.assertEqual(
            self.handoffs.get(receipt.handoff_id),
            receipt,
        )
        status_receipt = self.work.status(
            MISSION_ID,
            work_item_id=self.source.work_item_id,
        )
        status = status_receipt.work_items[0]
        self.assertEqual(status_receipt.to_dict()["schema_version"], 4)
        self.assertEqual(status.owner_profile_id, CANDIDATE_ID)
        self.assertEqual(
            status.planned_owner_profile_id,
            SOURCE_ID,
        )
        self.assertEqual(status.handoff_id, receipt.handoff_id)
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_candidate_can_claim_and_planned_owner_cannot(self) -> None:
        self._complete_readiness()
        self._handoff()
        with self.assertRaises(PrincipalAuthenticationError):
            self._claim(self.source, SOURCE_ID, "3", 0)
        claim = self._claim(
            self.source,
            CANDIDATE_ID,
            "4",
            0,
        )
        self.assertEqual(claim.owner_profile_id, CANDIDATE_ID)
        replay = self.work.claim(
            self._assertion(
                PrincipalOperation.WORK_CLAIM,
                {
                    "expected_generation": 0,
                    "mission_id": MISSION_ID,
                    "plan_content_sha256": self.plan.content_sha256,
                    "plan_id": self.plan.plan_id,
                    "principal_profile_id": CANDIDATE_ID,
                    "work_item_id": self.source.work_item_id,
                },
                "4",
                CANDIDATE_ID,
            ),
            MISSION_ID,
            self.source.work_item_id,
            expected_generation=0,
        )
        self.assertEqual(replay, claim)

    def test_active_lease_rejected_and_exact_expiry_allows(self) -> None:
        self._complete_readiness()
        claim = self._claim(self.source, SOURCE_ID, "1", 0)
        pair = self._handoff_pair(
            "2",
            "3",
            generation=1,
            previous=claim,
        )
        with self.assertRaisesRegex(
            StoreConflictError,
            "Active work item lease",
        ):
            self.handoffs.handoff(
                *pair,
                MISSION_ID,
                self.source.work_item_id,
                expected_generation=1,
                previous_transition_id=claim.transition_id,
                expected_lease_expires_at=claim.lease_expires_at,
                reason_code="load_balance",
                reason="Balance the assigned specialist workload",
            )
        self.now = datetime(
            2026,
            7,
            30,
            10,
            20,
            tzinfo=UTC,
        )
        _, receipt = self._handoff(
            "4",
            "5",
            generation=1,
            previous=claim,
        )
        self.assertEqual(receipt.expected_generation, 1)

    def test_wrong_command_candidate_is_rejected(self) -> None:
        pair = self._handoff_pair(
            candidate_id=WRONG_COMMAND_ID,
        )
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "same command",
        ):
            self.handoffs.handoff(
                *pair,
                MISSION_ID,
                self.source.work_item_id,
                expected_generation=0,
                previous_transition_id=None,
                expected_lease_expires_at=None,
                reason_code="load_balance",
                reason="Balance the assigned specialist workload",
            )

    def test_non_specialist_handoff_intent_is_rejected(self) -> None:
        with self.assertRaises(PrincipalAuthenticationError):
            self._handoff_pair(
                item=self.readiness,
            )

    def test_handoff_preserves_attempts_and_candidate_can_recover(
        self,
    ) -> None:
        self._complete_readiness()
        latest = None
        for index, tokens in enumerate(
            (("1", "2"), ("3", "4"), ("5", "6")),
            start=1,
        ):
            claim = self._claim(
                self.source,
                SOURCE_ID,
                tokens[0],
                index - 1,
            )
            latest = self._release(
                claim,
                SOURCE_ID,
                tokens[1],
            )
        self._handoff(
            "7",
            "8",
            generation=3,
            previous=latest,
        )
        status = self.work.status(
            MISSION_ID,
            work_item_id=self.source.work_item_id,
        ).work_items[0]
        self.assertEqual(status.owner_profile_id, CANDIDATE_ID)
        self.assertEqual(status.generation, 3)
        self.assertEqual(status.attempts_remaining, 0)
        intent = {
            "expected_generation": 3,
            "expected_lease_expires_at": latest.lease_expires_at,
            "mission_id": MISSION_ID,
            "plan_content_sha256": self.plan.content_sha256,
            "plan_id": self.plan.plan_id,
            "previous_transition_id": latest.transition_id,
            "principal_profile_id": CANDIDATE_ID,
            "reason": "Three attempts were exhausted",
            "reason_code": "attempts_exhausted",
            "remediation": "Apply the reviewed recovery procedure",
            "requested_attempts": 3,
            "work_item_id": self.source.work_item_id,
        }
        assertion = self._assertion(
            PrincipalOperation.WORK_RECOVERY_REQUEST,
            intent,
            "9",
            CANDIDATE_ID,
        )
        receipt = self.recovery.request(
            assertion,
            MISSION_ID,
            self.source.work_item_id,
            expected_generation=3,
            previous_transition_id=latest.transition_id,
            expected_lease_expires_at=latest.lease_expires_at,
            reason_code="attempts_exhausted",
            reason="Three attempts were exhausted",
            remediation="Apply the reviewed recovery procedure",
        )
        self.assertEqual(receipt.owner_profile_id, CANDIDATE_ID)
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_pre_handoff_transition_replay_remains_stable(self) -> None:
        self._complete_readiness()
        claim = self._claim(self.source, SOURCE_ID, "1", 0)
        release_intent = {
            "claim_generation": claim.generation,
            "expected_lease_expires_at": claim.lease_expires_at,
            "mission_id": MISSION_ID,
            "plan_content_sha256": self.plan.content_sha256,
            "plan_id": self.plan.plan_id,
            "previous_transition_id": claim.transition_id,
            "principal_profile_id": SOURCE_ID,
            "reason": "Attempt incomplete",
            "reason_code": "attempt_incomplete",
            "work_item_id": claim.work_item_id,
        }
        assertion = self._assertion(
            PrincipalOperation.WORK_RELEASE,
            release_intent,
            "2",
            SOURCE_ID,
        )
        released = self.work.release(
            assertion,
            MISSION_ID,
            claim.work_item_id,
            claim_generation=claim.generation,
            previous_transition_id=claim.transition_id,
            expected_lease_expires_at=claim.lease_expires_at,
            reason_code="attempt_incomplete",
            reason="Attempt incomplete",
        )
        self._handoff(
            "3",
            "4",
            generation=1,
            previous=released,
        )
        replay = self.work.release(
            assertion,
            MISSION_ID,
            claim.work_item_id,
            claim_generation=claim.generation,
            previous_transition_id=claim.transition_id,
            expected_lease_expires_at=claim.lease_expires_at,
            reason_code="attempt_incomplete",
            reason="Attempt incomplete",
        )
        self.assertEqual(replay, released)
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_cancellation_after_handoff_binds_candidate_owner(
        self,
    ) -> None:
        self._handoff()
        affected = (
            self.cancellations.affected_work_item_ids(
                self.plan,
                self.source.work_item_id,
            )
        )
        intent = {
            "affected_work_item_ids": list(affected),
            "cancellation_scope": "item_and_descendants",
            "decision_owner": "independent-control",
            "expected_generation": 0,
            "expected_lease_expires_at": None,
            "mission_id": MISSION_ID,
            "owner_profile_id": CANDIDATE_ID,
            "plan_content_sha256": self.plan.content_sha256,
            "plan_id": self.plan.plan_id,
            "previous_transition_id": None,
            "principal_profile_id": CONTROL_ID,
            "reason": "The package is no longer required",
            "reason_code": "scope_reduced",
            "risk": "Continuing exceeds the revised mission need",
            "work_item_id": self.source.work_item_id,
        }
        assertion = self._assertion(
            PrincipalOperation.WORK_CANCEL,
            intent,
            "3",
            CONTROL_ID,
        )
        receipt = self.cancellations.cancel(
            assertion,
            MISSION_ID,
            self.source.work_item_id,
            expected_generation=0,
            previous_transition_id=None,
            expected_lease_expires_at=None,
            reason_code="scope_reduced",
            reason="The package is no longer required",
            risk="Continuing exceeds the revised mission need",
            decision_owner="independent-control",
        )
        self.assertEqual(receipt.owner_profile_id, CANDIDATE_ID)
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_preexisting_cancellation_blocks_handoff(self) -> None:
        affected = (
            self.cancellations.affected_work_item_ids(
                self.plan,
                self.source.work_item_id,
            )
        )
        intent = {
            "affected_work_item_ids": list(affected),
            "cancellation_scope": "item_and_descendants",
            "decision_owner": "independent-control",
            "expected_generation": 0,
            "expected_lease_expires_at": None,
            "mission_id": MISSION_ID,
            "owner_profile_id": SOURCE_ID,
            "plan_content_sha256": self.plan.content_sha256,
            "plan_id": self.plan.plan_id,
            "previous_transition_id": None,
            "principal_profile_id": CONTROL_ID,
            "reason": "The package is no longer required",
            "reason_code": "scope_reduced",
            "risk": "Continuing exceeds the revised mission need",
            "work_item_id": self.source.work_item_id,
        }
        assertion = self._assertion(
            PrincipalOperation.WORK_CANCEL,
            intent,
            "1",
            CONTROL_ID,
        )
        self.cancellations.cancel(
            assertion,
            MISSION_ID,
            self.source.work_item_id,
            expected_generation=0,
            previous_transition_id=None,
            expected_lease_expires_at=None,
            reason_code="scope_reduced",
            reason="The package is no longer required",
            risk="Continuing exceeds the revised mission need",
            decision_owner="independent-control",
        )
        with self.assertRaisesRegex(StoreConflictError, "Cancelled"):
            self._handoff("2", "3")

    def test_preexisting_recovery_request_blocks_handoff(self) -> None:
        self._complete_readiness()
        latest = None
        for index, tokens in enumerate(
            (("1", "2"), ("3", "4"), ("5", "6")),
            start=1,
        ):
            claim = self._claim(
                self.source,
                SOURCE_ID,
                tokens[0],
                index - 1,
            )
            latest = self._release(
                claim,
                SOURCE_ID,
                tokens[1],
            )
        intent = {
            "expected_generation": 3,
            "expected_lease_expires_at": latest.lease_expires_at,
            "mission_id": MISSION_ID,
            "plan_content_sha256": self.plan.content_sha256,
            "plan_id": self.plan.plan_id,
            "previous_transition_id": latest.transition_id,
            "principal_profile_id": SOURCE_ID,
            "reason": "Three attempts were exhausted",
            "reason_code": "attempts_exhausted",
            "remediation": "Apply the reviewed recovery procedure",
            "requested_attempts": 3,
            "work_item_id": self.source.work_item_id,
        }
        assertion = self._assertion(
            PrincipalOperation.WORK_RECOVERY_REQUEST,
            intent,
            "7",
            SOURCE_ID,
        )
        self.recovery.request(
            assertion,
            MISSION_ID,
            self.source.work_item_id,
            expected_generation=3,
            previous_transition_id=latest.transition_id,
            expected_lease_expires_at=latest.lease_expires_at,
            reason_code="attempts_exhausted",
            reason="Three attempts were exhausted",
            remediation="Apply the reviewed recovery procedure",
        )
        with self.assertRaisesRegex(
            StoreConflictError,
            "Recover",
        ):
            self._handoff(
                "8",
                "9",
                generation=3,
                previous=latest,
            )

    def test_stop_blocks_new_handoff_but_preserves_replay(self) -> None:
        pair, receipt = self._handoff()
        stop_values = {
            "decision_owner": "range-control",
            "expected_version": 1,
            "mission_id": MISSION_ID,
            "principal_profile_id": CONTROL_ID,
            "reason": "Operator stopped the mission",
            "reason_code": "operator_request",
            "risk": "Further work is outside the decision",
        }
        stop_assertion = self._assertion(
            PrincipalOperation.MISSION_STOP,
            {
                **stop_values,
                "idempotency_key_sha256": sha256_text(
                    "phase18-stop"
                ),
            },
            "3",
            CONTROL_ID,
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
            idempotency_key="phase18-stop",
            expected_version=1,
        )
        replay = self.handoffs.handoff(
            *pair,
            MISSION_ID,
            self.source.work_item_id,
            expected_generation=0,
            previous_transition_id=None,
            expected_lease_expires_at=None,
            reason_code="load_balance",
            reason="Balance the assigned specialist workload",
        )
        self.assertEqual(replay, receipt)
        with self.assertRaises(MissionStoppedError):
            self._handoff(
                "4",
                "5",
                candidate_id=SOURCE_ID,
                item=self.candidate_item,
            )

    def test_changed_pair_does_not_partially_commit(self) -> None:
        owner, candidate = self._handoff_pair()
        changed_intent = self._handoff_intent(
            CANDIDATE_ID,
            "1",
            "2",
            reason="A different unsigned reason",
        )
        changed_candidate = self._assertion(
            PrincipalOperation.WORK_HANDOFF_ACCEPT,
            changed_intent,
            "2",
            CANDIDATE_ID,
        )
        with self.assertRaises(PrincipalAuthenticationError):
            self.handoffs.handoff(
                owner,
                changed_candidate,
                MISSION_ID,
                self.source.work_item_id,
                expected_generation=0,
                previous_transition_id=None,
                expected_lease_expires_at=None,
                reason_code="load_balance",
                reason="Balance the assigned specialist workload",
            )
        with self.store._read_connection() as connection:
            self.assertEqual(
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM collaboration_work_item_handoffs
                    """
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM principal_assertion_uses
                    WHERE operation IN (?, ?)
                    """,
                    (
                        PrincipalOperation
                        .WORK_HANDOFF_AUTHORIZE.value,
                        PrincipalOperation.WORK_HANDOFF_ACCEPT.value,
                    ),
                ).fetchone()[0],
                0,
            )

    def test_competing_handoffs_have_one_winner(self) -> None:
        pairs = (
            self._handoff_pair("1", "2"),
            self._handoff_pair("3", "4"),
        )

        def transfer(pair):
            return self.handoffs.handoff(
                *pair,
                MISSION_ID,
                self.source.work_item_id,
                expected_generation=0,
                previous_transition_id=None,
                expected_lease_expires_at=None,
                reason_code="load_balance",
                reason="Balance the assigned specialist workload",
            )

        successes = []
        failures = []
        with ThreadPoolExecutor(max_workers=2) as pool:
            for future in (
                pool.submit(transfer, pair)
                for pair in pairs
            ):
                try:
                    successes.append(future.result())
                except StoreConflictError as exc:
                    failures.append(exc)
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 1)
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_handoff_module_has_no_execution_surface(self) -> None:
        module = (
            ROOT
            / "src"
            / "sunderkey"
            / "authenticated_work_handoffs.py"
        )
        tree = ast.parse(module.read_text(encoding="utf-8"))
        imported_roots = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertTrue(
            {"subprocess", "socket", "requests", "httpx", "urllib"}
            .isdisjoint(imported_roots)
        )


if __name__ == "__main__":
    unittest.main()
