"""Focused tests for authenticated Phase 16 same-owner recovery."""

from __future__ import annotations

import ast
from concurrent.futures import ThreadPoolExecutor

from sunderkey.authenticated import AuthenticatedMissionControlService
from sunderkey.authenticated_work import WorkItemRuntimeState
from sunderkey.authenticated_work_recovery import (
    AuthenticatedWorkRecoveryService,
    WorkRecoveryDecision,
)
from sunderkey.errors import (
    MissionStoppedError,
    PrincipalAuthenticationError,
    StoreConflictError,
)
from sunderkey.identity import (
    PrincipalOperation,
)
from sunderkey.store import sha256_text

from .test_authenticated_work_phase15 import (
    CONTROL_ID,
    MISSION_ID,
    OWNER_ID,
    ROOT,
    AuthenticatedWorkPhase15Tests,
)


class AuthenticatedWorkRecoveryPhase16Tests(
    AuthenticatedWorkPhase15Tests
):
    """Exercise the one-epoch recovery contract."""

    def setUp(self) -> None:
        super().setUp()
        self.recovery = AuthenticatedWorkRecoveryService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        )

    def _exhaust(self):
        latest = None
        for generation, claim_token, release_token in (
            (1, "1", "2"),
            (2, "3", "4"),
            (3, "5", "6"),
        ):
            _, claim = self._claim(
                claim_token,
                expected_generation=generation - 1,
            )
            release_intent = self._active_intent(
                PrincipalOperation.WORK_RELEASE,
                claim,
                extra={
                    "reason": "Attempt did not complete",
                    "reason_code": "attempt_incomplete",
                },
            )
            release_assertion = self._assertion(
                PrincipalOperation.WORK_RELEASE,
                release_intent,
                release_token,
                OWNER_ID,
                self.owner_grant,
            )
            latest = self.service.release(
                release_assertion,
                MISSION_ID,
                self.readiness.work_item_id,
                claim_generation=generation,
                previous_transition_id=claim.transition_id,
                expected_lease_expires_at=claim.lease_expires_at,
                reason_code="attempt_incomplete",
                reason="Attempt did not complete",
            )
        return latest

    def _request_intent(self, latest) -> dict:
        return {
            "expected_generation": 3,
            "expected_lease_expires_at": latest.lease_expires_at,
            "mission_id": MISSION_ID,
            "plan_content_sha256": self.plan.content_sha256,
            "plan_id": self.plan.plan_id,
            "previous_transition_id": latest.transition_id,
            "principal_profile_id": OWNER_ID,
            "reason": "Three attempts were exhausted",
            "reason_code": "attempts_exhausted",
            "remediation": "Apply the reviewed recovery procedure",
            "requested_attempts": 3,
            "work_item_id": self.readiness.work_item_id,
        }

    def _request(self, latest, token: str = "7"):
        intent = self._request_intent(latest)
        assertion = self._assertion(
            PrincipalOperation.WORK_RECOVERY_REQUEST,
            intent,
            token,
            OWNER_ID,
            self.owner_grant,
        )
        return assertion, self.recovery.request(
            assertion,
            MISSION_ID,
            self.readiness.work_item_id,
            expected_generation=3,
            previous_transition_id=latest.transition_id,
            expected_lease_expires_at=latest.lease_expires_at,
            reason_code="attempts_exhausted",
            reason="Three attempts were exhausted",
            remediation="Apply the reviewed recovery procedure",
        )

    def _approve_intent(self, request, profile_id=CONTROL_ID) -> dict:
        return {
            "additional_attempts": 3,
            "authority": "Independent Control",
            "constraints": ["same owner only"],
            "decision_owner": "independent-control",
            "mission_id": MISSION_ID,
            "owner_profile_id": OWNER_ID,
            "plan_content_sha256": self.plan.content_sha256,
            "plan_id": self.plan.plan_id,
            "principal_profile_id": profile_id,
            "recovery_epoch": 1,
            "recovery_request_id": request.recovery_request_id,
            "recovery_request_sha256": request.request_sha256,
            "work_item_id": self.readiness.work_item_id,
        }

    def test_request_is_owner_only_and_exactly_replayable(self) -> None:
        latest = self._exhaust()
        assertion, receipt = self._request(latest)
        replay = self.recovery.request(
            assertion,
            MISSION_ID,
            self.readiness.work_item_id,
            expected_generation=3,
            previous_transition_id=latest.transition_id,
            expected_lease_expires_at=latest.lease_expires_at,
            reason_code="attempts_exhausted",
            reason="Three attempts were exhausted",
            remediation="Apply the reviewed recovery procedure",
        )
        self.assertEqual(replay, receipt)
        status = self.service.status(
            MISSION_ID,
            work_item_id=self.readiness.work_item_id,
        ).work_items[0]
        self.assertEqual(
            status.state,
            WorkItemRuntimeState.RECOVERY_PENDING,
        )
        self.assertEqual(
            status.recovery_request_id,
            receipt.recovery_request_id,
        )
        recovered = self.recovery.get(receipt.recovery_request_id)
        self.assertEqual(
            recovered["request"]["request_sha256"],
            receipt.request_sha256,
        )
        self.assertIsNone(recovered["decision"])

    def test_pending_request_blocks_claim(self) -> None:
        latest = self._exhaust()
        self._request(latest)
        assertion = self._assertion(
            PrincipalOperation.WORK_CLAIM,
            self._claim_intent(self.readiness, 3),
            "8",
            OWNER_ID,
            self.owner_grant,
        )
        with self.assertRaises(StoreConflictError):
            self.service.claim(
                assertion,
                MISSION_ID,
                self.readiness.work_item_id,
                expected_generation=3,
            )

    def test_independent_control_approval_opens_generations_four_to_six(
        self,
    ) -> None:
        latest = self._exhaust()
        _, request = self._request(latest)
        approve_intent = self._approve_intent(request)
        assertion = self._assertion(
            PrincipalOperation.WORK_RECOVERY_APPROVE,
            approve_intent,
            "8",
            CONTROL_ID,
            self.control_grant,
        )
        decision = self.recovery.approve(
            assertion,
            request.recovery_request_id,
            decision_owner="independent-control",
            authority="Independent Control",
            constraints=["same owner only"],
        )
        self.assertEqual(
            decision.decision,
            WorkRecoveryDecision.APPROVE,
        )
        claim_assertion = self._assertion(
            PrincipalOperation.WORK_CLAIM,
            self._claim_intent(self.readiness, 3),
            "9",
            OWNER_ID,
            self.owner_grant,
        )
        claim = self.service.claim(
            claim_assertion,
            MISSION_ID,
            self.readiness.work_item_id,
            expected_generation=3,
        )
        self.assertEqual(claim.generation, 4)
        status = self.service.status(
            MISSION_ID,
            work_item_id=self.readiness.work_item_id,
        ).work_items[0]
        self.assertEqual(status.state, WorkItemRuntimeState.LEASED)
        self.assertEqual(status.attempts_remaining, 2)
        self.assertEqual(status.recovery_decision, "approve")

    def test_non_control_cannot_approve(self) -> None:
        latest = self._exhaust()
        _, request = self._request(latest)
        approve_intent = self._approve_intent(
            request,
            profile_id=OWNER_ID,
        )
        assertion = self._assertion(
            PrincipalOperation.WORK_RECOVERY_APPROVE,
            approve_intent,
            "8",
            OWNER_ID,
            self.owner_grant,
        )
        with self.assertRaises(PrincipalAuthenticationError):
            self.recovery.approve(
                assertion,
                request.recovery_request_id,
                decision_owner="independent-control",
                authority="Independent Control",
                constraints=["same owner only"],
            )

    def test_approved_epoch_exhausts_at_generation_six(self) -> None:
        latest = self._exhaust()
        _, request = self._request(latest)
        assertion = self._assertion(
            PrincipalOperation.WORK_RECOVERY_APPROVE,
            self._approve_intent(request),
            "8",
            CONTROL_ID,
            self.control_grant,
        )
        self.recovery.approve(
            assertion,
            request.recovery_request_id,
            decision_owner="independent-control",
            authority="Independent Control",
            constraints=["same owner only"],
        )
        for generation, claim_token, release_token in (
            (4, "9", "B"),
            (5, "C", "D"),
            (6, "E", "F"),
        ):
            claim_assertion = self._assertion(
                PrincipalOperation.WORK_CLAIM,
                self._claim_intent(
                    self.readiness,
                    generation - 1,
                ),
                claim_token,
                OWNER_ID,
                self.owner_grant,
            )
            claim = self.service.claim(
                claim_assertion,
                MISSION_ID,
                self.readiness.work_item_id,
                expected_generation=generation - 1,
            )
            release_assertion = self._assertion(
                PrincipalOperation.WORK_RELEASE,
                self._active_intent(
                    PrincipalOperation.WORK_RELEASE,
                    claim,
                    extra={
                        "reason": "Recovery attempt incomplete",
                        "reason_code": "recovery_incomplete",
                    },
                ),
                release_token,
                OWNER_ID,
                self.owner_grant,
            )
            self.service.release(
                release_assertion,
                MISSION_ID,
                self.readiness.work_item_id,
                claim_generation=generation,
                previous_transition_id=claim.transition_id,
                expected_lease_expires_at=claim.lease_expires_at,
                reason_code="recovery_incomplete",
                reason="Recovery attempt incomplete",
            )
        status = self.service.status(
            MISSION_ID,
            work_item_id=self.readiness.work_item_id,
        ).work_items[0]
        self.assertEqual(status.state, WorkItemRuntimeState.FAILED)
        self.assertEqual(status.generation, 6)
        self.assertEqual(status.attempts_remaining, 0)
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_recovery_completion_unblocks_dependencies(self) -> None:
        latest = self._exhaust()
        _, request = self._request(latest)
        approve_assertion = self._assertion(
            PrincipalOperation.WORK_RECOVERY_APPROVE,
            self._approve_intent(request),
            "8",
            CONTROL_ID,
            self.control_grant,
        )
        self.recovery.approve(
            approve_assertion,
            request.recovery_request_id,
            decision_owner="independent-control",
            authority="Independent Control",
            constraints=["same owner only"],
        )
        claim_assertion = self._assertion(
            PrincipalOperation.WORK_CLAIM,
            self._claim_intent(self.readiness, 3),
            "9",
            OWNER_ID,
            self.owner_grant,
        )
        claim = self.service.claim(
            claim_assertion,
            MISSION_ID,
            self.readiness.work_item_id,
            expected_generation=3,
        )
        completion_values = {
            "evidence_manifest_sha256": "sha256:" + "6" * 64,
            "result_id": "RES-RECOVERY-001",
            "result_sha256": "sha256:" + "7" * 64,
        }
        complete_assertion = self._assertion(
            PrincipalOperation.WORK_COMPLETE,
            self._active_intent(
                PrincipalOperation.WORK_COMPLETE,
                claim,
                extra=completion_values,
            ),
            "B",
            OWNER_ID,
            self.owner_grant,
        )
        self.service.complete(
            complete_assertion,
            MISSION_ID,
            self.readiness.work_item_id,
            claim_generation=4,
            previous_transition_id=claim.transition_id,
            expected_lease_expires_at=claim.lease_expires_at,
            **completion_values,
        )
        by_id = {
            item.work_item_id: item
            for item in self.service.status(MISSION_ID).work_items
        }
        self.assertEqual(
            by_id[self.readiness.work_item_id].state,
            WorkItemRuntimeState.COMPLETED,
        )
        self.assertEqual(
            by_id[self.specialist.work_item_id].state,
            WorkItemRuntimeState.READY,
        )
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_stop_blocks_new_decision_but_preserves_request_replay(
        self,
    ) -> None:
        latest = self._exhaust()
        request_assertion, request = self._request(latest)
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
                    "phase16-stop"
                ),
            },
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
            idempotency_key="phase16-stop",
            expected_version=1,
        )
        replay = self.recovery.request(
            request_assertion,
            MISSION_ID,
            self.readiness.work_item_id,
            expected_generation=3,
            previous_transition_id=latest.transition_id,
            expected_lease_expires_at=latest.lease_expires_at,
            reason_code="attempts_exhausted",
            reason="Three attempts were exhausted",
            remediation="Apply the reviewed recovery procedure",
        )
        self.assertEqual(replay, request)
        approve_assertion = self._assertion(
            PrincipalOperation.WORK_RECOVERY_APPROVE,
            self._approve_intent(request),
            "8",
            CONTROL_ID,
            self.control_grant,
        )
        with self.assertRaises(MissionStoppedError):
            self.recovery.approve(
                approve_assertion,
                request.recovery_request_id,
                decision_owner="independent-control",
                authority="Independent Control",
                constraints=["same owner only"],
            )

    def test_denial_records_terminal_failure(self) -> None:
        latest = self._exhaust()
        _, request = self._request(latest)
        intent = {
            "additional_attempts": 3,
            "decision_owner": "independent-control",
            "mission_id": MISSION_ID,
            "owner_profile_id": OWNER_ID,
            "plan_content_sha256": self.plan.content_sha256,
            "plan_id": self.plan.plan_id,
            "principal_profile_id": CONTROL_ID,
            "reason": "Recovery risk is not acceptable",
            "reason_code": "risk_unacceptable",
            "recovery_epoch": 1,
            "recovery_request_id": request.recovery_request_id,
            "recovery_request_sha256": request.request_sha256,
            "risk": "Further execution exceeds the reviewed boundary",
            "work_item_id": self.readiness.work_item_id,
        }
        assertion = self._assertion(
            PrincipalOperation.WORK_RECOVERY_DENY,
            intent,
            "8",
            CONTROL_ID,
            self.control_grant,
        )
        decision = self.recovery.deny(
            assertion,
            request.recovery_request_id,
            decision_owner="independent-control",
            reason_code="risk_unacceptable",
            reason="Recovery risk is not acceptable",
            risk="Further execution exceeds the reviewed boundary",
        )
        self.assertEqual(decision.decision, WorkRecoveryDecision.DENY)
        status = self.service.status(
            MISSION_ID,
            work_item_id=self.readiness.work_item_id,
        ).work_items[0]
        self.assertEqual(status.state, WorkItemRuntimeState.FAILED)
        self.assertEqual(status.attempts_remaining, 0)

    def test_competing_control_decisions_commit_one_result(
        self,
    ) -> None:
        latest = self._exhaust()
        _, request = self._request(latest)
        approve_assertion = self._assertion(
            PrincipalOperation.WORK_RECOVERY_APPROVE,
            self._approve_intent(request),
            "8",
            CONTROL_ID,
            self.control_grant,
        )
        deny_intent = {
            "additional_attempts": 3,
            "decision_owner": "independent-control",
            "mission_id": MISSION_ID,
            "owner_profile_id": OWNER_ID,
            "plan_content_sha256": self.plan.content_sha256,
            "plan_id": self.plan.plan_id,
            "principal_profile_id": CONTROL_ID,
            "reason": "Recovery risk is not acceptable",
            "reason_code": "risk_unacceptable",
            "recovery_epoch": 1,
            "recovery_request_id": request.recovery_request_id,
            "recovery_request_sha256": request.request_sha256,
            "risk": "Further execution exceeds the reviewed boundary",
            "work_item_id": self.readiness.work_item_id,
        }
        deny_assertion = self._assertion(
            PrincipalOperation.WORK_RECOVERY_DENY,
            deny_intent,
            "9",
            CONTROL_ID,
            self.control_grant,
        )

        def approve():
            return self.recovery.approve(
                approve_assertion,
                request.recovery_request_id,
                decision_owner="independent-control",
                authority="Independent Control",
                constraints=["same owner only"],
            )

        def deny():
            return self.recovery.deny(
                deny_assertion,
                request.recovery_request_id,
                decision_owner="independent-control",
                reason_code="risk_unacceptable",
                reason="Recovery risk is not acceptable",
                risk=(
                    "Further execution exceeds the reviewed boundary"
                ),
            )

        outcomes = []
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = (pool.submit(approve), pool.submit(deny))
            for future in futures:
                try:
                    outcomes.append(future.result())
                except StoreConflictError:
                    outcomes.append("conflict")
        self.assertEqual(
            sum(value != "conflict" for value in outcomes),
            1,
        )
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_recovery_module_has_no_execution_surface(self) -> None:
        module = (
            ROOT
            / "src"
            / "sunderkey"
            / "authenticated_work_recovery.py"
        )
        tree = ast.parse(module.read_text(encoding="utf-8"))
        imported_roots = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        self.assertTrue(
            {"subprocess", "socket", "requests", "httpx", "urllib"}
            .isdisjoint(imported_roots)
        )


del AuthenticatedWorkPhase15Tests
