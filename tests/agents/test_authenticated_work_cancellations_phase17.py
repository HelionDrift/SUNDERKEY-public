"""Focused tests for authenticated Phase 17 work cancellation."""

from __future__ import annotations

import ast
from concurrent.futures import ThreadPoolExecutor

from sunderkey.authenticated import AuthenticatedMissionControlService
from sunderkey.authenticated_work import WorkItemRuntimeState
from sunderkey.authenticated_work_cancellations import (
    AuthenticatedWorkCancellationService,
)
from sunderkey.authenticated_work_recovery import (
    AuthenticatedWorkRecoveryService,
)
from sunderkey.errors import (
    MissionStoppedError,
    PrincipalAuthenticationError,
    StoreConflictError,
)
from sunderkey.identity import PrincipalOperation
from sunderkey.store import sha256_text

from .test_authenticated_work_phase15 import (
    CONTROL_ID,
    MISSION_ID,
    OWNER_ID,
    ROOT,
    AuthenticatedWorkPhase15Tests,
)


class AuthenticatedWorkCancellationPhase17Tests(
    AuthenticatedWorkPhase15Tests
):
    """Exercise independent Control cancellation and propagation."""

    def setUp(self) -> None:
        super().setUp()
        self.cancellations = AuthenticatedWorkCancellationService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        )
        self.recovery = AuthenticatedWorkRecoveryService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        )

    def _cancel_intent(
        self,
        item,
        *,
        generation: int = 0,
        previous=None,
        profile_id: str = CONTROL_ID,
    ) -> dict:
        return {
            "affected_work_item_ids": list(
                self.cancellations.affected_work_item_ids(
                    self.plan,
                    item.work_item_id,
                )
            ),
            "cancellation_scope": "item_and_descendants",
            "decision_owner": "independent-control",
            "expected_generation": generation,
            "expected_lease_expires_at": (
                None if previous is None else previous.lease_expires_at
            ),
            "mission_id": MISSION_ID,
            "owner_profile_id": item.owner_profile_id,
            "plan_content_sha256": self.plan.content_sha256,
            "plan_id": self.plan.plan_id,
            "previous_transition_id": (
                None if previous is None else previous.transition_id
            ),
            "principal_profile_id": profile_id,
            "reason": "The work package is no longer required",
            "reason_code": "scope_reduced",
            "risk": "Continuing would exceed the revised mission need",
            "work_item_id": item.work_item_id,
        }

    def _cancel(
        self,
        item,
        token: str,
        *,
        generation: int = 0,
        previous=None,
        profile_id: str = CONTROL_ID,
        grant=None,
    ):
        assertion = self._assertion(
            PrincipalOperation.WORK_CANCEL,
            self._cancel_intent(
                item,
                generation=generation,
                previous=previous,
                profile_id=profile_id,
            ),
            token,
            profile_id,
            grant or self.control_grant,
        )
        receipt = self.cancellations.cancel(
            assertion,
            MISSION_ID,
            item.work_item_id,
            expected_generation=generation,
            previous_transition_id=(
                None if previous is None else previous.transition_id
            ),
            expected_lease_expires_at=(
                None if previous is None else previous.lease_expires_at
            ),
            reason_code="scope_reduced",
            reason="The work package is no longer required",
            risk="Continuing would exceed the revised mission need",
            decision_owner="independent-control",
        )
        return assertion, receipt

    def _complete_readiness(self):
        _, claim = self._claim("1")
        values = {
            "evidence_manifest_sha256": "sha256:" + "6" * 64,
            "result_id": "RES-READINESS-PHASE17",
            "result_sha256": "sha256:" + "7" * 64,
        }
        assertion = self._assertion(
            PrincipalOperation.WORK_COMPLETE,
            self._active_intent(
                PrincipalOperation.WORK_COMPLETE,
                claim,
                extra=values,
            ),
            "2",
            OWNER_ID,
            self.owner_grant,
        )
        return self.service.complete(
            assertion,
            MISSION_ID,
            self.readiness.work_item_id,
            claim_generation=1,
            previous_transition_id=claim.transition_id,
            expected_lease_expires_at=claim.lease_expires_at,
            **values,
        )

    def _exhaust_readiness(self):
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
            assertion = self._assertion(
                PrincipalOperation.WORK_RELEASE,
                self._active_intent(
                    PrincipalOperation.WORK_RELEASE,
                    claim,
                    extra={
                        "reason": "Attempt incomplete",
                        "reason_code": "attempt_incomplete",
                    },
                ),
                release_token,
                OWNER_ID,
                self.owner_grant,
            )
            latest = self.service.release(
                assertion,
                MISSION_ID,
                self.readiness.work_item_id,
                claim_generation=generation,
                previous_transition_id=claim.transition_id,
                expected_lease_expires_at=claim.lease_expires_at,
                reason_code="attempt_incomplete",
                reason="Attempt incomplete",
            )
        return latest

    def test_unclaimed_cancellation_propagates_and_replays(self) -> None:
        assertion, receipt = self._cancel(self.readiness, "1")
        replay = self.cancellations.cancel(
            assertion,
            MISSION_ID,
            self.readiness.work_item_id,
            expected_generation=0,
            previous_transition_id=None,
            expected_lease_expires_at=None,
            reason_code="scope_reduced",
            reason="The work package is no longer required",
            risk="Continuing would exceed the revised mission need",
            decision_owner="independent-control",
        )
        self.assertEqual(replay, receipt)
        self.assertEqual(
            self.cancellations.get(receipt.cancellation_id),
            receipt,
        )
        statuses = self.service.status(MISSION_ID).work_items
        by_id = {item.work_item_id: item for item in statuses}
        self.assertEqual(
            by_id[self.readiness.work_item_id].state,
            WorkItemRuntimeState.CANCELLED,
        )
        self.assertTrue(
            all(
                status.state
                is WorkItemRuntimeState.CANCELLED_DEPENDENCY
                for status in statuses
                if status.work_item_id
                != self.readiness.work_item_id
            )
        )
        self.assertTrue(
            all(status.attempts_remaining == 0 for status in statuses)
        )

    def test_specialist_cancellation_preserves_completed_ancestors(
        self,
    ) -> None:
        self._complete_readiness()
        _, receipt = self._cancel(self.specialist, "3")
        by_id = {
            item.work_item_id: item
            for item in self.service.status(MISSION_ID).work_items
        }
        self.assertEqual(
            by_id[self.specialist.work_item_id].state,
            WorkItemRuntimeState.CANCELLED,
        )
        self.assertEqual(
            by_id[self.readiness.work_item_id].state,
            WorkItemRuntimeState.COMPLETED,
        )
        self.assertEqual(
            by_id[self.specialist.work_item_id].cancellation_ids,
            (receipt.cancellation_id,),
        )
        assertion = self._assertion(
            PrincipalOperation.WORK_CLAIM,
            self._claim_intent(self.specialist, 0),
            "4",
            self.specialist.owner_profile_id,
            self.specialist_grant,
        )
        with self.assertRaises(StoreConflictError):
            self.service.claim(
                assertion,
                MISSION_ID,
                self.specialist.work_item_id,
                expected_generation=0,
            )

    def test_active_lease_cancellation_invalidates_owner_mutation(
        self,
    ) -> None:
        _, claim = self._claim("1")
        _, receipt = self._cancel(
            self.readiness,
            "2",
            generation=1,
            previous=claim,
        )
        status = self.service.status(
            MISSION_ID,
            work_item_id=self.readiness.work_item_id,
        ).work_items[0]
        self.assertEqual(status.state, WorkItemRuntimeState.CANCELLED)
        self.assertEqual(status.cancellation_ids, (receipt.cancellation_id,))
        renew = self._assertion(
            PrincipalOperation.WORK_RENEW,
            self._active_intent(
                PrincipalOperation.WORK_RENEW,
                claim,
            ),
            "3",
            OWNER_ID,
            self.owner_grant,
        )
        with self.assertRaises(StoreConflictError):
            self.service.renew(
                renew,
                MISSION_ID,
                self.readiness.work_item_id,
                claim_generation=1,
                previous_transition_id=claim.transition_id,
                expected_lease_expires_at=claim.lease_expires_at,
            )

    def test_later_ancestor_cancellation_preserves_both_causes(
        self,
    ) -> None:
        _, first = self._cancel(self.specialist, "1")
        _, second = self._cancel(self.readiness, "2")
        status = self.service.status(
            MISSION_ID,
            work_item_id=self.specialist.work_item_id,
        ).work_items[0]
        self.assertEqual(status.state, WorkItemRuntimeState.CANCELLED)
        self.assertEqual(
            set(status.cancellation_ids),
            {first.cancellation_id, second.cancellation_id},
        )
        self.assertEqual(
            set(status.cancellation_source_work_item_ids),
            {
                self.specialist.work_item_id,
                self.readiness.work_item_id,
            },
        )
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_cancellation_requires_independent_assigned_control(
        self,
    ) -> None:
        with self.assertRaises(PrincipalAuthenticationError):
            self._cancel(
                self.readiness,
                "1",
                profile_id=OWNER_ID,
                grant=self.owner_grant,
            )

    def test_completed_work_cannot_be_cancelled(self) -> None:
        completion = self._complete_readiness()
        with self.assertRaises(StoreConflictError):
            self._cancel(
                self.readiness,
                "3",
                generation=1,
                previous=completion,
            )

    def test_cancellation_supersedes_pending_recovery(self) -> None:
        latest = self._exhaust_readiness()
        request_intent = {
            "expected_generation": 3,
            "expected_lease_expires_at": latest.lease_expires_at,
            "mission_id": MISSION_ID,
            "plan_content_sha256": self.plan.content_sha256,
            "plan_id": self.plan.plan_id,
            "previous_transition_id": latest.transition_id,
            "principal_profile_id": OWNER_ID,
            "reason": "Three attempts were exhausted",
            "reason_code": "attempts_exhausted",
            "remediation": "Apply reviewed recovery procedure",
            "requested_attempts": 3,
            "work_item_id": self.readiness.work_item_id,
        }
        request_assertion = self._assertion(
            PrincipalOperation.WORK_RECOVERY_REQUEST,
            request_intent,
            "7",
            OWNER_ID,
            self.owner_grant,
        )
        request = self.recovery.request(
            request_assertion,
            MISSION_ID,
            self.readiness.work_item_id,
            expected_generation=3,
            previous_transition_id=latest.transition_id,
            expected_lease_expires_at=latest.lease_expires_at,
            reason_code="attempts_exhausted",
            reason="Three attempts were exhausted",
            remediation="Apply reviewed recovery procedure",
        )
        self._cancel(
            self.readiness,
            "8",
            generation=3,
            previous=latest,
        )
        approve_intent = {
            "additional_attempts": 3,
            "authority": "Independent Control",
            "constraints": ["same owner only"],
            "decision_owner": "independent-control",
            "mission_id": MISSION_ID,
            "owner_profile_id": OWNER_ID,
            "plan_content_sha256": self.plan.content_sha256,
            "plan_id": self.plan.plan_id,
            "principal_profile_id": CONTROL_ID,
            "recovery_epoch": 1,
            "recovery_request_id": request.recovery_request_id,
            "recovery_request_sha256": request.request_sha256,
            "work_item_id": self.readiness.work_item_id,
        }
        approval = self._assertion(
            PrincipalOperation.WORK_RECOVERY_APPROVE,
            approve_intent,
            "9",
            CONTROL_ID,
            self.control_grant,
        )
        with self.assertRaises(StoreConflictError):
            self.recovery.approve(
                approval,
                request.recovery_request_id,
                decision_owner="independent-control",
                authority="Independent Control",
                constraints=["same owner only"],
            )
        status = self.service.status(
            MISSION_ID,
            work_item_id=self.readiness.work_item_id,
        ).work_items[0]
        self.assertEqual(status.state, WorkItemRuntimeState.CANCELLED)

    def test_stop_blocks_new_cancellation_but_preserves_replay(
        self,
    ) -> None:
        assertion, receipt = self._cancel(self.specialist, "1")
        stop_values = {
            "decision_owner": "range-control",
            "expected_version": 1,
            "mission_id": MISSION_ID,
            "principal_profile_id": CONTROL_ID,
            "reason": "Operator stopped the mission",
            "reason_code": "operator_request",
            "risk": "Further work is outside the decision",
        }
        stop = self._assertion(
            PrincipalOperation.MISSION_STOP,
            {
                **stop_values,
                "idempotency_key_sha256": sha256_text(
                    "phase17-stop"
                ),
            },
            "2",
            CONTROL_ID,
            self.control_grant,
        )
        AuthenticatedMissionControlService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        ).stop(
            stop,
            MISSION_ID,
            reason_code=stop_values["reason_code"],
            reason=stop_values["reason"],
            risk=stop_values["risk"],
            decision_owner=stop_values["decision_owner"],
            idempotency_key="phase17-stop",
            expected_version=1,
        )
        replay = self.cancellations.cancel(
            assertion,
            MISSION_ID,
            self.specialist.work_item_id,
            expected_generation=0,
            previous_transition_id=None,
            expected_lease_expires_at=None,
            reason_code="scope_reduced",
            reason="The work package is no longer required",
            risk="Continuing would exceed the revised mission need",
            decision_owner="independent-control",
        )
        self.assertEqual(replay, receipt)
        with self.assertRaises(MissionStoppedError):
            self._cancel(self.readiness, "3")

    def test_competing_cancellations_commit_one_result(self) -> None:
        assertions = tuple(
            self._assertion(
                PrincipalOperation.WORK_CANCEL,
                self._cancel_intent(self.readiness),
                token,
                CONTROL_ID,
                self.control_grant,
            )
            for token in ("1", "2")
        )

        def cancel(assertion):
            return self.cancellations.cancel(
                assertion,
                MISSION_ID,
                self.readiness.work_item_id,
                expected_generation=0,
                previous_transition_id=None,
                expected_lease_expires_at=None,
                reason_code="scope_reduced",
                reason="The work package is no longer required",
                risk=(
                    "Continuing would exceed the revised mission need"
                ),
                decision_owner="independent-control",
            )

        outcomes = []
        with ThreadPoolExecutor(max_workers=2) as pool:
            for future in (
                pool.submit(cancel, assertion)
                for assertion in assertions
            ):
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

    def test_cancellation_module_has_no_execution_surface(self) -> None:
        module = (
            ROOT
            / "src"
            / "sunderkey"
            / "authenticated_work_cancellations.py"
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
