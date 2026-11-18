"""Adversarial, repository-only mission scenario tests."""

from __future__ import annotations

import copy
import unittest
from dataclasses import replace

from sunderkey.end_to_end_conformance import Budget, ExecutionBinding
from sunderkey.offline_assessment_scenario_harness import (
    CHECKPOINTS,
    AckState,
    Checkpoint,
    ScenarioError,
    ScenarioObservation,
    ScenarioPlan,
    run_scenario,
    verify_scenario_receipt,
)

SOURCE = "sha256:" + "a" * 64
OTHER_SOURCE = "sha256:" + "b" * 64
ARTIFACT = "sha256:" + "c" * 64
REPORT = "sha256:" + "d" * 64


def plan() -> ScenarioPlan:
    return ScenarioPlan.create(
        case_id="mission-adversarial-001",
        binding=ExecutionBinding(
            "tenantref:alpha",
            "contextref:assessment-1",
            "scoperef:scope-1",
            "missionref:mission-1",
            "operatorref:operator-1",
        ),
        source_sha256=SOURCE,
        authority_epoch=5,
        fence_epoch=7,
        reviewer_ref="reviewerref:independent-1",
        budget_ceiling=Budget(8, 800, 80, 8000),
    )


def observation(checkpoint: Checkpoint) -> ScenarioObservation:
    return ScenarioObservation(
        checkpoint=checkpoint,
        tenant_ref="tenantref:alpha",
        source_sha256=SOURCE,
        authority_epoch=5,
        fence_epoch=7,
        authority_active=True,
        health_ready=True,
        budget_used=Budget(1, 10, 1, 10),
        admission_granted=True
        if checkpoint in {
            Checkpoint.ADMISSION, Checkpoint.PRE_DISPATCH, Checkpoint.PRE_PUBLICATION
        } else None,
        ack_state=AckState.ACCEPTED if checkpoint is Checkpoint.DISPATCH_ACK else None,
        artifact_sha256=ARTIFACT if checkpoint is Checkpoint.EVIDENCE else None,
        reviewer_ref="reviewerref:independent-1" if checkpoint is Checkpoint.REVIEW else None,
        reviewed_artifact_sha256=ARTIFACT if checkpoint is Checkpoint.REVIEW else None,
        report_sha256=REPORT
        if checkpoint in {Checkpoint.REPORT, Checkpoint.PRE_PUBLICATION}
        else None,
    )


def observers(overrides=None):
    calls = []
    configured = {}
    for checkpoint in CHECKPOINTS:
        def observe(probe, selected=checkpoint):
            calls.append(probe)
            item = observation(selected)
            change = {} if overrides is None else overrides.get(selected, {})
            return replace(item, **change)

        configured[checkpoint] = observe
    return configured, calls


class OfflineAssessmentScenarioHarnessTests(unittest.TestCase):
    def test_complete_path_is_deterministic_and_nonqualifying(self) -> None:
        current = plan()
        configured, calls = observers()
        first = run_scenario(current, configured)
        second = run_scenario(current, observers()[0])
        self.assertEqual(first, second)
        self.assertEqual(first, verify_scenario_receipt(current, first))
        self.assertEqual(current, ScenarioPlan.from_dict(current.to_dict()))
        self.assertEqual(first["outcome"], "simulated_complete")
        self.assertEqual(first["simulated_dispatches"], 1)
        self.assertEqual(first["simulated_positive_publications"], 1)
        self.assertEqual(first["qualification_effect"], "none")
        self.assertTrue(
            all(
                value == "none"
                for key, value in first["effects"].items()
                if key != "credentials"
            )
        )
        self.assertEqual(len(calls), len(CHECKPOINTS))
        self.assertEqual(calls[0].prior_observation_sha256, None)
        self.assertEqual(
            calls[1].prior_observation_sha256,
            first["observations"][0]["observation_sha256"],
        )

    def test_revocation_after_admission_prevents_simulated_dispatch(self) -> None:
        configured, calls = observers({Checkpoint.PRE_DISPATCH: {"authority_active": False}})
        receipt = run_scenario(plan(), configured)
        self.assertEqual(receipt["reason"], "authority_revoked_or_stale")
        self.assertEqual(receipt["simulated_dispatches"], 0)
        self.assertEqual(receipt["simulated_positive_publications"], 0)
        self.assertEqual([call.checkpoint for call in calls], list(CHECKPOINTS[:3]))
        verify_scenario_receipt(plan(), receipt)

    def test_health_pause_before_dispatch_prevents_later_callbacks(self) -> None:
        configured, calls = observers({Checkpoint.PRE_DISPATCH: {"health_ready": False}})
        receipt = run_scenario(plan(), configured)
        self.assertEqual(receipt["reason"], "health_pause")
        self.assertEqual(len(calls), 3)
        self.assertEqual(receipt["simulated_dispatches"], 0)
        verify_scenario_receipt(plan(), receipt)

    def test_duplicate_and_lost_ack_require_reconciliation_without_retry(self) -> None:
        for state, reason in (
            (AckState.LOST, "ack_lost_reconciliation_required"),
            (AckState.DUPLICATE, "ack_duplicate_reconciliation_required"),
        ):
            with self.subTest(state=state):
                configured, calls = observers({Checkpoint.DISPATCH_ACK: {"ack_state": state}})
                receipt = run_scenario(plan(), configured)
                self.assertEqual(receipt["reason"], reason)
                self.assertEqual(receipt["simulated_dispatches"], 1)
                self.assertEqual(receipt["simulated_positive_publications"], 0)
                self.assertEqual(len(calls), 4)
                verify_scenario_receipt(plan(), receipt)

    def test_stale_source_and_cross_tenant_handoff_stop_progress(self) -> None:
        for checkpoint, change, reason, count in (
            (Checkpoint.EVIDENCE, {"source_sha256": OTHER_SOURCE}, "stale_source", 5),
            (Checkpoint.PRE_DISPATCH, {"tenant_ref": "tenantref:beta"}, "cross_tenant_handoff", 3),
        ):
            with self.subTest(reason=reason):
                configured, calls = observers({checkpoint: change})
                receipt = run_scenario(plan(), configured)
                self.assertEqual(receipt["reason"], reason)
                self.assertEqual(len(calls), count)
                self.assertEqual(receipt["simulated_positive_publications"], 0)
                verify_scenario_receipt(plan(), receipt)

    def test_reviewer_or_evidence_mismatch_never_reaches_report(self) -> None:
        for change in (
            {"reviewer_ref": "reviewerref:operator-1"},
            {"reviewed_artifact_sha256": OTHER_SOURCE},
        ):
            with self.subTest(change=change):
                configured, calls = observers({Checkpoint.REVIEW: change})
                receipt = run_scenario(plan(), configured)
                self.assertEqual(receipt["reason"], "reviewer_or_evidence_mismatch")
                self.assertEqual(len(calls), 6)
                self.assertEqual(receipt["simulated_positive_publications"], 0)
                verify_scenario_receipt(plan(), receipt)

    def test_stale_fence_and_budget_overrun_fail_before_dispatch(self) -> None:
        for checkpoint, change, reason in (
            (Checkpoint.PRE_DISPATCH, {"fence_epoch": 6}, "stale_fence"),
            (Checkpoint.INTAKE, {"budget_used": Budget(9, 0, 0, 0)}, "budget_exceeded"),
        ):
            with self.subTest(reason=reason):
                configured, calls = observers({checkpoint: change})
                receipt = run_scenario(plan(), configured)
                self.assertEqual(receipt["reason"], reason)
                self.assertEqual(receipt["simulated_dispatches"], 0)
                self.assertEqual(receipt["simulated_positive_publications"], 0)
                self.assertLessEqual(len(calls), 3)
                verify_scenario_receipt(plan(), receipt)

    def test_admission_denial_and_report_rebinding_prevent_publication(self) -> None:
        for checkpoint, change, reason, expected_calls in (
            (Checkpoint.ADMISSION, {"admission_granted": False}, "admission_denied", 2),
            (Checkpoint.PRE_PUBLICATION, {"report_sha256": OTHER_SOURCE}, "report_rebound", 8),
        ):
            with self.subTest(reason=reason):
                configured, calls = observers({checkpoint: change})
                receipt = run_scenario(plan(), configured)
                self.assertEqual(receipt["reason"], reason)
                self.assertEqual(receipt["simulated_positive_publications"], 0)
                self.assertEqual(len(calls), expected_calls)
                verify_scenario_receipt(plan(), receipt)

    def test_admission_must_remain_current_before_dispatch_and_publication(self) -> None:
        for checkpoint, value, expected_calls in (
            (Checkpoint.PRE_DISPATCH, False, 3),
            (Checkpoint.PRE_DISPATCH, None, 3),
            (Checkpoint.PRE_PUBLICATION, False, 8),
            (Checkpoint.PRE_PUBLICATION, None, 8),
        ):
            with self.subTest(checkpoint=checkpoint, value=value):
                configured, calls = observers({checkpoint: {"admission_granted": value}})
                receipt = run_scenario(plan(), configured)
                self.assertIn(receipt["reason"], {"admission_denied", "admission_not_current"})
                self.assertEqual(receipt["simulated_positive_publications"], 0)
                self.assertEqual(len(calls), expected_calls)
                verify_scenario_receipt(plan(), receipt)

    def test_restart_does_not_repeat_dispatch_or_publication(self) -> None:
        for first, expected in (
            (
                run_scenario(
                    plan(),
                    observers({Checkpoint.DISPATCH_ACK: {"ack_state": AckState.LOST}})[0],
                ),
                "restart_reconciliation_required",
            ),
            (run_scenario(plan(), observers()[0]), "already_simulated_published"),
        ):
            with self.subTest(reason=expected):
                configured, calls = observers()
                restart = run_scenario(plan(), configured, prior_receipt=first)
                self.assertEqual(restart["reason"], expected)
                self.assertEqual(calls, [])
                self.assertEqual(restart["simulated_dispatches"], 0)
                self.assertEqual(restart["simulated_positive_publications"], 0)
                verify_scenario_receipt(plan(), restart, prior_receipt=first)

    def test_denied_prior_plan_does_not_auto_retry(self) -> None:
        first = run_scenario(
            plan(), observers({Checkpoint.PRE_DISPATCH: {"authority_active": False}})[0]
        )
        configured, calls = observers()
        restart = run_scenario(plan(), configured, prior_receipt=first)
        self.assertEqual(restart["reason"], "prior_terminal_plan")
        self.assertEqual(calls, [])
        verify_scenario_receipt(plan(), restart, prior_receipt=first)

    def test_missing_and_raising_observers_fail_closed(self) -> None:
        configured, calls = observers()
        del configured[Checkpoint.ADMISSION]
        missing = run_scenario(plan(), configured)
        self.assertEqual(missing["reason"], "missing_observer")
        self.assertEqual(len(calls), 1)
        verify_scenario_receipt(plan(), missing)

        configured, calls = observers()

        def raise_error(_probe):
            raise RuntimeError("offline fixture failed")

        configured[Checkpoint.PRE_DISPATCH] = raise_error
        failed = run_scenario(plan(), configured)
        self.assertEqual(failed["reason"], "observer_failure")
        self.assertEqual(len(calls), 2)
        self.assertEqual(failed["simulated_dispatches"], 0)
        verify_scenario_receipt(plan(), failed)

    def test_tampered_receipt_and_reordered_observations_are_rejected(self) -> None:
        current = plan()
        baseline = run_scenario(current, observers()[0])
        changed = copy.deepcopy(baseline)
        changed["observations"][1]["tenant_ref"] = "tenantref:beta"
        with self.assertRaises(ScenarioError):
            verify_scenario_receipt(current, changed)
        changed = copy.deepcopy(baseline)
        changed["observations"][0], changed["observations"][1] = (
            changed["observations"][1], changed["observations"][0]
        )
        with self.assertRaisesRegex(ScenarioError, "checkpoint order"):
            verify_scenario_receipt(current, changed)
        changed = copy.deepcopy(baseline)
        changed["simulated_positive_publications"] = 0
        with self.assertRaisesRegex(ScenarioError, "integrity or replay"):
            verify_scenario_receipt(current, changed)
        changed = copy.deepcopy(baseline)
        changed["simulated_dispatches"] = True
        with self.assertRaisesRegex(ScenarioError, "zero or one"):
            verify_scenario_receipt(current, changed)

    def test_plan_and_nested_binding_mutation_cannot_rebind_tenant(self) -> None:
        current = plan()
        baseline = run_scenario(current, observers()[0])
        object.__setattr__(current.binding, "tenant_ref", "tenantref:beta")
        with self.assertRaisesRegex(ScenarioError, "no longer matches"):
            run_scenario(current, observers()[0])
        with self.assertRaisesRegex(ScenarioError, "no longer matches"):
            verify_scenario_receipt(current, baseline)

        current = plan()
        configured, calls = observers()
        original = configured[Checkpoint.ADMISSION]

        def mutate_after_admission(probe):
            item = original(probe)
            object.__setattr__(current.binding, "tenant_ref", "tenantref:beta")
            return item

        configured[Checkpoint.ADMISSION] = mutate_after_admission
        with self.assertRaisesRegex(ScenarioError, "no longer matches"):
            run_scenario(current, configured)
        self.assertEqual(len(calls), 2)

        typed = plan().to_dict()
        typed["schema_version"] = True
        with self.assertRaisesRegex(ScenarioError, "envelope"):
            ScenarioPlan.from_dict(typed)

    def test_oversized_budget_and_epoch_fail_before_hashing(self) -> None:
        base = plan()
        with self.assertRaisesRegex(ScenarioError, "budget_ceiling"):
            ScenarioPlan.create(
                case_id=base.case_id,
                binding=base.binding,
                source_sha256=base.source_sha256,
                authority_epoch=base.authority_epoch,
                fence_epoch=base.fence_epoch,
                reviewer_ref=base.reviewer_ref,
                budget_ceiling=Budget(10**5000, 0, 0, 0),
            )
        with self.assertRaisesRegex(ScenarioError, "authority_epoch"):
            ScenarioPlan.create(
                case_id=base.case_id,
                binding=base.binding,
                source_sha256=base.source_sha256,
                authority_epoch=10**5000,
                fence_epoch=base.fence_epoch,
                reviewer_ref=base.reviewer_ref,
                budget_ceiling=base.budget_ceiling,
            )


if __name__ == "__main__":
    unittest.main()
