import copy
import unittest

from sunderkey.end_to_end_conformance import (
    STAGE_DEFINITIONS,
    Budget,
    ConformancePlan,
    ExecutionBinding,
    FenceBinding,
    ReceiptStatus,
    StageEvidence,
    StageStatus,
    canonical_sha256,
)
from sunderkey.offline_mission_conformance_checkpoint import (
    OfflineMissionCheckpoint,
    OfflineMissionCheckpointError,
)


def _plan() -> ConformancePlan:
    return ConformancePlan.create(
        binding=ExecutionBinding(
            "tenantref:tenant-a",
            "contextref:context-a",
            "scoperef:scope-a",
            "missionref:mission-a",
            "operatorref:operator-a",
        ),
        start_version=2,
        fence=FenceBinding("fenceref:mission-a", "fence-token-mission-a-00000001", 1),
        budget_ceiling=Budget(20, 2000, 2000, 2000),
        cleanup_obligation_sha256=canonical_sha256("cleanup"),
        rollback_policy_sha256=canonical_sha256("rollback"),
        idempotency_seed="idem:offline-mission-checkpoint-00000001",
        created_at="2026-09-20T12:00:00Z",
    )


def _evidence(checkpoint: OfflineMissionCheckpoint) -> StageEvidence:
    request = checkpoint.next_request
    assert request is not None
    definition = STAGE_DEFINITIONS[len(checkpoint.evidence)]
    reviewer = (
        f"reviewerref:control-{request.ordinal}"
        if definition.requires_independent_review
        else None
    )
    return StageEvidence.create(
        request,
        adapter_ref=f"adapterref:offline-{request.ordinal}",
        status=StageStatus.PASSED,
        artifact_sha256s=(canonical_sha256({"stage": request.stage.value}),),
        budget_used=Budget(1, 10, 10, 10),
        completed_at="2026-09-20T12:01:00Z",
        reviewer_ref=reviewer,
        reviewed_at="2026-09-20T12:02:00Z" if reviewer else None,
    )


class OfflineMissionCheckpointTests(unittest.TestCase):
    def test_restart_preserves_request_binding_without_invoking_adapters(self) -> None:
        checkpoint = OfflineMissionCheckpoint.create(_plan())
        self.assertEqual(checkpoint.next_request.ordinal, 1)
        for _ in range(4):
            checkpoint = checkpoint.append(_evidence(checkpoint))
            checkpoint = OfflineMissionCheckpoint.from_json(checkpoint.to_json())
        self.assertEqual(checkpoint.next_request.ordinal, 5)
        self.assertEqual(checkpoint.next_request.expected_version, 6)
        self.assertEqual(
            checkpoint.next_request.prior_stage_sha256,
            checkpoint.evidence[-1].evidence_sha256,
        )
        self.assertEqual(
            checkpoint.next_request.prior_custody_sha256,
            checkpoint.evidence[-1].custody_sha256,
        )
        self.assertEqual(checkpoint.next_request.binding, checkpoint.plan.binding)

    def test_complete_chain_reuses_existing_conformance_assessment(self) -> None:
        checkpoint = OfflineMissionCheckpoint.create(_plan())
        for _ in STAGE_DEFINITIONS:
            checkpoint = checkpoint.append(_evidence(checkpoint))
        self.assertIsNone(checkpoint.next_request)
        result = checkpoint.assess_completion(completed_at="2026-09-20T12:03:00Z")
        self.assertEqual(result.receipt.status, ReceiptStatus.CONFORMANT)
        self.assertEqual(result.gap_report.gaps, ())
        self.assertEqual(result.receipt.final_version, 13)
        self.assertEqual(
            OfflineMissionCheckpoint.from_json(checkpoint.to_json()), checkpoint
        )
        with self.assertRaises(OfflineMissionCheckpointError):
            checkpoint.append(checkpoint.evidence[-1])

    def test_missing_or_reordered_prefix_and_incomplete_result_fail_closed(self) -> None:
        checkpoint = OfflineMissionCheckpoint.create(_plan())
        with self.assertRaises(OfflineMissionCheckpointError):
            checkpoint.assess_completion(completed_at="2026-09-20T12:03:00Z")
        first = _evidence(checkpoint)
        checkpoint = checkpoint.append(first)
        second = _evidence(checkpoint)
        with self.assertRaises(OfflineMissionCheckpointError):
            OfflineMissionCheckpoint.create(_plan(), (second,))
        with self.assertRaises(OfflineMissionCheckpointError):
            OfflineMissionCheckpoint.create(_plan(), (second, first))

    def test_tampered_digest_and_cross_mission_evidence_fail_closed(self) -> None:
        checkpoint = OfflineMissionCheckpoint.create(_plan()).append(
            _evidence(OfflineMissionCheckpoint.create(_plan()))
        )
        raw = checkpoint.to_dict()
        changed = copy.deepcopy(raw)
        changed["evidence"][0]["artifact_sha256s"] = [canonical_sha256("changed")]
        with self.assertRaises(OfflineMissionCheckpointError):
            OfflineMissionCheckpoint.from_dict(changed)
        changed = copy.deepcopy(raw)
        changed["checkpoint_sha256"] = canonical_sha256("changed")
        with self.assertRaises(OfflineMissionCheckpointError):
            OfflineMissionCheckpoint.from_dict(changed)
        rebound_plan = ConformancePlan.create(
            binding=ExecutionBinding(
                "tenantref:tenant-b",
                "contextref:context-a",
                "scoperef:scope-a",
                "missionref:mission-a",
                "operatorref:operator-a",
            ),
            start_version=2,
            fence=_plan().fence,
            budget_ceiling=_plan().budget_ceiling,
            cleanup_obligation_sha256=_plan().cleanup_obligation_sha256,
            rollback_policy_sha256=_plan().rollback_policy_sha256,
            idempotency_seed=_plan().idempotency_seed,
            created_at=_plan().created_at,
        )
        with self.assertRaises(OfflineMissionCheckpointError):
            OfflineMissionCheckpoint.create(rebound_plan, checkpoint.evidence)

    def test_failed_stage_never_advances_checkpoint(self) -> None:
        checkpoint = OfflineMissionCheckpoint.create(_plan())
        failed = StageEvidence.create(
            checkpoint.next_request,
            adapter_ref="adapterref:offline-1",
            status=StageStatus.FAILED,
            artifact_sha256s=(canonical_sha256("failure"),),
            budget_used=Budget(0, 0, 0, 0),
            completed_at="2026-09-20T12:01:00Z",
            reason_code="denied_by_policy",
        )
        with self.assertRaises(OfflineMissionCheckpointError):
            checkpoint.append(failed)


if __name__ == "__main__":
    unittest.main()
