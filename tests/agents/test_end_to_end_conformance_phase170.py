import copy
import unittest
from dataclasses import replace
from pathlib import Path

from jsonschema import Draft202012Validator

import sunderkey
from sunderkey.end_to_end_conformance import (
    STAGE_DEFINITIONS,
    Budget,
    ConformancePlan,
    ConformanceStage,
    EndToEndConformanceError,
    ExecutionBinding,
    FenceBinding,
    GapReport,
    ReceiptStatus,
    ReviewDecision,
    StageEvidence,
    StageRequest,
    StageStatus,
    assess_conformance,
    canonical_sha256,
    parse_record,
    run_conformance,
)

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "src" / "sunderkey" / "end_to_end_conformance.py"
SCHEMA = ROOT / "registry" / "schemas" / "end-to-end-conformance-receipt-v1.schema.json"
DOC = ROOT / "docs" / "end-to-end-conformance.md"
FILES = (MODULE, Path(__file__), SCHEMA, DOC)

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
NOW = "2026-09-20T12:00:00Z"
DONE = "2026-09-20T12:01:00Z"
REVIEWED = "2026-09-20T12:02:00Z"


def make_plan(**overrides) -> ConformancePlan:
    values = {
        "binding": ExecutionBinding(
            "tenantref:tenant-a",
            "contextref:assessment-42",
            "scoperef:scope-42",
            "missionref:mission-42",
            "operatorref:operator-a",
        ),
        "start_version": 7,
        "fence": FenceBinding(
            "fenceref:mission-42",
            "fence-token-mission-42-00000001",
            12,
        ),
        "budget_ceiling": Budget(100, 100_000, 1_000_000, 10_000_000),
        "cleanup_obligation_sha256": DIGEST_A,
        "rollback_policy_sha256": DIGEST_B,
        "idempotency_seed": "idem:conformance-mission-42-00000001",
        "created_at": NOW,
    }
    values.update(overrides)
    return ConformancePlan.create(**values)


class FakeAdapter:
    def __init__(self, transform=None) -> None:
        self.transform = transform
        self.calls: list[StageRequest] = []

    def observe_stage(self, request: StageRequest):
        self.calls.append(request)
        active = request if self.transform is None else self.transform(request)
        definition = STAGE_DEFINITIONS[active.ordinal - 1]
        reviewer = (
            f"reviewerref:control-{active.ordinal}"
            if definition.requires_independent_review
            else None
        )
        artifact = canonical_sha256(
            {"ordinal": active.ordinal, "stage": active.stage.value, "test": "offline"}
        )
        return StageEvidence.create(
            active,
            adapter_ref=f"adapterref:stage-{active.ordinal}",
            status=StageStatus.PASSED,
            artifact_sha256s=(artifact,),
            budget_used=Budget(1, 100, 10, 1000),
            completed_at=DONE,
            reviewer_ref=reviewer,
            reviewed_at=REVIEWED if reviewer is not None else None,
        )


def adapters(transform_stage=None, transform=None):
    result = {}
    for definition in STAGE_DEFINITIONS:
        selected = transform if definition.stage is transform_stage else None
        result[definition.stage] = FakeAdapter(selected)
    return result


class EndToEndConformancePhase170Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        import json

        cls.validator = Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8")))

    def test_plan_is_deterministic_content_addressed_and_exactly_ordered(self) -> None:
        first = make_plan()
        second = make_plan()
        self.assertEqual(first, second)
        self.assertEqual(first, ConformancePlan.from_json(first.to_json()))
        self.assertEqual(first, parse_record(first.to_dict()))
        self.assertEqual(
            first.to_dict()["stage_order"],
            [item.stage.value for item in STAGE_DEFINITIONS],
        )
        self.assertEqual(len(first.to_dict()["stage_order"]), 11)
        self.assertFalse(list(self.validator.iter_errors(first.to_dict())))

    def test_full_offline_chain_binds_versions_fence_custody_controls_and_review(self) -> None:
        plan = make_plan()
        result = run_conformance(plan, adapters(), completed_at=REVIEWED)
        self.assertEqual(result.receipt.status, ReceiptStatus.CONFORMANT)
        self.assertEqual(result.gap_report.gaps, ())
        self.assertEqual(len(result.evidence), len(STAGE_DEFINITIONS))
        self.assertEqual(result.receipt.final_version, plan.start_version + 11)
        self.assertEqual(
            [item.version_before for item in result.evidence],
            list(range(plan.start_version, plan.start_version + 11)),
        )
        for previous, current in zip(result.evidence, result.evidence[1:], strict=False):
            self.assertEqual(current.prior_stage_sha256, previous.evidence_sha256)
            self.assertEqual(current.prior_custody_sha256, previous.custody_sha256)
            self.assertEqual(current.fence, plan.fence)
            self.assertEqual(current.binding, plan.binding)
        by_stage = {item.stage: item for item in result.evidence}
        self.assertEqual(
            by_stage[ConformanceStage.ACTIVATION].control_links,
            {
                "activation_review_evidence": by_stage[
                    ConformanceStage.ACTIVATION_REVIEW
                ].evidence_sha256
            },
        )
        self.assertEqual(
            by_stage[ConformanceStage.CLEANUP_RESTORATION].control_links["cleanup_obligation"],
            plan.cleanup_obligation_sha256,
        )
        rollback = by_stage[ConformanceStage.ROLLBACK_VERIFICATION].control_links
        self.assertEqual(
            rollback["activation_evidence"],
            by_stage[ConformanceStage.ACTIVATION].evidence_sha256,
        )
        self.assertEqual(
            rollback["cleanup_restoration_evidence"],
            by_stage[ConformanceStage.CLEANUP_RESTORATION].evidence_sha256,
        )
        for definition, item in zip(STAGE_DEFINITIONS, result.evidence, strict=True):
            self.assertEqual(item.review is not None, definition.requires_independent_review)
            self.assertFalse(list(self.validator.iter_errors(item.to_dict())))
        self.assertFalse(list(self.validator.iter_errors(result.gap_report.to_dict())))
        self.assertFalse(list(self.validator.iter_errors(result.receipt.to_dict())))

    def test_replay_is_deterministic_and_adapters_are_injected_only(self) -> None:
        plan = make_plan()
        first_adapters = adapters()
        second_adapters = adapters()
        first = run_conformance(plan, first_adapters, completed_at=REVIEWED)
        second = run_conformance(plan, second_adapters, completed_at=REVIEWED)
        self.assertEqual(first, second)
        self.assertEqual(sum(len(item.calls) for item in first_adapters.values()), 11)
        self.assertEqual(first.receipt, parse_record(first.receipt.to_dict()))
        self.assertEqual(first.gap_report, parse_record(first.gap_report.to_dict()))

    def test_missing_adapter_halts_and_reports_remaining_stages(self) -> None:
        plan = make_plan()
        configured = adapters()
        del configured[ConformanceStage.ACTION_ADMISSION]
        result = run_conformance(plan, configured, completed_at=REVIEWED)
        codes = {(item.stage, item.code) for item in result.gap_report.gaps}
        self.assertEqual(result.receipt.status, ReceiptStatus.NONCONFORMANT)
        self.assertIn((ConformanceStage.ACTION_ADMISSION, "missing_stage_adapter"), codes)
        self.assertIn((ConformanceStage.ACTION_ADMISSION, "missing_stage"), codes)
        self.assertEqual(len(result.evidence), 2)
        self.assertEqual(
            configured[ConformanceStage.SPECIALIST_EXECUTION].calls,
            [],
        )

    def test_failed_and_skipped_stages_are_terminal_and_explicit(self) -> None:
        class TerminalAdapter(FakeAdapter):
            def __init__(self, terminal_status: StageStatus, reason: str) -> None:
                super().__init__()
                self.terminal_status = terminal_status
                self.reason = reason

            def observe_stage(self, request: StageRequest):
                self.calls.append(request)
                return StageEvidence.create(
                    request,
                    adapter_ref="adapterref:terminal-stage",
                    status=self.terminal_status,
                    artifact_sha256s=(DIGEST_A,),
                    budget_used=Budget(1, 10, 1, 10),
                    completed_at=DONE,
                    reason_code=self.reason,
                )

        for status, reason, expected_code in (
            (StageStatus.FAILED, "adapter_failure", "failed_stage"),
            (StageStatus.SKIPPED, "policy_skip", "skipped_stage"),
        ):
            with self.subTest(status=status):
                configured = adapters()
                configured[ConformanceStage.SPECIALIST_EXECUTION] = TerminalAdapter(status, reason)
                result = run_conformance(make_plan(), configured, completed_at=REVIEWED)
                codes = {item.code for item in result.gap_report.gaps}
                self.assertIn(expected_code, codes)
                self.assertEqual(len(result.evidence), 4)
                self.assertEqual(
                    configured[ConformanceStage.EVIDENCE_RECORDING].calls,
                    [],
                )

    def test_missing_duplicate_and_reordered_evidence_fail_closed(self) -> None:
        baseline = run_conformance(make_plan(), adapters(), completed_at=REVIEWED)
        cases = {
            "missing_stage": baseline.evidence[:-1],
            "duplicate_stage": (baseline.evidence[0],) + baseline.evidence,
            "reordered_stage": (
                baseline.evidence[1],
                baseline.evidence[0],
                *baseline.evidence[2:],
            ),
        }
        for code, evidence in cases.items():
            with self.subTest(code=code):
                result = assess_conformance(make_plan(), evidence, completed_at=REVIEWED)
                self.assertEqual(result.receipt.status, ReceiptStatus.NONCONFORMANT)
                self.assertIn(code, {item.code for item in result.gap_report.gaps})

    def test_tampered_record_fails_integrity_and_yields_gap_report(self) -> None:
        baseline = run_conformance(make_plan(), adapters(), completed_at=REVIEWED)
        changed = [item.to_dict() for item in baseline.evidence]
        changed[3] = copy.deepcopy(changed[3])
        changed[3]["artifact_sha256s"] = [DIGEST_B]
        with self.assertRaisesRegex(EndToEndConformanceError, "content address"):
            StageEvidence.from_dict(changed[3])
        result = assess_conformance(make_plan(), changed, completed_at=REVIEWED)
        self.assertEqual(result.receipt.status, ReceiptStatus.NONCONFORMANT)
        self.assertIn("tampered_stage", {item.code for item in result.gap_report.gaps})

    def test_rebound_stale_and_idempotency_substitutions_fail_closed(self) -> None:
        other_binding = ExecutionBinding(
            "tenantref:tenant-b",
            "contextref:assessment-42",
            "scoperef:scope-42",
            "missionref:mission-42",
            "operatorref:operator-a",
        )
        transforms = (
            (lambda request: replace(request, binding=other_binding), "rebound_context"),
            (
                lambda request: replace(request, expected_version=request.expected_version + 4),
                "stale_version",
            ),
            (
                lambda request: replace(request, idempotency_key="idem:substituted-stage-00000001"),
                "idempotency_mismatch",
            ),
            (
                lambda request: replace(
                    request,
                    fence=FenceBinding(
                        request.fence.fence_ref,
                        "fence-token-mission-42-00000002",
                        request.fence.fence_epoch + 1,
                    ),
                ),
                "stale_fence",
            ),
        )
        for transform, code in transforms:
            with self.subTest(code=code):
                result = run_conformance(
                    make_plan(),
                    adapters(ConformanceStage.SERVICE_INTAKE, transform),
                    completed_at=REVIEWED,
                )
                self.assertIn(code, {item.code for item in result.gap_report.gaps})

    def test_budget_overrun_fails_before_later_adapters_are_called(self) -> None:
        class ExpensiveAdapter(FakeAdapter):
            def observe_stage(self, request: StageRequest):
                self.calls.append(request)
                return StageEvidence.create(
                    request,
                    adapter_ref="adapterref:expensive-stage",
                    status=StageStatus.PASSED,
                    artifact_sha256s=(DIGEST_A,),
                    budget_used=Budget(101, 0, 0, 0),
                    completed_at=DONE,
                )

        configured = adapters()
        configured[ConformanceStage.SERVICE_INTAKE] = ExpensiveAdapter()
        result = run_conformance(make_plan(), configured, completed_at=REVIEWED)
        self.assertIn("budget_exceeded", {item.code for item in result.gap_report.gaps})
        self.assertEqual(configured[ConformanceStage.SCHEDULER_DISPATCH].calls, [])

    def test_required_reviews_are_missing_rejected_or_nonindependent(self) -> None:
        def make_review_transform(mode):
            class ReviewAdapter(FakeAdapter):
                def observe_stage(self, request: StageRequest):
                    self.calls.append(request)
                    kwargs = {}
                    if mode == "rejected":
                        kwargs = {
                            "reviewer_ref": "reviewerref:control-reviewer",
                            "review_decision": ReviewDecision.REJECTED,
                            "reviewed_at": REVIEWED,
                        }
                    elif mode == "nonindependent":
                        kwargs = {
                            "reviewer_ref": "reviewerref:operator-a",
                            "reviewed_at": REVIEWED,
                        }
                    return StageEvidence.create(
                        request,
                        adapter_ref="adapterref:admission-stage",
                        status=StageStatus.PASSED,
                        artifact_sha256s=(DIGEST_A,),
                        budget_used=Budget(1, 1, 1, 1),
                        completed_at=DONE,
                        **kwargs,
                    )

            return ReviewAdapter()

        for mode, code in (
            ("missing", "unreviewed_stage"),
            ("rejected", "review_rejected"),
            ("nonindependent", "nonindependent_review"),
        ):
            with self.subTest(mode=mode):
                configured = adapters()
                configured[ConformanceStage.ACTION_ADMISSION] = make_review_transform(mode)
                result = run_conformance(make_plan(), configured, completed_at=REVIEWED)
                self.assertIn(code, {item.code for item in result.gap_report.gaps})

    def test_cleanup_and_rollback_links_cannot_be_rebound(self) -> None:
        def wrong_cleanup(request: StageRequest) -> StageRequest:
            return replace(
                request,
                required_control_links={
                    **dict(request.required_control_links),
                    "cleanup_obligation": DIGEST_B,
                },
            )

        result = run_conformance(
            make_plan(),
            adapters(ConformanceStage.CLEANUP_RESTORATION, wrong_cleanup),
            completed_at=REVIEWED,
        )
        self.assertIn("control_link_mismatch", {item.code for item in result.gap_report.gaps})
        self.assertFalse(
            any(item.stage is ConformanceStage.ROLLBACK_VERIFICATION for item in result.evidence)
        )

    def test_exact_field_canonical_json_and_content_addresses_fail_closed(self) -> None:
        plan = make_plan()
        changed = copy.deepcopy(plan.to_dict())
        changed["unexpected"] = True
        with self.assertRaisesRegex(EndToEndConformanceError, "fields"):
            ConformancePlan.from_dict(changed)
        changed = copy.deepcopy(plan.to_dict())
        changed["start_version"] = 99
        with self.assertRaisesRegex(EndToEndConformanceError, "content address"):
            ConformancePlan.from_dict(changed)
        with self.assertRaisesRegex(EndToEndConformanceError, "canonical"):
            ConformancePlan.from_json(plan.to_json() + "\n")

    def test_gap_report_and_receipt_are_bound_and_nonqualifying(self) -> None:
        result = run_conformance(make_plan(), {}, completed_at=REVIEWED)
        self.assertEqual(result.receipt.gap_report_id, result.gap_report.report_id)
        self.assertEqual(result.receipt.gap_report_sha256, result.gap_report.report_sha256)
        self.assertEqual(result.receipt.to_dict()["qualification_effect"], "none")
        self.assertEqual(result.receipt.to_dict()["effects"]["network"], "none")
        self.assertEqual(result.gap_report, GapReport.from_json(result.gap_report.to_json()))

    def test_files_are_ascii_without_markers_or_runtime_side_effect_apis(self) -> None:
        marker = "written" + " by ai"
        forbidden = (
            marker,
            "chat" + "gpt",
            "co-authored" + "-by",
            "sub" + "process",
            "sock" + "et.",
            "req" + "uests.",
            "url" + "lib.",
            "open(" + '"http',
            "pathlib.path." + "cwd",
            "os." + "environ",
        )
        for path in FILES:
            with self.subTest(path=path.name):
                raw = path.read_bytes()
                text = raw.decode("ascii")
                lowered = text.lower()
                self.assertNotIn("\u2013", text)
                self.assertNotIn("\u2014", text)
                for value in forbidden:
                    self.assertNotIn(value, lowered)

    def test_public_package_exports_end_to_end_conformance_boundary(self) -> None:
        self.assertIs(sunderkey.run_end_to_end_conformance, run_conformance)
        self.assertIs(sunderkey.assess_end_to_end_conformance, assess_conformance)
        self.assertIs(sunderkey.parse_end_to_end_conformance_record, parse_record)


if __name__ == "__main__":
    unittest.main()
