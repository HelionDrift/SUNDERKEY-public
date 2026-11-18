"""Focused local finding origin checks for assessment reports."""

from __future__ import annotations

import copy
import unittest
from collections import deque
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import MappingProxyType

from sunderkey.assessment_reporting import (
    FindingLifecycleReference,
    FindingReport,
    PentestReport,
    build_assessment_report_bundle,
)
from sunderkey.finding_lifecycle import (
    FindingClassification,
    FindingIdentity,
    FindingSnapshot,
    FindingState,
    add_finding_evidence,
    create_finding,
    transition_finding,
)
from sunderkey.offline_report_finding_origins import (
    OfflineReportFindingOriginsError,
    verify_report_finding_origins,
)
from tests.agents import test_assessment_reporting_phase161 as reporting_fixture

DIGESTS = reporting_fixture.DIGESTS


class OfflineReportFindingOriginsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = reporting_fixture.AssessmentReportingPhase161Tests()
        origin = create_finding(
            FindingIdentity(
                asset="asset.api",
                surface="api",
                vulnerability_class="broken_access_control",
                root_cause="missing authorization",
                affected_boundary="op0",
                semantic_claim="operation accepts an unauthorized caller",
            ),
            classification=FindingClassification(
                severity="critical",
                cwe_refs=("CWE-862",),
                cvss_refs=("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",),
            ),
            evidence_digests=(DIGESTS[4],),
            created_at="2026-09-20T03:11:00Z",
            actor_id="reviewer.1",
            authority_ref="authority.1",
            provenance_digests=(DIGESTS[3],),
        )
        triaged = self._transition(origin, FindingState.TRIAGED, "2026-09-20T03:12:00Z")
        validated = self._transition(
            triaged, FindingState.VALIDATED, "2026-09-20T03:13:00Z"
        )
        self.history = (origin, triaged, validated)
        self.report = self._report(validated)

    @staticmethod
    def _transition(
        finding: FindingSnapshot, target: FindingState, occurred_at: str
    ) -> FindingSnapshot:
        return transition_finding(
            finding,
            target,
            occurred_at=occurred_at,
            actor_id="reviewer.1",
            authority_ref="authority.1",
            provenance_digests=(DIGESTS[3],),
            review_decision="pending",
            reason_code="reviewed_transition",
        )

    def _report(
        self,
        head: FindingSnapshot,
        *,
        digest_override: str | None = None,
        finding_overrides: dict[str, object] | None = None,
    ) -> PentestReport:
        digest = digest_override or head.snapshot_sha256
        assessment = replace(
            self.fixture.assessment(),
            finding_lifecycle=(
                FindingLifecycleReference(
                    finding_id=head.finding_id,
                    snapshot_sha256=digest,
                    state=head.state.value,
                    updated_at=head.updated_at,
                ),
            ),
        )
        finding: FindingReport = replace(
            self.fixture.finding(assessment),
            finding_id=head.finding_id,
            lifecycle_snapshot_sha256=digest,
            status=head.state.value,
            **(finding_overrides or {}),
        )
        report_roles, attestation_roles = self.fixture.reviewers()
        return build_assessment_report_bundle(
            assessment,
            (finding,),
            report_reviewers=report_roles,
            attestation_reviewers=attestation_roles,
            attested_at="2026-09-20T03:22:00Z",
        ).report

    def _verify(self, histories: dict[str, tuple[FindingSnapshot, ...]] | None = None):
        return verify_report_finding_origins(
            report=self.report,
            snapshot_histories=histories or {self.history[-1].finding_id: self.history},
        )

    def test_matches_complete_exact_originals_without_effects_or_writes(self) -> None:
        before_report = copy.deepcopy(self.report.to_dict())
        before_history = [copy.deepcopy(item.to_dict()) for item in self.history]
        result = self._verify()
        self.assertEqual(result["status"], "matched_local_originals")
        self.assertEqual(result["finding_count"], 1)
        self.assertEqual(result["snapshot_count"], 3)
        self.assertEqual(result["report_sha256"], self.report.report_sha256)
        self.assertEqual(result["asset_operation_identity_binding"], "not_proven")
        self.assertEqual(result["live_source_currentness"], "not_proven")
        self.assertEqual(result["authenticated_review"], "not_proven")
        self.assertEqual(result["external_anti_rollback"], "not_proven")
        for effect in ("authorization_effect", "qualification_effect", "target_effect"):
            self.assertEqual(result[effect], "none")
        self.assertEqual(self.report.to_dict(), before_report)
        self.assertEqual([item.to_dict() for item in self.history], before_history)

    def test_missing_extra_and_reordered_histories_fail(self) -> None:
        head_id = self.history[-1].finding_id
        for histories in (
            {},
            {head_id: self.history[1:]},
            {head_id: self.history + (self.history[-1],)},
            {head_id: (self.history[0], self.history[2], self.history[1])},
            {head_id: self.history, "FND-extra": self.history},
        ):
            with self.subTest(histories=list(histories)):
                with self.assertRaises(OfflineReportFindingOriginsError):
                    verify_report_finding_origins(
                        report=self.report, snapshot_histories=histories
                    )

    def test_non_native_containers_fail_before_origin_read(self) -> None:
        history_map = {self.history[-1].finding_id: self.history}
        with self.assertRaisesRegex(OfflineReportFindingOriginsError, "native dict"):
            verify_report_finding_origins(
                report=self.report,
                snapshot_histories=MappingProxyType(history_map),
            )
        with self.assertRaisesRegex(OfflineReportFindingOriginsError, "native list or tuple"):
            verify_report_finding_origins(
                report=self.report,
                snapshot_histories={self.history[-1].finding_id: deque(self.history)},
            )

    def test_forged_report_digest_and_substituted_origin_fail(self) -> None:
        fake_report = self._report(self.history[-1], digest_override=DIGESTS[9])
        with self.assertRaisesRegex(OfflineReportFindingOriginsError, "reference"):
            verify_report_finding_origins(
                report=fake_report,
                snapshot_histories={self.history[-1].finding_id: self.history},
            )
        altered = replace(self.history[-1], snapshot_sha256=DIGESTS[9])
        with self.assertRaises(OfflineReportFindingOriginsError):
            self._verify({altered.finding_id: (*self.history[:-1], altered)})

    def test_broken_event_chain_and_parent_link_fail(self) -> None:
        bad_event = replace(self.history[1].events[-1], event_sha256=DIGESTS[9])
        altered_event = replace(
            self.history[1], events=(*self.history[1].events[:-1], bad_event)
        )
        altered_parent = replace(self.history[2], parent_snapshot_sha256=DIGESTS[9])
        for history in (
            (self.history[0], altered_event, self.history[2]),
            (self.history[0], self.history[1], altered_parent),
        ):
            with self.assertRaises(OfflineReportFindingOriginsError):
                self._verify({self.history[-1].finding_id: history})

    def test_report_detail_drift_fails(self) -> None:
        for overrides in (
            {"cwe_ref": "CWE-89"},
            {"vulnerability_class": "other_class"},
            {"evidence_digests": (DIGESTS[5],)},
        ):
            with self.subTest(overrides=overrides):
                drifted = self._report(self.history[-1], finding_overrides=overrides)
                with self.assertRaisesRegex(OfflineReportFindingOriginsError, "details"):
                    verify_report_finding_origins(
                        report=drifted,
                        snapshot_histories={self.history[-1].finding_id: self.history},
                    )

    def test_report_reference_time_drift_fails(self) -> None:
        original = self.report.assessment.finding_lifecycle[0]
        assessment = replace(
            self.report.assessment,
            finding_lifecycle=(replace(original, updated_at="2026-09-20T03:14:00Z"),),
        )
        report_roles, attestation_roles = self.fixture.reviewers()
        drifted = build_assessment_report_bundle(
            assessment,
            self.report.findings,
            report_reviewers=report_roles,
            attestation_reviewers=attestation_roles,
            attested_at="2026-09-20T03:22:00Z",
        ).report
        with self.assertRaisesRegex(OfflineReportFindingOriginsError, "reference"):
            verify_report_finding_origins(
                report=drifted,
                snapshot_histories={self.history[-1].finding_id: self.history},
            )

    def test_long_valid_chain_is_bounded_by_embedded_event_work(self) -> None:
        history = list(self.history)
        start = datetime(2026, 9, 20, 3, 13, tzinfo=UTC)
        for index in range(1, 61):
            history.append(
                add_finding_evidence(
                    history[-1],
                    (f"sha256:{index + 1000:064x}",),
                    occurred_at=(start + timedelta(seconds=index)).strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    ),
                    actor_id="reviewer.1",
                    authority_ref="authority.1",
                    provenance_digests=(DIGESTS[3],),
                    review_decision="pending",
                )
            )
        # Versions one through 63 contain 2,016 embedded event copies.
        report = self._report(history[-1])
        result = verify_report_finding_origins(
            report=report,
            snapshot_histories={history[-1].finding_id: tuple(history)},
        )
        self.assertEqual(result["snapshot_count"], 63)
        next_head = add_finding_evidence(
            history[-1],
            (f"sha256:{1061:064x}",),
            occurred_at="2026-09-20T03:14:01Z",
            actor_id="reviewer.1",
            authority_ref="authority.1",
            provenance_digests=(DIGESTS[3],),
            review_decision="pending",
        )
        history.append(next_head)
        with self.assertRaisesRegex(OfflineReportFindingOriginsError, "embedded"):
            verify_report_finding_origins(
                report=self._report(next_head),
                snapshot_histories={next_head.finding_id: tuple(history)},
            )


if __name__ == "__main__":
    unittest.main()
