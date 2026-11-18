"""Exact native JSON replay for pure finding and assessment report contracts."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from dataclasses import replace
from typing import Any

from sunderkey import assessment_reporting as reporting
from sunderkey import finding_lifecycle as lifecycle
from tests.agents import test_assessment_reporting_phase161 as report_fixtures
from tests.agents import test_finding_lifecycle_phase161 as finding_fixtures


def _native_json(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def _native_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_native_json(value).encode("ascii")).hexdigest()


def _finding_digest(raw: dict[str, Any], id_field: str, hash_field: str) -> str:
    return _native_digest(
        {key: value for key, value in raw.items() if key not in (id_field, hash_field)}
    )


def _report_digest(raw: dict[str, Any], id_field: str, hash_field: str) -> str:
    body = {
        key: value
        for key, value in raw.items()
        if key not in (id_field, hash_field, "effects", "kind", "schema_version")
    }
    return _native_digest({"domain": raw["kind"], "content": body})


class FindingReportExactReplayTests(unittest.TestCase):
    def setUp(self) -> None:
        finding_fixture = finding_fixtures.FindingLifecyclePhase161Tests()
        self.finding = finding_fixture.make_finding()
        pending = finding_fixture.make_retest_pending()
        self.plan = finding_fixture.make_plan(pending)
        self.merge = lifecycle.create_merge_record(
            self.finding,
            (finding_fixture.make_finding(minute=2), finding_fixture.make_finding(minute=1)),
            created_at="2026-09-20T02:00:00Z",
            actor_id="principal.reviewer.2",
            authority_ref="authority.canonicalization.1",
            provenance_digests=(finding_fixtures.digest("d"),),
            review_decision="approved",
            reason_code="reviewed_duplicate",
        )
        self.attempt, self.retested = lifecycle.record_retest_attempt(
            self.plan,
            pending,
            result="fixed",
            new_evidence_digests=(finding_fixtures.digest("f"),),
            recorded_at="2026-09-20T02:01:00Z",
            actor_id="principal.validator.1",
            authority_ref="authority.retest.1",
            provenance_digests=(finding_fixtures.digest("e"),),
            review_decision="approved",
        )
        self.bundle = report_fixtures.AssessmentReportingPhase161Tests().bundle()

    def lifecycle_records(self) -> tuple[tuple[Any, str, str, str], ...]:
        return (
            (
                self.finding.events[0],
                "event_id",
                "event_sha256",
                "sha256:b8fae0948c8156b1300d027a75259791f16fa3d23b57281e8caac614f357eed7",
            ),
            (
                self.finding,
                "snapshot_id",
                "snapshot_sha256",
                "sha256:54d0aa26052f5c61581716f8e9c5d3d68ea38e3f2eda94406ef7348056106bd6",
            ),
            (
                self.merge,
                "record_id",
                "record_sha256",
                "sha256:1f76028770c59dd66cc1e0650278111bb45b5c5fa5ee547f611bdbce98355712",
            ),
            (
                self.plan,
                "plan_id",
                "plan_sha256",
                "sha256:ed97f936e224774d754191459cf277e31ac0b4edada6edacce0c6fe5adae1022",
            ),
            (
                self.attempt,
                "attempt_id",
                "attempt_sha256",
                "sha256:06c61059e3dd20aec15f7f4c8753a2f8fa8a5faf66b4f6600ee4dc947bd9b9c4",
            ),
        )

    def report_records(self) -> tuple[tuple[Any, str, str, str], ...]:
        return (
            (
                self.bundle.report.assessment.assets[0],
                "asset_record_id",
                "asset_sha256",
                "sha256:33c9a240d2ada0a7e52f63d3ad1f3422f61f95cc9b4cdc216ed8a1ffa9265e93",
            ),
            (
                self.bundle.report.assessment,
                "assessment_id",
                "assessment_sha256",
                "sha256:0291a4af2670511f909eb02fb859b6ee929f5e665ef81294c23c8db65b45e6bf",
            ),
            (
                self.bundle.report.findings[0],
                "finding_report_id",
                "finding_report_sha256",
                "sha256:bdbfe7509440283365566bea93c326ead8fdaa73072ba06e2e25cbd9240a70b2",
            ),
            (
                self.bundle.report.executive_summary,
                "executive_summary_id",
                "executive_summary_sha256",
                "sha256:e328fc2d49dc35e9a5f32bc9ed034c8b0754a1e6aab400a5f2ae2148de3321f1",
            ),
            (
                self.bundle.report,
                "report_id",
                "report_sha256",
                "sha256:d99ab1ba242b664d4f50e0ab9db79106d29efd72dbd5cae3a69d03b49ca79663",
            ),
            (
                self.bundle.attestation,
                "attestation_id",
                "attestation_sha256",
                "sha256:19839d4d496faba91641b6c4f5054d2878d5a5bc6c0648505b7186963fbaeff3",
            ),
            (
                self.bundle,
                "bundle_id",
                "bundle_sha256",
                "sha256:0ec635c1ac1104352f6094e0d7ae3d5433c84c571e81785d596268ba65cf3b4b",
            ),
        )

    def test_all_five_lifecycle_identities_and_canonical_round_trips_are_unchanged(self) -> None:
        for record, id_field, hash_field, expected_hash in self.lifecycle_records():
            with self.subTest(record=type(record).__name__):
                raw = record.to_dict()
                self.assertEqual(raw[hash_field], expected_hash)
                self.assertEqual(_finding_digest(raw, id_field, hash_field), expected_hash)
                parsed = type(record).from_dict(dict(reversed(tuple(raw.items()))))
                self.assertEqual(_native_json(parsed.to_dict()), _native_json(raw))
                self.assertEqual(parsed.to_dict()[id_field], raw[id_field])
                self.assertEqual(set(raw["effects"].values()), {"none"})
        self.assertEqual(self.plan.to_dict()["status"], "authorized_plan_only")
        self.assertEqual(self.finding.state, lifecycle.FindingState.NEW)
        self.assertEqual(self.retested.state, lifecycle.FindingState.RESOLVED)

    def test_all_five_lifecycle_parsers_reject_equal_schema_type_substitution(self) -> None:
        for record, id_field, hash_field, _ in self.lifecycle_records():
            ordinary = record.to_dict()
            for replacement in (True, 1.0):
                with self.subTest(record=type(record).__name__, replacement=replacement):
                    raw = copy.deepcopy(ordinary)
                    raw["schema_version"] = replacement
                    before = _native_json(raw)
                    self.assertEqual(raw, ordinary)
                    self.assertNotEqual(before, _native_json(ordinary))
                    self.assertNotEqual(_finding_digest(raw, id_field, hash_field), raw[hash_field])
                    with self.assertRaises(lifecycle.FindingLifecycleError):
                        type(record).from_dict(raw)
                    self.assertEqual(_native_json(raw), before)

    def test_snapshot_rejects_equal_derived_version_without_rehashing(self) -> None:
        for snapshot, replacement in (
            (self.finding, True),
            (self.finding, 1.0),
            (self.retested, float(self.retested.finding_version)),
        ):
            with self.subTest(version=snapshot.finding_version, replacement=replacement):
                raw = snapshot.to_dict()
                raw["finding_version"] = replacement
                before = _native_json(raw)
                self.assertNotEqual(
                    _finding_digest(raw, "snapshot_id", "snapshot_sha256"),
                    snapshot.snapshot_sha256,
                )
                with self.assertRaises(lifecycle.FindingLifecycleError):
                    lifecycle.FindingSnapshot.from_dict(raw)
                self.assertEqual(_native_json(raw), before)

    def test_nested_event_type_substitution_cannot_bind_the_old_snapshot(self) -> None:
        for replacement in (True, 1.0):
            with self.subTest(replacement=replacement):
                raw = self.finding.to_dict()
                raw["events"][0]["schema_version"] = replacement
                self.assertNotEqual(
                    _finding_digest(raw, "snapshot_id", "snapshot_sha256"),
                    raw["snapshot_sha256"],
                )
                with self.assertRaises(lifecycle.FindingLifecycleError):
                    lifecycle.FindingSnapshot.from_dict(raw)

    def test_existing_source_integer_and_boolean_guards_still_reject_aliases(self) -> None:
        for field in ("sequence", "finding_version"):
            for replacement in (True, 1.0):
                with self.subTest(record="event", field=field, replacement=replacement):
                    raw = self.finding.events[0].to_dict()
                    raw[field] = replacement
                    with self.assertRaisesRegex(lifecycle.FindingLifecycleError, "positive"):
                        lifecycle.FindingEvent.from_dict(raw)
        raw = self.plan.to_dict()
        raw["prior_finding_version"] = float(self.plan.prior_finding_version)
        with self.assertRaisesRegex(lifecycle.FindingLifecycleError, "positive"):
            lifecycle.RetestPlan.from_dict(raw)
        for replacement in (1, 1.0):
            raw = self.bundle.report.assessment.task_transcripts[0].to_dict()
            raw["restoration_required"] = replacement
            with self.assertRaisesRegex(reporting.AssessmentReportingError, "boolean"):
                reporting.TaskTranscript.from_dict(raw)
        for replacement in (True, 1.0):
            raw = self.bundle.report.assessment.coverage_metrics.to_dict()
            raw["tested"] = replacement
            with self.assertRaisesRegex(reporting.AssessmentReportingError, "integer"):
                reporting.CoverageMetrics.from_dict(raw)

    def test_all_seven_report_identities_and_canonical_round_trips_are_unchanged(self) -> None:
        for record, id_field, hash_field, expected_hash in self.report_records():
            with self.subTest(record=type(record).__name__):
                raw = record.to_dict()
                self.assertEqual(raw[hash_field], expected_hash)
                self.assertEqual(_report_digest(raw, id_field, hash_field), expected_hash)
                parsed = type(record).from_dict(dict(reversed(tuple(raw.items()))))
                self.assertEqual(_native_json(parsed.to_dict()), _native_json(raw))
                self.assertEqual(parsed.to_dict()[id_field], raw[id_field])
                self.assertEqual(set(raw["effects"].values()), {"none"})
        self.assertEqual(
            reporting.AssessmentReportBundle.from_json(self.bundle.to_json()), self.bundle
        )
        self.assertEqual(reporting.export_report_bundle_json(self.bundle), self.bundle.to_json())
        self.assertEqual(
            reporting.export_report_bundle_sarif(self.bundle), self.bundle.to_sarif_json()
        )
        self.assertEqual(self.bundle.attestation.compliance_claim, "not_assessed")
        self.assertEqual(
            self.bundle.attestation.conclusion, "evidence_only_no_compliance_determination"
        )

    def test_all_seven_report_parsers_reject_equal_schema_type_substitution(self) -> None:
        for record, _, hash_field, _ in self.report_records():
            ordinary = record.to_dict()
            for replacement in (True, 1.0):
                with self.subTest(record=type(record).__name__, replacement=replacement):
                    raw = copy.deepcopy(ordinary)
                    raw["schema_version"] = replacement
                    before = _native_json(raw)
                    self.assertEqual(raw, ordinary)
                    self.assertEqual(raw[hash_field], ordinary[hash_field])
                    self.assertNotEqual(before, _native_json(ordinary))
                    with self.assertRaises(reporting.AssessmentReportingError):
                        type(record).from_dict(raw)
                    self.assertEqual(_native_json(raw), before)

    def test_assessment_rejects_every_equal_coverage_counter_substitution(self) -> None:
        assessment = self.bundle.report.assessment
        for field, value in assessment.coverage_metrics.to_dict().items():
            replacements = (float(value), bool(value)) if value in (0, 1) else (float(value),)
            for replacement in replacements:
                with self.subTest(field=field, replacement=replacement):
                    raw = assessment.to_dict()
                    raw["coverage_metrics"][field] = replacement
                    before = _native_json(raw)
                    self.assertEqual(raw, assessment.to_dict())
                    self.assertNotEqual(
                        _report_digest(raw, "assessment_id", "assessment_sha256"),
                        raw["assessment_sha256"],
                    )
                    with self.assertRaises(reporting.AssessmentReportingError):
                        reporting.AssessmentRecord.from_dict(raw)
                    self.assertEqual(_native_json(raw), before)

    def test_derived_basis_points_reject_float_and_equal_boolean_representations(self) -> None:
        fixture = report_fixtures.AssessmentReportingPhase161Tests()
        for metrics in (
            self.bundle.report.assessment.coverage_metrics,
            fixture.assessment(("abstained", "not_determined")).coverage_metrics,
            fixture.assessment(
                ("tested", "negative", "abstained", "blocked", "untested", "not_determined")
            ).coverage_metrics,
            reporting.CoverageMetrics(10_000, 1, 0, 0, 9_999, 0, 0),
        ):
            ordinary = metrics.to_dict()
            self.assertEqual(reporting.CoverageMetrics.from_dict(ordinary), metrics)
            value = metrics.coverage_basis_points
            replacements = (float(value), bool(value)) if value in (0, 1) else (float(value),)
            for replacement in replacements:
                with self.subTest(basis_points=value, replacement=replacement):
                    raw = metrics.to_dict()
                    raw["coverage_basis_points"] = replacement
                    self.assertEqual(raw, ordinary)
                    self.assertNotEqual(_native_json(raw), _native_json(ordinary))
                    with self.assertRaisesRegex(reporting.AssessmentReportingError, "inflated"):
                        reporting.CoverageMetrics.from_dict(raw)

    def test_nested_report_types_cannot_bind_old_report_or_bundle_hashes(self) -> None:
        changes = (
            (("report", "assessment", "coverage_metrics", "tested"), True),
            (("report", "assessment", "coverage_metrics", "tested"), 1.0),
            (("report", "executive_summary", "coverage_metrics", "coverage_basis_points"), 10000.0),
            (("report", "assessment", "assets", 0, "schema_version"), True),
            (("report", "findings", 0, "schema_version"), 1.0),
            (("attestation", "schema_version"), True),
        )
        for path, replacement in changes:
            with self.subTest(path=path, replacement=replacement):
                raw = self.bundle.to_dict()
                container = raw
                for field in path[:-1]:
                    container = container[field]
                container[path[-1]] = replacement
                before = _native_json(raw)
                self.assertEqual(raw, self.bundle.to_dict())
                self.assertNotEqual(
                    _report_digest(raw, "bundle_id", "bundle_sha256"), raw["bundle_sha256"]
                )
                if path[0] == "report":
                    report = raw["report"]
                    self.assertNotEqual(
                        _report_digest(report, "report_id", "report_sha256"),
                        report["report_sha256"],
                    )
                    with self.assertRaises(reporting.AssessmentReportingError):
                        reporting.PentestReport.from_dict(report)
                with self.assertRaises(reporting.AssessmentReportingError):
                    reporting.AssessmentReportBundle.from_dict(raw)
                with self.assertRaises(reporting.AssessmentReportingError):
                    reporting.AssessmentReportBundle.from_json(before)
                self.assertEqual(_native_json(raw), before)

    def test_cvss_constructor_compatibility_does_not_normalize_malformed_wire_scores(self) -> None:
        for score, vector, severity in (
            (10, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "critical"),
            (0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "informational"),
        ):
            with self.subTest(score=score):
                record = replace(
                    self.bundle.report.findings[0],
                    cvss_vector=vector,
                    cvss_score=score,
                    severity=severity,
                )
                ordinary = record.to_dict()
                self.assertIs(type(ordinary["cvss_score"]), float)
                self.assertEqual(reporting.FindingReport.from_dict(ordinary), record)
                raw = record.to_dict()
                raw["cvss_score"] = score
                before = _native_json(raw)
                self.assertEqual(raw, ordinary)
                self.assertNotEqual(
                    _report_digest(raw, "finding_report_id", "finding_report_sha256"),
                    raw["finding_report_sha256"],
                )
                with self.assertRaises(reporting.AssessmentReportingError):
                    reporting.FindingReport.from_dict(raw)
                self.assertEqual(_native_json(raw), before)


if __name__ == "__main__":
    unittest.main()
