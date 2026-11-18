"""Phase 161 assessment reporting and export contract coverage."""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.assessment_reporting import (
    NO_EFFECTS,
    AssessmentRecord,
    AssessmentReportBundle,
    AssessmentReportingError,
    AssetRecord,
    FindingLifecycleReference,
    FindingReport,
    ReviewerRole,
    TaskTranscript,
    ValidatorResultReference,
    build_assessment_report_bundle,
    export_report_bundle_json,
    export_report_bundle_sarif,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "assessment-report-bundle-v1.schema.json"
FILES = (
    ROOT / "src" / "sunderkey" / "assessment_reporting.py",
    Path(__file__),
    SCHEMA,
    ROOT / "docs" / "assessment-reporting.md",
)
DIGESTS = tuple("sha256:" + character * 64 for character in "0123456789abcdef")
SCOPE = DIGESTS[0]
WORLD = DIGESTS[1]
SCHEDULE = DIGESTS[2]


class AssessmentReportingPhase161Tests(unittest.TestCase):
    def asset(self, operations: tuple[str, ...] = ("read", "write")) -> AssetRecord:
        return AssetRecord(
            asset_id="asset.api",
            asset_type="http_service",
            display_name="Example API",
            operation_ids=operations,
            signed_scope_sha256=SCOPE,
            evidence_digests=(DIGESTS[3],),
        )

    def task(
        self,
        operation: str,
        status: str,
        index: int,
        *,
        restoration_required: bool = False,
        restoration_status: str = "not_required",
    ) -> TaskTranscript:
        return TaskTranscript(
            task_id=f"task.{operation}",
            transcript_sha256=DIGESTS[index],
            coverage_area_id=f"asset.api::{operation}",
            technique_id=f"TECH-{index:03d}",
            profile_id=f"profile.{operation}",
            status=status,
            started_at="2026-09-20T03:05:00Z",
            ended_at="2026-09-20T03:10:00Z",
            signed_scope_sha256=SCOPE,
            world_snapshot_sha256=WORLD,
            schedule_sha256=SCHEDULE,
            evidence_digests=(DIGESTS[index],),
            blocker_code="dependency_unavailable" if status == "blocked" else None,
            restoration_required=restoration_required,
            restoration_status=restoration_status,
        )

    def assessment(
        self,
        statuses: tuple[str, ...] = ("tested", "negative"),
        *,
        restoration_status: str = "verified",
    ) -> AssessmentRecord:
        operations = tuple(f"op{index}" for index in range(len(statuses)))
        tasks = tuple(
            self.task(
                operation,
                status,
                4 + index,
                restoration_required=index == 0,
                restoration_status=restoration_status if index == 0 else "not_required",
            )
            for index, (operation, status) in enumerate(zip(operations, statuses, strict=True))
        )
        validators = tuple(
            ValidatorResultReference(
                validator_id=f"validator.{operation}",
                task_id=task.task_id,
                result_sha256=DIGESTS[10 + index],
                outcome={
                    "tested": "validated",
                    "negative": "negative",
                    "abstained": "abstained",
                    "not_determined": "inconclusive",
                }[task.status.value],
                evidence_digests=task.evidence_digests,
            )
            for index, (operation, task) in enumerate(zip(operations, tasks, strict=True))
            if task.status.value in {"tested", "negative", "abstained", "not_determined"}
        )
        lifecycle = (
            FindingLifecycleReference(
                finding_id="FND-001",
                snapshot_sha256=DIGESTS[9],
                state="validated",
                updated_at="2026-09-20T03:11:00Z",
            ),
        )
        return AssessmentRecord(
            assets=(self.asset(operations),),
            signed_scope_sha256=SCOPE,
            world_snapshot_sha256=WORLD,
            schedule_sha256=SCHEDULE,
            task_transcripts=tasks,
            validator_results=validators,
            finding_lifecycle=lifecycle,
            started_at="2026-09-20T03:00:00Z",
            ended_at="2026-09-20T03:20:00Z",
            source_observed_at="2026-09-20T03:19:00Z",
            generated_at="2026-09-20T03:21:00Z",
            max_source_age_seconds=300,
            residual_risk="Some application risk remains outside the bounded test coverage.",
            residual_risk_rating="medium",
            scope_limits=("Only explicitly listed operations were assessed.",),
        )

    def finding(self, assessment: AssessmentRecord) -> FindingReport:
        validator = next(
            item for item in assessment.validator_results if item.outcome == "validated"
        )
        return FindingReport(
            finding_id="FND-001",
            lifecycle_snapshot_sha256=DIGESTS[9],
            title="Missing authorization boundary",
            affected_asset_id="asset.api",
            affected_operation_id="op0",
            vulnerability_class="broken_access_control",
            cwe_ref="CWE-862",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cvss_score=9.8,
            severity="critical",
            confidence="high",
            status="validated",
            evidence_digests=(DIGESTS[4],),
            impact_description=(
                "A caller could reach an operation without the expected boundary check."
            ),
            reproduction_summary=(
                "Use a synthetic account with the documented lowest privilege.",
                "Request the named operation and compare the authorization outcome.",
            ),
            remediation_guidance="Enforce object and operation authorization before processing.",
            validation_status="validated",
            validation_result_sha256=validator.result_sha256,
            retest_status="pending",
        )

    def reviewers(self) -> tuple[tuple[ReviewerRole, ...], tuple[ReviewerRole, ...]]:
        report = (
            ReviewerRole("reviewer.author", "report_author"),
            ReviewerRole("reviewer.technical", "technical_reviewer"),
        )
        attestation = (
            ReviewerRole("reviewer.control", "independent_control"),
            ReviewerRole("reviewer.assurance", "independent_assurance"),
            ReviewerRole("reviewer.attestor", "attestor"),
        )
        return report, attestation

    def bundle(
        self,
        statuses: tuple[str, ...] = ("tested", "negative"),
        *,
        restoration_status: str = "verified",
    ) -> AssessmentReportBundle:
        assessment = self.assessment(statuses, restoration_status=restoration_status)
        report_reviewers, attestation_reviewers = self.reviewers()
        return build_assessment_report_bundle(
            assessment,
            (self.finding(assessment),),
            report_reviewers=report_reviewers,
            attestation_reviewers=attestation_reviewers,
            attested_at="2026-09-20T03:22:00Z",
        )

    def test_immutable_content_addressed_round_trip_and_schema(self) -> None:
        bundle = self.bundle()
        self.assertEqual(bundle, AssessmentReportBundle.from_json(bundle.to_json()))
        with self.assertRaises(FrozenInstanceError):
            bundle.bundle_sha256 = DIGESTS[15]  # type: ignore[misc]
        if Draft202012Validator is not None:
            schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(bundle.to_dict())

    def test_redaction_rejects_secrets_and_payloads(self) -> None:
        assessment = self.assessment()
        finding = self.finding(assessment)
        secret = {**finding.__dict__, "impact_description": "Authorization: Bearer abcdefghijk"}
        secret.pop("finding_report_id")
        secret.pop("finding_report_sha256")
        with self.assertRaisesRegex(AssessmentReportingError, "secret"):
            FindingReport(**secret)
        payload = {
            **finding.__dict__,
            "reproduction_summary": ("Run UNION SELECT against the input.",),
        }
        payload.pop("finding_report_id")
        payload.pop("finding_report_sha256")
        with self.assertRaisesRegex(AssessmentReportingError, "payload"):
            FindingReport(**payload)
        response = {
            **finding.__dict__,
            "impact_description": '{"account":"unredacted body"}',
        }
        response.pop("finding_report_id")
        response.pop("finding_report_sha256")
        with self.assertRaisesRegex(AssessmentReportingError, "response body"):
            FindingReport(**response)
        serialized = self.bundle().to_json().lower()
        for forbidden in (
            "authorization: bearer",
            '"credential_value"',
            '"raw_response_body"',
            '"exploit_payload"',
        ):
            self.assertNotIn(forbidden, serialized)

    def test_redaction_rejects_secret_phrases_and_standalone_keys(self) -> None:
        assessment = self.assessment()
        finding = self.finding(assessment)
        base = dict(finding.__dict__)
        base.pop("finding_report_id")
        base.pop("finding_report_sha256")
        for text in (
            "Password is hunter2",
            "The API key is sk-" + "proj-abcdefghijklmnopqrstuvwxyz0123456789",
            "Observed AS" + "IAABCDEFGHIJKLMNOP in a log",
            "Observed sk-" + "abcdefghijklmnopqrstuvwxyz0123456789 in a note",
        ):
            with self.subTest(text=text), self.assertRaisesRegex(
                AssessmentReportingError, "secret-like",
            ):
                FindingReport(**{**base, "impact_description": text})
        safe = FindingReport(
            **{**base, "impact_description": "The password is rotated by policy."}
        )
        self.assertEqual(safe.impact_description, "The password is rotated by policy.")

    def test_cvss_is_optional_but_never_invented_or_inconsistent(self) -> None:
        assessment = self.assessment()
        finding = self.finding(assessment)
        base = dict(finding.__dict__)
        base.pop("finding_report_id")
        base.pop("finding_report_sha256")
        with self.assertRaisesRegex(AssessmentReportingError, "does not match"):
            FindingReport(**{**base, "cvss_score": 9.7})
        with self.assertRaisesRegex(AssessmentReportingError, "supplied together"):
            FindingReport(**{**base, "cvss_score": None})
        unrated = FindingReport(
            **{**base, "cvss_vector": None, "cvss_score": None, "severity": "unrated"}
        )
        self.assertIsNone(unrated.cvss_score)
        self.assertIsNone(unrated.to_dict()["cvss_vector"])

    def test_metrics_include_negative_abstained_blocked_and_unknown(self) -> None:
        statuses = ("tested", "negative", "abstained", "blocked", "untested", "not_determined")
        bundle = self.bundle(statuses)
        metrics = bundle.report.executive_summary.coverage_metrics
        self.assertEqual(metrics.total_areas, 6)
        self.assertEqual(metrics.coverage_basis_points, 3333)
        self.assertEqual(metrics.negative_results, 1)
        self.assertEqual(metrics.abstentions, 1)
        self.assertEqual(metrics.blocked, 1)
        self.assertEqual(metrics.untested, 1)
        self.assertEqual(metrics.not_determined, 1)
        self.assertEqual(bundle.report.executive_summary.completeness, "partial")
        self.assertEqual(bundle.attestation.tested_areas, ("asset.api::op0", "asset.api::op1"))
        self.assertEqual(bundle.attestation.not_tested_areas, ("asset.api::op3", "asset.api::op4"))
        self.assertEqual(
            bundle.attestation.not_determined_areas, ("asset.api::op2", "asset.api::op5")
        )

    def test_report_and_attestation_overclaim_is_rejected(self) -> None:
        bundle = self.bundle(("tested", "negative", "abstained"))
        document = bundle.to_dict()
        inflated = copy.deepcopy(document)
        inflated["report"]["executive_summary"]["coverage_metrics"]["tested"] += 1
        with self.assertRaises(AssessmentReportingError):
            AssessmentReportBundle.from_dict(inflated)
        overclaim = copy.deepcopy(document)
        overclaim["attestation"]["compliance_claim"] = "compliant"
        with self.assertRaisesRegex(AssessmentReportingError, "overclaims"):
            AssessmentReportBundle.from_dict(overclaim)
        omission = copy.deepcopy(document)
        omission["attestation"]["abstained_task_ids"] = []
        with self.assertRaises(AssessmentReportingError):
            AssessmentReportBundle.from_dict(omission)

    def test_deterministic_json_and_sarif_like_export(self) -> None:
        first = self.bundle(("tested", "negative", "abstained", "blocked", "untested"))
        second = self.bundle(("tested", "negative", "abstained", "blocked", "untested"))
        self.assertEqual(first.to_json(), second.to_json())
        self.assertEqual(first.to_sarif_json(), second.to_sarif_json())
        self.assertEqual(export_report_bundle_json(first), first.to_json())
        self.assertEqual(export_report_bundle_sarif(first), first.to_sarif_json())
        sarif = json.loads(first.to_sarif_json())
        self.assertEqual(sarif["version"], "2.1.0")
        properties = sarif["runs"][0]["invocations"][0]["properties"]
        self.assertEqual(properties["completeness"], "partial")
        self.assertTrue(properties["negativeResultTaskIds"])
        self.assertTrue(properties["abstainedTaskIds"])
        self.assertTrue(properties["blockedAreas"])
        self.assertTrue(properties["notTestedAreas"])

    def test_tamper_and_noncanonical_json_fail_closed(self) -> None:
        bundle = self.bundle()
        document = bundle.to_dict()
        tampered = copy.deepcopy(document)
        tampered["report"]["findings"][0]["title"] = "Changed title"
        with self.assertRaises(AssessmentReportingError):
            AssessmentReportBundle.from_dict(tampered)
        pretty = json.dumps(document, indent=2, sort_keys=True)
        with self.assertRaisesRegex(AssessmentReportingError, "not canonical"):
            AssessmentReportBundle.from_json(pretty)

    def test_reviewer_separation_of_duty(self) -> None:
        assessment = self.assessment()
        report_reviewers, attestation_reviewers = self.reviewers()
        overlapping = (
            ReviewerRole("reviewer.author", "independent_control"),
            *attestation_reviewers[1:],
        )
        with self.assertRaisesRegex(AssessmentReportingError, "independent"):
            build_assessment_report_bundle(
                assessment,
                (self.finding(assessment),),
                report_reviewers=report_reviewers,
                attestation_reviewers=overlapping,
                attested_at="2026-09-20T03:22:00Z",
            )
        duplicate_role_holder = (
            ReviewerRole("reviewer.same", "independent_control"),
            ReviewerRole("reviewer.same", "independent_assurance"),
            ReviewerRole("reviewer.attestor", "attestor"),
        )
        with self.assertRaisesRegex(AssessmentReportingError, "separation"):
            build_assessment_report_bundle(
                assessment,
                (self.finding(assessment),),
                report_reviewers=report_reviewers,
                attestation_reviewers=duplicate_role_holder,
                attested_at="2026-09-20T03:22:00Z",
            )
        participant_overlap = (
            ReviewerRole("profile.op0", "independent_control"),
            *attestation_reviewers[1:],
        )
        with self.assertRaisesRegex(AssessmentReportingError, "profiles"):
            build_assessment_report_bundle(
                assessment,
                (self.finding(assessment),),
                report_reviewers=report_reviewers,
                attestation_reviewers=participant_overlap,
                attested_at="2026-09-20T03:22:00Z",
            )

    def test_unresolved_restoration_is_preserved_everywhere(self) -> None:
        bundle = self.bundle(restoration_status="incomplete")
        self.assertEqual(bundle.report.assessment.restoration_status, "incomplete")
        self.assertEqual(bundle.report.executive_summary.restoration_status, "incomplete")
        self.assertEqual(bundle.attestation.restoration_status, "incomplete")
        self.assertEqual(
            bundle.report.executive_summary.incomplete_restoration_task_ids, ("task.op0",)
        )

    def test_missing_coverage_mismatched_and_stale_inputs_fail(self) -> None:
        assessment = self.assessment()
        values = dict(assessment.__dict__)
        for name in (
            "assessment_id",
            "assessment_sha256",
            "completeness",
            "coverage_metrics",
            "restoration_status",
        ):
            values.pop(name)
        with self.assertRaisesRegex(AssessmentReportingError, "exactly cover"):
            AssessmentRecord(**{**values, "task_transcripts": assessment.task_transcripts[:1]})
        wrong_task = copy.deepcopy(assessment.task_transcripts[0].to_dict())
        wrong_task["world_snapshot_sha256"] = DIGESTS[15]
        wrong_task.pop("transcript_record_sha256")
        with self.assertRaisesRegex(AssessmentReportingError, "source digest"):
            AssessmentRecord(
                **{
                    **values,
                    "task_transcripts": (
                        TaskTranscript(**wrong_task),
                        assessment.task_transcripts[1],
                    ),
                }
            )
        with self.assertRaisesRegex(AssessmentReportingError, "stale"):
            AssessmentRecord(**{**values, "source_observed_at": "2026-09-20T02:00:00Z"})

    def test_effect_escalation_is_rejected_and_no_effects_are_explicit(self) -> None:
        bundle = self.bundle()
        document = bundle.to_dict()
        mutated = copy.deepcopy(document)
        mutated["effects"]["network"] = "allowed"
        with self.assertRaisesRegex(AssessmentReportingError, "effect escalation"):
            AssessmentReportBundle.from_dict(mutated)
        self.assertEqual(document["effects"], NO_EFFECTS)
        self.assertEqual(document["report"]["effects"], NO_EFFECTS)
        self.assertEqual(document["report"]["assessment"]["effects"], NO_EFFECTS)
        self.assertEqual(document["report"]["executive_summary"]["effects"], NO_EFFECTS)
        self.assertEqual(document["report"]["findings"][0]["effects"], NO_EFFECTS)
        self.assertEqual(document["attestation"]["effects"], NO_EFFECTS)

    def test_source_files_have_no_dash_or_placeholder_markers(self) -> None:
        markers = (
            "TO" + "DO",
            "FIX" + "ME",
            "T" + "BD",
            "X" + "XX",
            "PLACE" + "HOLDER",
        )
        for path in FILES:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("\u2013", text, str(path))
            self.assertNotIn("\u2014", text, str(path))
            for marker in markers:
                self.assertNotIn(marker, text, str(path))


if __name__ == "__main__":
    unittest.main()
