"""Finding validator task lineage at the public report boundaries."""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import replace

from sunderkey.assessment_reporting import (
    BUNDLE_KIND,
    NO_EFFECTS,
    TASK_STATUSES,
    AssessmentAttestation,
    AssessmentRecord,
    AssessmentReportBundle,
    AssessmentReportingError,
    AssetRecord,
    ExecutiveSummary,
    FindingLifecycleReference,
    FindingReport,
    PentestReport,
    TaskTranscript,
    ValidatorResultReference,
    build_assessment_report_bundle,
    canonical_json,
    canonical_sha256,
    export_report_bundle_json,
    export_report_bundle_sarif,
)
from tests.agents import test_assessment_reporting_phase161 as phase161


def readdress_document(
    document: dict[str, object],
    *,
    prefix: str,
    domain: str,
    id_field: str,
    digest_field: str,
) -> None:
    body = {
        name: value
        for name, value in document.items()
        if name not in {id_field, digest_field, "effects", "kind", "schema_version"}
    }
    digest = canonical_sha256({"content": body, "domain": domain})
    document[id_field] = prefix + "-" + digest[7:39].upper()
    document[digest_field] = digest


class ReportTaskLineageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = phase161.AssessmentReportingPhase161Tests(methodName="runTest")
        self.report_reviewers, self.attestation_reviewers = self.fixture.reviewers()

    def build(
        self,
        assessment: AssessmentRecord,
        findings: tuple[FindingReport, ...],
    ) -> AssessmentReportBundle:
        return build_assessment_report_bundle(
            assessment,
            findings,
            report_reviewers=self.report_reviewers,
            attestation_reviewers=self.attestation_reviewers,
            attested_at="2026-09-20T03:22:00Z",
        )

    def different_asset_assessment(self) -> AssessmentRecord:
        original = self.fixture.assessment(("tested", "tested"))
        first_asset = replace(original.assets[0], operation_ids=("op0",))
        other_asset = replace(
            original.assets[0],
            asset_id="asset.other",
            display_name="Other synthetic API",
            operation_ids=("op0",),
        )
        first_task, original_second = original.task_transcripts
        other_task = replace(
            original_second,
            task_id="task.other.op0",
            coverage_area_id="asset.other::op0",
            profile_id="profile.other.op0",
        )
        other_validator = replace(
            original.validator_results[1],
            task_id=other_task.task_id,
            validator_id="validator.other.op0",
        )
        return replace(
            original,
            assets=(first_asset, other_asset),
            task_transcripts=(first_task, other_task),
            validator_results=(original.validator_results[0], other_validator),
        )

    def delimiter_assessment(self, pairs: tuple[tuple[str, str], ...]) -> AssessmentRecord:
        original = self.fixture.assessment(tuple("tested" for _ in pairs))
        assets = tuple(
            replace(original.assets[0], asset_id=asset_id, operation_ids=(operation_id,))
            for asset_id, operation_id in pairs
        )
        tasks = tuple(
            replace(task, coverage_area_id=f"{asset_id}::{operation_id}")
            for task, (asset_id, operation_id) in zip(original.task_transcripts, pairs, strict=True)
        )
        return replace(original, assets=assets, task_transcripts=tasks)

    def collision_inputs(self) -> tuple[AssessmentRecord, tuple[AssetRecord, ...]]:
        assessment = self.delimiter_assessment((("asset.api", "namespace::op0"),))
        other_asset = replace(
            assessment.assets[0], asset_id="asset.api::namespace", operation_ids=("op0",)
        )
        assets = (assessment.assets[0], other_asset)
        pairs = tuple(
            (asset.asset_id, operation_id)
            for asset in assets
            for operation_id in asset.operation_ids
        )
        areas = tuple(area for asset in assets for area in asset.coverage_area_ids)
        self.assertEqual(len(set(pairs)), 2)
        self.assertEqual(areas, ("asset.api::namespace::op0",) * 2)
        self.assertEqual(len(set(areas)), 1)
        self.assertEqual(len(assessment.task_transcripts), 1)
        self.assertEqual(assessment.coverage_metrics.total_areas, 1)
        self.assertEqual(assessment.completeness, "complete")
        return assessment, assets

    def collision_source_document(self) -> dict[str, object]:
        assessment, assets = self.collision_inputs()
        document = copy.deepcopy(assessment.to_dict())
        document["assets"] = [asset.to_dict() for asset in assets]
        readdress_document(
            document,
            prefix="ASM",
            domain=AssessmentRecord.KIND,
            id_field="assessment_id",
            digest_field="assessment_sha256",
        )
        self.assertNotEqual(document["assessment_sha256"], assessment.assessment_sha256)
        return document

    def collision_bundle_vectors(self):
        assessment, _ = self.collision_inputs()
        original_finding = replace(
            self.fixture.finding(assessment), affected_operation_id="namespace::op0"
        )
        good = self.build(assessment, (original_finding,))
        source = self.collision_source_document()
        for asset_id, operation_id in (
            ("asset.api", "namespace::op0"),
            ("asset.api::namespace", "op0"),
        ):
            finding = replace(
                original_finding,
                affected_asset_id=asset_id,
                affected_operation_id=operation_id,
            )
            self.assertEqual(
                f"{finding.affected_asset_id}::{finding.affected_operation_id}",
                assessment.task_transcripts[0].coverage_area_id,
            )
            document = self.coherent_relabelled_document(good, finding)
            report = document["report"]
            report["assessment"] = copy.deepcopy(source)
            summary = report["executive_summary"]
            summary["assessment_id"] = source["assessment_id"]
            summary["assessment_sha256"] = source["assessment_sha256"]
            readdress_document(
                summary,
                prefix="EXS",
                domain=ExecutiveSummary.KIND,
                id_field="executive_summary_id",
                digest_field="executive_summary_sha256",
            )
            readdress_document(
                report,
                prefix="PTR",
                domain=PentestReport.KIND,
                id_field="report_id",
                digest_field="report_sha256",
            )
            attestation = document["attestation"]
            attestation["assessment_id"] = source["assessment_id"]
            attestation["assessment_sha256"] = source["assessment_sha256"]
            attestation["report_id"] = report["report_id"]
            attestation["report_sha256"] = report["report_sha256"]
            readdress_document(
                attestation,
                prefix="ATT",
                domain=AssessmentAttestation.KIND,
                id_field="attestation_id",
                digest_field="attestation_sha256",
            )
            readdress_document(
                document,
                prefix="ARB",
                domain=BUNDLE_KIND,
                id_field="bundle_id",
                digest_field="bundle_sha256",
            )
            yield (asset_id, operation_id), good, document

    def native_collision_for_checked_export(
        self,
        good: AssessmentReportBundle,
        document: dict[str, object],
    ) -> AssessmentReportBundle:
        """Coherent local frozen-source misuse, not a process-isolation claim."""

        candidate = copy.deepcopy(good)
        report = document["report"]
        source = report["assessment"]
        object.__setattr__(
            candidate.report.assessment,
            "assets",
            tuple(AssetRecord.from_dict(raw) for raw in source["assets"]),
        )
        object.__setattr__(candidate.report.assessment, "assessment_id", source["assessment_id"])
        object.__setattr__(
            candidate.report.assessment, "assessment_sha256", source["assessment_sha256"]
        )
        object.__setattr__(
            candidate.report, "findings", (FindingReport.from_dict(report["findings"][0]),)
        )
        object.__setattr__(
            candidate.report,
            "executive_summary",
            ExecutiveSummary.from_dict(report["executive_summary"]),
        )
        object.__setattr__(candidate.report, "report_id", report["report_id"])
        object.__setattr__(candidate.report, "report_sha256", report["report_sha256"])
        object.__setattr__(
            candidate,
            "attestation",
            AssessmentAttestation.from_dict(document["attestation"]),
        )
        object.__setattr__(candidate, "bundle_id", document["bundle_id"])
        object.__setattr__(candidate, "bundle_sha256", document["bundle_sha256"])
        self.assertEqual(canonical_json(candidate.to_dict()), canonical_json(document))
        return candidate

    def assert_valid_delimiter_pairs(self, pairs: tuple[tuple[str, str], ...]) -> None:
        assessment = self.delimiter_assessment(pairs)
        self.assertEqual(assessment.coverage_metrics.total_areas, len(pairs))
        self.assertEqual(assessment.coverage_metrics.tested, len(pairs))
        self.assertEqual(assessment.completeness, "complete")
        self.assertEqual(
            canonical_json(AssessmentRecord.from_dict(assessment.to_dict()).to_dict()),
            canonical_json(assessment.to_dict()),
        )
        asset_id, operation_id = pairs[0]
        finding = replace(
            self.fixture.finding(assessment),
            affected_asset_id=asset_id,
            affected_operation_id=operation_id,
        )
        bundle = self.build(assessment, (finding,))
        self.assertEqual(
            AssessmentReportBundle.from_json(export_report_bundle_json(bundle)), bundle
        )
        sarif = json.loads(export_report_bundle_sarif(bundle))
        self.assertEqual(
            sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
                "uri"
            ],
            f"asset:{asset_id}/{operation_id}",
        )
        self.assertEqual(bundle.to_dict()["effects"], NO_EFFECTS)

    def mismatch_vectors(self):
        for status in TASK_STATUSES:
            assessment = self.fixture.assessment(("tested", status))
            source_finding = self.fixture.finding(assessment)
            yield (
                "other_operation_" + status,
                assessment,
                source_finding,
                replace(source_finding, affected_operation_id="op1"),
            )
        assessment = self.different_asset_assessment()
        source_finding = self.fixture.finding(assessment)
        yield (
            "other_asset_same_operation",
            assessment,
            source_finding,
            replace(source_finding, affected_asset_id="asset.other"),
        )

    def assert_independent_inputs_are_valid(
        self,
        assessment: AssessmentRecord,
        source_finding: FindingReport,
        relabelled: FindingReport,
    ) -> None:
        self.assertEqual(
            canonical_json(AssessmentRecord.from_dict(assessment.to_dict()).to_dict()),
            canonical_json(assessment.to_dict()),
        )
        self.assertEqual(
            canonical_json(FindingReport.from_dict(relabelled.to_dict()).to_dict()),
            canonical_json(relabelled.to_dict()),
        )
        validator = next(
            item
            for item in assessment.validator_results
            if item.result_sha256 == relabelled.validation_result_sha256
        )
        task = next(
            item for item in assessment.task_transcripts if item.task_id == validator.task_id
        )
        named_area = relabelled.affected_asset_id + "::" + relabelled.affected_operation_id
        self.assertIn(
            named_area, {area for asset in assessment.assets for area in asset.coverage_area_ids}
        )
        self.assertNotEqual(task.coverage_area_id, named_area)
        self.assertEqual(
            relabelled.validation_result_sha256, source_finding.validation_result_sha256
        )
        self.assertEqual(relabelled.validation_status, validator.outcome)
        self.assertNotEqual(relabelled.finding_report_sha256, source_finding.finding_report_sha256)

    def coherent_relabelled_document(
        self,
        bundle: AssessmentReportBundle,
        relabelled: FindingReport,
    ) -> dict[str, object]:
        document = copy.deepcopy(bundle.to_dict())
        report = document["report"]
        report["findings"] = [relabelled.to_dict()]
        readdress_document(
            report,
            prefix="PTR",
            domain=PentestReport.KIND,
            id_field="report_id",
            digest_field="report_sha256",
        )
        attestation = document["attestation"]
        attestation["report_id"] = report["report_id"]
        attestation["report_sha256"] = report["report_sha256"]
        readdress_document(
            attestation,
            prefix="ATT",
            domain=AssessmentAttestation.KIND,
            id_field="attestation_id",
            digest_field="attestation_sha256",
        )
        readdress_document(
            document,
            prefix="ARB",
            domain=BUNDLE_KIND,
            id_field="bundle_id",
            digest_field="bundle_sha256",
        )
        return document

    def native_relabelled_for_checked_export(
        self,
        bundle: AssessmentReportBundle,
        document: dict[str, object],
    ) -> AssessmentReportBundle:
        """Local frozen-object misuse probe, not a process-isolation claim."""

        candidate = copy.deepcopy(bundle)
        report = document["report"]
        finding = FindingReport.from_dict(report["findings"][0])
        object.__setattr__(candidate.report, "findings", (finding,))
        object.__setattr__(candidate.report, "report_id", report["report_id"])
        object.__setattr__(candidate.report, "report_sha256", report["report_sha256"])
        object.__setattr__(
            candidate,
            "attestation",
            AssessmentAttestation.from_dict(document["attestation"]),
        )
        object.__setattr__(candidate, "bundle_id", document["bundle_id"])
        object.__setattr__(candidate, "bundle_sha256", document["bundle_sha256"])
        self.assertEqual(canonical_json(candidate.to_dict()), canonical_json(document))
        return candidate

    def test_public_report_constructor_rejects_all_coherent_wrong_task_vectors(self) -> None:
        for label, assessment, correct, relabelled in self.mismatch_vectors():
            with self.subTest(vector=label):
                self.assert_independent_inputs_are_valid(assessment, correct, relabelled)
                good = self.build(assessment, (correct,))
                with self.assertRaisesRegex(AssessmentReportingError, "validator task"):
                    PentestReport(
                        assessment,
                        good.report.executive_summary,
                        (relabelled,),
                        self.report_reviewers,
                    )

    def test_public_bundle_builder_rejects_all_coherent_wrong_task_vectors(self) -> None:
        for label, assessment, correct, relabelled in self.mismatch_vectors():
            with self.subTest(vector=label):
                self.assert_independent_inputs_are_valid(assessment, correct, relabelled)
                with self.assertRaisesRegex(AssessmentReportingError, "validator task"):
                    self.build(assessment, (relabelled,))

    def test_report_parser_rejects_independently_readdressed_wrong_task_vectors(self) -> None:
        for label, assessment, correct, relabelled in self.mismatch_vectors():
            with self.subTest(vector=label):
                good = self.build(assessment, (correct,))
                document = self.coherent_relabelled_document(good, relabelled)
                with self.assertRaisesRegex(AssessmentReportingError, "validator task"):
                    PentestReport.from_dict(document["report"])

    def test_bundle_parser_rejects_independently_readdressed_wrong_task_vectors(self) -> None:
        for label, assessment, correct, relabelled in self.mismatch_vectors():
            with self.subTest(vector=label):
                good = self.build(assessment, (correct,))
                document = self.coherent_relabelled_document(good, relabelled)
                with self.assertRaisesRegex(AssessmentReportingError, "validator task"):
                    AssessmentReportBundle.from_dict(document)

    def test_canonical_json_parser_rejects_readdressed_wrong_task_vectors(self) -> None:
        for label, assessment, correct, relabelled in self.mismatch_vectors():
            with self.subTest(vector=label):
                good = self.build(assessment, (correct,))
                document = self.coherent_relabelled_document(good, relabelled)
                with self.assertRaisesRegex(AssessmentReportingError, "validator task"):
                    AssessmentReportBundle.from_json(canonical_json(document))

    def test_checked_json_export_rejects_coherently_mutated_native_wrong_task(self) -> None:
        for label, assessment, correct, relabelled in self.mismatch_vectors():
            with self.subTest(vector=label):
                good = self.build(assessment, (correct,))
                document = self.coherent_relabelled_document(good, relabelled)
                candidate = self.native_relabelled_for_checked_export(good, document)
                with self.assertRaisesRegex(AssessmentReportingError, "validator task"):
                    export_report_bundle_json(candidate)

    def test_checked_sarif_export_rejects_coherently_mutated_native_wrong_task(self) -> None:
        for label, assessment, correct, relabelled in self.mismatch_vectors():
            with self.subTest(vector=label):
                good = self.build(assessment, (correct,))
                document = self.coherent_relabelled_document(good, relabelled)
                candidate = self.native_relabelled_for_checked_export(good, document)
                with self.assertRaisesRegex(AssessmentReportingError, "validator task"):
                    export_report_bundle_sarif(candidate)

    def test_both_tested_wrong_operation_is_not_covered_by_another_task_validator(self) -> None:
        assessment = self.fixture.assessment(("tested", "tested"))
        correct = self.fixture.finding(assessment)
        relabelled = replace(correct, affected_operation_id="op1")
        self.assertEqual(assessment.completeness, "complete")
        self.assertEqual(assessment.coverage_metrics.tested, 2)
        self.assertTrue(
            all(result.outcome == "validated" for result in assessment.validator_results)
        )
        with self.assertRaisesRegex(AssessmentReportingError, "validator task"):
            self.build(assessment, (relabelled,))

    def test_correct_original_task_remains_valid_with_every_other_operation_status(self) -> None:
        for status in TASK_STATUSES:
            with self.subTest(other_status=status):
                assessment = self.fixture.assessment(("tested", status))
                finding = self.fixture.finding(assessment)
                bundle = self.build(assessment, (finding,))
                self.assertEqual(
                    canonical_json(PentestReport.from_dict(bundle.report.to_dict()).to_dict()),
                    canonical_json(bundle.report.to_dict()),
                )
                self.assertEqual(
                    AssessmentReportBundle.from_json(export_report_bundle_json(bundle)), bundle
                )
                sarif = json.loads(export_report_bundle_sarif(bundle))
                self.assertEqual(
                    sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
                        "artifactLocation"
                    ]["uri"],
                    "asset:asset.api/op0",
                )
                self.assertEqual(bundle.to_dict()["effects"], NO_EFFECTS)

    def test_correct_other_tested_operation_uses_its_own_task_validator(self) -> None:
        assessment = self.fixture.assessment(("tested", "tested"))
        validator = next(
            item for item in assessment.validator_results if item.task_id == "task.op1"
        )
        task = next(
            item for item in assessment.task_transcripts if item.task_id == validator.task_id
        )
        finding = replace(
            self.fixture.finding(assessment),
            affected_operation_id="op1",
            validation_result_sha256=validator.result_sha256,
            evidence_digests=task.evidence_digests,
        )
        bundle = self.build(assessment, (finding,))
        self.assertEqual(
            AssessmentReportBundle.from_json(export_report_bundle_json(bundle)), bundle
        )
        sarif = json.loads(export_report_bundle_sarif(bundle))
        self.assertEqual(
            sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
                "uri"
            ],
            "asset:asset.api/op1",
        )

    def test_correct_other_asset_same_operation_uses_its_exact_task_validator(self) -> None:
        assessment = self.different_asset_assessment()
        validator = next(
            item for item in assessment.validator_results if item.task_id == "task.other.op0"
        )
        task = next(
            item for item in assessment.task_transcripts if item.task_id == validator.task_id
        )
        finding = replace(
            self.fixture.finding(assessment),
            affected_asset_id="asset.other",
            validation_result_sha256=validator.result_sha256,
            evidence_digests=task.evidence_digests,
        )
        bundle = self.build(assessment, (finding,))
        self.assertEqual(
            AssessmentReportBundle.from_json(export_report_bundle_json(bundle)), bundle
        )
        sarif = json.loads(export_report_bundle_sarif(bundle))
        self.assertEqual(
            sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
                "uri"
            ],
            "asset:asset.other/op0",
        )

    def test_readdressed_negative_inputs_keep_all_standalone_contracts_valid(self) -> None:
        for label, assessment, correct, relabelled in self.mismatch_vectors():
            with self.subTest(vector=label):
                self.assert_independent_inputs_are_valid(assessment, correct, relabelled)
                good = self.build(assessment, (correct,))
                document = self.coherent_relabelled_document(good, relabelled)
                report = document["report"]
                for raw, parser in (
                    (report["assessment"], AssessmentRecord.from_dict),
                    (report["findings"][0], FindingReport.from_dict),
                    (report["executive_summary"], ExecutiveSummary.from_dict),
                    (document["attestation"], AssessmentAttestation.from_dict),
                ):
                    self.assertEqual(canonical_json(parser(raw).to_dict()), canonical_json(raw))

    def test_original_literal_report_identities_and_effects_remain_unchanged(self) -> None:
        bundle = self.fixture.bundle()
        expected = (
            (
                bundle.report.assessment,
                "assessment_id",
                "assessment_sha256",
                "ASM-0291A4AF2670511F909EB02FB859B6EE",
                "sha256:0291a4af2670511f909eb02fb859b6ee929f5e665ef81294c23c8db65b45e6bf",
            ),
            (
                bundle.report.findings[0],
                "finding_report_id",
                "finding_report_sha256",
                "FRP-BDBFE7509440283365566BEA93C326EA",
                "sha256:bdbfe7509440283365566bea93c326ead8fdaa73072ba06e2e25cbd9240a70b2",
            ),
            (
                bundle.report,
                "report_id",
                "report_sha256",
                "PTR-D99AB1BA242B664D4F50E0AB9DB79106",
                "sha256:d99ab1ba242b664d4f50e0ab9db79106d29efd72dbd5cae3a69d03b49ca79663",
            ),
            (
                bundle.attestation,
                "attestation_id",
                "attestation_sha256",
                "ATT-19839D4D496FABA91641B6C4F5054D28",
                "sha256:19839d4d496faba91641b6c4f5054d2878d5a5bc6c0648505b7186963fbaeff3",
            ),
            (
                bundle,
                "bundle_id",
                "bundle_sha256",
                "ARB-0EC635C1AC1104352F6094E0D7AE3D54",
                "sha256:0ec635c1ac1104352f6094e0d7ae3d5433c84c571e81785d596268ba65cf3b4b",
            ),
        )
        for record, id_field, digest_field, identifier, digest in expected:
            with self.subTest(record=type(record).__name__):
                self.assertEqual(getattr(record, id_field), identifier)
                self.assertEqual(getattr(record, digest_field), digest)
                self.assertEqual(record.to_dict()["effects"], NO_EFFECTS)
        self.assertEqual(export_report_bundle_json(bundle), bundle.to_json())
        self.assertEqual(export_report_bundle_sarif(bundle), bundle.to_sarif_json())

    def test_contextual_finding_evidence_can_still_include_other_assessment_evidence(self) -> None:
        assessment = self.fixture.assessment(("tested", "negative"))
        finding = replace(
            self.fixture.finding(assessment),
            evidence_digests=(phase161.DIGESTS[3], phase161.DIGESTS[4], phase161.DIGESTS[5]),
        )
        bundle = self.build(assessment, (finding,))
        self.assertEqual(
            AssessmentReportBundle.from_json(export_report_bundle_json(bundle)), bundle
        )

    def test_multiple_findings_on_the_same_validator_task_remain_supported(self) -> None:
        assessment = self.fixture.assessment()
        lifecycle = FindingLifecycleReference(
            finding_id="FND-002",
            snapshot_sha256=phase161.DIGESTS[8],
            state="validated",
            updated_at="2026-09-20T03:11:00Z",
        )
        assessment = replace(
            assessment, finding_lifecycle=(*assessment.finding_lifecycle, lifecycle)
        )
        first = self.fixture.finding(assessment)
        second = replace(
            first,
            finding_id=lifecycle.finding_id,
            lifecycle_snapshot_sha256=lifecycle.snapshot_sha256,
            title="Another finding within the same task",
        )
        bundle = self.build(assessment, (first, second))
        self.assertEqual(len(bundle.report.findings), 2)
        self.assertEqual(
            AssessmentReportBundle.from_json(export_report_bundle_json(bundle)), bundle
        )

    def test_assessment_without_findings_keeps_empty_report_supported(self) -> None:
        assessment = replace(self.fixture.assessment(), finding_lifecycle=())
        bundle = self.build(assessment, ())
        self.assertEqual(bundle.report.findings, ())
        self.assertEqual(
            AssessmentReportBundle.from_json(export_report_bundle_json(bundle)), bundle
        )
        self.assertEqual(json.loads(export_report_bundle_sarif(bundle))["runs"][0]["results"], [])

    def test_assessment_constructor_rejects_distinct_pairs_with_one_derived_area(self) -> None:
        assessment, assets = self.collision_inputs()
        with self.assertRaisesRegex(AssessmentReportingError, "coverage area.*ambiguous"):
            replace(assessment, assets=assets)

    def test_assessment_parser_rejects_coherently_readdressed_shared_derived_area(self) -> None:
        document = self.collision_source_document()
        with self.assertRaisesRegex(AssessmentReportingError, "coverage area.*ambiguous"):
            AssessmentRecord.from_dict(document)

    def test_report_parser_rejects_both_primary_findings_for_shared_derived_area(self) -> None:
        for pair, _, document in self.collision_bundle_vectors():
            with (
                self.subTest(affected_pair=pair),
                self.assertRaisesRegex(AssessmentReportingError, "coverage area.*ambiguous"),
            ):
                PentestReport.from_dict(document["report"])

    def test_bundle_parser_rejects_both_primary_findings_for_shared_derived_area(self) -> None:
        for pair, _, document in self.collision_bundle_vectors():
            with (
                self.subTest(affected_pair=pair),
                self.assertRaisesRegex(AssessmentReportingError, "coverage area.*ambiguous"),
            ):
                AssessmentReportBundle.from_dict(document)

    def test_canonical_json_parser_rejects_shared_derived_area_with_valid_addresses(self) -> None:
        for pair, _, document in self.collision_bundle_vectors():
            with (
                self.subTest(affected_pair=pair),
                self.assertRaisesRegex(AssessmentReportingError, "coverage area.*ambiguous"),
            ):
                AssessmentReportBundle.from_json(canonical_json(document))

    def test_checked_json_export_rejects_coherently_mutated_shared_derived_area(self) -> None:
        for pair, good, document in self.collision_bundle_vectors():
            with self.subTest(affected_pair=pair):
                candidate = self.native_collision_for_checked_export(good, document)
                with self.assertRaisesRegex(AssessmentReportingError, "coverage area.*ambiguous"):
                    export_report_bundle_json(candidate)

    def test_checked_sarif_export_rejects_coherently_mutated_shared_derived_area(self) -> None:
        for pair, good, document in self.collision_bundle_vectors():
            with self.subTest(affected_pair=pair):
                candidate = self.native_collision_for_checked_export(good, document)
                with self.assertRaisesRegex(AssessmentReportingError, "coverage area.*ambiguous"):
                    export_report_bundle_sarif(candidate)

    def test_collision_documents_preserve_valid_independent_leaf_sources(self) -> None:
        for pair, _, document in self.collision_bundle_vectors():
            with self.subTest(affected_pair=pair):
                report = document["report"]
                source = report["assessment"]
                for raws, parser in (
                    (source["assets"], AssetRecord.from_dict),
                    (source["task_transcripts"], TaskTranscript.from_dict),
                    (source["validator_results"], ValidatorResultReference.from_dict),
                    (report["findings"], FindingReport.from_dict),
                ):
                    for raw in raws:
                        self.assertEqual(canonical_json(parser(raw).to_dict()), canonical_json(raw))
                for raw, parser in (
                    (report["executive_summary"], ExecutiveSummary.from_dict),
                    (document["attestation"], AssessmentAttestation.from_dict),
                ):
                    self.assertEqual(canonical_json(parser(raw).to_dict()), canonical_json(raw))
                self.assertEqual(len(source["assets"]), 2)
                self.assertEqual(len(source["task_transcripts"]), 1)
                self.assertEqual(source["coverage_metrics"]["total_areas"], 1)
                self.assertEqual(source["completeness"], "complete")

    def test_single_delimiter_bearing_asset_identifier_remains_valid(self) -> None:
        self.assert_valid_delimiter_pairs((("asset.api::namespace", "op0"),))

    def test_single_delimiter_bearing_operation_identifier_remains_valid(self) -> None:
        self.assert_valid_delimiter_pairs((("asset.api", "namespace::op0"),))

    def test_multiple_noncolliding_delimiter_bearing_pairs_remain_valid(self) -> None:
        for pairs in (
            (("asset.api", "namespace::op0"), ("asset.api::namespace", "op1")),
            (("asset.api::alpha", "beta::op0"), ("asset.api::gamma", "beta::op1")),
        ):
            with self.subTest(pairs=pairs):
                self.assert_valid_delimiter_pairs(pairs)

    def test_single_colons_in_asset_and_operation_identifiers_remain_valid(self) -> None:
        self.assert_valid_delimiter_pairs((("asset.api:namespace", "op0:namespace"),))


if __name__ == "__main__":
    unittest.main()
