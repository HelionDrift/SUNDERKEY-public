"""Declared report/attestation chronology through supported public APIs."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from dataclasses import replace
from typing import Any

from sunderkey.assessment_report_rendering import (
    render_assessment_report_html,
    render_assessment_report_text,
)
from sunderkey.assessment_reporting import (
    NO_EFFECTS,
    AssessmentAttestation,
    AssessmentReportBundle,
    AssessmentReportingError,
    PentestReport,
    build_assessment_report_bundle,
    export_report_bundle_json,
    export_report_bundle_sarif,
)
from tests.agents import test_assessment_reporting_phase161 as fixtures

BEFORE_GENERATION = (
    "2026-09-20T03:20:59Z",
    "2026-09-20T03:20:00Z",
)
VALID_ATTESTATION_TIMES = (
    "2026-09-20T03:21:00Z",
    "2026-09-20T03:21:01Z",
    "2026-09-20T03:22:00Z",
)
CHRONOLOGY_ERROR = "attestation predates report generation"
GOLDENS = (
    (
        "ASM-0291A4AF2670511F909EB02FB859B6EE",
        "sha256:0291a4af2670511f909eb02fb859b6ee929f5e665ef81294c23c8db65b45e6bf",
    ),
    (
        "FRP-BDBFE7509440283365566BEA93C326EA",
        "sha256:bdbfe7509440283365566bea93c326ead8fdaa73072ba06e2e25cbd9240a70b2",
    ),
    (
        "PTR-D99AB1BA242B664D4F50E0AB9DB79106",
        "sha256:d99ab1ba242b664d4f50e0ab9db79106d29efd72dbd5cae3a69d03b49ca79663",
    ),
    (
        "ATT-19839D4D496FABA91641B6C4F5054D28",
        "sha256:19839d4d496faba91641b6c4f5054d2878d5a5bc6c0648505b7186963fbaeff3",
    ),
    (
        "ARB-0EC635C1AC1104352F6094E0D7AE3D54",
        "sha256:0ec635c1ac1104352f6094e0d7ae3d5433c84c571e81785d596268ba65cf3b4b",
    ),
)


def _canonical(document: Any) -> str:
    return json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def _address(
    document: dict[str, Any], *, prefix: str, id_field: str, sha_field: str
) -> tuple[str, str]:
    excluded = {"effects", "kind", "schema_version", id_field, sha_field}
    body = {key: value for key, value in document.items() if key not in excluded}
    seed = {"content": body, "domain": document["kind"]}
    digest = hashlib.sha256(_canonical(seed).encode("ascii")).hexdigest()
    return prefix + "-" + digest[:32].upper(), "sha256:" + digest


def _readdress(document: dict[str, Any], *, prefix: str, id_field: str, sha_field: str) -> None:
    document[id_field], document[sha_field] = _address(
        document, prefix=prefix, id_field=id_field, sha_field=sha_field
    )


class ReportAttestationChronologyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = fixtures.AssessmentReportingPhase161Tests()
        self.valid = self.fixture.bundle()
        self.original_json = self.valid.to_json()

    def tearDown(self) -> None:
        self.assertEqual(self.valid.to_json(), self.original_json)

    def _attestation(self, at: str) -> AssessmentAttestation:
        # An attestation alone does not contain the report's generation time.
        return replace(self.valid.attestation, attested_at=at)

    def _document(self, at: str) -> dict[str, Any]:
        document = copy.deepcopy(self.valid.to_dict())
        attestation = document["attestation"]
        attestation["attested_at"] = at
        _readdress(
            attestation,
            prefix="ATT",
            id_field="attestation_id",
            sha_field="attestation_sha256",
        )
        _readdress(
            document,
            prefix="ARB",
            id_field="bundle_id",
            sha_field="bundle_sha256",
        )
        # Independent addresses agree with supported standalone constructors.
        self.assertEqual(attestation, self._attestation(at).to_dict())
        self.assertEqual(AssessmentAttestation.from_dict(attestation).to_dict(), attestation)
        self.assertEqual(
            PentestReport.from_dict(document["report"]).to_dict(),
            self.valid.report.to_dict(),
        )
        return document

    def _build(self, at: str) -> AssessmentReportBundle:
        report = self.valid.report
        return build_assessment_report_bundle(
            report.assessment,
            report.findings,
            report_reviewers=report.reviewer_roles,
            attestation_reviewers=self.valid.attestation.reviewer_roles,
            attested_at=at,
        )

    def test_original_five_literal_identities_and_digests_are_preserved(self) -> None:
        report = self.valid.report
        actual = (
            (report.assessment.assessment_id, report.assessment.assessment_sha256),
            (
                report.findings[0].finding_report_id,
                report.findings[0].finding_report_sha256,
            ),
            (report.report_id, report.report_sha256),
            (
                self.valid.attestation.attestation_id,
                self.valid.attestation.attestation_sha256,
            ),
            (self.valid.bundle_id, self.valid.bundle_sha256),
        )
        self.assertEqual(actual, GOLDENS)

    def test_original_bundle_round_trips_and_checked_views_are_unchanged(self) -> None:
        self.assertEqual(AssessmentReportBundle.from_dict(self.valid.to_dict()), self.valid)
        self.assertEqual(AssessmentReportBundle.from_json(self.original_json), self.valid)
        self.assertEqual(export_report_bundle_json(self.valid), self.original_json)
        self.assertEqual(export_report_bundle_sarif(self.valid), self.valid.to_sarif_json())
        self.assertIn(self.valid.bundle_id, render_assessment_report_html(self.valid))
        self.assertIn(self.valid.bundle_id, render_assessment_report_text(self.valid))

    def test_original_schema_domains_and_effects_are_preserved(self) -> None:
        document = self.valid.to_dict()
        members = (
            (document["report"]["assessment"], "sunderkey.assessment-record.v1"),
            (document["report"]["findings"][0], "sunderkey.finding-report.v1"),
            (document["report"], "sunderkey.pentest-report.v1"),
            (document["attestation"], "sunderkey.assessment-attestation.v1"),
            (document, "sunderkey.assessment-report-bundle.v1"),
        )
        for member, kind in members:
            with self.subTest(kind=kind):
                self.assertIs(type(member["schema_version"]), int)
                self.assertEqual(member["schema_version"], 1)
                self.assertEqual(member["kind"], kind)
                self.assertEqual(member["effects"], NO_EFFECTS)
                self.assertEqual(set(member["effects"].values()), {"none"})
        self.assertEqual(document["attestation"]["compliance_claim"], "not_assessed")
        self.assertEqual(
            document["attestation"]["conclusion"],
            "evidence_only_no_compliance_determination",
        )

    def test_standalone_attestation_historical_inspection_needs_no_report(self) -> None:
        for at in BEFORE_GENERATION:
            with self.subTest(at=at):
                attestation = self._attestation(at)
                document = attestation.to_dict()
                self.assertEqual(AssessmentAttestation.from_dict(document), attestation)
                self.assertEqual(
                    AssessmentAttestation.from_dict(json.loads(_canonical(document))),
                    attestation,
                )

    def test_builder_already_rejects_attestation_before_generation(self) -> None:
        for at in BEFORE_GENERATION:
            with self.subTest(at=at):
                with self.assertRaisesRegex(AssessmentReportingError, CHRONOLOGY_ERROR):
                    self._build(at)

    def test_generation_equality_and_later_times_preserve_builder_identity(self) -> None:
        for at in VALID_ATTESTATION_TIMES:
            with self.subTest(at=at):
                direct = AssessmentReportBundle(self.valid.report, self._attestation(at))
                self.assertEqual(self._build(at), direct)
                self.assertEqual(direct.to_dict(), self._document(at))
                self.assertEqual(direct.report.to_dict(), self.valid.report.to_dict())

    def test_generation_equality_and_later_times_allow_all_public_views(self) -> None:
        for at in VALID_ATTESTATION_TIMES:
            with self.subTest(at=at):
                document = self._document(at)
                payload = _canonical(document)
                bundle = AssessmentReportBundle.from_json(payload)
                self.assertEqual(AssessmentReportBundle.from_dict(document), bundle)
                self.assertEqual(export_report_bundle_json(bundle), payload)
                self.assertEqual(export_report_bundle_sarif(bundle), bundle.to_sarif_json())
                self.assertIn(at, render_assessment_report_html(bundle))
                self.assertIn(at, render_assessment_report_text(bundle))

    def test_old_time_documents_are_truthfully_readdressed_without_other_changes(
        self,
    ) -> None:
        original = self.valid.to_dict()
        for at in BEFORE_GENERATION:
            with self.subTest(at=at):
                document = self._document(at)
                self.assertEqual(document["report"], original["report"])
                restored = copy.deepcopy(document)
                for key in ("attested_at", "attestation_id", "attestation_sha256"):
                    restored["attestation"][key] = original["attestation"][key]
                for key in ("bundle_id", "bundle_sha256"):
                    restored[key] = original[key]
                self.assertEqual(restored, original)

    def test_direct_bundle_constructor_rejects_attestation_before_generation(self) -> None:
        for at in BEFORE_GENERATION:
            attestation = self._attestation(at)
            with self.subTest(at=at):
                with self.assertRaisesRegex(AssessmentReportingError, CHRONOLOGY_ERROR):
                    AssessmentReportBundle(self.valid.report, attestation)

    def test_from_dict_rejects_truthfully_readdressed_old_attestation(self) -> None:
        for at in BEFORE_GENERATION:
            document = self._document(at)
            original = copy.deepcopy(document)
            with self.subTest(at=at):
                with self.assertRaisesRegex(AssessmentReportingError, CHRONOLOGY_ERROR):
                    AssessmentReportBundle.from_dict(document)
                self.assertEqual(document, original)

    def test_canonical_from_json_rejects_truthfully_readdressed_old_attestation(
        self,
    ) -> None:
        for at in BEFORE_GENERATION:
            payload = _canonical(self._document(at))
            with self.subTest(at=at):
                with self.assertRaisesRegex(AssessmentReportingError, CHRONOLOGY_ERROR):
                    AssessmentReportBundle.from_json(payload)

    # These pipelines reach the real consumer on RED. On GREEN the supported
    # public parser rejects first, without fabricating a native invalid bundle.
    def test_public_parser_to_checked_json_export_rejects_old_attestation(self) -> None:
        for at in BEFORE_GENERATION:
            payload = _canonical(self._document(at))
            with self.subTest(at=at):
                with self.assertRaisesRegex(AssessmentReportingError, CHRONOLOGY_ERROR):
                    export_report_bundle_json(AssessmentReportBundle.from_json(payload))

    def test_public_parser_to_checked_sarif_export_rejects_old_attestation(self) -> None:
        for at in BEFORE_GENERATION:
            payload = _canonical(self._document(at))
            with self.subTest(at=at):
                with self.assertRaisesRegex(AssessmentReportingError, CHRONOLOGY_ERROR):
                    export_report_bundle_sarif(AssessmentReportBundle.from_json(payload))

    def test_public_parser_to_html_renderer_rejects_old_attestation(self) -> None:
        for at in BEFORE_GENERATION:
            payload = _canonical(self._document(at))
            with self.subTest(at=at):
                with self.assertRaisesRegex(AssessmentReportingError, CHRONOLOGY_ERROR):
                    render_assessment_report_html(AssessmentReportBundle.from_json(payload))

    def test_public_parser_to_text_renderer_rejects_old_attestation(self) -> None:
        for at in BEFORE_GENERATION:
            payload = _canonical(self._document(at))
            with self.subTest(at=at):
                with self.assertRaisesRegex(AssessmentReportingError, CHRONOLOGY_ERROR):
                    render_assessment_report_text(AssessmentReportBundle.from_json(payload))


if __name__ == "__main__":
    unittest.main()
