"""Phase 162 standards qualification matrix tests."""

from __future__ import annotations

import ast
import json
import re
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.standards_qualification_matrix import (
    DIMENSIONS,
    RECOMMENDED_STANDARD_IDS,
    MatrixLimits,
    QualificationScenario,
    StandardControlReference,
    StandardReleasePin,
    StandardsQualificationMatrix,
    StandardsQualificationMatrixError,
    TechniqueQualificationMapping,
    build_standards_qualification_matrix,
)

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "src" / "sunderkey" / "standards_qualification_matrix.py"
SCHEMA = ROOT / "registry" / "schemas" / "standards-qualification-matrix-v1.schema.json"
DOC = ROOT / "docs" / "standards-qualification-matrix.md"
FILES = (MODULE, Path(__file__), SCHEMA, DOC)


def pin(
    standard_id: str = "owasp.asvs",
    *,
    release_id: str = "5.0.0",
    publication_date: str = "2025-05-30",
    reviewed_on: str = "2026-08-01",
    fill: str = "a",
) -> StandardReleasePin:
    return StandardReleasePin(
        standard_id=standard_id,
        release_id=release_id,
        publication_date=publication_date,
        reviewed_on=reviewed_on,
        artifact_sha256="sha256:" + fill * 64,
    )


def scenario() -> QualificationScenario:
    return QualificationScenario(
        scenario_id="scenario.api.authorization-boundary",
        prerequisite_ids=("prerequisite.scope-approved",),
        safe_proof_ids=("proof.read-only-differential",),
        negative_control_ids=("control.authorized-baseline",),
        restoration_ids=("restoration.no-mutation-required",),
        evidence_requirement_ids=("evidence.request-response-pair",),
        validator_ids=("validator.api.authorization-differential",),
    )


def complete_mapping() -> TechniqueQualificationMapping:
    return TechniqueQualificationMapping(
        technique_id="AT3-API-D01-S01-01",
        specialist_profile_ids=("specialist.api.authorization",),
        standard_controls=(StandardControlReference("owasp.asvs", ("V4.2.1",)),),
        prerequisite_ids=("prerequisite.scope-approved",),
        safe_proof_ids=("proof.read-only-differential",),
        negative_control_ids=("control.authorized-baseline",),
        restoration_ids=("restoration.no-mutation-required",),
        evidence_requirement_ids=("evidence.request-response-pair",),
        validator_ids=("validator.api.authorization-differential",),
        scenarios=(scenario(),),
        coverage_status="complete",
        missing_dimensions=(),
    )


def build(**overrides) -> StandardsQualificationMatrix:
    values = {
        "release_id": "standards-matrix.2026.09",
        "as_of_date": "2026-09-20",
        "pins": (pin(),),
        "mappings": (complete_mapping(),),
        "expected_standard_ids": ("owasp.asvs",),
        "expected_technique_ids": ("AT3-API-D01-S01-01",),
        "expected_specialist_profile_ids": ("specialist.api.authorization",),
        "max_review_age_days": 365,
    }
    values.update(overrides)
    return build_standards_qualification_matrix(**values)


class StandardsQualificationMatrixPhase162Tests(unittest.TestCase):
    def test_deterministic_round_trip_and_schema(self) -> None:
        first = build()
        second = build()
        self.assertEqual(first.document_json, second.document_json)
        self.assertEqual(first.matrix_sha256, second.matrix_sha256)
        self.assertEqual(
            StandardsQualificationMatrix.from_json(first.document_json).to_dict(),
            first.to_dict(),
        )
        if Draft202012Validator is not None:
            schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(first.to_dict())

    def test_pin_and_matrix_tampering_fail_closed(self) -> None:
        matrix = build()
        changed = matrix.to_dict()
        changed["pins"][0]["reviewed_on"] = "2026-08-02"
        with self.assertRaisesRegex(StandardsQualificationMatrixError, "hash mismatch"):
            StandardsQualificationMatrix.from_dict(changed)

        changed = matrix.to_dict()
        changed["coverage_metrics"]["complete_technique_count"] = 0
        with self.assertRaisesRegex(StandardsQualificationMatrixError, "content or hash"):
            StandardsQualificationMatrix.from_dict(changed)

    def test_exact_pins_are_required_and_missing_references_fail(self) -> None:
        with self.assertRaisesRegex(StandardsQualificationMatrixError, "exact release"):
            pin(release_id="latest")
        unpinned = TechniqueQualificationMapping(
            technique_id="AT3-CLOUD-D01-S01-01",
            specialist_profile_ids=("specialist.cloud.identity",),
            standard_controls=(StandardControlReference("nist.sp.800-53.assessment", ("CA-8",)),),
            prerequisite_ids=("prerequisite.scope-approved",),
            safe_proof_ids=("proof.configuration-read",),
            negative_control_ids=("control.expected-denial",),
            restoration_ids=("restoration.no-mutation-required",),
            evidence_requirement_ids=("evidence.configuration-snapshot",),
            validator_ids=("validator.cloud.configuration",),
            scenarios=(
                QualificationScenario(
                    "scenario.cloud.configuration",
                    ("prerequisite.scope-approved",),
                    ("proof.configuration-read",),
                    ("control.expected-denial",),
                    ("restoration.no-mutation-required",),
                    ("evidence.configuration-snapshot",),
                    ("validator.cloud.configuration",),
                ),
            ),
            coverage_status="complete",
            missing_dimensions=(),
        )
        with self.assertRaisesRegex(StandardsQualificationMatrixError, "missing standard"):
            build(mappings=(unpinned,))

    def test_duplicate_pins_and_mappings_fail(self) -> None:
        same_pin = pin()
        with self.assertRaisesRegex(StandardsQualificationMatrixError, "duplicate standard"):
            build(pins=(same_pin, same_pin))
        same_mapping = complete_mapping()
        with self.assertRaisesRegex(StandardsQualificationMatrixError, "duplicate technique"):
            build(mappings=(same_mapping, same_mapping))

    def test_incomplete_or_unbound_scenarios_fail(self) -> None:
        with self.assertRaisesRegex(StandardsQualificationMatrixError, "cannot be empty"):
            QualificationScenario(
                scenario_id="scenario.incomplete",
                prerequisite_ids=("prerequisite.scope-approved",),
                safe_proof_ids=("proof.passive",),
                negative_control_ids=("control.baseline",),
                restoration_ids=("restoration.none",),
                evidence_requirement_ids=("evidence.snapshot",),
                validator_ids=(),
            )
        unbound = scenario()
        with self.assertRaisesRegex(StandardsQualificationMatrixError, "undeclared"):
            TechniqueQualificationMapping(
                technique_id="AT3-API-D01-S01-02",
                specialist_profile_ids=("specialist.api.authorization",),
                standard_controls=(StandardControlReference("owasp.asvs", ("V4.2.1",)),),
                prerequisite_ids=("prerequisite.other",),
                safe_proof_ids=unbound.safe_proof_ids,
                negative_control_ids=unbound.negative_control_ids,
                restoration_ids=unbound.restoration_ids,
                evidence_requirement_ids=unbound.evidence_requirement_ids,
                validator_ids=unbound.validator_ids,
                scenarios=(unbound,),
                coverage_status="complete",
                missing_dimensions=(),
            )

    def test_stale_reviews_are_reported_without_changing_the_pin(self) -> None:
        old = pin(reviewed_on="2024-01-01", publication_date="2023-12-01")
        matrix = build(pins=(old,), max_review_age_days=365)
        stale = [gap for gap in matrix.gaps if gap.reason_code == "stale_release_review"]
        self.assertEqual(len(stale), 1)
        self.assertEqual(stale[0].subject_id, "owasp.asvs")
        self.assertEqual(matrix.coverage_metrics.fresh_standard_count, 0)
        self.assertEqual(matrix.pins[0].reviewed_on, "2024-01-01")

    def test_missing_expected_items_become_explicit_gaps(self) -> None:
        matrix = build(
            expected_standard_ids=("owasp.asvs", "owasp.wstg"),
            expected_technique_ids=("AT3-API-D01-S01-01", "AT3-WEB-D02-S01-01"),
            expected_specialist_profile_ids=(
                "specialist.api.authorization",
                "specialist.web.client",
            ),
        )
        gaps = {(gap.gap_type, gap.subject_id, gap.reason_code) for gap in matrix.gaps}
        self.assertIn(("standard", "owasp.wstg", "missing_release_pin"), gaps)
        self.assertIn(("technique", "AT3-WEB-D02-S01-01", "missing_mapping"), gaps)
        self.assertIn(("specialist", "specialist.web.client", "missing_mapping"), gaps)
        serialized = matrix.to_dict()
        self.assertEqual(len(serialized["mappings"]), 1)

    def test_partial_and_gap_coverage_are_not_promoted(self) -> None:
        partial = TechniqueQualificationMapping(
            technique_id="AT3-API-D01-S01-02",
            specialist_profile_ids=("specialist.api.authorization",),
            standard_controls=(StandardControlReference("owasp.asvs", ("V4.2.2",)),),
            prerequisite_ids=("prerequisite.scope-approved",),
            safe_proof_ids=("proof.read-only-differential",),
            coverage_status="partial",
            missing_dimensions=(
                "negative_controls",
                "restoration",
                "evidence",
                "validators",
                "scenarios",
            ),
        )
        explicit_gap = TechniqueQualificationMapping(
            technique_id="AT3-API-D01-S01-03",
            specialist_profile_ids=("specialist.api.authorization",),
        )
        matrix = build(
            mappings=(complete_mapping(), partial, explicit_gap),
            expected_technique_ids=(
                "AT3-API-D01-S01-01",
                "AT3-API-D01-S01-02",
                "AT3-API-D01-S01-03",
            ),
        )
        metrics = matrix.coverage_metrics
        self.assertEqual(metrics.complete_technique_count, 1)
        self.assertEqual(metrics.partial_technique_count, 1)
        self.assertEqual(metrics.gap_technique_count, 1)
        self.assertEqual(metrics.technique_coverage_basis_points, 3333)

    def test_gap_mapping_cannot_contain_invented_content(self) -> None:
        with self.assertRaisesRegex(StandardsQualificationMatrixError, "missing_dimensions"):
            TechniqueQualificationMapping(
                technique_id="AT3-WEB-D01-S01-01",
                specialist_profile_ids=("specialist.web.server",),
                safe_proof_ids=("proof.unverified",),
            )
        self.assertEqual(
            set(DIMENSIONS),
            set(
                TechniqueQualificationMapping(
                    technique_id="AT3-WEB-D01-S01-01",
                    specialist_profile_ids=("specialist.web.server",),
                ).missing_dimensions
            ),
        )

    def test_effects_are_none_and_module_has_no_network_client(self) -> None:
        effects = build().to_dict()["effects"]
        self.assertTrue(effects)
        self.assertEqual(set(effects.values()), {"none"})
        tree = ast.parse(MODULE.read_text(encoding="utf-8"))
        imported_roots = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertTrue(imported_roots.isdisjoint({"httpx", "requests", "socket", "urllib"}))

    def test_limits_and_future_dates_fail_closed(self) -> None:
        with self.assertRaisesRegex(StandardsQualificationMatrixError, "configured limit"):
            build(limits=MatrixLimits(max_pins=1), pins=(pin(), pin("owasp.wstg", fill="b")))
        with self.assertRaisesRegex(StandardsQualificationMatrixError, "follow as_of_date"):
            build(pins=(pin(reviewed_on="2026-10-01"),))

    def test_recommended_domains_cover_the_required_families(self) -> None:
        required = {
            "mitre.attack.enterprise",
            "mitre.attack.mobile",
            "mitre.attack.ics",
            "owasp.asvs",
            "owasp.api-security-top-10",
            "owasp.top-10",
            "owasp.wstg",
            "cwe",
            "capec",
            "nist.sp.800-115",
            "nist.sp.800-53.assessment",
            "ptes",
            "osstmm",
            "crest.penetration-testing-guidance",
            "pci.dss.testing",
            "iec.62443",
            "cloud.aws.security-guidance",
            "cloud.azure.security-guidance",
            "cloud.gcp.security-guidance",
        }
        self.assertTrue(required.issubset(RECOMMENDED_STANDARD_IDS))
        self.assertNotIn("latest", " ".join(RECOMMENDED_STANDARD_IDS).lower())

    def test_created_files_have_no_forbidden_marks(self) -> None:
        forbidden_marker = re.compile(
            "(?i)(" + "chat" + "gpt|gene" + "rated by " + "ai|clau" + "de|co-" + "authored-by)"
        )
        for path in FILES:
            text = path.read_text(encoding="utf-8")
            self.assertNotRegex(text, "[\u2013\u2014]", path.name)
            self.assertIsNone(forbidden_marker.search(text), path.name)


if __name__ == "__main__":
    unittest.main()
