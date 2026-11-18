"""Phase 172 deterministic attack coverage matrix tests."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

import sunderkey
from sunderkey.attack_coverage_matrix import (
    MATRIX_DOMAIN,
    NO_CLAIMS,
    NO_EFFECTS,
    AttackCoverageMatrix,
    AttackCoverageMatrixError,
    AttackDomain,
    BlockedReason,
    CoverageMapping,
    CoverageStatus,
    EvidenceGrade,
    SpecialistCapabilityReference,
    TechniqueReference,
    build_attack_coverage_matrix,
    build_default_attack_coverage_matrix,
    canonical_json,
    canonical_sha256,
    verify_attack_coverage_matrix,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "registry" / "schemas" / "attack-coverage-matrix-v1.schema.json"


def _sha(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("ascii")).hexdigest()


def _technique(suffix: str = "web", **changes: object) -> TechniqueReference:
    values: dict[str, object] = {
        "tenant_ref": "tenantref:acme",
        "context_ref": "contextref:assessment-172",
        "scope_sha256": _sha("scope"),
        "catalog_ref": "catalogref:governed-vectors",
        "catalog_version": "1.2.0",
        "technique_ref": f"techniqueref:{suffix}",
        "technique_version": "2.1.0",
        "domain": AttackDomain.WEB,
        "asset_types": ("assettype:web-application",),
    }
    values.update(changes)
    return TechniqueReference(**values)  # type: ignore[arg-type]


def _specialist(suffix: str = "web", **changes: object) -> SpecialistCapabilityReference:
    values: dict[str, object] = {
        "tenant_ref": "tenantref:acme",
        "context_ref": "contextref:assessment-172",
        "scope_sha256": _sha("scope"),
        "specialist_ref": f"specialistref:{suffix}",
        "specialist_version": "2.0.0",
        "capability_ref": f"capabilityref:{suffix}",
        "capability_version": "1.0.0",
        "domains": (AttackDomain.WEB,),
        "evidence_grade": EvidenceGrade.OFFLINE_DETERMINISTIC,
        "evidence_sha256": _sha(f"evidence-{suffix}"),
    }
    values.update(changes)
    return SpecialistCapabilityReference(**values)  # type: ignore[arg-type]


def _matrix(
    technique: TechniqueReference | None = None,
    specialist: SpecialistCapabilityReference | None = None,
    **mapping_changes: object,
) -> AttackCoverageMatrix:
    technique = technique or _technique()
    specialist = specialist or _specialist()
    values: dict[str, object] = {
        "mapping_key": "mapping:web",
        "technique_reference_id": technique.reference_id,
        "specialist_reference_ids": (specialist.reference_id,),
        "status": CoverageStatus.REPOSITORY_COVERED,
        "prerequisite_refs": ("prerequisite:explicit-scope",),
        "negative_space_gaps": (),
        "blocked_reasons": (),
    }
    values.update(mapping_changes)
    mapping = CoverageMapping(**values)  # type: ignore[arg-type]
    return build_attack_coverage_matrix(
        technique_references=(technique,),
        specialist_references=(specialist,),
        mappings=(mapping,),
    )


class AttackCoverageMatrixPhase172Tests(unittest.TestCase):
    def test_public_exports_keep_identity(self) -> None:
        self.assertIs(sunderkey.AttackCoverageMatrix, AttackCoverageMatrix)
        self.assertIs(sunderkey.AttackCoverageMatrixError, AttackCoverageMatrixError)
        self.assertIs(sunderkey.AttackDomain, AttackDomain)
        self.assertIs(sunderkey.build_attack_coverage_matrix, build_attack_coverage_matrix)
        self.assertIs(sunderkey.verify_attack_coverage_matrix, verify_attack_coverage_matrix)

    def test_default_matrix_maps_every_required_domain_without_live_claims(self) -> None:
        matrix = build_default_attack_coverage_matrix(
            tenant_ref="tenantref:acme",
            context_ref="contextref:assessment-172",
            scope_sha256=_sha("scope"),
        )
        expected = {item.value for item in AttackDomain}
        self.assertEqual({row.domain.value for row in matrix.rows}, expected)
        self.assertEqual(len(matrix.rows), 20)
        self.assertEqual(matrix.summary["domain_counts"], {key: 1 for key in sorted(expected)})
        self.assertEqual(matrix.summary["technique_reference_count"], 20)
        self.assertEqual(matrix.summary["specialist_reference_count"], 20)
        self.assertGreater(matrix.summary["negative_space_gap_count"], 0)
        self.assertEqual(matrix.to_dict()["claims"], dict(NO_CLAIMS))
        self.assertEqual(matrix.to_dict()["effects"], dict(NO_EFFECTS))
        self.assertNotIn("live_validated", matrix.summary["evidence_grade_counts"])

    def test_explicit_asset_type_mapping_is_complete(self) -> None:
        matrix = build_default_attack_coverage_matrix(
            tenant_ref="tenantref:acme",
            context_ref="contextref:assessment-172",
            scope_sha256=_sha("scope"),
        )
        rows = {row.domain: row for row in matrix.rows}
        self.assertEqual(
            rows[AttackDomain.API].asset_types, ("assettype:graphql-api", "assettype:http-api")
        )
        self.assertEqual(
            rows[AttackDomain.HARDWARE_FIRMWARE].asset_types,
            ("assettype:firmware-image", "assettype:hardware-device"),
        )
        self.assertEqual(
            rows[AttackDomain.CRYPTOGRAPHIC_PKI].asset_types,
            ("assettype:cryptographic-protocol", "assettype:pki-service"),
        )

    def test_matrix_is_deterministic_under_input_reordering(self) -> None:
        first = build_default_attack_coverage_matrix(
            tenant_ref="tenantref:acme",
            context_ref="contextref:assessment-172",
            scope_sha256=_sha("scope"),
        )
        techniques = tuple(row.technique_reference for row in first.rows)
        specialists = tuple(item for row in first.rows for item in row.specialist_references)
        mappings = tuple(
            CoverageMapping(
                row.mapping_key,
                row.technique_reference.reference_id,
                tuple(item.reference_id for item in row.specialist_references),
                row.status,
                row.prerequisite_refs,
                row.negative_space_gaps,
                row.blocked_reasons,
            )
            for row in first.rows
        )
        reverse = build_attack_coverage_matrix(
            technique_references=tuple(reversed(techniques)),
            specialist_references=tuple(reversed(specialists)),
            mappings=tuple(reversed(mappings)),
        )
        self.assertEqual(first.document_json, reverse.document_json)

    def test_round_trip_is_strict_canonical_and_schema_valid(self) -> None:
        matrix = _matrix()
        parsed = AttackCoverageMatrix.from_json(matrix.document_json)
        self.assertEqual(matrix, parsed)
        self.assertEqual(matrix, verify_attack_coverage_matrix(matrix.to_dict()))
        self.assertEqual(matrix.document_json.encode("ascii").decode("ascii"), matrix.document_json)
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(matrix.to_dict())
        pretty = json.dumps(matrix.to_dict(), indent=2, sort_keys=True)
        with self.assertRaisesRegex(AttackCoverageMatrixError, "not canonical"):
            AttackCoverageMatrix.from_json(pretty)

    def test_nested_and_outer_content_address_tampering_is_rejected(self) -> None:
        original = _matrix().to_dict()
        nested = copy.deepcopy(original)
        nested["rows"][0]["prerequisite_refs"] = [
            "prerequisite:explicit-scope",
            "prerequisite:altered",
        ]
        self._readdress_matrix(nested)
        with self.assertRaisesRegex(AttackCoverageMatrixError, "coverage row content address"):
            AttackCoverageMatrix.from_dict(nested)

        outer = copy.deepcopy(original)
        outer["summary"]["row_count"] = 2
        with self.assertRaisesRegex(AttackCoverageMatrixError, "derived values"):
            AttackCoverageMatrix.from_dict(outer)

    def test_duplicate_keys_and_references_fail_closed(self) -> None:
        technique = _technique()
        specialist = _specialist()
        mapping = CoverageMapping(
            "mapping:web",
            technique.reference_id,
            (specialist.reference_id,),
            CoverageStatus.REPOSITORY_COVERED,
            (),
            (),
            (),
        )
        cases = (
            ((technique, technique), (specialist,), (mapping,), "duplicate technique"),
            ((technique,), (specialist, specialist), (mapping,), "duplicate specialist"),
            ((technique,), (specialist,), (mapping, mapping), "duplicate mapping key"),
        )
        for techniques, specialists, mappings, message in cases:
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(AttackCoverageMatrixError, message),
            ):
                build_attack_coverage_matrix(
                    technique_references=techniques,
                    specialist_references=specialists,
                    mappings=mappings,
                )

    def test_duplicate_nested_values_fail_closed(self) -> None:
        with self.assertRaisesRegex(AttackCoverageMatrixError, "asset_types contains duplicates"):
            _technique(asset_types=("assettype:web", "assettype:web"))
        with self.assertRaisesRegex(
            AttackCoverageMatrixError, "domains must be nonempty and unique"
        ):
            _specialist(domains=(AttackDomain.WEB, AttackDomain.WEB))
        with self.assertRaisesRegex(
            AttackCoverageMatrixError, "blocked_reasons contains duplicates"
        ):
            CoverageMapping(
                "mapping:web",
                _technique().reference_id,
                (),
                CoverageStatus.GAP,
                (),
                ("No mapped specialist.",),
                (BlockedReason.CAPABILITY_MISSING, BlockedReason.CAPABILITY_MISSING),
            )

    def test_cross_tenant_context_and_scope_references_fail_closed(self) -> None:
        technique = _technique()
        changes = (
            {"tenant_ref": "tenantref:other"},
            {"context_ref": "contextref:other"},
            {"scope_sha256": _sha("other-scope")},
        )
        for change in changes:
            specialist = _specialist(**change)
            with (
                self.subTest(change=change),
                self.assertRaisesRegex(
                    AttackCoverageMatrixError, "cross tenant, context, or scope"
                ),
            ):
                _matrix(technique, specialist)

    def test_unknown_domain_status_grade_and_reason_fail_closed(self) -> None:
        with self.assertRaisesRegex(AttackCoverageMatrixError, "domain is unknown"):
            _technique(domain="quantum")
        with self.assertRaisesRegex(AttackCoverageMatrixError, "evidence_grade is unknown"):
            _specialist(evidence_grade="live_validated")
        with self.assertRaisesRegex(AttackCoverageMatrixError, "status is unknown"):
            _matrix(status="ready")
        with self.assertRaisesRegex(AttackCoverageMatrixError, "blocked_reasons is unknown"):
            _matrix(
                status=CoverageStatus.BLOCKED,
                negative_space_gaps=("Infrastructure remains unavailable.",),
                blocked_reasons=("unknown_reason",),
            )

    def test_moving_versions_are_rejected(self) -> None:
        for field in ("catalog_version", "technique_version"):
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(AttackCoverageMatrixError, "exact version"),
            ):
                _technique(**{field: "latest"})
        for field in ("specialist_version", "capability_version"):
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(AttackCoverageMatrixError, "exact version"),
            ):
                _specialist(**{field: "main"})

    def test_malformed_digests_and_content_ids_are_rejected(self) -> None:
        with self.assertRaisesRegex(AttackCoverageMatrixError, "sha256 digest"):
            _technique(scope_sha256="sha256:bad")
        with self.assertRaisesRegex(AttackCoverageMatrixError, "sha256 digest"):
            _specialist(evidence_sha256="sha256:bad")
        with self.assertRaisesRegex(AttackCoverageMatrixError, "technique_reference_id is invalid"):
            CoverageMapping(
                "mapping:web",
                "ATR-bad",
                (),
                CoverageStatus.GAP,
                (),
                ("Gap.",),
                (BlockedReason.CAPABILITY_MISSING,),
            )

    def test_secret_like_and_executable_payload_material_is_rejected(self) -> None:
        for value in (
            "password=correct-horse-battery-staple",
            "Bearer abcdefghijklmnop",
            "curl https://example.invalid/tool",
            "safe; rm -rf /tmp/example",
            "<script>alert(1)</script>",
        ):
            with self.subTest(value=value), self.assertRaises(AttackCoverageMatrixError):
                CoverageMapping(
                    "mapping:web",
                    _technique().reference_id,
                    (),
                    CoverageStatus.GAP,
                    (),
                    (value,),
                    (BlockedReason.CAPABILITY_MISSING,),
                )
        with self.assertRaisesRegex(AttackCoverageMatrixError, "secret-like"):
            canonical_json({"note": "api_key=abcdefghijk"})

    def test_status_invariants_reject_overclaims_and_incomplete_gaps(self) -> None:
        technique = _technique()
        catalog_specialist = _specialist(
            evidence_grade=EvidenceGrade.CATALOG_ONLY,
            evidence_sha256=_sha("catalog"),
        )
        with self.assertRaisesRegex(AttackCoverageMatrixError, "lacks repository evidence"):
            _matrix(technique, catalog_specialist)
        with self.assertRaisesRegex(AttackCoverageMatrixError, "repository covered mapping"):
            _matrix(negative_space_gaps=("Unresolved gap.",))
        with self.assertRaisesRegex(AttackCoverageMatrixError, "gap mapping"):
            _matrix(status=CoverageStatus.GAP, specialist_reference_ids=())
        with self.assertRaisesRegex(AttackCoverageMatrixError, "blocked mapping"):
            _matrix(status=CoverageStatus.BLOCKED, negative_space_gaps=("Blocked.",))

    def test_grade_none_requires_absent_evidence_and_other_grades_require_digest(self) -> None:
        with self.assertRaisesRegex(AttackCoverageMatrixError, "cannot bind evidence"):
            _specialist(evidence_grade=EvidenceGrade.NONE)
        with self.assertRaisesRegex(AttackCoverageMatrixError, "requires evidence digest"):
            _specialist(evidence_grade=EvidenceGrade.REPOSITORY_CONTRACT, evidence_sha256=None)

    def test_specialist_must_cover_mapped_domain(self) -> None:
        specialist = _specialist(domains=(AttackDomain.API,))
        with self.assertRaisesRegex(AttackCoverageMatrixError, "does not cover"):
            _matrix(specialist=specialist)

    def test_unknown_and_unused_references_are_rejected(self) -> None:
        technique = _technique()
        specialist = _specialist()
        unused = _specialist("unused")
        mapping = CoverageMapping(
            "mapping:web",
            technique.reference_id,
            (specialist.reference_id,),
            CoverageStatus.REPOSITORY_COVERED,
            (),
            (),
            (),
        )
        with self.assertRaisesRegex(
            AttackCoverageMatrixError, "specialist references and mappings differ"
        ):
            build_attack_coverage_matrix(
                technique_references=(technique,),
                specialist_references=(specialist, unused),
                mappings=(mapping,),
            )

    def test_exact_field_parser_rejects_extensions(self) -> None:
        document = _matrix().to_dict()
        document["unexpected"] = True
        with self.assertRaisesRegex(AttackCoverageMatrixError, "fields do not match"):
            AttackCoverageMatrix.from_dict(document)
        row_document = _matrix().to_dict()
        row_document["rows"][0]["unexpected"] = True
        with self.assertRaisesRegex(AttackCoverageMatrixError, "fields do not match"):
            AttackCoverageMatrix.from_dict(row_document)

    def test_duplicate_json_object_keys_are_rejected(self) -> None:
        duplicate = '{"schema_version":1,"schema_version":1}'
        with self.assertRaisesRegex(AttackCoverageMatrixError, "duplicate JSON object key"):
            AttackCoverageMatrix.from_json(duplicate)

    @staticmethod
    def _readdress_matrix(document: dict[str, object]) -> None:
        unsigned = copy.deepcopy(document)
        unsigned.pop("matrix_id", None)
        unsigned.pop("matrix_sha256", None)
        digest = canonical_sha256({"content": unsigned, "domain": MATRIX_DOMAIN})
        document["matrix_sha256"] = digest
        document["matrix_id"] = f"ACM-{digest[7:39].upper()}"


if __name__ == "__main__":
    unittest.main()
