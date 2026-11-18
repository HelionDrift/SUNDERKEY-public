import ast
import json
import unittest
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover
    Draft202012Validator = None

from sunderkey.crypto_pki_specialist_contracts import (
    AdapterDisposition,
    AssessmentBudget,
    AssessmentCheck,
    AssessmentFinding,
    AssessmentOutcome,
    ConfidenceBasis,
    CryptoPKISpecialistContractError,
    EvidenceKind,
    EvidenceProvenance,
    FindingCategory,
    FindingSeverity,
    ReceiptStatus,
    SpecialistAssessmentContext,
    SpecialistAssessmentObservation,
    SpecialistAssessmentReceipt,
    SpecialistAssessmentRequest,
    SpecialistFamily,
    canonical_json,
    canonical_sha256,
    dispatch_specialist_assessment,
    parse_contract,
    recommended_capability_declarations,
)

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "src" / "sunderkey" / "crypto_pki_specialist_contracts.py"
SCHEMA = ROOT / "registry" / "schemas" / "crypto-pki-specialist-contract-v1.schema.json"
DOC = ROOT / "docs" / "crypto-pki-specialist-contracts.md"
FILES = (MODULE, SCHEMA, DOC, Path(__file__))


def digest(label: str) -> str:
    return canonical_sha256({"label": label})


def context(*, context_ref: str = "contextref:primary") -> SpecialistAssessmentContext:
    return SpecialistAssessmentContext(
        tenant_ref="tenantref:example",
        context_ref=context_ref,
        context_binding_sha256=digest("context"),
        scope_ref="scoperef:repository-evidence",
        scope_sha256=digest("scope"),
        authorization_ref="authorizationref:explicit-review",
        authorization_sha256=digest("authorization"),
        action_admission_ref="admissionref:repository-only",
        action_admission_sha256=digest("admission"),
        evidence_plan_ref="evidenceplanref:sanitized-digests",
        evidence_plan_sha256=digest("evidence-plan"),
        cryptographic_policy_ref="policyref:cryptographic-baseline",
        cryptographic_policy_sha256=digest("cryptographic-policy"),
        trust_policy_ref="trustref:approved-roots",
        trust_policy_sha256=digest("trust-policy"),
        authorized_at="2026-09-20T10:00:00Z",
        authorization_expires_at="2026-09-20T11:00:00Z",
        repository_assessment_authorized=True,
        target_interaction_authorized=False,
        budget=AssessmentBudget(
            budget_ref="budgetref:repository-assessment",
            maximum_evidence_items=8,
            maximum_findings=8,
            maximum_observed_bytes=4096,
            maximum_duration_seconds=60,
        ),
    )


def evidence(*, evidence_ref: str = "evidenceref:tls-summary-001") -> EvidenceProvenance:
    return EvidenceProvenance(
        evidence_ref=evidence_ref,
        evidence_kind=EvidenceKind.SANITIZED_TLS_CONFIGURATION,
        content_sha256=digest("sanitized-tls-configuration"),
        source_manifest_sha256=digest("source-manifest"),
        collector_ref="collectorref:approved-import",
        collected_at="2026-09-20T10:01:00Z",
        observed_bytes=512,
        provenance_chain=(digest("custody-1"), digest("custody-2")),
    )


def request(
    *,
    family: SpecialistFamily = SpecialistFamily.TLS_MTLS,
    check: AssessmentCheck = AssessmentCheck.TLS_ENDPOINT_CONFIGURATION,
    selected_context: SpecialistAssessmentContext | None = None,
) -> SpecialistAssessmentRequest:
    declaration = next(
        item for item in recommended_capability_declarations() if item.family is family
    )
    return SpecialistAssessmentRequest(
        declaration_id=declaration.declaration_id,
        declaration_sha256=declaration.declaration_sha256,
        family=family,
        capability_ref=declaration.capability_ref,
        check=check,
        context=selected_context or context(),
        evidence=(evidence(),),
        expected_policy_sha256=digest("expected-policy"),
        estimated_evidence_items=2,
        estimated_findings=2,
        estimated_observed_bytes=1024,
        estimated_duration_seconds=30,
        idempotency_sha256=digest("idempotency"),
        issued_at="2026-09-20T10:00:00Z",
        expires_at="2026-09-20T10:10:00Z",
    )


def finding(*, evidence_ref: str = "evidenceref:tls-summary-001") -> AssessmentFinding:
    return AssessmentFinding(
        category=FindingCategory.HOST_IDENTITY_GAP,
        severity=FindingSeverity.HIGH,
        rule_ref="ruleref:tls-host-identity",
        evidence_refs=(evidence_ref,),
        remediation_ref="remediationref:enforce-host-identity",
        confidence_basis=ConfidenceBasis.DETERMINISTIC_POLICY_MATCH,
    )


def observation(
    selected_request: SpecialistAssessmentRequest,
    *,
    outcome: AssessmentOutcome = AssessmentOutcome.PASS,
    findings: tuple[AssessmentFinding, ...] = (),
) -> SpecialistAssessmentObservation:
    return SpecialistAssessmentObservation(
        request_id=selected_request.request_id,
        request_sha256=selected_request.request_sha256,
        assessment_context_sha256=selected_request.context.assessment_context_sha256,
        evidence_set_sha256=selected_request.evidence_set_sha256,
        disposition=AdapterDisposition.COMPLETED,
        outcome=outcome,
        findings=findings,
        analysis_evidence_sha256=digest("analysis-evidence"),
        actual_evidence_items=1,
        actual_findings=len(findings),
        actual_observed_bytes=512,
        actual_duration_seconds=10,
        network_call_performed=False,
        scanner_execution_performed=False,
        command_execution_performed=False,
        key_generation_performed=False,
        key_access_performed=False,
        secret_access_performed=False,
        credential_handling_performed=False,
        target_interaction_performed=False,
        started_at="2026-09-20T10:02:00Z",
        completed_at="2026-09-20T10:02:10Z",
    )


class RecordingAdapter:
    def __init__(self, selected_observation: SpecialistAssessmentObservation):
        self.selected_observation = selected_observation
        self.calls: list[SpecialistAssessmentRequest] = []

    def assess(self, selected_request: SpecialistAssessmentRequest):
        self.calls.append(selected_request)
        return self.selected_observation


class CryptoPKISpecialistContractsPhase168Tests(unittest.TestCase):
    def test_recommended_declarations_cover_all_families_and_checks(self):
        declarations = recommended_capability_declarations()
        self.assertEqual({item.family for item in declarations}, set(SpecialistFamily))
        covered = {check for item in declarations for check in item.checks}
        self.assertEqual(covered, set(AssessmentCheck))
        self.assertEqual(len(declarations), 8)

    def test_all_wire_records_are_deterministic_and_parseable(self):
        selected_request = request()
        declaration = next(
            item
            for item in recommended_capability_declarations()
            if item.family is SpecialistFamily.TLS_MTLS
        )
        selected_evidence = selected_request.evidence[0]
        selected_observation = observation(
            selected_request,
            outcome=AssessmentOutcome.CONTROL_GAP,
            findings=(finding(),),
        )
        receipt = dispatch_specialist_assessment(
            selected_request,
            declaration,
            selected_request.context,
            RecordingAdapter(selected_observation),
            evaluated_at=datetime(2026, 9, 20, 10, 3, tzinfo=UTC),
        )
        self.assertEqual(request().to_dict(), selected_request.to_dict())
        for record in (
            declaration.to_dict(),
            selected_evidence.to_dict(),
            selected_request.to_dict(),
            receipt.to_dict(),
        ):
            self.assertEqual(parse_contract(record), record)

    def test_context_requires_explicit_repository_only_authorization(self):
        for changes in (
            {"repository_assessment_authorized": False},
            {"target_interaction_authorized": True},
        ):
            with (
                self.subTest(changes=changes),
                self.assertRaises(CryptoPKISpecialistContractError),
            ):
                replace(context(), **changes)

    def test_request_must_stay_inside_authorization_window(self):
        selected_context = replace(
            context(),
            authorized_at="2026-09-20T10:05:00Z",
        )
        with self.assertRaises(CryptoPKISpecialistContractError):
            request(selected_context=selected_context)

    def test_secret_patterns_are_rejected(self):
        with self.assertRaises(CryptoPKISpecialistContractError):
            canonical_json({"value": "client_secret=forbidden-value"})

    def test_evidence_rejects_sensitive_or_active_material(self):
        for field_name in (
            "contains_private_key",
            "contains_secret_value",
            "contains_credential",
            "contains_live_target_capture",
            "includes_executable_material",
        ):
            with (
                self.subTest(field_name=field_name),
                self.assertRaises(CryptoPKISpecialistContractError),
            ):
                replace(evidence(), **{field_name: True})
        with self.assertRaises(CryptoPKISpecialistContractError):
            replace(evidence(), contains_secret_value=0)

    def test_duplicate_evidence_and_evidence_budget_are_rejected(self):
        selected_request = request()
        with self.assertRaises(CryptoPKISpecialistContractError):
            replace(
                selected_request,
                evidence=(selected_request.evidence[0], selected_request.evidence[0]),
            )
        with self.assertRaises(CryptoPKISpecialistContractError):
            replace(selected_request, estimated_observed_bytes=511)

    def test_cross_family_check_is_rejected(self):
        with self.assertRaises(CryptoPKISpecialistContractError):
            request(
                family=SpecialistFamily.CERTIFICATE_LIFECYCLE,
                check=AssessmentCheck.TOKEN_VALIDATION,
            )

    def test_context_declaration_and_replay_fail_before_adapter(self):
        selected_request = request()
        declaration = next(
            item
            for item in recommended_capability_declarations()
            if item.family is SpecialistFamily.TLS_MTLS
        )
        cases = (
            {
                "declaration": recommended_capability_declarations()[0],
                "expected_context": selected_request.context,
            },
            {
                "declaration": declaration,
                "expected_context": context(context_ref="contextref:foreign"),
            },
            {
                "declaration": declaration,
                "expected_context": selected_request.context,
                "seen_request_ids": (selected_request.request_id,),
            },
            {
                "declaration": declaration,
                "expected_context": selected_request.context,
                "seen_idempotency_sha256": (selected_request.idempotency_sha256,),
            },
        )
        for values in cases:
            adapter = RecordingAdapter(observation(selected_request))
            with self.subTest(values=values), self.assertRaises(CryptoPKISpecialistContractError):
                dispatch_specialist_assessment(
                    selected_request,
                    values.pop("declaration"),
                    values.pop("expected_context"),
                    adapter,
                    evaluated_at=datetime(2026, 9, 20, 10, 3, tzinfo=UTC),
                    **values,
                )
            self.assertEqual(adapter.calls, [])

    def test_inactive_request_fails_before_adapter(self):
        selected_request = request()
        declaration = next(
            item
            for item in recommended_capability_declarations()
            if item.family is SpecialistFamily.TLS_MTLS
        )
        adapter = RecordingAdapter(observation(selected_request))
        with self.assertRaises(CryptoPKISpecialistContractError):
            dispatch_specialist_assessment(
                selected_request,
                declaration,
                selected_request.context,
                adapter,
                evaluated_at=datetime(2026, 9, 20, 10, 11, tzinfo=UTC),
            )
        self.assertEqual(adapter.calls, [])

    def test_observation_binding_mismatch_is_rejected(self):
        selected_request = request()
        declaration = next(
            item
            for item in recommended_capability_declarations()
            if item.family is SpecialistFamily.TLS_MTLS
        )
        adapter = RecordingAdapter(
            replace(observation(selected_request), evidence_set_sha256=digest("foreign"))
        )
        with self.assertRaises(CryptoPKISpecialistContractError):
            dispatch_specialist_assessment(
                selected_request,
                declaration,
                selected_request.context,
                adapter,
                evaluated_at=datetime(2026, 9, 20, 10, 3, tzinfo=UTC),
            )
        self.assertEqual(len(adapter.calls), 1)

    def test_receipt_revalidates_internal_bindings(self):
        selected_request = request()
        mismatched = replace(
            observation(selected_request),
            evidence_set_sha256=digest("foreign"),
        )
        with self.assertRaises(CryptoPKISpecialistContractError):
            SpecialistAssessmentReceipt(
                request=selected_request,
                observation=mismatched,
                status=ReceiptStatus.COMPLETED,
            )

    def test_finding_must_cite_request_evidence(self):
        selected_request = request()
        declaration = next(
            item
            for item in recommended_capability_declarations()
            if item.family is SpecialistFamily.TLS_MTLS
        )
        foreign_finding = finding(evidence_ref="evidenceref:foreign")
        selected_observation = observation(
            selected_request,
            outcome=AssessmentOutcome.CONTROL_GAP,
            findings=(foreign_finding,),
        )
        with self.assertRaises(CryptoPKISpecialistContractError):
            dispatch_specialist_assessment(
                selected_request,
                declaration,
                selected_request.context,
                RecordingAdapter(selected_observation),
                evaluated_at=datetime(2026, 9, 20, 10, 3, tzinfo=UTC),
            )

    def test_finding_category_must_match_requested_check(self):
        selected_request = request()
        declaration = next(
            item
            for item in recommended_capability_declarations()
            if item.family is SpecialistFamily.TLS_MTLS
        )
        wrong_category = replace(
            finding(),
            category=FindingCategory.TOKEN_VALIDATION_GAP,
        )
        selected_observation = observation(
            selected_request,
            outcome=AssessmentOutcome.CONTROL_GAP,
            findings=(wrong_category,),
        )
        with self.assertRaises(CryptoPKISpecialistContractError):
            dispatch_specialist_assessment(
                selected_request,
                declaration,
                selected_request.context,
                RecordingAdapter(selected_observation),
                evaluated_at=datetime(2026, 9, 20, 10, 3, tzinfo=UTC),
            )

    def test_adapter_boundary_effects_fail_closed(self):
        selected_request = request()
        for field_name in (
            "network_call_performed",
            "scanner_execution_performed",
            "command_execution_performed",
            "key_generation_performed",
            "key_access_performed",
            "secret_access_performed",
            "credential_handling_performed",
            "target_interaction_performed",
        ):
            with (
                self.subTest(field_name=field_name),
                self.assertRaises(CryptoPKISpecialistContractError),
            ):
                replace(observation(selected_request), **{field_name: True})
        with self.assertRaises(CryptoPKISpecialistContractError):
            replace(observation(selected_request), key_access_performed=0)

    def test_adapter_cannot_exceed_request_or_context_budget(self):
        selected_request = request()
        declaration = next(
            item
            for item in recommended_capability_declarations()
            if item.family is SpecialistFamily.TLS_MTLS
        )
        adapter = RecordingAdapter(
            replace(observation(selected_request), actual_observed_bytes=1025)
        )
        with self.assertRaises(CryptoPKISpecialistContractError):
            dispatch_specialist_assessment(
                selected_request,
                declaration,
                selected_request.context,
                adapter,
                evaluated_at=datetime(2026, 9, 20, 10, 3, tzinfo=UTC),
            )

    def test_outcome_and_disposition_consistency_is_enforced(self):
        selected_request = request()
        with self.assertRaises(CryptoPKISpecialistContractError):
            observation(selected_request, findings=(finding(),))
        with self.assertRaises(CryptoPKISpecialistContractError):
            observation(selected_request, outcome=AssessmentOutcome.CONTROL_GAP)
        with self.assertRaises(CryptoPKISpecialistContractError):
            replace(observation(selected_request), disposition=AdapterDisposition.DENIED)
        with self.assertRaises(CryptoPKISpecialistContractError):
            replace(observation(selected_request), actual_evidence_items=0)

    def test_control_gap_receipt_is_completed_and_nonqualifying(self):
        selected_request = request()
        declaration = next(
            item
            for item in recommended_capability_declarations()
            if item.family is SpecialistFamily.TLS_MTLS
        )
        receipt = dispatch_specialist_assessment(
            selected_request,
            declaration,
            selected_request.context,
            RecordingAdapter(
                observation(
                    selected_request,
                    outcome=AssessmentOutcome.CONTROL_GAP,
                    findings=(finding(),),
                )
            ),
            evaluated_at=datetime(2026, 9, 20, 10, 3, tzinfo=UTC),
        )
        self.assertEqual(receipt.status, ReceiptStatus.COMPLETED)
        self.assertEqual(receipt.to_dict()["qualification_effect"], "none")

    def test_parser_rejects_tampering_and_malformed_records(self):
        record = request().to_dict()
        record["estimated_findings"] = 1
        with self.assertRaises(CryptoPKISpecialistContractError):
            parse_contract(record)
        with self.assertRaises(CryptoPKISpecialistContractError):
            parse_contract({"kind": "crypto_pki_specialist_assessment_request"})
        with self.assertRaises(CryptoPKISpecialistContractError):
            parse_contract({"kind": "unknown"})

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_schema_accepts_all_wire_records_and_rejects_extra_fields(self):
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        selected_request = request()
        declaration = next(
            item
            for item in recommended_capability_declarations()
            if item.family is SpecialistFamily.TLS_MTLS
        )
        receipt = dispatch_specialist_assessment(
            selected_request,
            declaration,
            selected_request.context,
            RecordingAdapter(observation(selected_request)),
            evaluated_at=datetime(2026, 9, 20, 10, 3, tzinfo=UTC),
        )
        for record in (
            declaration.to_dict(),
            selected_request.evidence[0].to_dict(),
            selected_request.to_dict(),
            receipt.to_dict(),
        ):
            errors = list(validator.iter_errors(record))
            self.assertEqual(errors, [], errors)
        altered = selected_request.to_dict()
        altered["unexpected"] = True
        self.assertNotEqual(list(validator.iter_errors(altered)), [])

    def test_module_has_no_active_or_sensitive_imports(self):
        tree = ast.parse(MODULE.read_text(encoding="utf-8"))
        imports = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imports.update(
            node.module.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        )
        self.assertTrue(
            imports.isdisjoint(
                {
                    "requests",
                    "httpx",
                    "urllib",
                    "socket",
                    "subprocess",
                    "ssl",
                    "cryptography",
                    "keyring",
                }
            )
        )

    def test_documentation_covers_required_specialist_surfaces(self):
        content = DOC.read_text(encoding="utf-8").lower()
        for phrase in (
            "cryptographic protocols",
            "pki",
            "tls and mtls",
            "certificate lifecycle",
            "secrets and key management",
            "signing and verification",
            "token and identity protocols",
            "cryptographic misuse",
            "qualification_effect",
        ):
            self.assertIn(phrase, content)

    def test_increment_has_no_forbidden_unicode(self):
        for path in FILES:
            content = path.read_text(encoding="utf-8")
            self.assertNotIn("\u2013", content, path)
            self.assertNotIn("\u2014", content, path)

    def test_public_package_exports_specialist_boundary(self):
        import sunderkey

        self.assertIs(sunderkey.CryptoPkiAssessmentRequest, SpecialistAssessmentRequest)
        self.assertIs(
            sunderkey.dispatch_crypto_pki_specialist_assessment,
            dispatch_specialist_assessment,
        )
        self.assertIs(sunderkey.parse_crypto_pki_specialist_contract, parse_contract)
        self.assertIs(
            sunderkey.crypto_pki_specialist_capabilities,
            recommended_capability_declarations,
        )


if __name__ == "__main__":
    unittest.main()
