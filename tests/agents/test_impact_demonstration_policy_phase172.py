from __future__ import annotations

import copy
import json
import unittest
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

try:
    from jsonschema import Draft202012Validator, ValidationError
except ImportError:  # pragma: no cover
    Draft202012Validator = None
    ValidationError = None

import sunderkey
from sunderkey.impact_demonstration_policy import (
    ALWAYS_PROHIBITED,
    NO_EFFECTS,
    ArtifactClass,
    DemonstrationBinding,
    DemonstrationMode,
    ImpactDemonstrationPlan,
    ImpactDemonstrationPolicyError,
    ImpactDemonstrationReceipt,
    ImpactDemonstrationRequest,
    IndependentReview,
    OperatorApproval,
    PlanStatus,
    ProofCategory,
    ProofIntent,
    StepDisposition,
    build_impact_demonstration_plan,
    build_impact_demonstration_receipt,
    canonical_json,
    canonical_sha256,
    parse_impact_demonstration_plan,
    parse_impact_demonstration_receipt,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "registry" / "schemas" / "impact-demonstration-plan-v1.schema.json"
HASHES = tuple("sha256:" + f"{value:064x}" for value in range(1, 40))
NOW = datetime(2026, 9, 20, 12, 30, tzinfo=UTC)


def _binding(**changes: object) -> DemonstrationBinding:
    values: dict[str, object] = {
        "tenant_ref": "tenantref:acme",
        "context_ref": "contextref:assessment-172",
        "scope_ref": "scoperef:approved-web",
        "scope_sha256": HASHES[0],
        "target_ref": "targetref:service-a",
        "target_sha256": HASHES[1],
        "session_ref": "sessionref:window-172",
        "session_sha256": HASHES[2],
        "policy_ref": "policyref:impact-v1",
        "policy_sha256": HASHES[3],
        "protected_target": False,
        "production_data_present": False,
    }
    values.update(changes)
    return DemonstrationBinding(**values)


def _intent(
    category: ProofCategory,
    *,
    number: int,
    byte_limit: int = 1024,
    artifact_class: ArtifactClass = ArtifactClass.STATE_DELTA,
) -> ProofIntent:
    suffix = category.value.replace("_", "-")
    return ProofIntent(
        category=category,
        evidence_ref=f"evidenceref:{suffix}",
        evidence_sha256=HASHES[number],
        reversible_proof_ref=f"reversalref:{suffix}",
        reversible_proof_sha256=HASHES[number + 1],
        cleanup_plan_ref=f"cleanupref:{suffix}",
        cleanup_plan_sha256=HASHES[number + 2],
        artifact_class=artifact_class,
        artifact_byte_limit=byte_limit,
    )


def _approval(
    binding: DemonstrationBinding,
    mode: DemonstrationMode,
    categories: tuple[ProofCategory, ...],
    **changes: object,
) -> OperatorApproval:
    values: dict[str, object] = {
        "approval_ref": "approvalref:operator-impact-172",
        "approval_sha256": HASHES[20],
        "operator_ref": "principalref:operator-one",
        "binding_sha256": binding.binding_sha256,
        "approved_mode": mode,
        "approved_categories": categories,
        "issued_at": "2026-09-20T12:00:00Z",
        "expires_at": "2026-09-20T13:00:00Z",
    }
    values.update(changes)
    return OperatorApproval(**values)


def _review(
    binding: DemonstrationBinding,
    approval: OperatorApproval,
    categories: tuple[ProofCategory, ...],
    **changes: object,
) -> IndependentReview:
    values: dict[str, object] = {
        "review_ref": "reviewref:independent-impact-172",
        "review_sha256": HASHES[21],
        "reviewer_ref": "principalref:reviewer-two",
        "binding_sha256": binding.binding_sha256,
        "approval_sha256": approval.approval_sha256,
        "reviewed_mode": DemonstrationMode.DEEP,
        "reviewed_categories": categories,
        "decision": "accepted",
        "issued_at": "2026-09-20T12:05:00Z",
        "expires_at": "2026-09-20T12:55:00Z",
    }
    values.update(changes)
    return IndependentReview(**values)


def _request(
    mode: DemonstrationMode = DemonstrationMode.MODERATE,
    categories: tuple[ProofCategory, ...] = (
        ProofCategory.CAPTURED_CREDENTIAL,
        ProofCategory.ROLE_CHANGE,
    ),
    **changes: object,
) -> ImpactDemonstrationRequest:
    binding = changes.pop("binding", _binding())
    intents = tuple(
        _intent(category, number=4 + index * 3, byte_limit=1024)
        for index, category in enumerate(categories)
    )
    approval = None if mode is DemonstrationMode.OFF else _approval(binding, mode, categories)
    review = (
        _review(binding, approval, categories)
        if mode is DemonstrationMode.DEEP and approval is not None
        else None
    )
    values: dict[str, object] = {
        "binding": binding,
        "mode": mode,
        "intents": intents,
        "operator_approval": approval,
        "independent_review": review,
        "created_at": "2026-09-20T12:00:00Z",
        "expires_at": "2026-09-20T13:00:00Z",
    }
    values.update(changes)
    return ImpactDemonstrationRequest(**values)


class ImpactDemonstrationPolicyTests(unittest.TestCase):
    def test_public_exports_keep_identity(self) -> None:
        self.assertIs(sunderkey.DemonstrationMode, DemonstrationMode)
        self.assertIs(sunderkey.ImpactDemonstrationPlan, ImpactDemonstrationPlan)
        self.assertIs(sunderkey.ImpactDemonstrationRequest, ImpactDemonstrationRequest)
        self.assertIs(
            sunderkey.build_impact_demonstration_plan,
            build_impact_demonstration_plan,
        )
        self.assertIs(
            sunderkey.parse_impact_demonstration_receipt,
            parse_impact_demonstration_receipt,
        )

    def test_moderate_plan_is_deterministic_content_addressed_and_effect_free(self) -> None:
        first = build_impact_demonstration_plan(_request(), evaluated_at=NOW)
        second = build_impact_demonstration_plan(_request(), evaluated_at=NOW)
        self.assertEqual(first.plan_id, second.plan_id)
        self.assertEqual(first.plan_sha256, second.plan_sha256)
        self.assertEqual(first.status, PlanStatus.EVIDENCE_PLAN_ONLY)
        self.assertEqual(dict(first.effects), NO_EFFECTS)
        self.assertEqual(first.qualification_effect, "none")
        self.assertTrue(first.operator_approval_required)
        self.assertFalse(first.independent_review_required)
        self.assertTrue(first.cleanup_verification_required)
        self.assertEqual(first.artifact_total_byte_ceiling, 2048)
        self.assertTrue(
            all(item.disposition is StepDisposition.PLANNED_EVIDENCE_ONLY for item in first.steps)
        )

    def test_deep_requires_exact_operator_approval_and_independent_reviewer(self) -> None:
        categories = (
            ProofCategory.CAPTURED_CREDENTIAL,
            ProofCategory.ROLE_CHANGE,
            ProofCategory.LATERAL_PIVOT,
            ProofCategory.DATA_MODIFICATION,
        )
        plan = build_impact_demonstration_plan(
            _request(DemonstrationMode.DEEP, categories), evaluated_at=NOW
        )
        self.assertEqual(plan.status, PlanStatus.EVIDENCE_PLAN_ONLY)
        self.assertTrue(plan.operator_approval_satisfied)
        self.assertTrue(plan.independent_review_satisfied)
        self.assertEqual(
            {step.cleanup_verification_code for step in plan.steps},
            {
                "credential_invalidation_verified",
                "role_restoration_verified",
                "pivot_session_termination_verified",
                "data_restoration_verified",
            },
        )

    def test_off_suppresses_all_proof_and_needs_no_approval(self) -> None:
        request = _request(
            DemonstrationMode.OFF,
            (ProofCategory.CAPTURED_CREDENTIAL,),
        )
        plan = build_impact_demonstration_plan(request, evaluated_at=NOW)
        self.assertEqual(plan.status, PlanStatus.OFF)
        self.assertFalse(plan.operator_approval_required)
        self.assertTrue(plan.operator_approval_satisfied)
        self.assertFalse(plan.cleanup_verification_required)
        self.assertEqual(plan.artifact_total_byte_ceiling, 0)
        self.assertEqual(plan.steps[0].disposition, StepDisposition.SUPPRESSED)
        self.assertEqual(plan.steps[0].artifact_byte_limit, 0)

    def test_availability_and_destructive_categories_are_always_prohibited(self) -> None:
        self.assertEqual(
            ALWAYS_PROHIBITED,
            {ProofCategory.AVAILABILITY_IMPACT, ProofCategory.DESTRUCTIVE_PROOF},
        )
        for category in ALWAYS_PROHIBITED:
            with self.subTest(category=category):
                plan = build_impact_demonstration_plan(
                    _request(DemonstrationMode.DEEP, (category,)), evaluated_at=NOW
                )
                self.assertEqual(plan.status, PlanStatus.DENIED)
                self.assertIn("prohibited_proof_category", plan.denial_reasons)
                self.assertEqual(plan.steps[0].disposition, StepDisposition.PROHIBITED)

    def test_mode_ceiling_blocks_deep_categories_in_moderate_mode(self) -> None:
        plan = build_impact_demonstration_plan(
            _request(DemonstrationMode.MODERATE, (ProofCategory.LATERAL_PIVOT,)),
            evaluated_at=NOW,
        )
        self.assertEqual(plan.status, PlanStatus.DENIED)
        self.assertIn("mode_category_ceiling_exceeded", plan.denial_reasons)

    def test_protected_targets_and_production_data_fail_closed(self) -> None:
        for changes, reason in (
            ({"protected_target": True}, "protected_target_prohibited"),
            ({"production_data_present": True}, "production_data_prohibited"),
        ):
            with self.subTest(reason=reason):
                binding = _binding(**changes)
                categories = (ProofCategory.CAPTURED_CREDENTIAL,)
                request = _request(
                    DemonstrationMode.MODERATE,
                    categories,
                    binding=binding,
                    operator_approval=_approval(binding, DemonstrationMode.MODERATE, categories),
                )
                plan = build_impact_demonstration_plan(request, evaluated_at=NOW)
                self.assertEqual(plan.status, PlanStatus.DENIED)
                self.assertIn(reason, plan.denial_reasons)

    def test_missing_expired_or_mismatched_operator_approval_is_denied(self) -> None:
        base = _request()
        cases = (
            None,
            replace(base.operator_approval, binding_sha256=HASHES[35]),
            replace(base.operator_approval, approved_mode=DemonstrationMode.DEEP),
            replace(
                base.operator_approval,
                approved_categories=(ProofCategory.CAPTURED_CREDENTIAL,),
            ),
            replace(base.operator_approval, expires_at="2026-09-20T12:10:00Z"),
        )
        for approval in cases:
            with self.subTest(approval=approval):
                plan = build_impact_demonstration_plan(
                    replace(base, operator_approval=approval), evaluated_at=NOW
                )
                self.assertEqual(plan.status, PlanStatus.DENIED)
                self.assertIn("operator_approval_unsatisfied", plan.denial_reasons)

    def test_self_review_wrong_approval_and_expired_review_are_denied(self) -> None:
        categories = (ProofCategory.LATERAL_PIVOT,)
        base = _request(DemonstrationMode.DEEP, categories)
        cases = (
            None,
            replace(base.independent_review, reviewer_ref="principalref:operator-one"),
            replace(base.independent_review, approval_sha256=HASHES[35]),
            replace(base.independent_review, expires_at="2026-09-20T12:10:00Z"),
        )
        for review in cases:
            with self.subTest(review=review):
                plan = build_impact_demonstration_plan(
                    replace(base, independent_review=review), evaluated_at=NOW
                )
                self.assertEqual(plan.status, PlanStatus.DENIED)
                self.assertIn("independent_review_unsatisfied", plan.denial_reasons)

    def test_artifact_minimization_ceiling_and_no_raw_persistence(self) -> None:
        request = _request()
        large = tuple(replace(item, artifact_byte_limit=3000) for item in request.intents)
        plan = build_impact_demonstration_plan(replace(request, intents=large), evaluated_at=NOW)
        self.assertEqual(plan.status, PlanStatus.DENIED)
        self.assertIn("artifact_minimization_ceiling_exceeded", plan.denial_reasons)
        self.assertTrue(all(not step.persist_raw_content for step in plan.steps))
        self.assertTrue(all(not step.persist_secret_material for step in plan.steps))
        self.assertTrue(all(step.artifact_byte_limit == 0 for step in plan.steps))

    def test_receipt_is_content_addressed_and_preserves_no_effects(self) -> None:
        plan = build_impact_demonstration_plan(_request(), evaluated_at=NOW)
        receipt = build_impact_demonstration_receipt(plan)
        self.assertEqual(receipt.plan_id, plan.plan_id)
        self.assertEqual(receipt.plan_sha256, plan.plan_sha256)
        self.assertEqual(receipt.policy_result, "accepted_inert_plan")
        self.assertEqual(dict(receipt.effects), NO_EFFECTS)
        self.assertEqual(
            parse_impact_demonstration_receipt(canonical_json(receipt.to_dict())), receipt
        )

    def test_strict_parsers_reject_unknown_fields_and_noncanonical_json(self) -> None:
        plan = build_impact_demonstration_plan(_request(), evaluated_at=NOW)
        raw = plan.to_dict()
        raw["network_call_performed"] = False
        with self.assertRaisesRegex(ImpactDemonstrationPolicyError, "fields are invalid"):
            parse_impact_demonstration_plan(raw)
        pretty = json.dumps(plan.to_dict(), indent=2)
        with self.assertRaisesRegex(ImpactDemonstrationPolicyError, "canonical JSON"):
            parse_impact_demonstration_plan(pretty)
        with self.assertRaisesRegex(ImpactDemonstrationPolicyError, "UTF-8"):
            parse_impact_demonstration_plan(b"\xff\xfe")

    def test_tamper_substitution_and_effect_escalation_are_rejected(self) -> None:
        plan = build_impact_demonstration_plan(_request(), evaluated_at=NOW)
        raw = plan.to_dict()
        for mutate in (
            lambda value: value["steps"][0].update({"evidence_sha256": HASHES[38]}),
            lambda value: value["request"]["binding"].update({"target_sha256": HASHES[38]}),
            lambda value: value["effects"].update({"network": "allowed"}),
        ):
            tampered = copy.deepcopy(raw)
            mutate(tampered)
            with self.subTest(tampered=tampered), self.assertRaises(ImpactDemonstrationPolicyError):
                parse_impact_demonstration_plan(tampered)

    def test_semantic_tamper_fails_even_when_plan_is_rehashed(self) -> None:
        plan = build_impact_demonstration_plan(_request(), evaluated_at=NOW)
        raw = plan.to_dict()
        raw["cleanup_verification_required"] = False
        body = {key: value for key, value in raw.items() if key not in {"plan_id", "plan_sha256"}}
        digest = canonical_sha256({"content": body, "domain": ImpactDemonstrationPlan.DOMAIN})
        raw["plan_sha256"] = digest
        raw["plan_id"] = f"IDP-{digest[7:39].upper()}"
        with self.assertRaisesRegex(ImpactDemonstrationPolicyError, "cleanup verification"):
            parse_impact_demonstration_plan(raw)

    def test_raw_secrets_payloads_and_nonopaque_references_are_rejected(self) -> None:
        for evidence_ref in (
            "evidenceref:api_key=super-secret-value",
            "evidenceref:run-this-payload",
            "https://example.invalid/evidence",
        ):
            with (
                self.subTest(evidence_ref=evidence_ref),
                self.assertRaises(ImpactDemonstrationPolicyError),
            ):
                replace(
                    _intent(ProofCategory.CAPTURED_CREDENTIAL, number=4),
                    evidence_ref=evidence_ref,
                )

    def test_duplicate_categories_naive_time_and_stale_request_fail_closed(self) -> None:
        intent = _intent(ProofCategory.ROLE_CHANGE, number=4)
        with self.assertRaisesRegex(ImpactDemonstrationPolicyError, "unique"):
            _request(intents=(intent, intent))
        with self.assertRaisesRegex(ImpactDemonstrationPolicyError, "timezone-aware"):
            build_impact_demonstration_plan(_request(), evaluated_at=datetime(2026, 9, 20))
        stale = build_impact_demonstration_plan(
            _request(), evaluated_at=datetime(2026, 9, 21, tzinfo=UTC)
        )
        self.assertEqual(stale.status, PlanStatus.DENIED)
        self.assertIn("request_not_current", stale.denial_reasons)

    def test_mapping_and_canonical_ascii_json_round_trip(self) -> None:
        plan = build_impact_demonstration_plan(_request(), evaluated_at=NOW)
        serialized = canonical_json(plan.to_dict())
        self.assertTrue(serialized.isascii())
        self.assertEqual(parse_impact_demonstration_plan(serialized), plan)
        self.assertEqual(parse_impact_demonstration_plan(plan.to_dict()), plan)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is unavailable")
    def test_draft_2020_12_schema_accepts_plan_and_rejects_effects(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        raw = build_impact_demonstration_plan(_request(), evaluated_at=NOW).to_dict()
        validator.validate(raw)
        effectful = copy.deepcopy(raw)
        effectful["effects"]["network"] = "allowed"
        with self.assertRaises(ValidationError):
            validator.validate(effectful)
        extra = copy.deepcopy(raw)
        extra["execute"] = False
        with self.assertRaises(ValidationError):
            validator.validate(extra)

    def test_receipt_parser_rejects_tampering_and_unknown_fields(self) -> None:
        receipt = build_impact_demonstration_receipt(
            build_impact_demonstration_plan(_request(), evaluated_at=NOW)
        )
        raw = receipt.to_dict()
        raw["plan_sha256"] = HASHES[38]
        with self.assertRaisesRegex(ImpactDemonstrationPolicyError, "content address"):
            parse_impact_demonstration_receipt(raw)
        unknown = receipt.to_dict()
        unknown["target_contact"] = False
        with self.assertRaisesRegex(ImpactDemonstrationPolicyError, "fields are invalid"):
            ImpactDemonstrationReceipt.from_dict(unknown)


if __name__ == "__main__":
    unittest.main()
