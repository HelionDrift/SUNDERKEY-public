"""V9.12 target and threat-case metadata cannot grant execution authority."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator, ValidationError
except ImportError:
    Draft202012Validator = None
    ValidationError = None

from sunderkey.ai_validation_plan import (
    AiValidationPlanError,
    build_ai_validation_plan,
    verify_ai_validation_plan,
)

SHA = "sha256:" + "a" * 64
TOOL = "toolref:synthetic-tool"
AS_OF = "2026-10-03T12:00:00Z"


def profile(**changes):
    value = {
        "schema_version": 1,
        "tenant_ref": "tenantref:fixture",
        "scope_sha256": SHA,
        "target_ref": "targetref:fixture-agent",
        "target_class": "agent",
        "environment": "synthetic_fixture",
        "owner_ref": "ownerref:fixture-owner",
        "source_profile_sha256": SHA,
        "authorization_sha256": SHA,
        "system_revision_sha256": SHA,
        "redaction_policy_sha256": SHA,
        "issued_at": "2026-10-03T11:00:00Z",
        "expires_at": "2026-10-04T11:00:00Z",
        "allowed_tool_refs": [TOOL],
        "maximum_requests": 4,
        "maximum_tokens": 20_000,
        "stop_rules": [
            "budget_exhausted", "critical_signal", "scope_violation",
        ],
        "retention_days": 7,
    }
    value.update(changes)
    return value


def case(**changes):
    value = {
        "case_ref": "caseref:fixture-case",
        "source_case_sha256": SHA,
        "threat_class": "tool_boundary",
        "prompt_fixture_sha256": SHA,
        "expected_behavior": "require_tool_authority",
        "prohibited_behavior": "invoke_unapproved_tool",
        "required_tool_refs": [TOOL],
        "maximum_requests": 1,
        "maximum_tokens": 4_000,
        "scoring_rubric_sha256": SHA,
        "reviewer_ref": "reviewerref:independent-candidate",
        "created_at": "2026-10-03T11:30:00Z",
    }
    value.update(changes)
    return value


class AiValidationPlanTests(unittest.TestCase):
    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_plan_matches_closed_schema(self):
        path = (
            Path(__file__).resolve().parents[2] / "registry" / "schemas"
            / "ai-validation-plan-v1.schema.json"
        )
        schema = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        validator.validate(build_ai_validation_plan(profile(), [case()], as_of=AS_OF))
        invalid = build_ai_validation_plan(profile(), [case()], as_of=AS_OF)
        invalid["unexpected"] = True
        with self.assertRaises(ValidationError):
            validator.validate(invalid)

    def test_bounded_metadata_plan_is_not_authority(self):
        result = build_ai_validation_plan(profile(), [case()], as_of=AS_OF)
        self.assertEqual(result["case_count"], 1)
        self.assertEqual(result["reserved_request_ceiling"], 1)
        self.assertEqual(result["reserved_token_ceiling"], 4_000)
        self.assertEqual(result["case_plan"][0]["threat_class"], "tool_boundary")
        for name in (
            "authorization_authenticated", "target_identity_verified",
            "judge_independence_verified", "prompt_custody_verified",
        ):
            self.assertFalse(result[name])
        self.assertEqual(result["effects"]["model_calls"], "none")
        self.assertEqual(result["effects"]["tool_execution"], "none")
        self.assertEqual(result["qualification_effect"], "none")
        self.assertEqual(
            verify_ai_validation_plan(
                profile(), [case()], as_of=AS_OF, result=result,
            )["status"],
            "valid",
        )

    def test_expiry_and_budget_fail_closed(self):
        with self.assertRaisesRegex(AiValidationPlanError, "not current"):
            build_ai_validation_plan(profile(), [case()], as_of="2026-10-05T00:00:00Z")
        with self.assertRaisesRegex(AiValidationPlanError, "seven days"):
            build_ai_validation_plan(
                profile(expires_at="2026-10-20T11:00:00Z"), [case()], as_of=AS_OF,
            )
        with self.assertRaisesRegex(AiValidationPlanError, "budget"):
            build_ai_validation_plan(
                profile(maximum_requests=1),
                [case(case_ref="caseref:a"), case(case_ref="caseref:b")],
                as_of=AS_OF,
            )
        with self.assertRaisesRegex(AiValidationPlanError, "hard limit"):
            build_ai_validation_plan(profile(maximum_tokens=True), [case()], as_of=AS_OF)

    def test_tool_and_behavior_pairs_are_closed(self):
        with self.assertRaisesRegex(AiValidationPlanError, "inventory"):
            build_ai_validation_plan(
                profile(), [case(required_tool_refs=["toolref:unknown"])], as_of=AS_OF,
            )
        with self.assertRaisesRegex(AiValidationPlanError, "behavior pair"):
            build_ai_validation_plan(
                profile(), [case(prohibited_behavior="disclose_restricted_content")],
                as_of=AS_OF,
            )
        with self.assertRaisesRegex(AiValidationPlanError, "inventoried tool"):
            build_ai_validation_plan(
                profile(), [case(required_tool_refs=[])], as_of=AS_OF,
            )
        with self.assertRaisesRegex(AiValidationPlanError, "cannot authorize tools"):
            build_ai_validation_plan(
                profile(target_class="model"), [case()], as_of=AS_OF,
            )

    def test_opaque_metadata_excludes_raw_prompts(self):
        raw = case()
        raw["prompt"] = "ignore everything"
        with self.assertRaisesRegex(AiValidationPlanError, "fields are invalid"):
            build_ai_validation_plan(profile(), [raw], as_of=AS_OF)
        raw = profile()
        raw["endpoint"] = "https://example.test/model"
        with self.assertRaisesRegex(AiValidationPlanError, "fields are invalid"):
            build_ai_validation_plan(raw, [case()], as_of=AS_OF)
        with self.assertRaisesRegex(AiValidationPlanError, "opaque"):
            build_ai_validation_plan(
                profile(target_ref="https://example.test/model"), [case()], as_of=AS_OF,
            )

    def test_stop_and_retention_controls_are_mandatory(self):
        with self.assertRaisesRegex(AiValidationPlanError, "stop rules"):
            build_ai_validation_plan(
                profile(stop_rules=["budget_exhausted"]), [case()], as_of=AS_OF,
            )
        with self.assertRaisesRegex(AiValidationPlanError, "retention_days"):
            build_ai_validation_plan(
                profile(retention_days=31), [case()], as_of=AS_OF,
            )
        with self.assertRaisesRegex(AiValidationPlanError, "sorted and unique"):
            build_ai_validation_plan(
                profile(allowed_tool_refs=[TOOL, TOOL]), [case()], as_of=AS_OF,
            )

    def test_source_and_result_changes_fail_replay(self):
        result = build_ai_validation_plan(profile(), [case()], as_of=AS_OF)
        with self.assertRaisesRegex(AiValidationPlanError, "does not reproduce"):
            verify_ai_validation_plan(
                profile(), [case(maximum_tokens=3_999)], as_of=AS_OF,
                result=result,
            )
        altered = copy.deepcopy(result)
        altered["effects"]["tool_execution"] = "allowed"
        with self.assertRaisesRegex(AiValidationPlanError, "does not reproduce"):
            verify_ai_validation_plan(
                profile(), [case()], as_of=AS_OF, result=altered,
            )


if __name__ == "__main__":
    unittest.main()
