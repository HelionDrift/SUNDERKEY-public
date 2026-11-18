"""Cross-service chain review retains per-hop authority and proof limits."""

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

from sunderkey.cross_service_chain_review import (
    CrossServiceChainReviewError,
    _sha,
    build_cross_service_chain_review,
    verify_cross_service_chain_review,
)

SCOPE = "sha256:" + "a" * 64
SOURCE = "sha256:" + "b" * 64
ACTION1 = "sha256:" + "c" * 64
ACTION2 = "sha256:" + "d" * 64
ADMISSION1 = "sha256:" + "e" * 64
ADMISSION2 = "sha256:" + "f" * 64
BINDING1 = "sha256:" + "1" * 64
BINDING2 = "sha256:" + "2" * 64
CREDENTIAL = "credentialref:sha256:" + "3" * 64
APP = "surfaceref:sha256:" + "4" * 64
IDENTITY = "surfaceref:sha256:" + "5" * 64
CLOUD = "surfaceref:sha256:" + "6" * 64
AS_OF = "2026-10-15T13:00:00Z"


def hop(ref, source, target, from_domain, to_domain, action, transition, binding):
    return {
        "hop_ref": ref,
        "from_surface_ref": source,
        "to_surface_ref": target,
        "from_domain": from_domain,
        "to_domain": to_domain,
        "boundary_kind": "cross_domain",
        "action_tier": "R1",
        "action_sha256": action,
        "policy_snapshot_sha256": SOURCE,
        "evidence_requirement_sha256": SOURCE,
        "cleanup_requirement_sha256": SOURCE,
        "credential_transition": transition,
        "credential_ref": CREDENTIAL,
        "credential_binding_sha256": binding,
    }


def plan():
    return {
        "schema_version": 1,
        "tenant_ref": "tenantref:fixture",
        "mission_ref": "missionref:fixture",
        "scope_sha256": SCOPE,
        "chain_ref": "chainref:fixture",
        "source_plan_sha256": SOURCE,
        "created_at": "2026-10-15T12:00:00Z",
        "expires_at": "2026-10-16T12:00:00Z",
        "hops": [
            hop(
                "hopref:one", APP, IDENTITY, "application", "identity",
                ACTION1, "synthetic_seed", BINDING1,
            ),
            hop(
                "hopref:two", IDENTITY, CLOUD, "identity", "cloud",
                ACTION2, "brokered_opaque", BINDING2,
            ),
        ],
    }


def observation(
    planned_hop, *, admission, issued, expires, attempted, attempt_ref,
    outcome="declared_passed", cleanup="pending",
):
    cleaned_at = "2026-10-15T12:20:00Z" if cleanup == "declared_complete" else None
    return {
        "hop_ref": planned_hop["hop_ref"],
        "planned_hop_sha256": _sha(planned_hop),
        "admission_sha256": admission,
        "admission_issued_at": issued,
        "admission_expires_at": expires,
        "admission_scope_sha256": SCOPE,
        "admission_action_sha256": planned_hop["action_sha256"],
        "admission_credential_binding_sha256": planned_hop[
            "credential_binding_sha256"
        ],
        "actor_ref": "actorref:fixture",
        "attempt_ref": attempt_ref,
        "attempted_at": attempted,
        "declared_outcome": outcome,
        "evidence_sha256": SOURCE,
        "custody_sha256": SOURCE,
        "cleanup_status": cleanup,
        "cleanup_at": cleaned_at,
        "cleanup_evidence_sha256": SOURCE if cleaned_at else None,
    }


def observations(planned=None):
    planned = plan() if planned is None else planned
    return [
        observation(
            planned["hops"][0], admission=ADMISSION1,
            issued="2026-10-15T12:10:00Z", expires="2026-10-15T12:30:00Z",
            attempted="2026-10-15T12:15:00Z", attempt_ref="attemptref:one",
            cleanup="declared_complete",
        ),
        observation(
            planned["hops"][1], admission=ADMISSION2,
            issued="2026-10-15T12:20:00Z", expires="2026-10-15T13:00:00Z",
            attempted="2026-10-15T12:25:00Z", attempt_ref="attemptref:two",
        ),
    ]


class CrossServiceChainReviewTests(unittest.TestCase):
    def test_complete_declared_chain_still_has_no_authority_or_proof(self):
        planned = plan()
        observed = observations(planned)
        result = build_cross_service_chain_review(planned, observed, as_of=AS_OF)
        self.assertEqual(result["planned_hop_count"], 2)
        self.assertEqual(result["observed_hop_count"], 2)
        self.assertEqual(result["declared_passed_hop_count"], 2)
        self.assertEqual(
            result["declared_terminal_state"],
            "declared_complete_pending_independent_review",
        )
        self.assertEqual(result["declared_end_surface_ref"], CLOUD)
        self.assertEqual(result["planned_credential_reuse_count"], 1)
        self.assertEqual(result["cleanup_due_hop_refs"], ["hopref:two"])
        self.assertFalse(result["per_hop_admission_authenticated"])
        self.assertFalse(result["transition_proof_verified"])
        self.assertFalse(result["cleanup_verified"])
        self.assertEqual(result["effects"]["target_interaction"], "none")
        self.assertEqual(result["qualification_effect"], "none")
        self.assertEqual(
            verify_cross_service_chain_review(
                planned, observed, as_of=AS_OF, result=result,
            )["status"],
            "valid",
        )

    def test_blocked_or_unknown_hop_stops_subsequent_observations(self):
        planned = plan()
        for outcome in ("declared_blocked", "unknown"):
            with self.subTest(outcome=outcome):
                observed = observations(planned)
                observed[0]["declared_outcome"] = outcome
                with self.assertRaisesRegex(CrossServiceChainReviewError, "stopped hop"):
                    build_cross_service_chain_review(planned, observed, as_of=AS_OF)
                result = build_cross_service_chain_review(
                    planned, observed[:1], as_of=AS_OF,
                )
                self.assertEqual(result["declared_terminal_state"], "declared_stopped")
                self.assertIsNone(result["declared_end_surface_ref"])

    def test_each_hop_needs_distinct_exact_admission(self):
        planned = plan()
        for field, value, reason in (
            ("admission_sha256", ADMISSION1, "reused"),
            ("admission_scope_sha256", SOURCE, "exact hop"),
            ("admission_action_sha256", ACTION1, "exact hop"),
            ("admission_credential_binding_sha256", BINDING1, "exact hop"),
            ("planned_hop_sha256", SOURCE, "planned hop"),
        ):
            with self.subTest(field=field):
                observed = observations(planned)
                observed[1][field] = value
                with self.assertRaisesRegex(CrossServiceChainReviewError, reason):
                    build_cross_service_chain_review(planned, observed, as_of=AS_OF)
        observed = observations(planned)
        observed[1]["attempt_ref"] = observed[0]["attempt_ref"]
        with self.assertRaisesRegex(CrossServiceChainReviewError, "reused"):
            build_cross_service_chain_review(planned, observed, as_of=AS_OF)

    def test_scope_surface_and_boundary_facts_are_closed(self):
        for field, value, reason in (
            ("from_surface_ref", "https://example.test", "opaque"),
            ("from_surface_ref", APP, "disconnected"),
            ("from_domain", "application", "disconnected"),
            ("boundary_kind", "same_domain", "contradicts"),
            ("credential_ref", "password:secret", "opaque"),
        ):
            with self.subTest(field=field):
                planned = plan()
                planned["hops"][1][field] = value
                with self.assertRaisesRegex(CrossServiceChainReviewError, reason):
                    build_cross_service_chain_review(planned, [], as_of=AS_OF)
        planned = plan()
        planned["hops"][1]["extra"] = True
        with self.assertRaisesRegex(CrossServiceChainReviewError, "fields are invalid"):
            build_cross_service_chain_review(planned, [], as_of=AS_OF)
        planned = plan()
        planned["hops"][0]["credential_transition"] = "none"
        with self.assertRaisesRegex(CrossServiceChainReviewError, "fields conflict"):
            build_cross_service_chain_review(planned, [], as_of=AS_OF)
        planned = plan()
        planned["hops"][1]["credential_transition"] = "synthetic_seed"
        with self.assertRaisesRegex(CrossServiceChainReviewError, "only valid at start"):
            build_cross_service_chain_review(planned, [], as_of=AS_OF)

    def test_no_credential_or_observation_is_a_nonexecuting_plan(self):
        planned = plan()
        planned["hops"][0].update({
            "credential_transition": "none",
            "credential_ref": None,
            "credential_binding_sha256": None,
        })
        planned["hops"][1].update({
            "credential_transition": "none",
            "credential_ref": None,
            "credential_binding_sha256": None,
        })
        result = build_cross_service_chain_review(planned, [], as_of=AS_OF)
        self.assertEqual(result["declared_terminal_state"], "not_started")
        self.assertEqual(result["planned_credential_reuse_count"], 0)
        self.assertEqual(result["observed_hop_count"], 0)
        self.assertEqual(result["effects"]["execution"], "none")

    def test_time_and_cleanup_claims_fail_closed(self):
        planned = plan()
        observed = observations(planned)
        observed[0]["attempted_at"] = "2026-10-15T12:30:00Z"
        with self.assertRaisesRegex(CrossServiceChainReviewError, "timing"):
            build_cross_service_chain_review(planned, observed, as_of=AS_OF)
        observed = observations(planned)
        observed[0]["cleanup_at"] = "2026-10-15T12:14:00Z"
        with self.assertRaisesRegex(CrossServiceChainReviewError, "cleanup timing"):
            build_cross_service_chain_review(planned, observed, as_of=AS_OF)
        observed = observations(planned)
        observed[1]["cleanup_evidence_sha256"] = SOURCE
        with self.assertRaisesRegex(CrossServiceChainReviewError, "pending cleanup"):
            build_cross_service_chain_review(planned, observed, as_of=AS_OF)
        planned = plan()
        planned["expires_at"] = "2026-10-17T12:00:00Z"
        with self.assertRaisesRegex(CrossServiceChainReviewError, "hard limit"):
            build_cross_service_chain_review(planned, [], as_of=AS_OF)

    def test_source_and_result_substitution_fail_replay(self):
        planned = plan()
        observed = observations(planned)
        result = build_cross_service_chain_review(planned, observed, as_of=AS_OF)
        altered = copy.deepcopy(result)
        altered["effects"]["execution"] = "allowed"
        with self.assertRaisesRegex(CrossServiceChainReviewError, "does not reproduce"):
            verify_cross_service_chain_review(
                planned, observed, as_of=AS_OF, result=altered,
            )
        altered_source = copy.deepcopy(observed)
        altered_source[1]["cleanup_status"] = "declared_complete"
        altered_source[1]["cleanup_at"] = "2026-10-15T12:30:00Z"
        altered_source[1]["cleanup_evidence_sha256"] = SOURCE
        with self.assertRaisesRegex(CrossServiceChainReviewError, "does not reproduce"):
            verify_cross_service_chain_review(
                planned, altered_source, as_of=AS_OF, result=result,
            )

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_output_matches_closed_schema(self):
        path = (
            Path(__file__).resolve().parents[2] / "registry" / "schemas"
            / "cross-service-chain-review-v1.schema.json"
        )
        schema = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        validator.validate(build_cross_service_chain_review(
            plan(), observations(), as_of=AS_OF,
        ))
        invalid = build_cross_service_chain_review(plan(), observations(), as_of=AS_OF)
        invalid["unexpected"] = True
        with self.assertRaises(ValidationError):
            validator.validate(invalid)


if __name__ == "__main__":
    unittest.main()
