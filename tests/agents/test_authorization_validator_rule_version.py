"""Exact authorization rule identity and non-authorizing archive integrity."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

import sunderkey.coverage_scheduler as scheduler
import sunderkey.offline_api_planning_bundle as planning
from scripts.run_offline_api_assessment import _native_adapter
from sunderkey.attack_world_model import build_attack_world_snapshot
from sunderkey.coverage_capacity_rehearsal import (
    bind_rehearsal_to_army_registry,
    plan_capacity_rehearsal,
)
from sunderkey.coverage_scheduler import SchedulingLimits
from sunderkey.finding_validators import (
    DEFAULT_REGISTRY,
    AuthorizationDifferentialValidator,
    EvidenceRecord,
    FindingValidationError,
    FindingValidationRequest,
    FindingValidationResult,
    build_default_registry,
)
from sunderkey.offline_api_assessment import (
    RESULT_DOMAIN,
    OfflineApiAssessmentError,
    evaluate_offline_api_case,
    verify_offline_api_case,
)
from sunderkey.offline_api_world_projection import (
    NO_EFFECTS as PROJECTION_NO_EFFECTS,
)
from sunderkey.offline_api_world_projection import PROJECTION_DOMAIN
from sunderkey.registry import load_registry
from tests.agents.test_offline_api_assessment import invocation

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_ID = "validator.web.authorization-differential"
CURRENT_VERSION = "1.0.1"
OLD_VERSION = "1.0.0"
OLD_DESCRIPTOR_SHA256 = "sha256:ad87aebd28478403a9de814f4a52d6daf0cf1a124dd64ca701dab57eab4a7bad"
OLD_REGISTRY_SHA256 = "sha256:2e2a72c907c16d19257e93d94142dcfd03c3ef51bff47096086b5fb6d329e31a"
OLD_RESULT_SHA256 = "sha256:fb7ca462dc1417e75d35b3d179f7d1f97fdaf7d061d23eba39bf95991014297a"
OLD_EVIDENCE_SHA256S = (
    "sha256:dd54ae11e273ca8c77d056a71b675ceaa0ea3f0a0cb5cebeac57b3ed07445a56",
    "sha256:ff18ed277684b1a6867339a516c11a7870c6258f10da53c01bd0665b4638ef1d",
)


def digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def response(
    evidence_id: str,
    principal_id: str,
    expected_access: bool,
    status: int = 200,
    content: bytes = b"synthetic-record",
) -> EvidenceRecord:
    return EvidenceRecord.from_bytes(
        evidence_id,
        content,
        role="response",
        status_code=status,
        media_type="application/json",
        attributes={
            "principal_id": principal_id,
            "object_id": "object.one",
            "action": "read",
            "expected_access": expected_access,
        },
    )


def records() -> tuple[EvidenceRecord, ...]:
    return (
        response("owner", "principal.owner", True),
        response("other", "principal.other", False),
    )


def request(
    evidence: tuple[EvidenceRecord, ...],
    *,
    version: str = CURRENT_VERSION,
    registry_sha256: str | None = None,
) -> FindingValidationRequest:
    return FindingValidationRequest(
        scope_id="scope.synthetic.version",
        technique_id="API.AUTHORIZATION.1",
        validator_id=VALIDATOR_ID,
        validator_version=version,
        evidence=evidence,
        expected_evidence_hashes=tuple(item.evidence_sha256 for item in evidence),
        registry_sha256=registry_sha256,
    )


def historical_document() -> dict:
    """Return bounded inert wire metadata captured from c1c35f6^.

    The old rule is not imported, registered, or used for current assessment.
    The fixed digest covers this harmless distinct-principal fixture exactly.
    """

    return {
        "schema_version": 1,
        "result_id": "FVR-FB7CA462DC1417E75D35B3D179F7D1F9",
        "result_sha256": OLD_RESULT_SHA256,
        "registry_sha256": OLD_REGISTRY_SHA256,
        "input_sha256": ("sha256:826880978dd9b0eccbc0bed7943993ebd8edbe35f15533ccd587eb4784cf82a8"),
        "scope_id": "scope.synthetic.version",
        "technique_id": "API.AUTHORIZATION.1",
        "finding_impact": "medium",
        "validator": {
            "id": VALIDATOR_ID,
            "version": OLD_VERSION,
            "descriptor_sha256": OLD_DESCRIPTOR_SHA256,
        },
        "state": "verified",
        "confidence": 0.98,
        "reason_codes": ["unauthorized_equivalent_access"],
        "evidence_hashes": list(OLD_EVIDENCE_SHA256S),
        "restoration_evidence_hashes": [],
        "observations": [
            {
                "code": "authorization_outcomes",
                "evidence_hashes": list(OLD_EVIDENCE_SHA256S),
                "attributes": {
                    "authorized_success_count": 1,
                    "matching_representation_count": 1,
                    "unauthorized_denial_count": 0,
                    "unauthorized_success_count": 1,
                },
            }
        ],
        "false_positive_checks": [
            {
                "code": code,
                "evidence_hashes": list(OLD_EVIDENCE_SHA256S),
                "passed": True,
            }
            for code in (
                "same_object_action",
                "distinct_principals",
                "access_polarity_present",
            )
        ],
        "corroboration": {
            "required": 3,
            "observed_signals": [
                "authorized_control",
                "representation_match",
                "unauthorized_success",
            ],
            "satisfied": True,
        },
        "restoration": "not_applicable",
        "effects": {
            name: "none"
            for name in (
                "authority",
                "credentials",
                "deployment",
                "execution",
                "network",
                "qualification",
                "routing",
            )
        },
    }


def archived_planning_bundle() -> tuple[dict, object]:
    """Assemble empty archive metadata without case replay or an adapter."""

    snapshot = build_attack_world_snapshot((), ())
    limits = SchedulingLimits(
        as_of="2026-09-24T12:01:00Z",
        max_tasks=1,
        max_total_cost_units=1,
        max_total_requests=1,
        max_concurrency=1,
        max_tasks_per_asset=1,
        max_snapshot_age_seconds=3600,
        review_impact_tier="R0",
    )
    # This content-addressed empty schedule is not a current-use proposal.
    schedule = scheduler._address_schedule(
        scope_sha256="sha256:" + "a" * 64,
        world_snapshot_sha256=snapshot.snapshot_sha256,
        parent_schedule_sha256=None,
        supersedes_schedule_id=None,
        limits=limits,
        effective_max_concurrency=1,
        tasks=(),
        accepted_prior_outcome_ids=(),
        blocked_reasons=(),
    )
    rehearsal = plan_capacity_rehearsal(
        schedule, specialist_capacity={}, commander_capacity={}, validator_capacity={}
    )
    army_registry = load_registry(ROOT / "registry" / "army-v2.json")
    binding = bind_rehearsal_to_army_registry(schedule, rehearsal, army_registry)
    batch_sha256 = digest({"archived_validator_result_sha256": OLD_RESULT_SHA256})
    projection_body = {
        "schema_version": 1,
        "batch_sha256": batch_sha256,
        "snapshot": snapshot.to_dict(),
        "skipped_case_ids": [],
        "origin_authentication": "not_verified",
        "path_verification": "not_established",
        "effects": dict(PROJECTION_NO_EFFECTS),
    }
    projection = {
        **projection_body,
        "projection_sha256": digest({"domain": PROJECTION_DOMAIN, "projection": projection_body}),
    }
    body = {
        "schema_version": 1,
        "batch_sha256": batch_sha256,
        "scope_sha256": schedule.scope_sha256,
        "target_context_sha256": None,
        "projection": projection,
        "schedule": schedule.to_dict(),
        "capacity_rehearsal": rehearsal.to_dict(),
        "army_roster_binding": binding.to_dict(),
        "effects": dict(planning.NO_EFFECTS),
    }
    return {
        **body,
        "bundle_sha256": digest({"domain": planning.BUNDLE_DOMAIN, "bundle": body}),
    }, army_registry


class AuthorizationValidatorRuleVersionTests(unittest.TestCase):
    def test_rule_descriptor_and_registry_have_new_exact_identities(self) -> None:
        descriptor = AuthorizationDifferentialValidator.descriptor
        self.assertEqual(descriptor.version, CURRENT_VERSION)
        self.assertNotEqual(descriptor.descriptor_sha256, OLD_DESCRIPTOR_SHA256)
        self.assertNotEqual(DEFAULT_REGISTRY.registry_sha256, OLD_REGISTRY_SHA256)
        legacy_body = {
            "validator_id": VALIDATOR_ID,
            "version": OLD_VERSION,
            "evidence_kind": "authorization_differential",
            "required_signal_codes": [
                "unauthorized_success",
                "authorized_control",
                "representation_match",
            ],
            "minimum_corroboration": 3,
        }
        self.assertEqual(
            digest(
                {"domain": "sunderkey.finding-validator-descriptor.v1", "descriptor": legacy_body}
            ),
            OLD_DESCRIPTOR_SHA256,
        )
        legacy_descriptors = [item.to_dict() for item in DEFAULT_REGISTRY.descriptors]
        for item in legacy_descriptors:
            if item["validator_id"] == VALIDATOR_ID:
                item.update(legacy_body, descriptor_sha256=OLD_DESCRIPTOR_SHA256)
        self.assertEqual(
            digest(
                {
                    "domain": "sunderkey.finding-validator-registry.v1",
                    "registry": {
                        "validators": legacy_descriptors,
                    },
                }
            ),
            OLD_REGISTRY_SHA256,
        )

    def test_old_exact_lookup_and_request_have_no_current_fallback(self) -> None:
        self.assertIsInstance(
            DEFAULT_REGISTRY.get(VALIDATOR_ID, CURRENT_VERSION),
            AuthorizationDifferentialValidator,
        )
        with self.assertRaisesRegex(FindingValidationError, "exact validator"):
            DEFAULT_REGISTRY.get(VALIDATOR_ID, OLD_VERSION)
        with self.assertRaisesRegex(FindingValidationError, "exact validator"):
            DEFAULT_REGISTRY.validate(request(records(), version=OLD_VERSION))

    def test_old_registry_request_is_rejected_before_assessment(self) -> None:
        with patch.object(
            AuthorizationDifferentialValidator,
            "assess",
            side_effect=AssertionError("old registry must fail before assessment"),
        ):
            with self.assertRaisesRegex(FindingValidationError, "registry hash"):
                DEFAULT_REGISTRY.validate(request(records(), registry_sha256=OLD_REGISTRY_SHA256))

    def test_valid_states_are_preserved_with_complete_current_checks(self) -> None:
        owner = response("owner", "principal.owner", True)
        cases = (
            ("verified", response("other", "principal.other", False)),
            ("negative", response("other", "principal.other", False, 403, b"denied")),
            ("hypothesis", response("other", "principal.other", False, 200, b"different")),
        )
        for state, subject in cases:
            with self.subTest(state=state):
                result = DEFAULT_REGISTRY.validate(request((owner, subject)))
                self.assertEqual(result.state, state)
                self.assertEqual(result.validator_version, CURRENT_VERSION)
                checks = {item["code"]: item["passed"] for item in result.false_positive_checks}
                for code in (
                    "principal_identities_present",
                    "access_polarity_complete",
                    "principal_access_consistent",
                ):
                    self.assertIs(checks[code], True)
                self.assertTrue(
                    all(value == "none" for value in result.to_dict()["effects"].values())
                )

    def test_ambiguous_pair_cannot_borrow_an_unrelated_principal(self) -> None:
        evidence = (
            response("owner", "principal.same", True),
            response("other", "principal.same", False),
            response("third", "principal.distinct", True, 403, b"denied"),
        )
        result = DEFAULT_REGISTRY.validate(request(evidence))
        self.assertEqual(result.state, "abstained")
        checks = {item["code"]: item["passed"] for item in result.false_positive_checks}
        self.assertIs(checks["distinct_principals"], True)
        self.assertIs(checks["principal_access_consistent"], False)

    def test_current_replay_is_deterministic_and_version_bound(self) -> None:
        evidence = records()
        first = DEFAULT_REGISTRY.validate(request(evidence))
        second = build_default_registry().validate(request(tuple(reversed(evidence))))
        self.assertEqual(first.document_json, second.document_json)
        self.assertEqual(first.result_id, second.result_id)
        self.assertEqual(first.result_sha256, second.result_sha256)
        self.assertEqual(first.evidence_hashes, OLD_EVIDENCE_SHA256S)
        self.assertNotEqual(first.input_sha256, historical_document()["input_sha256"])
        self.assertNotEqual(first.result_sha256, OLD_RESULT_SHA256)
        self.assertEqual(DEFAULT_REGISTRY.verify_result(first.to_dict()), first)

    def test_old_archive_hash_is_intact_but_cannot_bind_current_registry(self) -> None:
        document = historical_document()
        body = {
            key: value
            for key, value in document.items()
            if key not in {"result_id", "result_sha256"}
        }
        self.assertEqual(
            digest({"domain": "sunderkey.finding-validation-result.v1", "result": body}),
            OLD_RESULT_SHA256,
        )
        archived = FindingValidationResult.from_dict(document)
        self.assertEqual(archived.validator_version, OLD_VERSION)
        self.assertEqual(archived.result_sha256, OLD_RESULT_SHA256)
        for value in (document, archived):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaisesRegex(FindingValidationError, "registry drift"):
                    DEFAULT_REGISTRY.verify_result(value)
        changed = copy.deepcopy(document)
        changed["false_positive_checks"][0]["passed"] = False
        with self.assertRaisesRegex(FindingValidationError, "hash does not match"):
            FindingValidationResult.from_dict(changed)

    def test_current_api_replay_rejects_an_archived_validator_binding(self) -> None:
        # This deny-all R0 reference compares synthetic metadata only.
        adapter = _native_adapter()
        owner = response("owner", "principal.owner", True)
        cases = (
            ("verified", response("other", "principal.other", False)),
            ("negative", response("other", "principal.other", False, 403, b"denied")),
            ("hypothesis", response("other", "principal.other", False, 200, b"different")),
        )
        for state, subject in cases:
            evidence = (owner, subject)
            inputs = {
                "adapter": adapter,
                "case_id": "case.synthetic.version." + state,
                "invocation": invocation(adapter, evidence),
                "evidence": evidence,
            }
            current = evaluate_offline_api_case(**inputs)
            with self.subTest(state=state):
                self.assertEqual(current.validator_state, state)
                self.assertEqual(
                    verify_offline_api_case(**inputs, result=current.to_dict()), current
                )
                archived = current.to_dict()
                archived["validator_result_sha256"] = OLD_RESULT_SHA256
                body = {key: value for key, value in archived.items() if key != "result_sha256"}
                archived["result_sha256"] = digest({"domain": RESULT_DOMAIN, "result": body})
                # An intact outer address does not replay or authenticate the old binding.
                with self.assertRaisesRegex(OfflineApiAssessmentError, "source evidence"):
                    verify_offline_api_case(**inputs, result=archived)

    def test_planning_archive_inspection_remains_non_authorizing(self) -> None:
        with (
            patch.object(
                planning, "verify_offline_api_batch", side_effect=AssertionError("no source replay")
            ),
            patch.object(
                planning,
                "build_offline_api_world_projection",
                side_effect=AssertionError("no case replay"),
            ),
            patch(
                "sunderkey.reference_adapters.OfflineReferenceAdapter.execute",
                side_effect=AssertionError("no adapter invocation"),
            ),
        ):
            bundle, army_registry = archived_planning_bundle()
            report = planning.inspect_offline_api_planning_integrity(
                bundle=bundle, registry=army_registry
            )
        self.assertEqual(report["status"], "valid_historical_integrity")
        self.assertEqual(report["bundle_sha256"], bundle["bundle_sha256"])
        self.assertIs(report["source_replay_performed"], False)
        self.assertIs(report["positive_use_approved"], False)
        self.assertEqual(report["qualification_effect"], "none")


if __name__ == "__main__":
    unittest.main()
