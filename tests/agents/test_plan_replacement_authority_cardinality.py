"""Exact bounded replacement authority follows actual plans, not a sixteen-item fixture."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from itertools import repeat
from pathlib import Path

from scripts.build_collaboration_plan_replacement_authority_plan import (
    ASSURANCE_ID,
    CANCELLED_SPECIALIST_ID,
    CONTROL_ID,
    READINESS_ID,
    SPECIALIST_ID,
    _assertion,
    _mapping,
    _plan,
    _policy_commit,
    build_artifact,
    build_parser,
    build_sources,
)
from sunderkey.collaboration import MAX_WORK_ITEMS, build_collaboration_plan
from sunderkey.collaboration_mission_policy import (
    build_collaboration_mission_reconfiguration_policy,
)
from sunderkey.collaboration_plan_replacement_authentication import (
    EXPECTED_REQUIREMENT_COUNT,
    MAX_AUTHORITY_REQUIREMENT_COUNT,
    _normalize_credentials,
    authenticate_collaboration_plan_replacement_authority,
    collaboration_plan_replacement_authority_replay_keys,
    validate_plan_replacement_authority_requirement_count,
    validate_verified_collaboration_plan_replacement_authority_bundle,
)
from sunderkey.collaboration_plan_replacement_authority import (
    build_collaboration_plan_replacement_authority_plan,
    verify_collaboration_plan_replacement_authority_plan_offline,
)
from sunderkey.collaboration_plan_replacement_authority_upgrade import (
    build_collaboration_plan_replacement_authority_upgrade,
)
from sunderkey.collaboration_plan_replacement_operations import (
    PREPARATION_DOMAIN,
    READINESS_DOMAIN,
    SOURCE_SNAPSHOT_FIELDS,
    CollaborationPlanReplacementReadiness,
    PreparedCollaborationPlanReplacement,
    load_collaboration_plan_replacement_credentials,
)
from sunderkey.collaboration_plan_replacement_preflight import (
    build_collaboration_plan_replacement_preflight,
)
from sunderkey.errors import CollaborationPlanError, PrincipalAuthenticationError
from sunderkey.mission import MissionRequest
from sunderkey.qualification import _canonical_sha256

from .test_collaboration_plan_replacement_authentication_phase186c import (
    AUDIENCE,
    CONSTRAINTS_HASH,
    MISSION_CONTEXT_HASH,
    NOW,
    SCOPE_DOCUMENT_HASH,
    SCOPE_REFERENCE,
    STORE_ID,
    ReplacementCredentialFactory,
)

ROOT = Path(__file__).resolve().parents[2]


def _address(document, domain, label, prefix):
    body = {
        key: value
        for key, value in document.items()
        if key not in {f"{label}_id", f"{label}_sha256"}
    }
    digest = _canonical_sha256({"domain": domain, label: body})
    return {
        **body,
        f"{label}_id": prefix + digest[7:39].upper(),
        f"{label}_sha256": digest,
    }


class PlanReplacementAuthorityCardinalityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.args = build_parser().parse_args([])
        (
            cls.legacy_preflight,
            cls.legacy_prior,
            cls.legacy_replacement,
            cls.authority_policy,
            cls.legacy_policy,
            cls.registry,
            cls.registry_bytes,
        ) = build_sources(cls.args)
        raw_mission = json.loads(
            (ROOT / "examples/missions/internet-api-to-data.json").read_text(encoding="utf-8")
        )
        raw_mission["requested_specialist_ids"] = sorted(
            [*raw_mission["requested_specialist_ids"], "AOE-GC-D11-S09"]
        )
        cls.prior = build_collaboration_plan(cls.registry, MissionRequest.from_dict(raw_mission))
        cls.replacement = _plan(
            cls.prior,
            plan_id="CLP-" + "3" * 24,
            item_ids=(
                READINESS_ID,
                SPECIALIST_ID,
                CANCELLED_SPECIALIST_ID,
                CONTROL_ID,
                ASSURANCE_ID,
            ),
            changes={
                CONTROL_ID: {"dependency_ids": [READINESS_ID], "layer": 1},
                ASSURANCE_ID: {"dependency_ids": [CONTROL_ID], "layer": 2},
            },
        )
        cls.mission_policy = build_collaboration_mission_reconfiguration_policy(
            authority_policy=cls.authority_policy,
            policy_version=1,
            previous_policy_sha256=None,
            mission_id=cls.prior.mission_id,
            collaboration_plan_id=cls.prior.plan_id,
            collaboration_plan_sha256=cls.prior.content_sha256,
            maximum_delegation_depth=3,
            reconfiguration_validity_seconds=3600,
            execution_ack_timeout_seconds=300,
            maximum_plan_replacement_items=100,
            transition_activation=cls.legacy_policy.to_dict()["transition_activation"],
            mission_owner_approval=_assertion("AOE-HQ-08", "A"),
            independent_control_approval=_assertion("AOE-HQ-14", "B"),
            effective_at="2026-08-03T00:00:00Z",
            expires_at="2026-08-03T01:00:00Z",
        )
        source_state = copy.deepcopy(cls.legacy_preflight.to_dict()["source_state"])
        source_state.update(
            {"active_plan_id": cls.prior.plan_id, "active_plan_sha256": cls.prior.content_sha256}
        )
        cls.preflight = build_collaboration_plan_replacement_preflight(
            prior_plan=cls.prior,
            replacement_plan=cls.replacement,
            mission_policy=cls.mission_policy,
            mission_policy_commit=_policy_commit(cls.mission_policy),
            source_state=source_state,
            mapping_inputs=[
                _mapping(item.work_item_id, item.work_item_id)
                for item in cls.replacement.work_items
            ],
            independent_assurance_profile_id="AOE-HQ-20",
            second_control_profile_id="AOE-HQ-15",
        )
        cls.plan = build_collaboration_plan_replacement_authority_plan(
            preflight=cls.preflight,
            authority_policy=cls.authority_policy,
            mission_policy=cls.mission_policy,
            registry=cls.registry,
            registry_source=cls.registry_bytes,
            issued_at="2026-08-03T00:03:00Z",
            expires_at="2026-08-03T00:33:00Z",
        )
        cls.verified_plan = verify_collaboration_plan_replacement_authority_plan_offline(
            cls.plan,
            preflight=cls.preflight,
            prior_plan=cls.prior,
            replacement_plan=cls.replacement,
            authority_policy=cls.authority_policy,
            mission_policy=cls.mission_policy,
            registry=cls.registry,
            registry_source=cls.registry_bytes,
            verified_at="2026-08-03T00:03:00Z",
        )
        cls.upgrade = build_collaboration_plan_replacement_authority_upgrade(
            preflight=cls.preflight, army_registry=cls.registry
        )
        cls.factory = ReplacementCredentialFactory(cls.upgrade.to_dict()["authority_requirements"])
        cls.replay_keys = collaboration_plan_replacement_authority_replay_keys(
            cls.verified_plan,
            cls.upgrade,
            preflight=cls.preflight,
            army_registry=cls.registry,
        )
        cls.credentials = cls.factory.credentials(cls.plan.to_dict(), cls.replay_keys)
        cls.policy = cls.factory.verified_policy()

    def _authenticate(self, **overrides):
        arguments = {
            "preflight": self.preflight,
            "army_registry": self.registry,
            "credentials": self.credentials,
            "verified_policy": self.policy,
            "expected_audience": AUDIENCE,
            "expected_store_id": STORE_ID,
            "expected_mission_context_hash": MISSION_CONTEXT_HASH,
            "expected_scope_reference": SCOPE_REFERENCE,
            "expected_scope_document_hash": SCOPE_DOCUMENT_HASH,
            "expected_environment": "test",
            "expected_max_action_tier": "R1",
            "expected_constraints_hash": CONSTRAINTS_HASH,
            "revoked_scope_grant_sha256s": (),
            "consumed_replay_keys": (),
            "clock": lambda: NOW,
        }
        arguments.update(overrides)
        return authenticate_collaboration_plan_replacement_authority(
            self.verified_plan, self.upgrade, **arguments
        )

    def _readiness_document(self):
        preflight = self.preflight.to_dict()
        requirements = preflight["authority_requirements"]
        body = {
            "schema_version": 1,
            "observed_at": preflight["source_state"]["observed_at"],
            "store_id": STORE_ID,
            "mission_id": self.prior.mission_id,
            "mission_revision": preflight["source_state"]["mission_revision"],
            "active_head": {
                "plan_id": self.prior.plan_id,
                "plan_sha256": self.prior.content_sha256,
                "plan_version": 1,
            },
            "prior_plan": self.prior.to_dict(),
            "replacement_plan": self.replacement.to_dict(),
            "mission_policy": self.mission_policy.to_dict(),
            "authority_policy": self.authority_policy.to_dict(),
            "trust_high_water": {
                "policy_id": "POLICY-CARDINALITY-OFFLINE",
                "policy_version": 1,
                "policy_sha256": "sha256:" + "a" * 64,
                "applied_at": "2026-08-03T00:01:00Z",
            },
            "scope_high_water": {
                "accepted_grant_count": 0,
                "revocation_count": 0,
                "revocation_head_sha256": "sha256:" + "b" * 64,
                "scope_state_sha256": "sha256:" + "c" * 64,
            },
            "principal_ledger_high_water": {
                "assertion_count": 0,
                "head_sha256": "sha256:" + "d" * 64,
                "expert_review_consumed_count": 0,
                "expert_review_consumed_sha256": "sha256:" + "e" * 64,
            },
            "replacement_replay_high_water": {
                "consumed_count": 0,
                "consumed_replay_keys_sha256": _canonical_sha256([]),
            },
            "source_snapshot_hashes": {
                name: preflight["source_state"][name] for name in SOURCE_SNAPSHOT_FIELDS
            },
            "mapping_intents": sorted(
                (
                    {
                        "source_work_item_id": item["source_work_item_id"],
                        "replacement_work_item_id": item["replacement_work_item_id"],
                        "cross_command_evidence": item["cross_command_evidence"],
                    }
                    for item in preflight["item_mappings"]
                ),
                key=lambda item: item["source_work_item_id"],
            ),
            "work_state": {
                item.work_item_id: {
                    "state": "not_completed",
                    "latest_transition_id": None,
                    "latest_transition_kind": None,
                    "completed_result_sha256": None,
                }
                for item in self.prior.work_items
            },
            "preflight": preflight,
            "required_authority_operations": [
                {
                    key: item[key]
                    for key in (
                        "requirement_id",
                        "operation",
                        "role",
                        "authority_id",
                        "work_item_id",
                    )
                }
                for item in requirements
            ],
            "required_assertion_count": len(requirements),
            "required_replay_key_count": len(requirements),
            "drain_blockers": [],
            "required_drain_operations": [],
            "readiness_status": "ready_for_signed_authority",
            "runtime_effect": "none",
        }
        return _address(body, READINESS_DOMAIN, "readiness", "RRA-")

    def _credential_document(self):
        return {
            "schema_version": 1,
            "credentials": [
                {
                    "source_requirement_id": item.source_requirement_id,
                    "upgraded_requirement_id": item.upgraded_requirement_id,
                    "replay_key_sha256": item.replay_key_sha256,
                    "scope_grant": item.scope_grant.to_dict(),
                    "assertion": item.assertion.to_dict(),
                }
                for item in self.credentials
            ],
        }

    def _load_credentials(self, document):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "offline-credentials.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            return load_collaboration_plan_replacement_credentials(path)

    def test_full_sixteen_item_plan_to_five_item_subset_derives_twenty_five(self):
        self.assertEqual(len(self.prior.work_items), 16)
        self.assertEqual(len(self.replacement.work_items), 5)
        self.assertEqual(len(self.preflight.to_dict()["cancellation_actions"]), 11)
        self.assertEqual(len(self.preflight.to_dict()["authority_requirements"]), 25)
        self.assertEqual(len(self.plan.to_dict()["assertion_requirements"]), 25)
        self.assertEqual(len(self.upgrade.to_dict()["authority_requirements"]), 25)
        bundle = self._authenticate()
        self.assertEqual(bundle.requirement_count, 25)
        self.assertEqual(len(bundle.requirements), 25)
        self.assertEqual(len(bundle.replay_keys), 25)
        refreshed = validate_verified_collaboration_plan_replacement_authority_bundle(
            bundle,
            verified_authority_plan=self.verified_plan,
            authority_upgrade=self.upgrade,
            preflight=self.preflight,
            army_registry=self.registry,
            verified_policy=self.policy,
            revoked_scope_grant_sha256s=(),
            consumed_replay_keys=(),
            clock=lambda: NOW,
        )
        self.assertEqual(refreshed.requirement_count, 25)
        self.assertEqual(refreshed.composition_sha256, bundle.composition_sha256)

    def test_legacy_sixteen_artifact_and_credentials_remain_compatible(self):
        checked = json.loads(
            (ROOT / "registry/collaboration-plan-replacement-authority-plan-v1.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(EXPECTED_REQUIREMENT_COUNT, 16)
        self.assertEqual(build_artifact(self.args), checked)
        self.assertEqual(len(checked["assertion_requirements"]), 16)
        legacy_plan = build_collaboration_plan_replacement_authority_plan(
            preflight=self.legacy_preflight,
            authority_policy=self.authority_policy,
            mission_policy=self.legacy_policy,
            registry=self.registry,
            registry_source=self.registry_bytes,
            issued_at="2026-08-03T00:03:00Z",
            expires_at="2026-08-03T00:33:00Z",
        )
        self.assertEqual(legacy_plan.to_dict(), checked)

    def test_native_bounded_requirement_count_rejects_aliases_and_out_of_bounds(self):
        class IntegerAlias(int):
            pass

        for value in (1, 16, 25, MAX_AUTHORITY_REQUIREMENT_COUNT):
            self.assertEqual(validate_plan_replacement_authority_requirement_count(value), value)
        self.assertEqual(MAX_AUTHORITY_REQUIREMENT_COUNT, 4 * MAX_WORK_ITEMS + 4)
        for value in (
            True,
            False,
            16.0,
            25.0,
            "25",
            None,
            0,
            -1,
            MAX_AUTHORITY_REQUIREMENT_COUNT + 1,
            IntegerAlias(25),
        ):
            with self.subTest(value=value), self.assertRaises(PrincipalAuthenticationError):
                validate_plan_replacement_authority_requirement_count(value)

    def test_missing_extra_or_duplicate_credentials_do_not_satisfy_dynamic_count(self):
        for credentials in (
            self.credentials[:-1],
            self.credentials + self.credentials[:1],
            self.credentials[:-1] + self.credentials[:1],
        ):
            with (
                self.subTest(count=len(credentials)),
                self.assertRaises(PrincipalAuthenticationError),
            ):
                self._authenticate(credentials=credentials)

    def test_dynamic_normalizer_bounds_even_an_unending_iterable(self):
        with self.assertRaises(PrincipalAuthenticationError):
            _normalize_credentials(repeat(self.credentials[0]))
        self.assertEqual(len(_normalize_credentials(iter(self.credentials))), 25)
        with self.assertRaises(PrincipalAuthenticationError):
            _normalize_credentials(())

    def test_readiness_and_preparation_accept_exact_twenty_five_counts(self):
        readiness = CollaborationPlanReplacementReadiness.from_dict(self._readiness_document())
        self.assertEqual(readiness.to_dict()["required_assertion_count"], 25)
        body = {
            "schema_version": 1,
            "prepared_at": readiness.to_dict()["observed_at"],
            "readiness": readiness.to_dict(),
            "authority_plan": self.plan.to_dict(),
            "authority_upgrade": self.upgrade.to_dict(),
            "expected_plan_version": 1,
            "preparation_status": "awaiting_exact_signed_authority",
            "runtime_effect": "none",
        }
        prepared = PreparedCollaborationPlanReplacement.from_dict(
            _address(body, PREPARATION_DOMAIN, "preparation", "RPP-")
        )
        self.assertEqual(prepared.to_dict()["readiness"]["required_replay_key_count"], 25)

    def test_readiness_rejects_resealed_native_alias_and_wrong_counts(self):
        for field in ("required_assertion_count", "required_replay_key_count"):
            for value in (True, 25.0, 16, 24, 26, 0, MAX_AUTHORITY_REQUIREMENT_COUNT + 1):
                document = self._readiness_document()
                document[field] = value
                with (
                    self.subTest(field=field, value=value),
                    self.assertRaises(CollaborationPlanError),
                ):
                    CollaborationPlanReplacementReadiness.from_dict(
                        _address(document, READINESS_DOMAIN, "readiness", "RRA-")
                    )

    def test_readiness_exact_operations_cannot_be_missing_extra_or_duplicated(self):
        original = self._readiness_document()
        for operations in (
            original["required_authority_operations"][:-1],
            original["required_authority_operations"]
            + original["required_authority_operations"][:1],
            original["required_authority_operations"][:-1]
            + original["required_authority_operations"][:1],
        ):
            document = copy.deepcopy(original)
            document["required_authority_operations"] = operations
            document["required_assertion_count"] = len(operations)
            document["required_replay_key_count"] = len(operations)
            with self.subTest(count=len(operations)), self.assertRaises(CollaborationPlanError):
                CollaborationPlanReplacementReadiness.from_dict(
                    _address(document, READINESS_DOMAIN, "readiness", "RRA-")
                )

    def test_credential_document_accepts_twenty_five_without_fabricating_authority(self):
        loaded = self._load_credentials(self._credential_document())
        self.assertEqual(loaded, self.credentials)
        self.assertEqual(self._authenticate(credentials=loaded).requirement_count, 25)

    def test_credential_document_rejects_native_schema_alias_and_duplicate_coverage(self):
        for schema_version in (True, 1.0):
            document = self._credential_document()
            document["schema_version"] = schema_version
            with (
                self.subTest(schema_version=schema_version),
                self.assertRaises(PrincipalAuthenticationError),
            ):
                self._load_credentials(document)
        duplicated = self._credential_document()
        duplicated["credentials"][-1] = duplicated["credentials"][0]
        with self.assertRaisesRegex(PrincipalAuthenticationError, "duplicate coverage"):
            self._load_credentials(duplicated)
        empty = self._credential_document()
        empty["credentials"] = []
        with self.assertRaises(PrincipalAuthenticationError):
            self._load_credentials(empty)


if __name__ == "__main__":
    unittest.main()
