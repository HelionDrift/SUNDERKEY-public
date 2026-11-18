"""Exact signed replacement lineage for mission-policy anchor refresh."""

from __future__ import annotations

import copy
import sqlite3
import unittest
from contextlib import closing
from dataclasses import replace

from sunderkey.collaboration_mission_policy import (
    POLICY_DOMAIN,
    CollaborationMissionReconfigurationPolicy,
    VerifiedMissionPolicyPlanAnchorTransition,
    _verified_mission_policy_plan_anchor_transition,
    validate_collaboration_mission_reconfiguration_policy,
    validate_collaboration_mission_reconfiguration_selection_bindings,
)
from sunderkey.collaboration_reconfiguration_policy import (
    load_collaboration_reconfiguration_authority_policy,
)
from sunderkey.errors import CollaborationPlanError, StoreIntegrityError
from sunderkey.qualification import _canonical_sha256

from .test_collaboration_mission_policy_phase86 import AUTHORITY_PATH, policy


def changed_policy(original, **changes):
    document = original.to_dict()
    document.update(changes)
    body = {
        key: value for key, value in document.items() if key not in {"policy_id", "policy_sha256"}
    }
    digest = _canonical_sha256({"domain": POLICY_DOMAIN, "policy": body})
    return CollaborationMissionReconfigurationPolicy.from_dict(
        {**body, "policy_id": "MRP-" + digest[7:39].upper(), "policy_sha256": digest}
    )


class MissionPolicySignedReplacementAnchorContractTests(unittest.TestCase):
    def setUp(self):
        self.authority = load_collaboration_reconfiguration_authority_policy(AUTHORITY_PATH)
        self.previous = policy()
        self.policy = changed_policy(
            self.previous,
            policy_version=2,
            previous_policy_sha256=self.previous.policy_sha256,
            collaboration_plan_id="PLAN-2",
            collaboration_plan_sha256="sha256:" + "b" * 64,
        )
        self.document = {
            "store_id": "STORE-1",
            "previous_policy": self.previous.to_dict(),
            "policy": self.policy.to_dict(),
            "replacement_commit_id": "CPR-" + "1" * 32,
            "receipt_sha256": "sha256:" + "1" * 64,
            "preflight_id": "PRF-" + "2" * 32,
            "preflight_sha256": "sha256:" + "2" * 64,
            "authentication_sha256": "sha256:" + "3" * 64,
            "previous_plan_version": 1,
            "plan_version": 2,
            "previous_control_use_sequence": 4,
            "first_authority_use_sequence": 5,
            "last_authority_use_sequence": 29,
            "owner_use_sequence": 30,
            "previous_committed_at": "2026-08-03T00:00:00Z",
            "replacement_committed_at": "2026-08-03T00:01:00Z",
            "committed_at": "2026-08-03T00:02:00Z",
        }

    def validate(self, selected=None, proof=None):
        selected = selected or self.policy
        value = selected.to_dict()
        return validate_collaboration_mission_reconfiguration_policy(
            selected,
            authority_policy=self.authority,
            expected_mission_id=value["mission_id"],
            expected_collaboration_plan_id=value["collaboration_plan_id"],
            expected_collaboration_plan_sha256=value["collaboration_plan_sha256"],
            previous_policy=self.previous,
            plan_anchor_transition=proof,
        )

    def test_default_rejects_anchor_change_and_mapping_or_boolean_escape(self):
        for proof in (None, True, self.document):
            with (
                self.subTest(proof=type(proof).__name__),
                self.assertRaises(CollaborationPlanError),
            ):
                self.validate(proof=proof)

    def test_internal_verified_context_preserves_exact_policy_chain_and_wire(self):
        proof = _verified_mission_policy_plan_anchor_transition(self.document)
        selected = self.validate(proof=proof)
        self.assertEqual(selected.to_dict(), self.policy.to_dict())
        self.assertEqual(selected.to_dict()["previous_policy_sha256"], self.previous.policy_sha256)
        self.assertEqual(selected.to_dict()["runtime_effect"], "none")

    def test_read_only_source_binding_check_does_not_claim_policy_chain_authority(self):
        bindings = {
            "authority_policy": self.authority,
            "expected_mission_id": "MISSION-1",
            "expected_collaboration_plan_id": "PLAN-2",
            "expected_collaboration_plan_sha256": "sha256:" + "b" * 64,
        }
        selected = validate_collaboration_mission_reconfiguration_selection_bindings(
            self.policy, **bindings
        )
        self.assertEqual(selected.policy_sha256, self.policy.policy_sha256)
        with self.assertRaisesRegex(CollaborationPlanError, "predecessor is required"):
            validate_collaboration_mission_reconfiguration_policy(self.policy, **bindings)
        with self.assertRaisesRegex(CollaborationPlanError, "binding is stale"):
            validate_collaboration_mission_reconfiguration_selection_bindings(
                self.policy, **{**bindings, "expected_collaboration_plan_id": "PLAN-3"}
            )

    def test_forged_or_substituted_ephemeral_proof_fails_closed(self):
        proof = _verified_mission_policy_plan_anchor_transition(self.document)
        with self.assertRaisesRegex(CollaborationPlanError, "durable verification"):
            VerifiedMissionPolicyPlanAnchorTransition(proof.document_json, b"0" * 32)
        with self.assertRaises(CollaborationPlanError):
            replace(proof, document_json=proof.document_json.replace("PLAN-2", "PLAN-3"))
        substituted = changed_policy(self.policy, collaboration_plan_sha256="sha256:" + "c" * 64)
        with self.assertRaisesRegex(CollaborationPlanError, "changed its anchor"):
            self.validate(selected=substituted, proof=proof)

    def test_wrong_mission_predecessor_or_skipped_plan_is_rejected(self):
        cases = (
            {"policy": changed_policy(self.policy, mission_id="MISSION-2").to_dict()},
            {
                "policy": changed_policy(
                    self.policy, previous_policy_sha256="sha256:" + "c" * 64
                ).to_dict()
            },
            {"policy": changed_policy(self.policy, policy_version=3).to_dict()},
            {"plan_version": 3},
            {"previous_control_use_sequence": 5},
            {"owner_use_sequence": 29},
            {"replacement_committed_at": "2026-08-02T00:00:00Z"},
        )
        for changes in cases:
            with self.subTest(changes=list(changes)), self.assertRaises(CollaborationPlanError):
                _verified_mission_policy_plan_anchor_transition({**self.document, **changes})

    def test_native_cardinality_and_closed_fields_reject_aliases(self):
        for value in (True, 2.0, "2", 0):
            with self.subTest(value=value), self.assertRaises(CollaborationPlanError):
                _verified_mission_policy_plan_anchor_transition(
                    {**self.document, "plan_version": value}
                )
        extra = copy.deepcopy(self.document)
        extra["allow_unsigned"] = True
        with self.assertRaises(CollaborationPlanError):
            _verified_mission_policy_plan_anchor_transition(extra)

    def test_same_anchor_refresh_needs_no_context_and_rejects_unnecessary_context(self):
        unchanged = changed_policy(
            self.previous,
            policy_version=2,
            previous_policy_sha256=self.previous.policy_sha256,
        )
        self.assertEqual(self.validate(selected=unchanged).policy_sha256, unchanged.policy_sha256)
        with self.assertRaisesRegex(CollaborationPlanError, "unnecessary"):
            self.validate(
                selected=unchanged,
                proof=_verified_mission_policy_plan_anchor_transition(self.document),
            )


class MissionPolicySignedReplacementAnchorStoreTests(unittest.TestCase):
    def test_signed_refresh_preserves_three_policy_anchors_and_historical_head(self):
        from .test_authenticated_collaboration_plan_replacement_phase186d import (
            AuthenticatedPlanReplacementFixture,
        )

        fixture = AuthenticatedPlanReplacementFixture(self)
        fixture.replace()
        third, _ = fixture._commit_mission_policy(
            plan=fixture.replacement,
            policy_version=3,
            previous_policy_sha256=fixture.mission_policy.policy_sha256,
            marker=5000,
        )
        self.assertEqual(fixture.store.verify_store(fixture.registry).status, "valid")
        with fixture.store._read_connection() as connection:
            rows = connection.execute(
                "SELECT policy_version, previous_policy_sha256 "
                "FROM collaboration_mission_policy_commits ORDER BY policy_version"
            ).fetchall()
            self.assertEqual([row["policy_version"] for row in rows], [1, 2, 3])
            self.assertEqual(
                rows[1]["previous_policy_sha256"], fixture.bootstrap_policy.policy_sha256
            )
            self.assertEqual(
                rows[2]["previous_policy_sha256"], fixture.mission_policy.policy_sha256
            )
            row = connection.execute(
                "SELECT use_sequence FROM principal_assertion_uses WHERE assertion_id = ?",
                (
                    fixture.mission_policy.to_dict()["approval_bindings"]["mission_owner"][
                        "assertion_id"
                    ],
                ),
            ).fetchone()
            proof = fixture.store._mission_policy_signed_plan_anchor_transition(
                connection,
                policy=fixture.mission_policy,
                previous_policy=fixture.bootstrap_policy,
                store_id=fixture.store_id,
                registry=fixture.registry,
                owner_use_sequence=row["use_sequence"],
                committed_at="2026-07-30T10:10:00Z",
            )
            self.assertEqual(proof.to_dict()["policy"], fixture.mission_policy.to_dict())
            ledger = connection.execute(
                "SELECT assertion_count FROM mission_principal_ledgers"
            ).fetchone()
            with self.assertRaisesRegex(StoreIntegrityError, "historical active head"):
                fixture.store._mission_policy_signed_plan_anchor_transition(
                    connection,
                    policy=fixture.mission_policy,
                    previous_policy=fixture.bootstrap_policy,
                    store_id=fixture.store_id,
                    registry=fixture.registry,
                    owner_use_sequence=ledger["assertion_count"] + 1,
                    committed_at="2026-07-30T10:10:00Z",
                )
            self.assertEqual(third.to_dict()["policy_version"], 3)
            third_use = connection.execute(
                "SELECT use_sequence FROM principal_assertion_uses WHERE assertion_id = ?",
                (third.to_dict()["approval_bindings"]["mission_owner"]["assertion_id"],),
            ).fetchone()
            for selected, predecessor, sequence, registry in (
                (third, fixture.bootstrap_policy, third_use["use_sequence"], fixture.registry),
                (fixture.mission_policy, fixture.bootstrap_policy, row["use_sequence"], None),
                (
                    changed_policy(fixture.mission_policy, mission_id="MISSION-WRONG"),
                    fixture.bootstrap_policy,
                    row["use_sequence"],
                    fixture.registry,
                ),
            ):
                with (
                    self.subTest(policy=selected.policy_id),
                    self.assertRaises(StoreIntegrityError),
                ):
                    fixture.store._mission_policy_signed_plan_anchor_transition(
                        connection,
                        policy=selected,
                        previous_policy=predecessor,
                        store_id=fixture.store_id,
                        registry=registry,
                        owner_use_sequence=sequence,
                        committed_at="2026-07-30T10:10:00Z",
                    )
            policy_use_sequence = row["use_sequence"]
        # Corruption probes use a rollback-only connection, never a runtime bypass.
        with closing(sqlite3.connect(fixture.path)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("SAVEPOINT missing_signed_custody")
            try:
                connection.execute(
                    "DROP TRIGGER collaboration_plan_replacement_authentications_no_delete"
                )
                connection.execute(
                    "DELETE FROM collaboration_plan_replacement_authentications "
                    "WHERE preflight_id = ?",
                    (proof.to_dict()["preflight_id"],),
                )
                with self.assertRaisesRegex(StoreIntegrityError, "signed authority custody"):
                    fixture.store._mission_policy_signed_plan_anchor_transition(
                        connection,
                        policy=fixture.mission_policy,
                        previous_policy=fixture.bootstrap_policy,
                        store_id=fixture.store_id,
                        registry=fixture.registry,
                        owner_use_sequence=policy_use_sequence,
                        committed_at="2026-07-30T10:10:00Z",
                    )
            finally:
                connection.execute("ROLLBACK TO missing_signed_custody")
                connection.execute("RELEASE missing_signed_custody")
        self.assertEqual(fixture.store.verify_store(fixture.registry).status, "valid")
