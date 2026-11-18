"""Authenticated MissionStore custody tests for Phase194 expert review."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator

from scripts.build_expert_review import (
    authenticated_expert_review_registration_schema,
)
from sunderkey.authenticated_expert_review import (
    AuthenticatedExpertReviewSnapshotRegistration,
    SQLiteAuthenticatedExpertReviewCustody,
    expert_review_snapshot_registration_intent,
    expert_work_product_review_intent,
    expert_workspace_review_close_intent,
    expert_workspace_review_revoke_intent,
    verify_authenticated_expert_review_store,
)
from sunderkey.collaboration_plan_replacement_operations import (
    _drain_state,
    _expert_review_high_water,
)
from sunderkey.errors import (
    PrincipalAuthenticationError,
    StoreConflictError,
    StoreError,
    StoreIntegrityError,
)
from sunderkey.expert_review import (
    ClosureDisposition,
    ReviewDecision,
    build_expert_review_closure_request,
    build_expert_review_submission,
)
from sunderkey.expert_runtime import (
    build_execution_envelope,
    content_address_work_product,
    parse_execution_envelope,
)
from sunderkey.expert_workspace import (
    SQLiteExpertWorkspaceStore,
    build_expert_workspace_definition,
)
from sunderkey.identity import (
    PrincipalOperation,
    PrincipalTrustPolicy,
    compute_operation_intent_hash,
)
from sunderkey.qualification import _canonical_sha256
from sunderkey.scope import ScopeGrantAcceptanceService

from . import test_authenticated_expert_model_execution_phase193 as phase193_fixture
from .test_identity_phase4 import AUDIENCE, SCOPE_DOCUMENT_HASH, SUBJECT, b64url

ASSURANCE_PROFILE = "AOE-HQ-18"
CONTROL_PROFILE = "AOE-HQ-12"
ASSURANCE_SUBJECT = "phase194-assurance-reviewer"
CONTROL_SUBJECT = "phase194-control-reviewer"
POLICY_VERSION = 194
ZERO = "sha256:" + "0" * 64
ONE = "sha256:" + "1" * 64
ACTIVATOR_ID = phase193_fixture.ACTIVATOR_ID
MISSION_ID = phase193_fixture.MISSION_ID


class AuthenticatedExpertReviewPhase194Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        fixture = phase193_fixture.AuthenticatedExpertModelExecutionPhase193Tests
        fixture.setUpClass()
        cls.registry = fixture.registry
        cls.catalog = fixture.catalog

    def setUp(self) -> None:
        phase193_fixture.AuthenticatedExpertModelExecutionPhase193Tests.setUp(self)
        self.now += timedelta(seconds=1)
        value = self.policy.to_dict()
        operations = sorted(
            {
                PrincipalOperation.COLLABORATION_ACTIVATE.value,
                PrincipalOperation.MODEL_EXECUTE.value,
                PrincipalOperation.EXPERT_REVIEW_SNAPSHOT_REGISTER.value,
                PrincipalOperation.EXPERT_WORK_PRODUCT_REVIEW.value,
                PrincipalOperation.EXPERT_WORKSPACE_REVIEW_CLOSE.value,
                PrincipalOperation.EXPERT_WORKSPACE_REVIEW_REVOKE.value,
            }
        )
        profiles = sorted({ACTIVATOR_ID, ASSURANCE_PROFILE, CONTROL_PROFILE})
        subjects = sorted({SUBJECT, ASSURANCE_SUBJECT, CONTROL_SUBJECT})
        value.update(
            {
                "policy_version": POLICY_VERSION,
                "allowed_operations": operations,
                "allowed_profiles": profiles,
                "allowed_subjects": subjects,
            }
        )
        for key in value["keys"]:
            key["allowed_operations"] = operations
            key["allowed_profiles"] = profiles
            key["allowed_subjects"] = subjects
        unsigned = PrincipalTrustPolicy.from_dict(value)
        policy = replace(
            unsigned,
            signature=b64url(self.factory.root_private.sign(unsigned.signing_bytes())),
        )
        self.trust.apply_policy(policy)
        self.review_policy = policy
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.workspace_path = Path(temporary.name) / "phase194-workspace.sqlite3"
        self.workspace = SQLiteExpertWorkspaceStore(self.workspace_path)
        self.workspace.initialize()
        self.workspace_state = self._complete_workspace()
        self.snapshot = self.workspace.export_review_snapshot(
            self.workspace_state.workspace_id,
            runtime_catalog=self.catalog,
            expert_registry=self.registry,
        )
        self.review = SQLiteAuthenticatedExpertReviewCustody(
            self.store,
            self.registry,
            workspace_store=self.workspace,
            runtime_catalog=self.catalog,
            clock=lambda: self.now,
        )

    def _complete_workspace(self):
        definition = build_expert_workspace_definition(
            self.catalog,
            tenant_id="tenant-phase194",
            mission_id=MISSION_ID,
            plan_id=self.plan.plan_id,
            target_scope_sha256=SCOPE_DOCUMENT_HASH,
            authority_snapshot_sha256=ZERO,
            evidence_snapshot_sha256=ONE,
            assignments=[
                {
                    "work_id": self.work.work_item_id,
                    "profile_id": self.pack["profile_id"],
                    "command_id": self.pack["command_id"],
                    "runtime_pack_id": self.pack["runtime_pack_id"],
                    "runtime_pack_sha256": self.pack["runtime_pack_sha256"],
                    "maximum_attempts": 2,
                }
            ],
            dependencies=[],
            review_requirements=[
                {
                    "work_id": self.work.work_item_id,
                    "required": True,
                    "reviewer_profile_ids": [ASSURANCE_PROFILE],
                    "producer_excluded": True,
                }
            ],
        )
        created_at = int(self.now.timestamp()) - 30
        state = self.workspace.create_workspace(
            definition,
            self.catalog,
            created_at=created_at,
        )
        envelope = build_execution_envelope(
            self.pack,
            self.catalog,
            mission_id=MISSION_ID,
            plan_id=self.plan.plan_id,
            work_id=self.work.work_item_id,
            target_scope_sha256=SCOPE_DOCUMENT_HASH,
            authority_snapshot_sha256=ZERO,
            evidence_snapshot_sha256=ONE,
            evidence_requirement_ids=["evidence-phase194"],
            cleanup_requirement_ids=["cleanup-phase194"],
            approval_requirement_ids=["approval-phase194"],
            context_items=[
                {
                    "context_id": "context-phase194",
                    "context_kind": "target_content",
                    "content": "Bounded authenticated review evidence.",
                    "content_sha256": _canonical_sha256("Bounded authenticated review evidence."),
                    "estimated_tokens": 38,
                    "trust": "untrusted_data",
                }
            ],
        )
        parsed = parse_execution_envelope(envelope, self.pack, self.catalog)
        lease = self.workspace.acquire_lease(
            state.workspace_id,
            tenant_id="tenant-phase194",
            expected_revision=0,
            envelope=envelope,
            runtime_catalog=self.catalog,
            acquired_at=created_at + 5,
            lease_seconds=20,
        )
        product = content_address_work_product(
            {
                "schema_version": 1,
                "product_type": "observation",
                "runtime_catalog_sha256": self.catalog.catalog_sha256,
                "runtime_pack_id": self.pack["runtime_pack_id"],
                "runtime_pack_sha256": self.pack["runtime_pack_sha256"],
                "producer_profile_id": self.pack["profile_id"],
                "execution_envelope_id": parsed.envelope_id,
                "execution_envelope_sha256": parsed.envelope_sha256,
                "mission_id": MISSION_ID,
                "plan_id": self.plan.plan_id,
                "work_id": self.work.work_item_id,
                "summary": "Authenticated review candidate.",
                "confidence": "moderate",
                "uncertainty": "Independent review is pending.",
                "evidence_refs": [ONE],
                "lineage_product_ids": [],
                "independent_review": {
                    "required": True,
                    "status": "not_reviewed",
                    "reviewer_profile_ids": [],
                    "producer_excluded": True,
                },
                "payload": {"observed_facts": ["Fact."], "collection_limits": ["Limit."]},
                "model_output_effect": "advisory_only",
                "tool_effect": "none",
                "authorization_effect": "none",
            }
        )
        self.workspace.accept_work_product(
            state.workspace_id,
            tenant_id="tenant-phase194",
            expected_revision=lease.workspace_revision,
            lease_id=lease.lease_id,
            fencing_token=lease.fencing_token,
            work_product=product,
            runtime_catalog=self.catalog,
            accepted_at=created_at + 10,
        )
        return state

    def _authority(self, profile_id, subject, operation, intent, letter):
        grant = self.factory.grant(
            grant_id="SGR-" + letter * 32,
            profile_id=profile_id,
            subject=subject,
            store_id=self.store_id,
            mission_id=MISSION_ID,
            mission_context_hash=self.stored.context_hash,
            scope_reference=self.mission.scope_reference,
            scope_document_hash=SCOPE_DOCUMENT_HASH,
            environment=self.mission.environment.value,
            max_action_tier=self.mission.max_action_tier.value,
            constraints_hash=self.model_grant.to_dict()["constraints_hash"],
            operations=[operation.value],
            issued_at="2026-07-30T10:05:00Z",
            not_before="2026-07-30T10:05:00Z",
            expires_at="2026-07-30T10:30:00Z",
            policy_version=POLICY_VERSION,
        )
        ScopeGrantAcceptanceService(self.store, self.registry).accept(grant)
        return self.factory.assertion(
            grant=grant,
            assertion_id="PAS-" + letter * 32,
            policy_version=POLICY_VERSION,
            scope_grant_id=grant.grant_id,
            subject=subject,
            profile_id=profile_id,
            audience=AUDIENCE,
            store_id=self.store_id,
            mission_id=MISSION_ID,
            operation=operation,
            operation_intent_sha256=compute_operation_intent_hash(operation, intent),
            issued_at="2026-07-30T10:05:00Z",
            not_before="2026-07-30T10:05:00Z",
            expires_at="2026-07-30T10:09:00Z",
        )

    def _close(self):
        register_intent = expert_review_snapshot_registration_intent(
            self.snapshot,
            active_plan_sha256=self.plan.content_sha256,
            active_plan_version=1,
            mission_revision=self.stored.revision,
            principal_profile_id=ASSURANCE_PROFILE,
        )
        register = self._authority(
            ASSURANCE_PROFILE,
            ASSURANCE_SUBJECT,
            PrincipalOperation.EXPERT_REVIEW_SNAPSHOT_REGISTER,
            register_intent,
            "C",
        )
        registration = self.review.register_snapshot(
            register,
            self.snapshot,
            workspace_store=self.workspace,
            runtime_catalog=self.catalog,
        )
        slot = self.snapshot.to_dict()["review_slots"][0]
        submission = build_expert_review_submission(
            snapshot=self.snapshot,
            work_id=slot["work_id"],
            product_id=slot["product_id"],
            product_sha256=slot["product_sha256"],
            reviewer_profile_id=ASSURANCE_PROFILE,
            reviewer_role=slot["reviewer_role"],
            decision=ReviewDecision.ACCEPTED,
            reason_code="evidence-sufficient",
            affected_work_ids=(),
            required_correction_ids=(),
            rationale="The bounded evidence supports the advisory result.",
        )
        review_intent = expert_work_product_review_intent(
            self.snapshot,
            submission,
            active_plan_sha256=self.plan.content_sha256,
            active_plan_version=1,
            mission_revision=self.stored.revision,
            principal_profile_id=ASSURANCE_PROFILE,
        )
        reviewer = self._authority(
            ASSURANCE_PROFILE,
            ASSURANCE_SUBJECT,
            PrincipalOperation.EXPERT_WORK_PRODUCT_REVIEW,
            review_intent,
            "D",
        )
        receipt = self.review.record_review(
            reviewer,
            submission,
            workspace_store=self.workspace,
            runtime_catalog=self.catalog,
        )
        request = build_expert_review_closure_request(
            self.snapshot,
            (receipt,),
            expected_disposition=ClosureDisposition.ACCEPTED,
            closer_profile_id=CONTROL_PROFILE,
            requested_at=int(self.now.timestamp()),
        )
        close_intent = expert_workspace_review_close_intent(
            self.snapshot,
            request,
            (receipt,),
            active_plan_sha256=self.plan.content_sha256,
            active_plan_version=1,
            mission_revision=self.stored.revision,
            principal_profile_id=CONTROL_PROFILE,
        )
        closer = self._authority(
            CONTROL_PROFILE,
            CONTROL_SUBJECT,
            PrincipalOperation.EXPERT_WORKSPACE_REVIEW_CLOSE,
            close_intent,
            "E",
        )
        proof = self.review.close_review(
            closer,
            request,
            workspace_store=self.workspace,
            runtime_catalog=self.catalog,
        )
        return registration, receipt, proof

    def _registration_authority(self, letter="C"):
        intent = expert_review_snapshot_registration_intent(
            self.snapshot,
            active_plan_sha256=self.plan.content_sha256,
            active_plan_version=1,
            mission_revision=self.stored.revision,
            principal_profile_id=ASSURANCE_PROFILE,
        )
        return self._authority(
            ASSURANCE_PROFILE,
            ASSURANCE_SUBJECT,
            PrincipalOperation.EXPERT_REVIEW_SNAPSHOT_REGISTER,
            intent,
            letter,
        )

    def test_authenticated_closure_projection_restart_and_replay(self) -> None:
        registration, receipt, proof = self._close()
        self.assertTrue(registration.registration_id.startswith("ERRG-"))
        self.assertTrue(receipt.receipt_id.startswith("ERR-"))
        application = self.review.apply_closure(
            proof,
            workspace_store=self.workspace,
            runtime_catalog=self.catalog,
        )
        restarted = SQLiteAuthenticatedExpertReviewCustody(
            self.store,
            self.registry,
            workspace_store=self.workspace,
            runtime_catalog=self.catalog,
            clock=lambda: self.now,
        )
        self.assertFalse(restarted.validates_closure_proof(proof))
        replay = restarted.verify_closure(
            proof.records.closure.closure_id,
            workspace_store=self.workspace,
            runtime_catalog=self.catalog,
        )
        self.assertEqual(
            application,
            restarted.apply_closure(
                replay,
                workspace_store=self.workspace,
                runtime_catalog=self.catalog,
            ),
        )
        with self.store._read_connection() as connection:
            verify_authenticated_expert_review_store(connection, mission_id=MISSION_ID)
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM authenticated_expert_review_closure_projections"
                ).fetchone()[0],
                1,
            )
        schema_path = (
            Path(__file__).resolve().parents[2]
            / "registry"
            / "schemas"
            / "authenticated-expert-review-registration-v1.schema.json"
        )
        schema = authenticated_expert_review_registration_schema()
        self.assertEqual(
            schema_path.read_text(encoding="utf-8"),
            json.dumps(schema, indent=2, sort_keys=True) + "\n",
        )
        Draft202012Validator(schema).validate(registration.to_dict())
        invalid = registration.to_dict()
        invalid["schema_version"] = True
        with self.assertRaises(StoreError):
            AuthenticatedExpertReviewSnapshotRegistration.from_dict(invalid)
        invalid = registration.to_dict()
        invalid["effects"]["network_call_performed"] = 0
        with self.assertRaises(StoreError):
            AuthenticatedExpertReviewSnapshotRegistration.from_dict(invalid)

    def test_portable_records_and_forged_proof_cannot_project(self) -> None:
        _registration, _receipt, proof = self._close()
        self.assertFalse(hasattr(type(proof), "_seal"))
        with self.assertRaisesRegex(StoreError, "authenticated closure proof"):
            self.workspace.apply_review_closure(
                proof.records,
                authority=self.review,
                authorization_token=b"portable-records-have-no-capability",
                mission_store_id=self.store_id,
                runtime_catalog=self.catalog,
                expert_registry=self.registry,
                applied_at=int(self.now.timestamp()),
            )
        with self.assertRaisesRegex(StoreError, "authenticated closure proof"):
            self.workspace.apply_review_closure(
                proof,
                authority=self.review,
                authorization_token=b"proof-alone-is-not-point-of-use-authority",
                mission_store_id=self.store_id,
                runtime_catalog=self.catalog,
                expert_registry=self.registry,
                applied_at=int(self.now.timestamp()),
            )
        forged = replace(proof, mission_revision=proof.mission_revision + 1)
        with self.assertRaisesRegex(PrincipalAuthenticationError, "valid local closure proof"):
            self.review.apply_closure(
                forged,
                workspace_store=self.workspace,
                runtime_catalog=self.catalog,
            )
        substituted_records = replace(proof.records, receipts=())
        substituted_proof = replace(proof, records=substituted_records)
        with self.assertRaisesRegex(StoreError, "authenticated closure proof"):
            self.workspace.apply_review_closure(
                substituted_proof,
                authority=self.review,
                authorization_token=b"substituted-proof-has-no-capability",
                mission_store_id=self.store_id,
                runtime_catalog=self.catalog,
                expert_registry=self.registry,
                applied_at=int(self.now.timestamp()),
            )

    def test_caller_cannot_substitute_workspace_or_catalog_authority(self) -> None:
        assertion = self._registration_authority()
        alternate_workspace = SQLiteExpertWorkspaceStore(self.workspace_path)
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "Workspace adapter is not the custody service authority",
        ):
            self.review.register_snapshot(
                assertion,
                self.snapshot,
                workspace_store=alternate_workspace,
                runtime_catalog=self.catalog,
            )
        substituted_catalog = replace(self.catalog)
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "Runtime catalog is not the custody service authority",
        ):
            self.review.register_snapshot(
                assertion,
                self.snapshot,
                workspace_store=self.workspace,
                runtime_catalog=substituted_catalog,
            )

    def test_concurrent_closure_projection_is_exactly_idempotent(self) -> None:
        _registration, _receipt, proof = self._close()

        def apply_once(_index):
            return self.review.apply_closure(
                proof,
                workspace_store=self.workspace,
                runtime_catalog=self.catalog,
            ).application_sha256

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(apply_once, range(2)))
        self.assertEqual(len(set(results)), 1)

    def test_revocation_revalidates_and_projects_under_control_authority(self) -> None:
        _registration, _receipt, proof = self._close()
        intent = expert_workspace_review_revoke_intent(
            proof.records.closure,
            active_plan_id=self.plan.plan_id,
            active_plan_sha256=self.plan.content_sha256,
            active_plan_version=1,
            mission_id=MISSION_ID,
            mission_revision=self.stored.revision,
            principal_profile_id=CONTROL_PROFILE,
            reason_code="control-revocation",
        )
        assertion = self._authority(
            CONTROL_PROFILE,
            CONTROL_SUBJECT,
            PrincipalOperation.EXPERT_WORKSPACE_REVIEW_REVOKE,
            intent,
            "F",
        )
        with self.assertRaisesRegex(StoreConflictError, "projected before"):
            self.review.revoke_closure(
                assertion,
                proof.records.closure.closure_id,
                reason_code="control-revocation",
                workspace_store=self.workspace,
                runtime_catalog=self.catalog,
            )
        self.review.apply_closure(
            proof,
            workspace_store=self.workspace,
            runtime_catalog=self.catalog,
        )
        revocation = self.review.revoke_closure(
            assertion,
            proof.records.closure.closure_id,
            reason_code="control-revocation",
            workspace_store=self.workspace,
            runtime_catalog=self.catalog,
        )
        with self.assertRaisesRegex(StoreConflictError, "revoked"):
            self.review.apply_closure(
                proof,
                workspace_store=self.workspace,
                runtime_catalog=self.catalog,
            )
        projected = self.review.apply_revocation(
            revocation,
            workspace_store=self.workspace,
            runtime_catalog=self.catalog,
        )
        self.assertEqual(projected, revocation.records.revocation)

    def test_whole_store_verifier_rejects_projection_coercion_and_tamper(self) -> None:
        _registration, _receipt, proof = self._close()
        self.review.apply_closure(
            proof,
            workspace_store=self.workspace,
            runtime_catalog=self.catalog,
        )
        with sqlite3.connect(self.path) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = OFF")
            connection.execute(
                "DROP TRIGGER authenticated_expert_review_closure_projection_immutable"
            )
            connection.execute(
                "UPDATE authenticated_expert_review_closure_projections SET application_json = ?",
                ('{"schema_version":true}',),
            )
            with self.assertRaises(StoreIntegrityError):
                verify_authenticated_expert_review_store(connection)

    def test_whole_store_verifier_rejects_normalized_snapshot_substitution(self) -> None:
        self.review.register_snapshot(
            self._registration_authority(),
            self.snapshot,
            workspace_store=self.workspace,
            runtime_catalog=self.catalog,
        )
        with sqlite3.connect(self.path) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("DROP TRIGGER authenticated_expert_review_product_immutable")
            connection.execute(
                "UPDATE authenticated_expert_review_snapshot_products "
                "SET command_id = command_id || '-substituted'"
            )
            with self.assertRaisesRegex(StoreIntegrityError, "normalized snapshot"):
                verify_authenticated_expert_review_store(connection)

    def test_whole_store_reconstructs_closure_and_authority_sources(self) -> None:
        _registration, receipt, _proof = self._close()
        with sqlite3.connect(self.path) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = OFF")
            connection.execute("DROP TRIGGER authenticated_expert_review_closure_immutable")
            connection.execute(
                "UPDATE authenticated_expert_review_closures SET rejected_work_ids_json = ?",
                ('["substituted-work"]',),
            )
            with self.assertRaisesRegex(StoreIntegrityError, "disposition material"):
                verify_authenticated_expert_review_store(connection)
            connection.rollback()
        with sqlite3.connect(self.path) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = OFF")
            connection.execute("DROP TRIGGER authenticated_expert_review_receipt_immutable")
            connection.execute("DROP TRIGGER authenticated_expert_review_replay_immutable")
            connection.execute("DROP TRIGGER principal_assertion_use_immutable")
            connection.execute(
                "UPDATE authenticated_expert_review_receipts "
                "SET domain_request_sha256 = ? WHERE receipt_id = ?",
                (ZERO, receipt.receipt_id),
            )
            connection.execute(
                "UPDATE authenticated_expert_review_replay_uses "
                "SET domain_request_sha256 = ? WHERE result_id = ?",
                (ZERO, receipt.receipt_id),
            )
            connection.execute(
                "UPDATE principal_assertion_uses SET domain_request_hash = ? WHERE operation = ?",
                (ZERO, PrincipalOperation.EXPERT_WORK_PRODUCT_REVIEW.value),
            )
            with self.assertRaisesRegex(StoreIntegrityError, "authority derivation"):
                verify_authenticated_expert_review_store(connection)

    def test_registration_failure_rolls_back_assertion_effect_and_domain_custody(self) -> None:
        assertion = self._registration_authority()
        with (
            patch(
                "sunderkey.authenticated_expert_review.verify_authenticated_expert_review_store",
                side_effect=StoreIntegrityError("injected verification failure"),
            ),
            self.assertRaisesRegex(StoreIntegrityError, "injected"),
        ):
            self.review.register_snapshot(
                assertion,
                self.snapshot,
                workspace_store=self.workspace,
                runtime_catalog=self.catalog,
            )
        with self.store._read_connection() as connection:
            for table, predicate in (
                ("principal_assertion_uses", "issuer = ? AND assertion_id = ?"),
                ("principal_assertion_effects", "issuer = ? AND assertion_id = ?"),
                (
                    "authenticated_expert_review_replay_uses",
                    "assertion_issuer = ? AND assertion_id = ?",
                ),
                (
                    "authenticated_expert_review_snapshot_registrations",
                    "assertion_issuer = ? AND assertion_id = ?",
                ),
            ):
                self.assertEqual(
                    connection.execute(
                        f"SELECT COUNT(*) FROM {table} WHERE {predicate}",
                        (assertion.issuer, assertion.assertion_id),
                    ).fetchone()[0],
                    0,
                )
        self.review.register_snapshot(
            assertion,
            self.snapshot,
            workspace_store=self.workspace,
            runtime_catalog=self.catalog,
        )

    def test_projection_crash_is_reconciled_without_portable_authority(self) -> None:
        _registration, _receipt, proof = self._close()
        original = verify_authenticated_expert_review_store
        calls = 0

        def fail_after_workspace_projection(connection, mission_id=None):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise StoreIntegrityError("injected projection custody failure")
            return original(connection, mission_id=mission_id)

        with (
            patch(
                "sunderkey.authenticated_expert_review.verify_authenticated_expert_review_store",
                side_effect=fail_after_workspace_projection,
            ),
            self.assertRaisesRegex(StoreIntegrityError, "injected projection"),
        ):
            self.review.apply_closure(
                proof,
                workspace_store=self.workspace,
                runtime_catalog=self.catalog,
            )
        with self.store._read_connection() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM authenticated_expert_review_closure_projections"
                ).fetchone()[0],
                0,
            )
        application = self.review.apply_closure(
            proof,
            workspace_store=self.workspace,
            runtime_catalog=self.catalog,
        )
        self.assertEqual(
            application.to_dict()["closure_id"],
            proof.records.closure.closure_id,
        )

    def test_proof_fails_closed_after_clock_or_trust_generation_drift(self) -> None:
        _registration, _receipt, proof = self._close()
        current = self.now
        self.now -= timedelta(minutes=1)
        with self.assertRaises(PrincipalAuthenticationError):
            self.review.apply_closure(
                proof,
                workspace_store=self.workspace,
                runtime_catalog=self.catalog,
            )
        self.now = current + timedelta(seconds=1)
        value = self.review_policy.to_dict()
        value["policy_version"] = POLICY_VERSION + 1
        unsigned = PrincipalTrustPolicy.from_dict(value)
        policy = replace(
            unsigned,
            signature=b64url(self.factory.root_private.sign(unsigned.signing_bytes())),
        )
        self.trust.apply_policy(policy)
        with self.assertRaises(PrincipalAuthenticationError):
            self.review.apply_closure(
                proof,
                workspace_store=self.workspace,
                runtime_catalog=self.catalog,
            )

    def test_plan_replacement_drain_tracks_review_and_projection_boundaries(self) -> None:
        assertion = self._registration_authority()
        self.review.register_snapshot(
            assertion,
            self.snapshot,
            workspace_store=self.workspace,
            runtime_catalog=self.catalog,
        )
        with self.store._read_connection() as connection:
            blockers, operations = _drain_state(
                connection,
                MISSION_ID,
                self.plan.plan_id,
                set(),
            )
        self.assertIn("expert_review_incomplete", {item["blocker_code"] for item in blockers})
        self.assertIn("complete_expert_review", {item["operation"] for item in operations})
        _registration, _receipt, proof = self._close()
        with self.store._read_connection() as connection:
            blockers, _operations = _drain_state(
                connection,
                MISSION_ID,
                self.plan.plan_id,
                set(),
            )
            high_water = _expert_review_high_water(connection, MISSION_ID)
        self.assertIn(
            "expert_review_closure_unprojected",
            {item["blocker_code"] for item in blockers},
        )
        self.assertEqual(high_water["expert_review_consumed_count"], 3)
        self.review.apply_closure(
            proof,
            workspace_store=self.workspace,
            runtime_catalog=self.catalog,
        )
        with self.store._read_connection() as connection:
            blockers, operations = _drain_state(
                connection,
                MISSION_ID,
                self.plan.plan_id,
                set(),
            )
        self.assertFalse(any(item["blocker_code"].startswith("expert_review") for item in blockers))
        self.assertFalse(
            any(item["operation"].startswith("project_expert_review") for item in operations)
        )


if __name__ == "__main__":
    unittest.main()
