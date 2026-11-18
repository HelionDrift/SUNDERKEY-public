"""Synthetic local reviewer custody, without providers, targets or persisted keys."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, nullcontext
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import sunderkey.plan_replacement_reviewer_admission as admission_module
from sunderkey.authenticated_collaboration import AuthenticatedCollaborationActivationService
from sunderkey.authenticated_collaboration_mission_policy import (
    AuthenticatedCollaborationMissionPolicyService,
)
from sunderkey.collaboration import build_collaboration_plan
from sunderkey.collaboration_mission_policy import (
    build_collaboration_mission_reconfiguration_policy,
    collaboration_mission_reconfiguration_selection_sha256,
)
from sunderkey.collaboration_reconfiguration_policy import (
    load_collaboration_reconfiguration_authority_policy,
)
from sunderkey.errors import PrincipalAuthenticationError, StoreConflictError, StoreIntegrityError
from sunderkey.identity import (
    PrincipalOperation,
    PrincipalTrustPolicy,
    ScopeGrantRevocation,
    compute_operation_intent_hash,
)
from sunderkey.mission import MissionRequest
from sunderkey.plan_replacement_reviewer_admission import (
    ADMISSION_DOMAIN,
    REVIEWER_OPERATIONS,
    AuthenticatedPlanReplacementReviewerAdmissionService,
    PlanReplacementReviewerAdmissionRequest,
    reviewer_admission_operation_intent,
    verify_plan_replacement_reviewer_admission_for_use,
)
from sunderkey.registry import load_registry
from sunderkey.scope import ScopeGrantAcceptanceService, ScopeGrantRevocationAcceptanceService
from sunderkey.store import MissionStore, canonical_json, sha256_text
from sunderkey.trust import TrustProvisioningService
from sunderkey.types import ActionTier, MissionEnvironment

from .test_authenticated_collaboration_plan_replacement_phase186d import (
    AUTHORITY_PATH,
    MISSION_ID,
    NOW,
    POLICY_VERSION,
    REGISTRY_PATH,
    ROOT,
    SCOPE_DOCUMENT_HASH,
)
from .test_identity_phase4 import (
    AUDIENCE,
    ROOT_KEY_ID,
    SUBJECT,
    ZERO_SIGNATURE,
    CredentialFactory,
    b64url,
    public_bytes,
)


def rehash(document):
    document["admission_sha256"] = sha256_text(
        canonical_json(
            {
                "domain": ADMISSION_DOMAIN,
                "admission": {
                    key: value for key, value in document.items() if key != "admission_sha256"
                },
            }
        )
    )
    return document


def _logical_store_snapshot(connection):
    tables = tuple(
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )
    )
    records = tuple(
        (
            table,
            tuple(
                sorted(
                    canonical_json(dict(row))
                    for row in connection.execute(
                        'SELECT * FROM "' + table.replace('"', '""') + '"'
                    )
                )
            ),
        )
        for table in tables
    )
    schema = tuple(
        tuple(row)
        for row in connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
        )
    )
    return records, schema


class ReviewerAdmissionFixture:
    """Only ephemeral synthetic Ed25519 keys and a temporary MissionStore."""

    def __init__(self, test):
        directory = tempfile.TemporaryDirectory()
        test.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "reviewers.sqlite3"
        self.registry = load_registry(REGISTRY_PATH)
        self.authority_policy = load_collaboration_reconfiguration_authority_policy(AUTHORITY_PATH)
        raw = json.loads(
            (ROOT / "examples/missions/internet-api-to-data.json").read_text(encoding="utf-8")
        )
        raw["scope_document_hash"] = SCOPE_DOCUMENT_HASH
        self.mission = MissionRequest.from_dict(raw)
        self.store = MissionStore(self.path, clock=lambda: NOW)
        self.store.initialize()
        self.stored = self.store.create_mission(self.registry, self.mission)
        self.plan = build_collaboration_plan(self.registry, self.mission)
        self.owner_profile = AuthenticatedCollaborationActivationService._readiness_owner(self.plan)
        self.control_profile = self.stored.control_profile_ids[0]
        self.control_subject = "principal:" + self.control_profile.lower()
        self.factory = CredentialFactory()
        trust = TrustProvisioningService(self.store)
        self.store_id = trust.status().store_id
        root_public = public_bytes(self.factory.root_private)
        trust.pin_root(
            ROOT_KEY_ID,
            AUDIENCE,
            b64url(root_public),
            "sha256:" + hashlib.sha256(root_public).hexdigest(),
        )
        profiles = sorted(self.registry.profiles_by_id)
        self.policy = self.factory.policy(
            policy_version=POLICY_VERSION,
            store_id=self.store_id,
            allowed_profiles=profiles,
            allowed_subjects=[SUBJECT, *("principal:" + profile.lower() for profile in profiles)],
            allowed_operations=[operation.value for operation in PrincipalOperation],
        )
        self.revocation_private = Ed25519PrivateKey.generate()
        policy_document = self.policy.to_dict()
        policy_document["signature"] = ZERO_SIGNATURE
        policy_document["keys"].append(
            {
                "key_id": "REVOCATION-REVIEWERS",
                "issuer": "reviewer-revocation-authority",
                "public_key": b64url(public_bytes(self.revocation_private)),
                "key_use": "scope_grant_revocation",
                "state": "active",
                "not_before": "2026-07-30T09:00:00Z",
                "not_after": "2026-07-30T12:00:00Z",
                "retire_at": None,
                "allowed_profiles": policy_document["allowed_profiles"],
                "allowed_subjects": policy_document["allowed_subjects"],
                "allowed_operations": policy_document["allowed_operations"],
            }
        )
        policy_document["keys"].sort(key=lambda key: key["key_id"])
        unsigned = PrincipalTrustPolicy.from_dict(policy_document)
        self.policy = replace(
            unsigned, signature=b64url(self.factory.root_private.sign(unsigned.signing_bytes()))
        )
        trust.apply_policy(self.policy)
        self.acceptance = ScopeGrantAcceptanceService(self.store, self.registry)
        activation_grant = self.grant(
            100, self.owner_profile, PrincipalOperation.COLLABORATION_ACTIVATE, SUBJECT
        )
        self.acceptance.accept(activation_grant)
        intent = {
            "mission_id": MISSION_ID,
            "plan_id": self.plan.plan_id,
            "plan_content_sha256": self.plan.content_sha256,
            "principal_profile_id": self.owner_profile,
        }
        activation = self.assertion(
            activation_grant, 100, PrincipalOperation.COLLABORATION_ACTIVATE, intent
        )
        AuthenticatedCollaborationActivationService(
            self.store, self.registry, clock=lambda: NOW
        ).activate(activation, self.plan)
        self._commit_policy()
        self.owner_grant = self.grant(
            201,
            self.owner_profile,
            PrincipalOperation.COLLABORATION_REPLACEMENT_REVIEWER_OWNER_AUTHORIZE,
            SUBJECT,
        )
        self.control_grant = self.grant(
            202,
            self.control_profile,
            PrincipalOperation.COLLABORATION_REPLACEMENT_REVIEWER_CONTROL_APPROVE,
            self.control_subject,
        )
        self.acceptance.accept(self.owner_grant)
        self.acceptance.accept(self.control_grant)
        self.service = AuthenticatedPlanReplacementReviewerAdmissionService(
            self.store, self.registry, clock=lambda: NOW
        )

    def grant(self, marker, profile, operation, subject=None, **changes):
        arguments = dict(
            grant_id=f"SGR-{marker:032X}",
            profile_id=profile,
            subject=subject or "principal:" + profile.lower(),
            audience=AUDIENCE,
            store_id=self.store_id,
            mission_id=MISSION_ID,
            mission_context_hash=self.stored.context_hash,
            scope_reference=self.mission.scope_reference,
            scope_document_hash=SCOPE_DOCUMENT_HASH,
            environment=self.mission.environment.value,
            max_action_tier=self.mission.max_action_tier.value,
            constraints_hash=sha256_text(canonical_json(self.mission.to_dict()["constraints"])),
            operations=[operation.value],
            policy_version=POLICY_VERSION,
            issued_at="2026-07-30T10:05:00Z",
            not_before="2026-07-30T10:05:00Z",
            expires_at="2026-07-30T10:30:00Z",
        )
        arguments.update(changes)
        return self.factory.grant(**arguments)

    def assertion(self, grant, marker, operation, intent):
        return self.factory.assertion(
            grant=grant,
            assertion_id=f"PAS-{marker:032X}",
            policy_version=POLICY_VERSION,
            scope_grant_id=grant.grant_id,
            subject=grant.subject,
            profile_id=grant.profile_id,
            audience=AUDIENCE,
            store_id=self.store_id,
            mission_id=MISSION_ID,
            operation=operation,
            operation_intent_sha256=compute_operation_intent_hash(operation, intent),
            issued_at="2026-07-30T10:09:00Z",
            not_before="2026-07-30T10:09:00Z",
            expires_at="2026-07-30T10:14:00Z",
        )

    def _commit_policy(self):
        owner = self.grant(
            110,
            self.owner_profile,
            PrincipalOperation.COLLABORATION_POLICY_OWNER_AUTHORIZE,
            SUBJECT,
        )
        control = self.grant(
            111,
            self.control_profile,
            PrincipalOperation.COLLABORATION_POLICY_CONTROL_APPROVE,
            self.control_subject,
        )
        self.acceptance.accept(owner)
        self.acceptance.accept(control)
        arguments = dict(
            authority_policy=self.authority_policy,
            policy_version=1,
            previous_policy_sha256=None,
            mission_id=MISSION_ID,
            collaboration_plan_id=self.plan.plan_id,
            collaboration_plan_sha256=self.plan.content_sha256,
            maximum_delegation_depth=3,
            reconfiguration_validity_seconds=3600,
            execution_ack_timeout_seconds=300,
            maximum_plan_replacement_items=100,
            transition_activation={
                "privileged_role_reassignment": False,
                "delegation_return_and_revocation": False,
                "cross_command_transfer": True,
                "activated_plan_replacement": True,
                "distributed_execution_transfer_or_cancellation": False,
            },
            effective_at="2026-07-30T10:00:00Z",
            expires_at="2026-07-30T11:00:00Z",
            mission_owner_approval={
                "profile_id": owner.profile_id,
                "assertion_id": f"PAS-{110:032X}",
                "assertion_sha256": "sha256:" + "1" * 64,
            },
            independent_control_approval={
                "profile_id": control.profile_id,
                "assertion_id": f"PAS-{111:032X}",
                "assertion_sha256": "sha256:" + "2" * 64,
            },
        )
        provisional = build_collaboration_mission_reconfiguration_policy(**arguments)
        selection = collaboration_mission_reconfiguration_selection_sha256(provisional)
        owner_assertion = self.assertion(
            owner,
            110,
            PrincipalOperation.COLLABORATION_POLICY_OWNER_AUTHORIZE,
            {
                "mission_id": MISSION_ID,
                "policy_selection_sha256": selection,
                "principal_profile_id": owner.profile_id,
            },
        )
        control_assertion = self.assertion(
            control,
            111,
            PrincipalOperation.COLLABORATION_POLICY_CONTROL_APPROVE,
            {
                "mission_id": MISSION_ID,
                "policy_selection_sha256": selection,
                "principal_profile_id": control.profile_id,
            },
        )
        for role, assertion in (
            ("mission_owner_approval", owner_assertion),
            ("independent_control_approval", control_assertion),
        ):
            arguments[role] = {
                "profile_id": assertion.profile_id,
                "assertion_id": assertion.assertion_id,
                "assertion_sha256": assertion.content_sha256,
            }
        policy = build_collaboration_mission_reconfiguration_policy(**arguments)
        AuthenticatedCollaborationMissionPolicyService(
            self.store, self.registry, clock=lambda: NOW
        ).commit(
            policy,
            authority_policy=self.authority_policy,
            mission_owner_assertion=owner_assertion,
            independent_control_assertion=control_assertion,
        )

    def request(self, marker=300, role="independent_control", profile="AOE-HQ-13", **grant_changes):
        grant = self.grant(marker, profile, REVIEWER_OPERATIONS[role], **grant_changes)
        return self.service.prepare(
            MISSION_ID,
            admission_id=f"RVA-{marker:032X}",
            reviewer_scope_grant=grant,
            reviewer_issuer="identity-provider",
            reviewer_subject=grant.subject,
            role=role,
            issued_at="2026-07-30T10:09:00Z",
            not_before="2026-07-30T10:09:00Z",
            expires_at="2026-07-30T10:25:00Z",
        )

    def approvals(self, request, marker=400, control_grant=None):
        owner_intent = reviewer_admission_operation_intent(
            request, principal_profile_id=self.owner_profile, role="mission_owner"
        )
        control = control_grant or self.control_grant
        control_intent = reviewer_admission_operation_intent(
            request, principal_profile_id=control.profile_id, role="independent_control"
        )
        return dict(
            mission_owner_assertion=self.assertion(
                self.owner_grant,
                marker,
                PrincipalOperation.COLLABORATION_REPLACEMENT_REVIEWER_OWNER_AUTHORIZE,
                owner_intent,
            ),
            independent_control_assertion=self.assertion(
                control,
                marker + 1,
                PrincipalOperation.COLLABORATION_REPLACEMENT_REVIEWER_CONTROL_APPROVE,
                control_intent,
            ),
        )

    def counts(self):
        with self.store._read_connection() as connection:
            return tuple(
                connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in (
                    "plan_replacement_reviewer_admissions",
                    "principal_assertion_uses",
                    "principal_assertion_effects",
                    "mission_scope_grants",
                )
            )

    def current_use(self, request, at=NOW, **changes):
        with self.store._read_connection() as connection:
            activation = AuthenticatedCollaborationActivationService(self.store, self.registry)
            _, policies, mission, scopes, _ = activation._verified_mission_state(
                connection, MISSION_ID
            )
            arguments = dict(
                store=self.store,
                mission=mission,
                registry=self.registry,
                trust_policies=policies,
                scope_grants=scopes,
                grant=request.scope_grant,
                role=request.to_dict()["reviewer"]["role"],
                at=at,
            )
            arguments.update(changes)
            return verify_plan_replacement_reviewer_admission_for_use(connection, **arguments)


class PlanReplacementReviewerAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = ReviewerAdmissionFixture(self)

    def test_initial_reserve_and_later_additions_preserve_mission_context(self):
        f = self.fixture
        original = f.store.get_mission(f.registry, MISSION_ID)
        before = f.counts()
        first = f.request()
        self.assertNotIn(first.scope_grant.profile_id, original.allowed_profile_ids)
        receipt = f.service.admit(first, **f.approvals(first))
        second = f.request(301, "second_control", "AOE-HQ-15")
        f.service.admit(second, **f.approvals(second, 410))
        third = f.request(302, "independent_assurance", "AOE-HQ-20")
        f.service.admit(third, **f.approvals(third, 420))
        after = f.counts()
        self.assertEqual(tuple(a - b for a, b in zip(after, before)), (3, 6, 6, 3))
        self.assertEqual(second.to_dict()["previous_admission_sha256"], first.admission_sha256)
        self.assertEqual(third.to_dict()["previous_admission_sha256"], second.admission_sha256)
        current = f.store.get_mission(f.registry, MISSION_ID)
        self.assertEqual(
            (
                current.context_hash,
                current.allowed_profile_ids,
                current.control_profile_ids,
                current.assurance_profile_ids,
            ),
            (
                original.context_hash,
                original.allowed_profile_ids,
                original.control_profile_ids,
                original.assurance_profile_ids,
            ),
        )
        self.assertEqual(f.current_use(first), first)
        self.assertEqual(receipt.to_dict()["target_authority"], "none")

    def test_assigned_assurance_also_requires_signed_admission(self):
        f = self.fixture
        request = f.request(300, "independent_assurance", f.stored.assurance_profile_ids[0])
        with self.assertRaises(PrincipalAuthenticationError):
            f.acceptance.accept(request.scope_grant)
        f.service.admit(request, **f.approvals(request))
        self.assertEqual(f.current_use(request), request)

    def test_scope_grant_alone_cannot_admit_an_unassigned_reviewer(self):
        f = self.fixture
        request = f.request()
        before = f.counts()
        with self.assertRaises(PrincipalAuthenticationError):
            f.acceptance.accept(request.scope_grant)
        with self.assertRaises(PrincipalAuthenticationError):
            f.current_use(request)
        self.assertEqual(f.counts(), before)

    def test_exact_retry_and_restart_do_not_consume_again(self):
        f = self.fixture
        request = f.request()
        approvals = f.approvals(request)
        receipt = f.service.admit(request, **approvals)
        before = f.counts()
        self.assertEqual(f.service.admit(request, **approvals), receipt)
        restarted = AuthenticatedPlanReplacementReviewerAdmissionService(
            MissionStore(f.path, clock=lambda: NOW), f.registry
        )
        self.assertEqual(restarted.get(MISSION_ID, request.admission_id), receipt)
        self.assertEqual(restarted.admit(request, **approvals), receipt)
        self.assertEqual(f.counts(), before)

    def test_admission_and_replay_keep_only_required_reconciliation(self):
        f = self.fixture
        request = f.request()
        approvals = f.approvals(request)
        before = f.counts()
        original = admission_module._verify_plan_replacement_reviewer_admission_state
        observations = []

        def observe(connection, **arguments):
            rows = connection.execute(
                "SELECT COUNT(*) FROM plan_replacement_reviewer_admissions WHERE mission_id=?",
                (MISSION_ID,),
            ).fetchone()[0]
            observations.append((connection, rows, connection.in_transaction))
            return original(connection, **arguments)

        with mock.patch.object(
            admission_module, "_verify_plan_replacement_reviewer_admission_state", observe
        ):
            receipt = f.service.admit(request, **approvals)
            self.assertEqual([row[1] for row in observations], [0, 1])
            self.assertIs(observations[0][0], observations[1][0])
            self.assertTrue(all(row[2] for row in observations))
            self.assertEqual(tuple(a - b for a, b in zip(f.counts(), before)), (1, 2, 2, 1))
            with f.store._read_connection() as connection:
                committed = _logical_store_snapshot(connection)
            restarted = AuthenticatedPlanReplacementReviewerAdmissionService(
                MissionStore(f.path, clock=lambda: NOW), f.registry
            )
            expired = AuthenticatedPlanReplacementReviewerAdmissionService(
                f.store, f.registry, clock=lambda: NOW + timedelta(hours=1)
            )
            for service in (f.service, restarted, expired):
                with self.subTest(service=service):
                    observations.clear()
                    with mock.patch.object(
                        admission_module,
                        "verify_plan_replacement_reviewer_admission_for_use",
                        wraps=verify_plan_replacement_reviewer_admission_for_use,
                    ) as live_use:
                        if service is expired:
                            with self.assertRaisesRegex(
                                PrincipalAuthenticationError, "not currently active"
                            ):
                                service.admit(request, **approvals)
                        else:
                            self.assertEqual(service.admit(request, **approvals), receipt)
                        live_use.assert_called_once()
                    self.assertEqual([row[1] for row in observations], [1])
                    self.assertTrue(observations[0][2])
                    with f.store._read_connection() as connection:
                        self.assertEqual(_logical_store_snapshot(connection), committed)

    def test_pre_and_post_reconciliation_failures_roll_back_complete_store(self):
        f = self.fixture
        request = f.request()
        approvals = f.approvals(request)
        original = admission_module._verify_plan_replacement_reviewer_admission_state
        with f.store._read_connection() as connection:
            before = _logical_store_snapshot(connection)
        for failure_rows in (0, 1):
            with self.subTest(failure_rows=failure_rows):
                observations = []

                def fail_after_real_reconciliation(connection, **arguments):
                    result = original(connection, **arguments)
                    rows = connection.execute(
                        "SELECT COUNT(*) FROM plan_replacement_reviewer_admissions "
                        "WHERE mission_id=?",
                        (MISSION_ID,),
                    ).fetchone()[0]
                    observations.append(rows)
                    if rows == failure_rows:
                        raise RuntimeError("forced reconciliation failure")
                    return result

                with (
                    mock.patch.object(
                        admission_module,
                        "_verify_plan_replacement_reviewer_admission_state",
                        fail_after_real_reconciliation,
                    ),
                    mock.patch.object(
                        f.service._policy,
                        "_record_assertion",
                        wraps=f.service._policy._record_assertion,
                    ) as record,
                    mock.patch.object(
                        f.service, "_insert_scope", wraps=f.service._insert_scope
                    ) as insert_scope,
                    self.assertRaisesRegex(RuntimeError, "forced reconciliation failure"),
                ):
                    f.service.admit(request, **approvals)
                self.assertEqual(observations, [0] if failure_rows == 0 else [0, 1])
                self.assertEqual(record.call_count, 0 if failure_rows == 0 else 2)
                self.assertEqual(insert_scope.call_count, failure_rows)
                with f.store._read_connection() as connection:
                    self.assertEqual(_logical_store_snapshot(connection), before)
                self.assertEqual(f.store.verify_store(f.registry).status, "valid")

    def test_orphaned_admission_custody_rejects_new_admit_before_recording(self):
        f = self.fixture
        self.assertIn("AOE-HQ-19", f.stored.assurance_profile_ids)
        first = f.request(300, "independent_assurance", "AOE-HQ-19")
        receipt = f.service.admit(first, **f.approvals(first))
        second = f.request(301, "second_control", "AOE-HQ-15")
        approvals = f.approvals(second, 410)
        original = admission_module._verify_plan_replacement_reviewer_admission_state
        with f.store._write_connection() as connection:
            before = _logical_store_snapshot(connection)
            trigger_name = "plan_replacement_reviewer_admissions_no_delete"
            trigger = connection.execute(
                "SELECT sql FROM sqlite_master WHERE name=?", (trigger_name,)
            ).fetchone()[0]
            connection.execute("SAVEPOINT orphan_admit_probe")
            try:
                connection.execute("DROP TRIGGER " + trigger_name)
                deleted = connection.execute(
                    "DELETE FROM plan_replacement_reviewer_admissions WHERE admission_id=?",
                    (first.admission_id,),
                )
                self.assertEqual(deleted.rowcount, 1)
                connection.execute(trigger)
                self.assertEqual(
                    connection.execute(
                        "SELECT sql FROM sqlite_master WHERE name=?", (trigger_name,)
                    ).fetchone()[0],
                    trigger,
                )
                orphaned = _logical_store_snapshot(connection)
                with (
                    mock.patch.object(
                        f.store, "_write_connection", side_effect=lambda: nullcontext(connection)
                    ),
                    mock.patch.object(
                        admission_module,
                        "_verify_plan_replacement_reviewer_admission_state",
                        wraps=original,
                    ) as reconcile,
                    mock.patch.object(
                        f.service._policy,
                        "_record_assertion",
                        wraps=f.service._policy._record_assertion,
                    ) as record,
                    mock.patch.object(
                        f.service, "_insert_scope", wraps=f.service._insert_scope
                    ) as insert_scope,
                    self.assertRaisesRegex(StoreIntegrityError, "approval custody is orphaned"),
                ):
                    f.service.admit(second, **approvals)
                reconcile.assert_called_once()
                record.assert_not_called()
                insert_scope.assert_not_called()
                self.assertEqual(_logical_store_snapshot(connection), orphaned)
            finally:
                connection.execute("ROLLBACK TO orphan_admit_probe")
                connection.execute("RELEASE orphan_admit_probe")
            self.assertEqual(_logical_store_snapshot(connection), before)
        self.assertEqual(f.service.get(MISSION_ID, first.admission_id), receipt)
        self.assertEqual(f.store.verify_store(f.registry).status, "valid")

    def test_concurrent_exact_retry_converges(self):
        f = self.fixture
        request = f.request()
        approvals = f.approvals(request)
        before = f.counts()
        with ThreadPoolExecutor(max_workers=2) as executor:
            receipts = list(executor.map(lambda _: f.service.admit(request, **approvals), range(2)))
        self.assertEqual(receipts[0], receipts[1])
        self.assertEqual(tuple(a - b for a, b in zip(f.counts(), before)), (1, 2, 2, 1))

    def test_competing_new_admissions_reject_stale_signed_fences(self):
        f = self.fixture
        first = f.request()
        second = f.request(301, "second_control", "AOE-HQ-15")
        first_approvals = f.approvals(first)
        second_approvals = f.approvals(second, 410)
        f.service.admit(first, **first_approvals)
        before = f.counts()
        with self.assertRaisesRegex(StoreConflictError, "fence"):
            f.service.admit(second, **second_approvals)
        self.assertEqual(f.counts(), before)

    def test_exact_json_types_and_closed_fields_reject_rehashed_tampering(self):
        request = self.fixture.request()
        mutations = [
            lambda d: d.update(schema_version=True),
            lambda d: d.update(active_plan_version=1.0),
            lambda d: d["principal_ledger"].update(
                assertion_count=float(d["principal_ledger"]["assertion_count"])
            ),
            lambda d: d.update(review_only=1),
            lambda d: d.update(extra=False),
            lambda d: d["reviewer"].pop("issuer"),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                document = request.to_dict()
                mutate(document)
                with self.assertRaises(PrincipalAuthenticationError):
                    PlanReplacementReviewerAdmissionRequest.from_dict(rehash(document))

    def test_request_and_receipt_exports_are_detached(self):
        f = self.fixture
        request = f.request()
        document = request.to_dict()
        document["reviewer"]["scope_grant"]["operations"].clear()
        self.assertEqual(len(request.scope_grant.operations), 1)
        receipt = f.service.admit(request, **f.approvals(request))
        exported = receipt.to_dict()
        exported["admission"]["principal_ledger"]["assertion_count"] = 999
        self.assertEqual(receipt.request, request)

    def test_role_swap_and_mixed_authority_scope_are_rejected(self):
        f = self.fixture
        request = f.request()
        role_swap = request.to_dict()
        role_swap["reviewer"]["role"] = "second_control"
        with self.assertRaisesRegex(PrincipalAuthenticationError, "role-specific"):
            PlanReplacementReviewerAdmissionRequest.from_dict(rehash(role_swap))
        with self.assertRaisesRegex(PrincipalAuthenticationError, "role-specific"):
            f.request(
                300,
                operations=[
                    REVIEWER_OPERATIONS["independent_control"].value,
                    PrincipalOperation.EVENT_APPEND.value,
                ],
            )

    def test_wrong_category_and_suspended_reviewer_are_rejected(self):
        f = self.fixture
        with self.assertRaisesRegex(PrincipalAuthenticationError, "eligible"):
            f.request(profile=f.owner_profile)
        request = f.request()
        changed = replace(f.registry.profile("AOE-HQ-13"), status="retired")
        with mock.patch.object(
            f.registry.__class__,
            "profile",
            autospec=True,
            side_effect=lambda _, profile_id: (
                changed if profile_id == changed.id else original(profile_id)
            ),
        ):
            original = f.registry.profiles_by_id.__getitem__
            with self.assertRaisesRegex(PrincipalAuthenticationError, "eligible"):
                f.service.admit(request, **f.approvals(request))

    def test_authenticated_subject_collision_and_untrusted_issuer_are_rejected(self):
        f = self.fixture
        request = f.request(subject=SUBJECT)
        before = f.counts()
        with self.assertRaisesRegex(PrincipalAuthenticationError, "distinct"):
            f.service.admit(request, **f.approvals(request))
        document = f.request().to_dict()
        document["reviewer"]["issuer"] = "untrusted-provider"
        altered = PlanReplacementReviewerAdmissionRequest.from_dict(rehash(document))
        with self.assertRaisesRegex(PrincipalAuthenticationError, "issuer"):
            f.service.admit(altered, **f.approvals(altered))
        self.assertEqual(f.counts(), before)

    def test_unassigned_control_approval_cannot_bootstrap_admission(self):
        f = self.fixture
        request = f.request()
        reserve_control = f.grant(
            210, "AOE-HQ-15", PrincipalOperation.COLLABORATION_REPLACEMENT_REVIEWER_CONTROL_APPROVE
        )
        before = f.counts()
        with self.assertRaises(PrincipalAuthenticationError):
            f.acceptance.accept(reserve_control)
        with self.assertRaises(PrincipalAuthenticationError):
            f.service.admit(request, **f.approvals(request, control_grant=reserve_control))
        self.assertEqual(f.counts(), before)

    def test_signed_request_substitution_and_global_assertion_reuse_fail(self):
        f = self.fixture
        request = f.request()
        approvals = f.approvals(request)
        document = request.to_dict()
        document["expires_at"] = "2026-07-30T10:24:00Z"
        altered = PlanReplacementReviewerAdmissionRequest.from_dict(rehash(document))
        before = f.counts()
        with self.assertRaises(PrincipalAuthenticationError):
            f.service.admit(altered, **approvals)
        self.assertEqual(f.counts(), before)
        f.service.admit(request, **approvals)
        second = f.request(301, "second_control", "AOE-HQ-15")
        reused = f.approvals(second)
        before = f.counts()
        with self.assertRaises(StoreConflictError):
            f.service.admit(second, **reused)
        self.assertEqual(f.counts(), before)

    def test_foreign_context_and_scope_metadata_fail_without_consumption(self):
        f = self.fixture
        before = f.counts()
        with self.assertRaisesRegex(PrincipalAuthenticationError, "binding"):
            f.request(mission_context_hash="sha256:" + "f" * 64)
        request = f.request(scope_reference="scope://foreign")
        with self.assertRaises(PrincipalAuthenticationError):
            f.service.admit(request, **f.approvals(request))
        self.assertEqual(f.counts(), before)

    def test_sole_assigned_control_can_admit_reserves_but_cannot_admit_itself(self):
        f = self.fixture
        self.assertEqual(f.stored.control_profile_ids, (f.control_profile,))
        request = f.request(profile=f.control_profile)
        before = f.counts()
        with self.assertRaisesRegex(PrincipalAuthenticationError, "distinct"):
            f.service.admit(request, **f.approvals(request))
        self.assertEqual(f.counts(), before)
        reserve = f.request()
        f.service.admit(reserve, **f.approvals(reserve))
        self.assertEqual(f.current_use(reserve), reserve)

    def test_failure_after_consumption_and_after_scope_insert_roll_back_all_rows(self):
        f = self.fixture
        request = f.request()
        approvals = f.approvals(request)
        before = f.counts()
        with mock.patch.object(
            f.service, "_insert_scope", side_effect=RuntimeError("injected after both approvals")
        ):
            with self.assertRaisesRegex(RuntimeError, "injected"):
                f.service.admit(request, **approvals)
        self.assertEqual(f.counts(), before)
        real_insert = f.service._insert_scope

        def insert_then_fail(*args):
            real_insert(*args)
            raise RuntimeError("injected after scope insertion")

        with mock.patch.object(f.service, "_insert_scope", side_effect=insert_then_fail):
            with self.assertRaisesRegex(RuntimeError, "injected"):
                f.service.admit(request, **approvals)
        self.assertEqual(f.counts(), before)

    def test_expiry_blocks_new_use_and_retry_but_not_historical_inspection(self):
        f = self.fixture
        request = f.request()
        approvals = f.approvals(request)
        receipt = f.service.admit(request, **approvals)
        future = NOW + timedelta(minutes=16)
        with self.assertRaisesRegex(PrincipalAuthenticationError, "currently active"):
            f.current_use(request, at=future)
        service = AuthenticatedPlanReplacementReviewerAdmissionService(
            f.store, f.registry, clock=lambda: future
        )
        with self.assertRaises(PrincipalAuthenticationError):
            service.admit(request, **approvals)
        self.assertEqual(service.get(MISSION_ID, request.admission_id), receipt)

    def test_live_use_and_retry_require_active_mission_but_history_does_not(self):
        f = self.fixture
        request = f.request()
        approvals = f.approvals(request)
        receipt = f.service.admit(request, **approvals)
        before = f.counts()
        with mock.patch.object(
            f.store,
            "_require_mission_active",
            side_effect=PrincipalAuthenticationError("mission is not active"),
        ) as active_gate:
            with self.assertRaisesRegex(PrincipalAuthenticationError, "not active"):
                f.current_use(request)
            with self.assertRaisesRegex(PrincipalAuthenticationError, "not active"):
                f.service.admit(request, **approvals)
            self.assertEqual(f.service.get(MISSION_ID, request.admission_id), receipt)
            self.assertEqual(active_gate.call_count, 2)
        self.assertEqual(f.counts(), before)

    def test_point_use_role_scope_and_clock_substitution_fail(self):
        f = self.fixture
        request = f.request()
        f.service.admit(request, **f.approvals(request))
        with self.assertRaises(PrincipalAuthenticationError):
            f.current_use(request, role="second_control")
        other_grant = f.grant(301, "AOE-HQ-15", REVIEWER_OPERATIONS["independent_control"])
        with self.assertRaises(PrincipalAuthenticationError):
            f.current_use(request, grant=other_grant)
        with self.assertRaises(PrincipalAuthenticationError):
            f.current_use(request, at=NOW - timedelta(seconds=1))

    def test_append_only_and_rehashed_row_tampering_fail_after_restart(self):
        f = self.fixture
        request = f.request()
        f.service.admit(request, **f.approvals(request))
        with f.store._write_connection() as connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE plan_replacement_reviewer_admissions SET committed_at=?",
                    ("2026-07-30T10:11:00Z",),
                )
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("DELETE FROM plan_replacement_reviewer_admissions")
        with closing(sqlite3.connect(f.path)) as connection:
            trigger = connection.execute(
                "SELECT sql FROM sqlite_master WHERE name=?",
                ("plan_replacement_reviewer_admissions_immutable",),
            ).fetchone()[0]
            connection.execute("DROP TRIGGER plan_replacement_reviewer_admissions_immutable")
            connection.execute(
                "UPDATE plan_replacement_reviewer_admissions SET committed_at=?",
                ("2026-07-30T10:11:00Z",),
            )
            connection.execute(trigger)
            connection.commit()
        restarted = AuthenticatedPlanReplacementReviewerAdmissionService(
            MissionStore(f.path, clock=lambda: NOW), f.registry
        )
        with self.assertRaises(StoreIntegrityError):
            restarted.get(MISSION_ID, request.admission_id)
        # Restore the timestamp, then corrupt typed request data while preserving
        # the exact schema. The intended parser failure must become integrity failure.
        malformed = request.to_dict()
        malformed["schema_version"] = True
        rehash(malformed)
        with closing(sqlite3.connect(f.path)) as connection:
            connection.execute("DROP TRIGGER plan_replacement_reviewer_admissions_immutable")
            connection.execute(
                "UPDATE plan_replacement_reviewer_admissions "
                "SET committed_at=?,admission_json=?,admission_sha256=?",
                ("2026-07-30T10:10:00Z", canonical_json(malformed), malformed["admission_sha256"]),
            )
            connection.execute(trigger)
            connection.commit()
        with self.assertRaises(StoreIntegrityError):
            restarted.get(MISSION_ID, request.admission_id)

    def test_revoked_review_scope_blocks_use_and_retry_preserving_historical_receipt(self):
        f = self.fixture
        request = f.request()
        approvals = f.approvals(request)
        receipt = f.service.admit(request, **approvals)
        grant = request.scope_grant
        raw = {
            "schema_version": 1,
            "revocation_id": "SRV-" + "A" * 32,
            "policy_id": f.policy.policy_id,
            "policy_version": POLICY_VERSION,
            "issuer": "reviewer-revocation-authority",
            "key_id": "REVOCATION-REVIEWERS",
            "audience": AUDIENCE,
            "store_id": f.store_id,
            "mission_id": MISSION_ID,
            "mission_context_hash": f.stored.context_hash,
            "scope_grant_issuer": grant.issuer,
            "scope_grant_id": grant.grant_id,
            "scope_grant_sha256": grant.content_sha256,
            "scope_grant_subject": grant.subject,
            "scope_grant_profile_id": grant.profile_id,
            "reason_code": "authorization_withdrawn",
            "reason": "Synthetic reviewer withdrawal.",
            "issued_at": "2026-07-30T10:10:00Z",
            "not_before": "2026-07-30T10:10:00Z",
            "expires_at": "2026-07-30T10:14:00Z",
            "signature": ZERO_SIGNATURE,
        }
        unsigned = ScopeGrantRevocation.from_dict(raw)
        signed = replace(
            unsigned, signature=b64url(f.revocation_private.sign(unsigned.signing_bytes()))
        )
        ScopeGrantRevocationAcceptanceService(f.store, f.registry).accept(signed)
        before = f.counts()
        with self.assertRaisesRegex(PrincipalAuthenticationError, "revoked"):
            f.current_use(request)
        with self.assertRaises(PrincipalAuthenticationError):
            f.service.admit(request, **approvals)
        self.assertEqual(f.service.get(MISSION_ID, request.admission_id), receipt)
        self.assertEqual(f.counts(), before)

    def test_later_trust_high_water_blocks_rollback_and_old_scope_use(self):
        f = self.fixture
        request = f.request()
        approvals = f.approvals(request)
        receipt = f.service.admit(request, **approvals)
        later = NOW + timedelta(seconds=1)
        f.store._clock = lambda: later
        raw = f.policy.to_dict()
        raw["policy_version"] += 1
        raw["issued_at"] = "2026-07-30T10:10:01Z"
        raw["not_before"] = "2026-07-30T10:10:01Z"
        raw["signature"] = ZERO_SIGNATURE
        unsigned = PrincipalTrustPolicy.from_dict(raw)
        policy = replace(
            unsigned, signature=b64url(f.factory.root_private.sign(unsigned.signing_bytes()))
        )
        TrustProvisioningService(f.store).apply_policy(policy)
        with self.assertRaisesRegex(PrincipalAuthenticationError, "clock"):
            f.current_use(request)
        with self.assertRaises(PrincipalAuthenticationError):
            f.current_use(request, at=later)
        with self.assertRaises(PrincipalAuthenticationError):
            f.service.admit(request, **approvals)
        self.assertEqual(f.service.get(MISSION_ID, request.admission_id), receipt)

    def test_closed_schema_accepts_the_real_request(self):
        import jsonschema

        schema_path = ROOT / "registry/schemas/plan-replacement-reviewer-admission-v1.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(schema).validate(self.fixture.request().to_dict())
        scope_properties = schema["$defs"]["scopeGrant"]["properties"]
        self.assertEqual(
            set(scope_properties["max_action_tier"]["enum"]), {item.value for item in ActionTier}
        )
        self.assertEqual(
            set(scope_properties["environment"]["enum"]),
            {item.value for item in MissionEnvironment},
        )


if __name__ == "__main__":
    unittest.main()
