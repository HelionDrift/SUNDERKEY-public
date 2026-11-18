"""Schema v29 atomic collaboration plan replacement coverage."""

from __future__ import annotations

import copy
import json
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
from datetime import timedelta
from pathlib import Path
from typing import Any

from sunderkey.authenticated_collaboration_executor_dispatch import (
    AuthenticatedCollaborationExecutorDispatchService,
)
from sunderkey.authenticated_work import AuthenticatedWorkItemLeaseService
from sunderkey.collaboration import CollaborationPlan
from sunderkey.collaboration_execution_session_status import (
    CollaborationExecutionSessionAuthorityStatusService,
)
from sunderkey.collaboration_executor import (
    build_collaboration_executor_dispatch,
    collaboration_executor_operation_input_sha256,
)
from sunderkey.collaboration_plan_replacement_preflight import (
    PREFLIGHT_DOMAIN,
    CollaborationPlanReplacementPreflight,
)
from sunderkey.collaboration_plan_replacement_store import (
    ReplacementAuthorityEvidence,
    VerifiedReplacementAuthority,
    _CollaborationPlanReplacementAtomicStore,
    build_collaboration_plan_replacement_source_snapshots,
)
from sunderkey.errors import (
    PrincipalAuthenticationError,
    StoreConflictError,
    StoreError,
    StoreIntegrityError,
    StoreMigrationRequiredError,
)
from sunderkey.identity import PrincipalOperation
from sunderkey.mission_audit import MissionAuditSnapshotService
from sunderkey.store import (
    AUTHENTICATED_ACTION_ADMISSION_SCHEMA_VERSION,
    AUTHENTICATED_ACTION_EXECUTION_SCHEMA_VERSION,
    AUTHENTICATED_EXPERT_REVIEW_SCHEMA_VERSION,
    AUTHENTICATED_MODEL_EXECUTION_SCHEMA_VERSION,
    AUTHENTICATED_PLAN_REPLACEMENT_SCHEMA_VERSION,
    COLLABORATION_PLAN_REPLACEMENT_SCHEMA_VERSION,
    EXPECTED_SCHEMA_MANIFEST,
    EXPECTED_SCHEMA_MANIFEST_V28,
    EXPECTED_SCHEMA_MANIFEST_V29,
    EXPECTED_SCHEMA_MANIFEST_V30,
    EXPECTED_SCHEMA_MANIFEST_V31,
    EXPECTED_SCHEMA_MANIFEST_V32,
    SCHEMA_VERSION,
    MissionStore,
    _schema_manifest,
    canonical_json,
    sha256_text,
)

from . import (
    test_authenticated_collaboration_execution_session_authority_phase123 as session_fixture,
)
from . import test_authenticated_collaboration_mission_policy_phase88 as policy_fixture
from . import test_authenticated_collaboration_ownership_phase92 as ownership_fixture
from . import test_authenticated_collaboration_phase14 as phase14_fixture_module
from . import test_authenticated_work_phase15 as work_fixture
from . import test_collaboration_executor_dispatch_authentication_phase127 as dispatch_auth
from .test_store import (
    remove_schema_v29_objects,
    remove_schema_v31_objects,
)


def canonical_sha256(value: object) -> str:
    return sha256_text(canonical_json(value))


def replacement_plan(plan: CollaborationPlan, marker: str) -> CollaborationPlan:
    document = copy.deepcopy(plan.unsigned_dict())
    document["plan_id"] = "CLP-" + marker * 24
    document["content_sha256"] = canonical_sha256(document)
    return CollaborationPlan.from_dict(document)


def replacement_preflight(
    store: MissionStore,
    prior: CollaborationPlan,
    replacement: CollaborationPlan,
    *,
    completed: dict[str, str] | None = None,
    mission_revision_override: int | None = None,
) -> CollaborationPlanReplacementPreflight:
    completed = completed or {}
    snapshots = build_collaboration_plan_replacement_source_snapshots(
        store, prior.mission_id, prior.plan_id
    )
    with store._read_connection() as connection:
        mission_revision = int(
            connection.execute(
                "SELECT revision FROM missions WHERE mission_id = ?",
                (prior.mission_id,),
            ).fetchone()[0]
        )
    if mission_revision_override is not None:
        mission_revision = mission_revision_override
    requirement_marker = replacement.content_sha256.removeprefix("sha256:")
    requirement = {
        "requirement_id": "PAR-" + requirement_marker[:32].upper(),
        "role": "mission_owner",
        "authority_id": "AOE-HQ-08",
        "authority_kind": "principal_profile",
        "operation": "sunderkey.collaboration.plan-replacement.owner-authorize.v1",
        "work_item_id": None,
        "operation_intent_sha256": "sha256:" + requirement_marker,
    }
    mappings = [
        {
            "source_work_item_id": item.work_item_id,
            "replacement_work_item_id": item.work_item_id,
            "source_state": ("completed" if item.work_item_id in completed else "not_completed"),
            "disposition": (
                "preserve_completed_result"
                if item.work_item_id in completed
                else "restart_in_replacement"
            ),
            "completed_result_sha256": completed.get(item.work_item_id),
        }
        for item in prior.work_items
    ]
    policy_commit = {
        "policy_id": "CMP-TEST-POLICY",
        "policy_sha256": "sha256:" + "1" * 64,
        "policy_selection_sha256": "sha256:" + "2" * 64,
        "authentication_id": "MPA-" + "B" * 32,
        "authentication_sha256": "sha256:" + "3" * 64,
        "committed_at": "2026-07-30T10:04:00Z",
        "mission_owner_assertion_id": "PAS-" + "1" * 32,
        "mission_owner_assertion_sha256": "sha256:" + "4" * 64,
        "mission_owner_ledger_entry_sha256": "sha256:" + "5" * 64,
        "independent_control_assertion_id": "PAS-" + "2" * 32,
        "independent_control_assertion_sha256": "sha256:" + "6" * 64,
        "independent_control_ledger_entry_sha256": "sha256:" + "7" * 64,
        "commit_status": "committed_inactive",
    }
    body: dict[str, Any] = {
        "schema_version": 1,
        "selection_sha256": "sha256:" + "8" * 64,
        "mission_id": prior.mission_id,
        "prior_plan": {
            "plan_id": prior.plan_id,
            "plan_sha256": prior.content_sha256,
        },
        "replacement_plan": {
            "plan_id": replacement.plan_id,
            "plan_sha256": replacement.content_sha256,
        },
        "mission_policy_commit": policy_commit,
        "source_state": {
            "mission_revision": mission_revision,
            "active_plan_id": prior.plan_id,
            "active_plan_sha256": prior.content_sha256,
            **snapshots.hashes,
            "observed_at": "2026-07-30T10:05:00Z",
        },
        "item_mappings": mappings,
        "cancellation_actions": [],
        "new_item_actions": [],
        "authority_requirements": [requirement],
        "maximum_mapping_items": 100,
        "atomic_commit_required": True,
        "history_policy": "append_only_no_rewrite",
        "authentication_status": "authority_assertions_required",
        "runtime_effect": "none",
    }
    digest = canonical_sha256({"domain": PREFLIGHT_DOMAIN, "preflight": body})
    return CollaborationPlanReplacementPreflight.from_dict(
        {
            **body,
            "preflight_id": "PRF-" + digest.removeprefix("sha256:")[:32].upper(),
            "preflight_sha256": digest,
        }
    )


def authority_evidence(
    preflight: CollaborationPlanReplacementPreflight,
) -> tuple[ReplacementAuthorityEvidence, ...]:
    values = []
    for requirement in preflight.to_dict()["authority_requirements"]:
        evidence = {
            "accepted": True,
            "requirement_id": requirement["requirement_id"],
            "operation_intent_sha256": requirement["operation_intent_sha256"],
        }
        values.append(
            ReplacementAuthorityEvidence.from_dict(
                {
                    "requirement_id": requirement["requirement_id"],
                    "evidence_id": "PAE-" + requirement["requirement_id"][4:],
                    "evidence_sha256": canonical_sha256(evidence),
                    "evidence": evidence,
                }
            )
        )
    return tuple(values)


def completed_results(
    store: MissionStore,
    mission_id: str,
    plan_id: str,
) -> dict[str, str]:
    with store._read_connection() as connection:
        rows = connection.execute(
            """
            SELECT work_item_id, result_sha256
            FROM collaboration_work_item_transitions
            WHERE mission_id = ? AND plan_id = ?
              AND transition_kind = 'complete'
            UNION ALL
            SELECT work_item_id, result_sha256
            FROM collaboration_work_item_recovery_transitions
            WHERE mission_id = ? AND plan_id = ?
              AND transition_kind = 'complete'
            """,
            (mission_id, plan_id, mission_id, plan_id),
        ).fetchall()
    return {str(row["work_item_id"]): str(row["result_sha256"]) for row in rows}


class ExactAuthorityVerifier:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls: list[str] = []

    def verify(
        self,
        connection: sqlite3.Connection,
        *,
        requirement: dict[str, Any],
        evidence: ReplacementAuthorityEvidence,
        consumed_at: str,
    ) -> VerifiedReplacementAuthority:
        del connection, consumed_at
        self.calls.append(evidence.requirement_id)
        document = json.loads(evidence.evidence_json)
        if self.fail or document != {
            "accepted": True,
            "operation_intent_sha256": requirement["operation_intent_sha256"],
            "requirement_id": requirement["requirement_id"],
        }:
            raise PrincipalAuthenticationError("Authority evidence was rejected")
        return VerifiedReplacementAuthority(
            requirement_id=str(requirement["requirement_id"]),
            role=str(requirement["role"]),
            authority_id=str(requirement["authority_id"]),
            authority_kind=str(requirement["authority_kind"]),
            operation=str(requirement["operation"]),
            work_item_id=requirement.get("work_item_id"),
            operation_intent_sha256=str(requirement["operation_intent_sha256"]),
            evidence_id=evidence.evidence_id,
            evidence_sha256=evidence.evidence_sha256,
        )


class LegacyReplacementFixtureStore(MissionStore):
    """Test-only atomic transaction access for exact historical schema29 fixtures."""

    @contextmanager
    def _write_connection(self):
        connection = self._open_existing_connection(allow_legacy=True)
        try:
            if self._require_schema(connection, allow_legacy=True) != 29:
                raise AssertionError("The legacy replacement fixture must remain exact schema29")
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except Exception:
                connection.rollback()
                raise
            else:
                connection.commit()
        finally:
            connection.close()


def legacy_schema29_fixture(fixture: Any) -> Any:
    """Remove newer empty custody objects before isolated unsigned atomic-engine tests."""

    with closing(sqlite3.connect(fixture.path)) as connection:
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version != 29:
            connection.execute("PRAGMA foreign_keys = OFF")
            names = {(item[0], item[1]) for item in EXPECTED_SCHEMA_MANIFEST_V29}
            empty_history_baselines = {
                "action_target_health_gate_legacy_baselines",
                "action_execution_target_health_gate_legacy_baselines",
            }
            for item in _schema_manifest(connection):
                if (
                    item[0] == "table"
                    and (item[0], item[1]) not in names
                    and item[1] not in empty_history_baselines
                    and connection.execute(f'SELECT COUNT(*) FROM "{item[1]}"').fetchone()[0]
                ):
                    raise AssertionError(
                        "Newer custody history cannot become an unsigned legacy fixture"
                    )
            remove_schema_v31_objects(connection)
            additions = [
                item for item in EXPECTED_SCHEMA_MANIFEST_V30 if (item[0], item[1]) not in names
            ]
            for table in (
                "collaboration_plan_replacement_authority_consumptions",
                "collaboration_plan_replacement_authentications",
            ):
                if connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]:
                    raise AssertionError(
                        "Signed replacement history cannot become a legacy fixture"
                    )
            for kind in ("trigger", "index"):
                for item in additions:
                    if item[0] == kind:
                        connection.execute(f'DROP {kind.upper()} IF EXISTS "{item[1]}"')
            connection.execute("DROP TABLE collaboration_plan_replacement_authority_consumptions")
            connection.execute("DROP TABLE collaboration_plan_replacement_authentications")
            connection.execute(
                "UPDATE store_metadata SET value = '29' WHERE key = 'schema_version'"
            )
            connection.execute("PRAGMA user_version = 29")
            connection.commit()
        if _schema_manifest(connection) != EXPECTED_SCHEMA_MANIFEST_V29:
            raise AssertionError("Legacy fixture must retain the exact schema29 manifest")
    if not isinstance(fixture.store, LegacyReplacementFixtureStore):
        fixture.store = LegacyReplacementFixtureStore(fixture.path, clock=lambda: fixture.now)
    return fixture


def phase14_fixture(test: unittest.TestCase):
    fixture = phase14_fixture_module.AuthenticatedCollaborationPhase14Tests(methodName="runTest")
    phase14_fixture_module.AuthenticatedCollaborationPhase14Tests.setUpClass()
    fixture.setUp()
    test.addCleanup(fixture.doCleanups)
    fixture.service.activate(fixture.assertion, fixture.plan)
    return legacy_schema29_fixture(fixture)


def service_for(fixture: Any, verifier: ExactAuthorityVerifier | None = None):
    fixture = legacy_schema29_fixture(fixture)
    return _CollaborationPlanReplacementAtomicStore(
        fixture.store,
        fixture.registry,
        verifier or ExactAuthorityVerifier(),
        clock=lambda: fixture.now,
    )


class CollaborationPlanReplacementStorePhase186Tests(unittest.TestCase):
    def test_isolated_legacy_transaction_refuses_a_current_schema_store(self) -> None:
        fixture = phase14_fixture_module.AuthenticatedCollaborationPhase14Tests(
            methodName="runTest"
        )
        phase14_fixture_module.AuthenticatedCollaborationPhase14Tests.setUpClass()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.service.activate(fixture.assertion, fixture.plan)
        legacy = LegacyReplacementFixtureStore(fixture.path, clock=lambda: fixture.now)
        with closing(sqlite3.connect(fixture.path)) as connection:
            original = tuple(connection.iterdump())
        with (
            self.assertRaisesRegex(AssertionError, "must remain exact schema29"),
            legacy._write_connection(),
        ):
            self.fail("A current schema store cannot become a legacy write fixture")
        with closing(sqlite3.connect(fixture.path)) as connection:
            self.assertEqual(tuple(connection.iterdump()), original)
            self.assertEqual(
                connection.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION
            )

    def test_schema_v29_rebuilds_activation_and_adds_exact_objects(self) -> None:
        self.assertEqual(COLLABORATION_PLAN_REPLACEMENT_SCHEMA_VERSION, 29)
        self.assertEqual(AUTHENTICATED_PLAN_REPLACEMENT_SCHEMA_VERSION, 30)
        self.assertEqual(AUTHENTICATED_MODEL_EXECUTION_SCHEMA_VERSION, 31)
        self.assertEqual(AUTHENTICATED_EXPERT_REVIEW_SCHEMA_VERSION, 32)
        self.assertEqual(AUTHENTICATED_ACTION_ADMISSION_SCHEMA_VERSION, 33)
        self.assertEqual(AUTHENTICATED_ACTION_EXECUTION_SCHEMA_VERSION, 34)
        self.assertEqual(SCHEMA_VERSION, 39)
        v28 = {item[1]: item for item in EXPECTED_SCHEMA_MANIFEST_V28}
        v29 = {item[1]: item for item in EXPECTED_SCHEMA_MANIFEST_V29}
        self.assertNotEqual(
            v28["collaboration_plan_activations"], v29["collaboration_plan_activations"]
        )
        self.assertIn("collaboration_plan_active_heads", v29)
        self.assertIn("collaboration_plan_replacement_commits", v29)
        self.assertIn("collaboration_plan_replacement_authorities", v29)
        self.assertIn("collaboration_plan_replacement_source_settlements", v29)
        self.assertIn("collaboration_plan_completed_work_carry_forwards", v29)
        self.assertIn("collaboration_plan_work_initializations", v29)
        v30 = {item[1]: item for item in EXPECTED_SCHEMA_MANIFEST_V30}
        self.assertIn("collaboration_plan_replacement_authentications", v30)
        self.assertIn("collaboration_plan_replacement_authority_consumptions", v30)
        v31 = {item[1]: item for item in EXPECTED_SCHEMA_MANIFEST_V31}
        self.assertIn("authenticated_model_execution_admissions", v31)
        self.assertIn("authenticated_model_execution_budgets", v31)
        v32 = {item[1]: item for item in EXPECTED_SCHEMA_MANIFEST_V32}
        self.assertIn("authenticated_expert_review_snapshot_registrations", v32)
        self.assertIn("authenticated_expert_review_receipts", v32)

    def test_atomic_commit_advances_head_and_exact_replay_returns_original(self) -> None:
        fixture = phase14_fixture(self)
        target = replacement_plan(fixture.plan, "2")
        preflight = replacement_preflight(fixture.store, fixture.plan, target)
        verifier = ExactAuthorityVerifier()
        service = service_for(fixture, verifier)

        receipt = service.replace(
            preflight=preflight,
            prior_plan=fixture.plan,
            replacement_plan=target,
            authority_evidence=authority_evidence(preflight),
            expected_plan_version=1,
        )
        replay = service.replace(
            preflight=preflight,
            prior_plan=fixture.plan,
            replacement_plan=target,
            authority_evidence=authority_evidence(preflight),
            expected_plan_version=1,
        )

        self.assertEqual(replay.to_dict(), receipt.to_dict())
        self.assertEqual(
            verifier.calls,
            [preflight.to_dict()["authority_requirements"][0]["requirement_id"]],
        )
        with closing(sqlite3.connect(fixture.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT active_plan_id, plan_version FROM collaboration_plan_active_heads"
                ).fetchone(),
                (target.plan_id, 2),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM collaboration_plan_activations"
                ).fetchone()[0],
                2,
            )
        self.assertEqual(fixture.store.verify_store(fixture.registry).status, "valid")

    def test_active_head_drives_legacy_work_and_audit_requires_signed_migration(self) -> None:
        fixture = phase14_fixture(self)
        second = replacement_plan(fixture.plan, "C")
        second_preflight = replacement_preflight(
            fixture.store,
            fixture.plan,
            second,
        )
        service = service_for(fixture)
        service.replace(
            preflight=second_preflight,
            prior_plan=fixture.plan,
            replacement_plan=second,
            authority_evidence=authority_evidence(second_preflight),
            expected_plan_version=1,
        )

        work = AuthenticatedWorkItemLeaseService(
            fixture.store,
            fixture.registry,
            clock=lambda: fixture.now,
        )
        self.assertEqual(
            work.status(fixture.mission.mission_id).plan_id,
            second.plan_id,
        )
        with self.assertRaises(StoreMigrationRequiredError):
            MissionAuditSnapshotService(
                fixture.store,
                fixture.registry,
                clock=lambda: fixture.now,
            ).snapshot(fixture.mission.mission_id)
        with fixture.store._read_connection() as connection:
            activation = connection.execute(
                "SELECT plan_id, issuer, assertion_id FROM collaboration_plan_activations "
                "WHERE plan_id = ?",
                (second.plan_id,),
            ).fetchone()
            self.assertEqual(activation["plan_id"], second.plan_id)
            self.assertIsNone(activation["issuer"])
            self.assertIsNone(activation["assertion_id"])

        third = replacement_plan(second, "D")
        third_preflight = replacement_preflight(
            fixture.store,
            second,
            third,
        )
        third_receipt = service.replace(
            preflight=third_preflight,
            prior_plan=second,
            replacement_plan=third,
            authority_evidence=authority_evidence(third_preflight),
            expected_plan_version=2,
        )
        self.assertEqual(third_receipt.to_dict()["replacement_plan_version"], 3)
        self.assertEqual(
            work.status(fixture.mission.mission_id).plan_id,
            third.plan_id,
        )
        self.assertEqual(fixture.store.verify_store(fixture.registry).status, "valid")

    def test_historical_policy_and_ownership_survive_replacement(self) -> None:
        policy = policy_fixture.AuthenticatedCollaborationMissionPolicyPhase88Tests(
            methodName="runTest"
        )
        policy_fixture.AuthenticatedCollaborationMissionPolicyPhase88Tests.setUpClass()
        policy.setUp()
        self.addCleanup(policy.doCleanups)
        policy._commit()
        policy_target = replacement_plan(policy.plan, "E")
        policy_preflight = replacement_preflight(
            policy.store,
            policy.plan,
            policy_target,
        )
        service_for(policy).replace(
            preflight=policy_preflight,
            prior_plan=policy.plan,
            replacement_plan=policy_target,
            authority_evidence=authority_evidence(policy_preflight),
            expected_plan_version=1,
        )
        self.assertEqual(policy.store.verify_store(policy.registry).status, "valid")

        ownership = ownership_fixture.AuthenticatedCollaborationOwnershipPhase92Tests(
            methodName="runTest"
        )
        ownership_fixture.AuthenticatedCollaborationOwnershipPhase92Tests.setUpClass()
        ownership.setUp()
        self.addCleanup(ownership.doCleanups)
        ownership._commit()
        root = ownership.fixture
        ownership_target = replacement_plan(root.plan, "F")
        ownership_preflight = replacement_preflight(
            root.store,
            root.plan,
            ownership_target,
            completed=completed_results(
                root.store,
                root.mission.mission_id,
                root.plan.plan_id,
            ),
        )
        service_for(root).replace(
            preflight=ownership_preflight,
            prior_plan=root.plan,
            replacement_plan=ownership_target,
            authority_evidence=authority_evidence(ownership_preflight),
            expected_plan_version=1,
        )
        self.assertEqual(root.store.verify_store(root.registry).status, "valid")

    def test_historical_session_and_dispatch_survive_replacement(self) -> None:
        session = session_fixture.AuthenticatedCollaborationExecutionSessionAuthorityPhase123Tests(
            methodName="runTest"
        )
        session.setUp()
        self.addCleanup(session.doCleanups)
        session._activate()
        session._revoke()
        root = session.root
        root.now += timedelta(seconds=1)
        policy_version = dispatch_auth.POLICY_VERSION
        policy = root.factory.policy(
            max_assertion_lifetime_seconds=900,
            policy_version=policy_version,
            store_id=root.store_id,
            allowed_profiles=[session.control_id, session.worker_id],
            allowed_operations=[
                PrincipalOperation.EXECUTOR_DISPATCH_SAFETY_AUTHORIZE.value,
            ],
        )
        root.trust.apply_policy(policy)
        dispatch_authentication = (
            dispatch_auth.CollaborationExecutorDispatchAuthenticationPhase127Tests
        )
        grant = dispatch_authentication._grant(
            root,
            "SGR-" + "99" * 16,
            session.control_id,
            PrincipalOperation.EXECUTOR_DISPATCH_SAFETY_AUTHORIZE,
            expires_at="2026-07-30T10:20:00Z",
        )
        root.acceptance.accept(grant)
        status = CollaborationExecutionSessionAuthorityStatusService(
            root.store,
            root.registry,
            clock=lambda: root.now,
        ).get(session.authority.session_authority_id)
        operation_input = b"replacement-history-stop"
        dispatch = build_collaboration_executor_dispatch(
            status=status,
            authority=session.authority,
            collaboration_plan=root.plan,
            operation="stop",
            operation_sequence=1,
            tool_policy_sha256="sha256:" + "98" * 32,
            operation_input_sha256=(collaboration_executor_operation_input_sha256(operation_input)),
            issued_at="2026-07-30T10:09:01Z",
            expires_at="2026-07-30T10:10:00Z",
        )
        assertion = dispatch_authentication._assertion(
            root,
            grant,
            "PAS-" + "99" * 16,
            session.control_id,
            PrincipalOperation.EXECUTOR_DISPATCH_SAFETY_AUTHORIZE,
            dispatch,
            issued_at="2026-07-30T10:09:01Z",
            expires_at="2026-07-30T10:12:00Z",
        )
        AuthenticatedCollaborationExecutorDispatchService(
            root.store,
            root.registry,
            clock=lambda: root.now,
        ).reserve(
            dispatch,
            operation_input,
            authorizer_assertion=assertion,
        )
        target = replacement_plan(root.plan, "1")
        preflight = replacement_preflight(
            root.store,
            root.plan,
            target,
            completed=completed_results(
                root.store,
                root.mission.mission_id,
                root.plan.plan_id,
            ),
        )
        service_for(root).replace(
            preflight=preflight,
            prior_plan=root.plan,
            replacement_plan=target,
            authority_evidence=authority_evidence(preflight),
            expected_plan_version=1,
        )
        self.assertEqual(root.store.verify_store(root.registry).status, "valid")

    def test_conflicting_replay_fails_closed(self) -> None:
        fixture = phase14_fixture(self)
        target = replacement_plan(fixture.plan, "3")
        preflight = replacement_preflight(fixture.store, fixture.plan, target)
        service = service_for(fixture)
        service.replace(
            preflight=preflight,
            prior_plan=fixture.plan,
            replacement_plan=target,
            authority_evidence=authority_evidence(preflight),
            expected_plan_version=1,
        )
        evidence = list(authority_evidence(preflight))
        changed = evidence[0].to_dict()
        changed["evidence"] = {**changed["evidence"], "nonce": "different"}
        changed["evidence_sha256"] = canonical_sha256(changed["evidence"])
        evidence[0] = ReplacementAuthorityEvidence.from_dict(changed)
        with self.assertRaisesRegex(StoreConflictError, "already committed differently"):
            service.replace(
                preflight=preflight,
                prior_plan=fixture.plan,
                replacement_plan=target,
                authority_evidence=evidence,
                expected_plan_version=1,
            )

    def test_authority_failure_rolls_back_every_table(self) -> None:
        fixture = phase14_fixture(self)
        target = replacement_plan(fixture.plan, "4")
        preflight = replacement_preflight(fixture.store, fixture.plan, target)
        with self.assertRaises(PrincipalAuthenticationError):
            service_for(fixture, ExactAuthorityVerifier(fail=True)).replace(
                preflight=preflight,
                prior_plan=fixture.plan,
                replacement_plan=target,
                authority_evidence=authority_evidence(preflight),
                expected_plan_version=1,
            )
        with closing(sqlite3.connect(fixture.path)) as connection:
            for table in (
                "collaboration_plan_replacement_commits",
                "collaboration_plan_replacement_authorities",
                "collaboration_plan_replacement_source_settlements",
                "collaboration_plan_completed_work_carry_forwards",
                "collaboration_plan_work_initializations",
            ):
                self.assertEqual(
                    connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0], 0
                )
            self.assertEqual(
                connection.execute(
                    "SELECT active_plan_id, plan_version FROM collaboration_plan_active_heads"
                ).fetchone(),
                (fixture.plan.plan_id, 1),
            )

    def test_failure_after_writes_rolls_back_complete_graph(self) -> None:
        fixture = phase14_fixture(self)
        target = replacement_plan(fixture.plan, "5")
        preflight = replacement_preflight(fixture.store, fixture.plan, target)

        class FailingAfterWritesService(_CollaborationPlanReplacementAtomicStore):
            def _insert_commit_graph(self, *args: Any, **kwargs: Any) -> None:
                super()._insert_commit_graph(*args, **kwargs)
                raise StoreError("injected failure after writes")

        service = FailingAfterWritesService(
            fixture.store,
            fixture.registry,
            ExactAuthorityVerifier(),
            clock=lambda: fixture.now,
        )
        with self.assertRaisesRegex(StoreError, "injected failure"):
            service.replace(
                preflight=preflight,
                prior_plan=fixture.plan,
                replacement_plan=target,
                authority_evidence=authority_evidence(preflight),
                expected_plan_version=1,
            )
        with closing(sqlite3.connect(fixture.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM collaboration_plan_activations"
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM collaboration_plan_replacement_commits"
                ).fetchone()[0],
                0,
            )

    def test_source_revision_drift_fails_before_authority_consumption(self) -> None:
        fixture = phase14_fixture(self)
        target = replacement_plan(fixture.plan, "6")
        preflight = replacement_preflight(
            fixture.store,
            fixture.plan,
            target,
            mission_revision_override=1,
        )
        verifier = ExactAuthorityVerifier()
        with self.assertRaisesRegex(StoreConflictError, "Mission revision drifted"):
            service_for(fixture, verifier).replace(
                preflight=preflight,
                prior_plan=fixture.plan,
                replacement_plan=target,
                authority_evidence=authority_evidence(preflight),
                expected_plan_version=1,
            )
        self.assertEqual(verifier.calls, [])

    def test_active_work_lease_blocks_replacement(self) -> None:
        fixture = work_fixture.AuthenticatedWorkPhase15Tests(methodName="runTest")
        work_fixture.AuthenticatedWorkPhase15Tests.setUpClass()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture._claim(token="7")
        target = replacement_plan(fixture.plan, "7")
        preflight = replacement_preflight(fixture.store, fixture.plan, target)
        with self.assertRaisesRegex(StoreConflictError, "leases are not terminal"):
            service_for(fixture).replace(
                preflight=preflight,
                prior_plan=fixture.plan,
                replacement_plan=target,
                authority_evidence=authority_evidence(preflight),
                expected_plan_version=1,
            )

    def test_active_execution_session_blocks_replacement(self) -> None:
        fixture = session_fixture.AuthenticatedCollaborationExecutionSessionAuthorityPhase123Tests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture._activate()
        root = fixture.root
        target = replacement_plan(root.plan, "8")
        preflight = replacement_preflight(root.store, root.plan, target)
        with self.assertRaisesRegex(StoreConflictError, "sessions are not terminal"):
            service_for(root).replace(
                preflight=preflight,
                prior_plan=root.plan,
                replacement_plan=target,
                authority_evidence=authority_evidence(preflight),
                expected_plan_version=1,
            )

    def test_completed_and_remaining_work_are_conserved(self) -> None:
        fixture = work_fixture.AuthenticatedWorkPhase15Tests(methodName="runTest")
        work_fixture.AuthenticatedWorkPhase15Tests.setUpClass()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        _, claim = fixture._claim(token="8")
        fixture.now += timedelta(minutes=1)
        completion = {
            "evidence_manifest_sha256": "sha256:" + "6" * 64,
            "result_id": "RES-REPLACEMENT-CARRY-001",
            "result_sha256": "sha256:" + "7" * 64,
        }
        assertion = fixture._assertion(
            PrincipalOperation.WORK_COMPLETE,
            fixture._active_intent(
                PrincipalOperation.WORK_COMPLETE,
                claim,
                extra=completion,
            ),
            "9",
            fixture.readiness.owner_profile_id,
            fixture.owner_grant,
        )
        fixture.service.complete(
            assertion,
            fixture.mission.mission_id,
            fixture.readiness.work_item_id,
            claim_generation=claim.generation,
            previous_transition_id=claim.transition_id,
            expected_lease_expires_at=claim.lease_expires_at,
            **completion,
        )
        target = replacement_plan(fixture.plan, "9")
        preflight = replacement_preflight(
            fixture.store,
            fixture.plan,
            target,
            completed={fixture.readiness.work_item_id: completion["result_sha256"]},
        )
        receipt = service_for(fixture).replace(
            preflight=preflight,
            prior_plan=fixture.plan,
            replacement_plan=target,
            authority_evidence=authority_evidence(preflight),
            expected_plan_version=1,
        )
        self.assertEqual(receipt.to_dict()["completed_carry_forward_count"], 1)
        status = fixture.service.status(
            fixture.mission.mission_id,
            work_item_id=fixture.readiness.work_item_id,
        ).work_items[0]
        self.assertEqual(status.state.value, "completed")
        self.assertEqual(status.result_sha256, completion["result_sha256"])
        with closing(sqlite3.connect(fixture.path)) as connection:
            states = connection.execute(
                """
                SELECT initial_state, COUNT(*)
                FROM collaboration_plan_work_initializations
                GROUP BY initial_state ORDER BY initial_state
                """
            ).fetchall()
            self.assertEqual(
                dict(states),
                {
                    "completed_carried_forward": 1,
                    "pending": len(target.work_items) - 1,
                },
            )
        self.assertEqual(fixture.store.verify_store(fixture.registry).status, "valid")

    def test_competing_replacements_use_one_compare_and_swap_head(self) -> None:
        fixture = phase14_fixture(self)
        targets = (replacement_plan(fixture.plan, "A"), replacement_plan(fixture.plan, "B"))
        preflights = tuple(
            replacement_preflight(fixture.store, fixture.plan, target) for target in targets
        )

        def run(index: int):
            try:
                return service_for(fixture).replace(
                    preflight=preflights[index],
                    prior_plan=fixture.plan,
                    replacement_plan=targets[index],
                    authority_evidence=authority_evidence(preflights[index]),
                    expected_plan_version=1,
                )
            except Exception as exc:
                return exc

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = tuple(executor.map(run, (0, 1)))
        self.assertEqual(
            sum(not isinstance(result, Exception) for result in results),
            1,
        )
        self.assertEqual(
            sum(isinstance(result, StoreConflictError) for result in results),
            1,
        )
        with closing(sqlite3.connect(fixture.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM collaboration_plan_replacement_commits"
                ).fetchone()[0],
                1,
            )

    def test_v28_migration_backfills_version_one_head_and_restores_pragmas(self) -> None:
        fixture = phase14_fixture(self)
        self._downgrade_to_v28(fixture.path)
        with closing(sqlite3.connect(fixture.path)) as connection:
            self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST_V28)

        class RecordingStore(MissionStore):
            restored: tuple[int, int] | None = None

            def _restore_v29_schema_rebuild_pragmas(self, connection):
                super()._restore_v29_schema_rebuild_pragmas(connection)
                self.restored = (
                    int(connection.execute("PRAGMA foreign_keys").fetchone()[0]),
                    int(connection.execute("PRAGMA legacy_alter_table").fetchone()[0]),
                )

        store = RecordingStore(fixture.path, clock=lambda: fixture.now)
        with tempfile.TemporaryDirectory() as directory:
            report = store.migrate(
                fixture.registry,
                Path(directory) / "before-v29.sqlite3",
            )
        self.assertEqual(report.source_version, 28)
        self.assertEqual(report.target_version, 39)
        self.assertEqual(store.restored, (1, 0))
        with closing(sqlite3.connect(fixture.path)) as connection:
            self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST)
            self.assertEqual(
                connection.execute(
                    "SELECT active_plan_id, plan_version FROM collaboration_plan_active_heads"
                ).fetchone(),
                (fixture.plan.plan_id, 1),
            )
        self.assertEqual(store.verify_store(fixture.registry).status, "valid")

    def test_unsigned_schema29_history_cannot_be_promoted_to_signed_current_custody(self) -> None:
        fixture = phase14_fixture(self)
        target = replacement_plan(fixture.plan, "E")
        preflight = replacement_preflight(fixture.store, fixture.plan, target)
        receipt = service_for(fixture).replace(
            preflight=preflight,
            prior_plan=fixture.plan,
            replacement_plan=target,
            authority_evidence=authority_evidence(preflight),
            expected_plan_version=1,
        )
        with closing(sqlite3.connect(fixture.path)) as connection:
            original = tuple(connection.iterdump())
        store = MissionStore(fixture.path, clock=lambda: fixture.now)
        with tempfile.TemporaryDirectory() as directory:
            backup = Path(directory) / "unsigned-schema29-preserved.sqlite3"
            with self.assertRaisesRegex(StoreIntegrityError, "no signed authority custody"):
                store.migrate(fixture.registry, backup)
            self.assertTrue(backup.is_file())
            with closing(sqlite3.connect(backup)) as connection:
                self.assertEqual(tuple(connection.iterdump()), original)
                self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST_V29)
            with closing(sqlite3.connect(fixture.path)) as connection:
                self.assertEqual(tuple(connection.iterdump()), original)
                self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 29)
            self.assertEqual(service_for(fixture).get(fixture.mission.mission_id), receipt)
            self.assertEqual(store.verify_store(fixture.registry).status, "valid")

    @staticmethod
    def _downgrade_to_v28(path: Path) -> None:
        with closing(sqlite3.connect(path)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            remove_schema_v31_objects(connection)
            remove_schema_v29_objects(connection)
            connection.execute(
                "UPDATE store_metadata SET value = '28' WHERE key = 'schema_version'"
            )
            connection.execute("PRAGMA user_version = 28")
            connection.commit()


if __name__ == "__main__":
    unittest.main()
