"""Phase190 authenticated plan replacement operator boundary coverage."""

from __future__ import annotations

import json
import sqlite3
import unittest
from contextlib import closing
from dataclasses import replace
from unittest import mock

try:
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
except ImportError:  # pragma: no cover
    Draft202012Validator = None
    Registry = None
    Resource = None

from sunderkey.cli import build_parser
from sunderkey.collaboration_plan_replacement_operations import (
    PREPARATION_DOMAIN,
    READINESS_DOMAIN,
    CollaborationPlanReplacementOperationsService,
    CollaborationPlanReplacementReadiness,
    PlanReplacementCompareAndSwapError,
    PlanReplacementCustodyError,
    PlanReplacementDrainError,
    PreparedCollaborationPlanReplacement,
    StalePlanReplacementReadinessError,
    _canonical_sha256,
    _drain_state,
    load_collaboration_plan_replacement_credentials,
    load_collaboration_plan_replacement_readiness,
)
from sunderkey.errors import (
    CollaborationPlanError,
    PrincipalAuthenticationError,
    StoreConflictError,
    StoreIntegrityError,
)

from .test_authenticated_collaboration_plan_replacement_phase186d import (
    AUTHORITY_PATH,
    NOW,
    REGISTRY_PATH,
    AuthenticatedPlanReplacementFixture,
)


def _mapping_intents(fixture: AuthenticatedPlanReplacementFixture):
    return [
        {
            "source_work_item_id": item["source_work_item_id"],
            "replacement_work_item_id": item["replacement_work_item_id"],
            "cross_command_evidence": item["cross_command_evidence"],
        }
        for item in fixture.preflight.to_dict()["item_mappings"]
    ]


def _service(fixture: AuthenticatedPlanReplacementFixture):
    return CollaborationPlanReplacementOperationsService(
        fixture.store,
        fixture.registry,
        fixture.authority_policy,
        registry_source=REGISTRY_PATH,
        clock=lambda: NOW,
    )


def _prepare(fixture: AuthenticatedPlanReplacementFixture):
    return _service(fixture).prepare(
        replacement_plan=fixture.replacement,
        mapping_intents=_mapping_intents(fixture),
        independent_assurance_profile_id="AOE-HQ-18",
        second_control_profile_id="AOE-HQ-15",
        issued_at="2026-07-30T10:10:00Z",
        expires_at="2026-07-30T10:25:00Z",
    )


def _readdress_preparation(document):
    readiness = document["readiness"]
    readiness_body = {
        key: value
        for key, value in readiness.items()
        if key not in {"readiness_id", "readiness_sha256"}
    }
    readiness_digest = _canonical_sha256({"domain": READINESS_DOMAIN, "readiness": readiness_body})
    readiness["readiness_sha256"] = readiness_digest
    readiness["readiness_id"] = "RRA-" + readiness_digest.removeprefix("sha256:")[:32].upper()
    preparation_body = {
        key: value
        for key, value in document.items()
        if key not in {"preparation_id", "preparation_sha256"}
    }
    preparation_digest = _canonical_sha256(
        {"domain": PREPARATION_DOMAIN, "preparation": preparation_body}
    )
    document["preparation_sha256"] = preparation_digest
    document["preparation_id"] = "RPP-" + preparation_digest.removeprefix("sha256:")[:32].upper()
    return PreparedCollaborationPlanReplacement.from_dict(document)


def _readdress_readiness(document):
    body = {
        key: value
        for key, value in document.items()
        if key not in {"readiness_id", "readiness_sha256"}
    }
    digest = _canonical_sha256({"domain": READINESS_DOMAIN, "readiness": body})
    document["readiness_sha256"] = digest
    document["readiness_id"] = "RRA-" + digest.removeprefix("sha256:")[:32].upper()
    return document


def _table_counts(path) -> dict[str, int]:
    with closing(sqlite3.connect(path)) as connection:
        tables = [
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
        ]
        return {
            table: int(connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])
            for table in tables
        }


class CollaborationPlanReplacementOperationsPhase190Tests(unittest.TestCase):
    def test_readiness_and_preparation_are_exact_and_read_only(self) -> None:
        fixture = AuthenticatedPlanReplacementFixture(self)
        service = _service(fixture)
        counts_before = _table_counts(fixture.path)
        readiness = service.assess(
            replacement_plan=fixture.replacement,
            mapping_intents=_mapping_intents(fixture),
            independent_assurance_profile_id="AOE-HQ-18",
            second_control_profile_id="AOE-HQ-15",
        )
        document = readiness.to_dict()
        self.assertEqual(document["runtime_effect"], "none")
        self.assertEqual(document["readiness_status"], "ready_for_signed_authority")
        self.assertEqual(document["required_assertion_count"], 16)
        self.assertEqual(document["required_replay_key_count"], 16)
        self.assertEqual(document["preflight"], fixture.preflight.to_dict())
        self.assertEqual(
            CollaborationPlanReplacementReadiness.from_dict(document).to_dict(),
            document,
        )
        prepared = _prepare(fixture)
        self.assertEqual(prepared.to_dict()["authority_plan"], fixture.authority_plan.to_dict())
        self.assertEqual(_table_counts(fixture.path), counts_before)

    def test_execute_replay_conflict_and_work_conservation(self) -> None:
        fixture = AuthenticatedPlanReplacementFixture(self)
        service = _service(fixture)
        prepared = _prepare(fixture)
        alternate = service.prepare(
            replacement_plan=fixture.replacement,
            mapping_intents=_mapping_intents(fixture),
            independent_assurance_profile_id="AOE-HQ-18",
            second_control_profile_id="AOE-HQ-15",
            issued_at="2026-07-30T10:10:00Z",
            expires_at="2026-07-30T10:24:00Z",
        )
        receipt = service.execute(preparation=prepared, credentials=fixture.credentials)
        replay = service.execute(preparation=prepared, credentials=fixture.credentials)
        self.assertEqual(replay.to_dict(), receipt.to_dict())
        self.assertEqual(receipt.to_dict()["replacement_plan_id"], fixture.replacement.plan_id)
        altered_provenance = prepared.to_dict()
        altered_provenance["readiness"]["scope_high_water"]["accepted_grant_count"] += 1
        altered = _readdress_preparation(altered_provenance)
        with self.assertRaisesRegex(StoreConflictError, "replay preparation conflicts"):
            service.execute(preparation=altered, credentials=fixture.credentials)
        changed = list(fixture.credentials)
        changed[0] = replace(changed[0], assertion=changed[1].assertion)
        with self.assertRaisesRegex(StoreConflictError, "replay inputs conflict"):
            service.execute(preparation=prepared, credentials=changed)
        with self.assertRaisesRegex(StoreConflictError, "replay preparation conflicts"):
            service.execute(preparation=alternate, credentials=fixture.credentials)
        with closing(sqlite3.connect(fixture.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM collaboration_plan_replacement_source_settlements "
                    "WHERE replacement_commit_id = ?",
                    (receipt.replacement_commit_id,),
                ).fetchone()[0],
                len(fixture.prior.work_items),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM collaboration_plan_work_initializations "
                    "WHERE replacement_commit_id = ?",
                    (receipt.replacement_commit_id,),
                ).fetchone()[0],
                len(fixture.replacement.work_items),
            )

    def test_exact_replay_revalidates_durable_principal_custody(self) -> None:
        fixture = AuthenticatedPlanReplacementFixture(self)
        service = _service(fixture)
        prepared = _prepare(fixture)
        service.execute(preparation=prepared, credentials=fixture.credentials)
        credential = fixture.credentials[0]
        with closing(sqlite3.connect(fixture.path)) as connection:
            trigger_sql = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?",
                ("principal_assertion_use_immutable",),
            ).fetchone()[0]
            connection.execute("DROP TRIGGER principal_assertion_use_immutable")
            connection.execute(
                "UPDATE principal_assertion_uses SET subject = ? "
                "WHERE issuer = ? AND assertion_id = ?",
                (
                    "forged-subject",
                    credential.assertion.issuer,
                    credential.assertion.assertion_id,
                ),
            )
            connection.execute(trigger_sql)
            connection.commit()
        with self.assertRaisesRegex(StoreIntegrityError, "assertion use binding"):
            service.execute(preparation=prepared, credentials=fixture.credentials)

    def test_authentication_failure_and_stale_preparation_are_distinct(self) -> None:
        fixture = AuthenticatedPlanReplacementFixture(self)
        service = _service(fixture)
        prepared = _prepare(fixture)
        changed = list(fixture.credentials)
        changed[0] = replace(changed[0], assertion=changed[1].assertion)
        with self.assertRaises(PrincipalAuthenticationError):
            service.execute(preparation=prepared, credentials=changed)
        with closing(sqlite3.connect(fixture.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM collaboration_plan_replacement_authentications"
                ).fetchone()[0],
                fixture.baseline_counts["collaboration_plan_replacement_authentications"],
            )
        fixture.store._clock = lambda: NOW
        fixture._commit_mission_policy(
            plan=fixture.prior,
            policy_version=3,
            previous_policy_sha256=fixture.mission_policy.policy_sha256,
            marker=260,
        )
        with self.assertRaises(StalePlanReplacementReadinessError):
            service.execute(preparation=prepared, credentials=fixture.credentials)

    def test_readiness_rejects_tampering_and_blocked_preparation(self) -> None:
        fixture = AuthenticatedPlanReplacementFixture(self)
        service = _service(fixture)
        readiness = service.assess(
            replacement_plan=fixture.replacement,
            mapping_intents=_mapping_intents(fixture),
            independent_assurance_profile_id="AOE-HQ-18",
            second_control_profile_id="AOE-HQ-15",
        )
        tampered = readiness.to_dict()
        tampered["mission_revision"] += 1
        with self.assertRaises(CollaborationPlanError):
            CollaborationPlanReplacementReadiness.from_dict(tampered)
        boolean_revision = readiness.to_dict()
        boolean_revision["mission_revision"] = True
        with self.assertRaisesRegex(CollaborationPlanError, "source binding"):
            CollaborationPlanReplacementReadiness.from_dict(_readdress_readiness(boolean_revision))
        invalid_store = readiness.to_dict()
        invalid_store["store_id"] = "not-a-store"
        with self.assertRaisesRegex(CollaborationPlanError, "source binding"):
            CollaborationPlanReplacementReadiness.from_dict(_readdress_readiness(invalid_store))
        stale_intents = readiness.to_dict()
        stale_intents["mapping_intents"][0]["replacement_work_item_id"] = "WIT-FAKE"
        with self.assertRaisesRegex(CollaborationPlanError, "mapping intents are stale"):
            CollaborationPlanReplacementReadiness.from_dict(_readdress_readiness(stale_intents))
        unknown_snapshots = readiness.to_dict()
        unknown_snapshots["source_snapshot_hashes"] = {
            f"unknown_snapshot_{index}": None for index in range(5)
        }
        with self.assertRaisesRegex(CollaborationPlanError, "source snapshots"):
            CollaborationPlanReplacementReadiness.from_dict(unknown_snapshots)
        invalid_high_water = readiness.to_dict()
        invalid_high_water["trust_high_water"]["policy_version"] = None
        with self.assertRaisesRegex(CollaborationPlanError, "trust high-water"):
            CollaborationPlanReplacementReadiness.from_dict(invalid_high_water)
        invalid_high_water_time = readiness.to_dict()
        invalid_high_water_time["trust_high_water"]["applied_at"] = "not-a-timestamp"
        with self.assertRaisesRegex(CollaborationPlanError, "trust high-water"):
            CollaborationPlanReplacementReadiness.from_dict(
                _readdress_readiness(invalid_high_water_time)
            )
        blocked = readiness.to_dict()
        blocked["drain_blockers"] = [
            {
                "blocker_code": "active_work_lease",
                "subject_id": "WIT-TEST",
                "work_item_id": "WIT-TEST",
                "detail": "Source work lease must reach a terminal transition",
            }
        ]
        blocked["readiness_status"] = "blocked_pending_drain"
        body = {
            key: value
            for key, value in blocked.items()
            if key not in {"readiness_id", "readiness_sha256"}
        }
        digest = _canonical_sha256({"domain": READINESS_DOMAIN, "readiness": body})
        blocked["readiness_sha256"] = digest
        blocked["readiness_id"] = "RRA-" + digest.removeprefix("sha256:")[:32].upper()
        with self.assertRaises(PlanReplacementDrainError):
            service._raise_blockers(blocked)
        blocked["drain_blockers"][0]["blocker_code"] = "terminal_custody_missing"
        with self.assertRaises(PlanReplacementCustodyError):
            service._raise_blockers(blocked)

    def test_atomic_race_failures_have_distinct_operator_classes(self) -> None:
        fixture = AuthenticatedPlanReplacementFixture(self)
        service = _service(fixture)
        prepared = _prepare(fixture)
        target = (
            "sunderkey.collaboration_plan_replacement_operations."
            "AuthenticatedCollaborationPlanReplacementStoreService.replace"
        )
        with (
            mock.patch(
                target, side_effect=StoreConflictError("Active collaboration plan head changed")
            ),
            self.assertRaises(PlanReplacementCompareAndSwapError),
        ):
            service.execute(preparation=prepared, credentials=fixture.credentials)
        with (
            mock.patch(
                target,
                side_effect=StoreConflictError("Source execution sessions are not terminal"),
            ),
            self.assertRaises(PlanReplacementDrainError),
        ):
            service.execute(preparation=prepared, credentials=fixture.credentials)

    def test_loaders_reject_duplicate_keys_and_control_characters(self) -> None:
        fixture = AuthenticatedPlanReplacementFixture(self)
        readiness = _service(fixture).assess(
            replacement_plan=fixture.replacement,
            mapping_intents=_mapping_intents(fixture),
            independent_assurance_profile_id="AOE-HQ-18",
            second_control_profile_id="AOE-HQ-15",
        )
        payload = json.dumps(readiness.to_dict())
        self.assertNotIn("\\u2013", payload)
        self.assertNotIn("\\u2014", payload)
        duplicate = fixture.path.parent / "duplicate.json"
        duplicate.write_text(
            '{"schema_version":1,"schema_version":1,"credentials":[]}',
            encoding="utf-8",
        )
        with self.assertRaises(PrincipalAuthenticationError):
            load_collaboration_plan_replacement_credentials(duplicate)
        controlled = fixture.path.parent / "controlled.json"
        controlled.write_text(
            json.dumps({**readiness.to_dict(), "mission_id": "bad\u0000id"}),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(CollaborationPlanError, "control characters"):
            load_collaboration_plan_replacement_readiness(controlled)

    def test_drain_assessment_requires_exact_lease_session_and_custody(self) -> None:
        with closing(sqlite3.connect(":memory:")) as connection:
            connection.row_factory = sqlite3.Row
            connection.executescript(
                """
                CREATE TABLE collaboration_work_item_transitions (
                    transition_id TEXT, mission_id TEXT, plan_id TEXT,
                    work_item_id TEXT, generation INTEGER, transition_kind TEXT,
                    result_sha256 TEXT, recorded_at TEXT
                );
                CREATE TABLE collaboration_work_item_recovery_transitions (
                    transition_id TEXT, mission_id TEXT, plan_id TEXT,
                    work_item_id TEXT, generation INTEGER, transition_kind TEXT,
                    result_sha256 TEXT, recorded_at TEXT
                );
                CREATE TABLE execution_session_authority_commits (
                    session_authority_id TEXT, session_id TEXT, mission_id TEXT,
                    collaboration_plan_id TEXT, work_item_id TEXT
                );
                CREATE TABLE execution_session_activation_commits (
                    session_authority_id TEXT
                );
                CREATE TABLE execution_session_revocation_commits (
                    session_authority_id TEXT
                );
                CREATE TABLE execution_terminal_custody_commits (
                    mission_id TEXT, work_item_id TEXT, custody_plan_json TEXT
                );
                INSERT INTO collaboration_work_item_transitions VALUES
                    ('WTR-1', 'MSN-1', 'CLP-1', 'WIT-1', 1, 'claim', NULL,
                     '2026-09-20T18:00:00Z');
                INSERT INTO execution_session_authority_commits VALUES
                    ('ESA-1', 'SES-1', 'MSN-1', 'CLP-1', 'WIT-2');
                INSERT INTO execution_session_activation_commits VALUES ('ESA-1');
                """
            )
            blockers, operations = _drain_state(connection, "MSN-1", "CLP-1", {"WIT-2"})
            self.assertEqual(
                {item["blocker_code"] for item in blockers},
                {"active_work_lease", "active_execution_session"},
            )
            self.assertEqual(len(operations), 2)
            connection.execute(
                "INSERT INTO collaboration_work_item_transitions VALUES "
                "('WTR-2', 'MSN-1', 'CLP-1', 'WIT-1', 2, 'release', NULL, ?)",
                ("2026-09-20T18:01:00Z",),
            )
            connection.execute("INSERT INTO execution_session_revocation_commits VALUES ('ESA-1')")
            blockers, _operations = _drain_state(connection, "MSN-1", "CLP-1", {"WIT-2"})
            self.assertEqual(
                [item["blocker_code"] for item in blockers],
                ["terminal_custody_missing"],
            )
            connection.execute(
                "INSERT INTO execution_terminal_custody_commits VALUES (?, ?, ?)",
                (
                    "MSN-1",
                    "WIT-2",
                    json.dumps({"transfer_request": {"source_session": {"session_id": "SES-1"}}}),
                ),
            )
            blockers, operations = _drain_state(connection, "MSN-1", "CLP-1", {"WIT-2"})
            self.assertEqual((blockers, operations), ([], []))

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_readiness_and_preparation_match_schemas(self) -> None:
        fixture = AuthenticatedPlanReplacementFixture(self)
        preparation = _prepare(fixture)
        schema_root = REGISTRY_PATH.parent / "schemas"
        readiness_schema = json.loads(
            (schema_root / "collaboration-plan-replacement-readiness-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        preparation_schema = json.loads(
            (schema_root / "collaboration-plan-replacement-preparation-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        referenced_schemas = [
            json.loads((schema_root / name).read_text(encoding="utf-8"))
            for name in (
                "collaboration-plan.schema.json",
                "collaboration-mission-reconfiguration-policy-v1.schema.json",
                "collaboration-reconfiguration-authority-policy-v1.schema.json",
                "collaboration-plan-replacement-preflight-v1.schema.json",
                "collaboration-plan-replacement-authority-plan-v1.schema.json",
                "collaboration-plan-replacement-authority-upgrade-v2.schema.json",
            )
        ]
        Draft202012Validator.check_schema(readiness_schema)
        Draft202012Validator.check_schema(preparation_schema)
        registry = Registry().with_resources(
            (schema["$id"], Resource.from_contents(schema))
            for schema in (readiness_schema, *referenced_schemas)
        )
        Draft202012Validator(readiness_schema, registry=registry).validate(
            preparation.to_dict()["readiness"]
        )
        Draft202012Validator(preparation_schema, registry=registry).validate(preparation.to_dict())

    def test_cli_readiness_prepare_and_execute_use_operator_boundary(self) -> None:
        fixture = AuthenticatedPlanReplacementFixture(self)
        service = _service(fixture)
        directory = fixture.path.parent
        replacement_path = directory / "replacement.json"
        mapping_path = directory / "mappings.json"
        credentials_path = directory / "credentials.json"
        readiness_path = directory / "readiness.json"
        preparation_path = directory / "preparation.json"
        receipt_path = directory / "receipt.json"
        replacement_path.write_text(json.dumps(fixture.replacement.to_dict()), encoding="utf-8")
        mapping_path.write_text(
            json.dumps({"schema_version": 1, "mapping_intents": _mapping_intents(fixture)}),
            encoding="utf-8",
        )
        credentials_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "credentials": [
                        {
                            "source_requirement_id": item.source_requirement_id,
                            "upgraded_requirement_id": item.upgraded_requirement_id,
                            "replay_key_sha256": item.replay_key_sha256,
                            "scope_grant": item.scope_grant.to_dict(),
                            "assertion": item.assertion.to_dict(),
                        }
                        for item in fixture.credentials
                    ],
                }
            ),
            encoding="utf-8",
        )
        common = [
            "--store",
            str(fixture.path),
            "--registry",
            str(REGISTRY_PATH),
            "--authority-policy",
            str(AUTHORITY_PATH),
        ]
        with mock.patch(
            "sunderkey.cli._collaboration_plan_replacement_operations_service",
            return_value=service,
        ):
            readiness_args = build_parser().parse_args(
                [
                    "collaboration-plan-replacement-readiness",
                    *common,
                    "--replacement-plan",
                    str(replacement_path),
                    "--mapping-intents",
                    str(mapping_path),
                    "--independent-assurance-profile-id",
                    "AOE-HQ-18",
                    "--second-control-profile-id",
                    "AOE-HQ-15",
                    "--output",
                    str(readiness_path),
                ]
            )
            readiness_args.handler(readiness_args)
            prepare_args = build_parser().parse_args(
                [
                    "collaboration-plan-replacement-prepare",
                    *common,
                    "--replacement-plan",
                    str(replacement_path),
                    "--mapping-intents",
                    str(mapping_path),
                    "--independent-assurance-profile-id",
                    "AOE-HQ-18",
                    "--second-control-profile-id",
                    "AOE-HQ-15",
                    "--issued-at",
                    "2026-07-30T10:10:00Z",
                    "--expires-at",
                    "2026-07-30T10:25:00Z",
                    "--output",
                    str(preparation_path),
                ]
            )
            prepare_args.handler(prepare_args)
            execute_args = build_parser().parse_args(
                [
                    "collaboration-plan-replacement-execute",
                    *common,
                    "--preparation",
                    str(preparation_path),
                    "--credentials",
                    str(credentials_path),
                    "--output",
                    str(receipt_path),
                ]
            )
            execute_args.handler(execute_args)
        self.assertEqual(
            json.loads(readiness_path.read_text(encoding="utf-8"))["runtime_effect"],
            "none",
        )
        self.assertEqual(
            json.loads(receipt_path.read_text(encoding="utf-8"))["replacement_plan_id"],
            fixture.replacement.plan_id,
        )


if __name__ == "__main__":
    unittest.main()
