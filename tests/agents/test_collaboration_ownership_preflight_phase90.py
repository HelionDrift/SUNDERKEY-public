"""Phase 90 policy-backed ownership transition preflight coverage."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import tomllib
import unittest
from contextlib import closing
from datetime import timedelta
from pathlib import Path
from unittest.mock import Mock, call, patch

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.cli import build_parser as legacy_build_parser
from sunderkey.authenticated_collaboration_mission_policy import (
    AuthenticatedCollaborationMissionPolicyService,
)
from sunderkey.cli import build_parser
from sunderkey.collaboration_mission_policy import (
    build_collaboration_mission_reconfiguration_policy,
    collaboration_mission_reconfiguration_selection_sha256,
)
from sunderkey.collaboration_ownership_chain import (
    build_collaboration_ownership_chain_entry,
    collaboration_work_item_objective_sha256,
)
from sunderkey.collaboration_ownership_preflight import (
    PREFLIGHT_DOMAIN,
    CollaborationOwnershipTransitionPreflightService,
)
from sunderkey.collaboration_reconfiguration_policy import (
    load_collaboration_reconfiguration_authority_policy,
)
from sunderkey.errors import PrincipalAuthenticationError, StoreConflictError
from sunderkey.identity import PrincipalOperation, compute_operation_intent_hash
from sunderkey.scope import ScopeGrantAcceptanceService
from sunderkey.store import canonical_json, sha256_text

from . import test_authenticated_work_handoffs_phase18 as phase18
from .test_cli_phase5 import run_cli
from .test_cli_phase9 import command_parser, option_strings, required_destinations
from .test_identity_phase4 import AUDIENCE, SUBJECT
from .test_store import REGISTRY_PATH

ROOT = Path(__file__).resolve().parents[2]
AUTHORITY_PATH = ROOT / "registry/collaboration-reconfiguration-policy-d001-d005.json"
PREFLIGHT_SCHEMA_PATH = (
    ROOT / "registry/schemas/collaboration-ownership-transition-preflight-v1.schema.json"
)
ENTRY_SCHEMA_PATH = ROOT / "registry/schemas/collaboration-ownership-chain-entry-v1.schema.json"
MISSION_ID = "MISSION-PHASE18-HANDOFF"
CANDIDATE_ID = phase18.CANDIDATE_ID
CONTROL_ID = phase18.CONTROL_ID
OWNER_ID = phase18.OWNER_ID
SOURCE_ID = phase18.SOURCE_ID
WRONG_COMMAND_ID = phase18.WRONG_COMMAND_ID
OWNER_GRANT_ID = "SGR-" + "8" * 32
CONTROL_GRANT_ID = "SGR-" + "9" * 32
OWNER_ASSERTION_ID = "PAS-" + "8" * 32
CONTROL_ASSERTION_ID = "PAS-" + "9" * 32


class CollaborationOwnershipPreflightPhase90Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        phase18.AuthenticatedWorkHandoffPhase18Tests.setUpClass()
        cls.authority = load_collaboration_reconfiguration_authority_policy(AUTHORITY_PATH)

    def setUp(self) -> None:
        fixture = phase18.AuthenticatedWorkHandoffPhase18Tests(
            methodName="test_unclaimed_handoff_projects_owner_and_replays"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.now += timedelta(minutes=1)
        self.fixture = fixture
        self.policy = self._commit_policy()
        self.service = CollaborationOwnershipTransitionPreflightService(
            fixture.store,
            fixture.registry,
            clock=lambda: fixture.now,
        )

    def _commit_policy(
        self,
        *,
        privileged_role_reassignment: bool = False,
    ):
        fixture = self.fixture
        policy_version = fixture.policy.policy_version + 1
        self.trust_policy_version = policy_version
        operations = sorted(
            {
                *(operation.value for operation in fixture.policy.allowed_operations),
                PrincipalOperation.COLLABORATION_POLICY_OWNER_AUTHORIZE.value,
                PrincipalOperation.COLLABORATION_POLICY_CONTROL_APPROVE.value,
            }
        )
        trust_policy = fixture.factory.policy(
            policy_version=policy_version,
            store_id=fixture.store_id,
            allowed_profiles=[
                OWNER_ID,
                CONTROL_ID,
                SOURCE_ID,
                CANDIDATE_ID,
                WRONG_COMMAND_ID,
            ],
            allowed_operations=operations,
        )
        fixture.trust.apply_policy(trust_policy)
        constraints_hash = sha256_text(canonical_json(fixture.mission.to_dict()["constraints"]))

        def grant(grant_id: str, profile_id: str, operation: PrincipalOperation):
            return fixture.factory.grant(
                grant_id=grant_id,
                profile_id=profile_id,
                store_id=fixture.store_id,
                mission_id=MISSION_ID,
                mission_context_hash=fixture.stored.context_hash,
                scope_reference=fixture.mission.scope_reference,
                scope_document_hash=fixture.mission.scope_document_hash,
                environment=fixture.mission.environment.value,
                max_action_tier=fixture.mission.max_action_tier.value,
                constraints_hash=constraints_hash,
                operations=[operation.value],
                policy_version=policy_version,
            )

        owner_grant = grant(
            OWNER_GRANT_ID,
            OWNER_ID,
            PrincipalOperation.COLLABORATION_POLICY_OWNER_AUTHORIZE,
        )
        control_grant = grant(
            CONTROL_GRANT_ID,
            CONTROL_ID,
            PrincipalOperation.COLLABORATION_POLICY_CONTROL_APPROVE,
        )
        acceptance = ScopeGrantAcceptanceService(
            fixture.store,
            fixture.registry,
        )
        acceptance.accept(owner_grant)
        acceptance.accept(control_grant)

        def placeholder(profile_id: str, marker: str) -> dict[str, str]:
            return {
                "profile_id": profile_id,
                "assertion_id": "PAS-" + marker * 32,
                "assertion_sha256": "sha256:" + marker.lower() * 64,
            }

        def policy(owner_binding, control_binding):
            return build_collaboration_mission_reconfiguration_policy(
                authority_policy=self.authority,
                policy_version=1,
                previous_policy_sha256=None,
                mission_id=MISSION_ID,
                collaboration_plan_id=fixture.plan.plan_id,
                collaboration_plan_sha256=fixture.plan.content_sha256,
                maximum_delegation_depth=3,
                reconfiguration_validity_seconds=3600,
                execution_ack_timeout_seconds=300,
                maximum_plan_replacement_items=100,
                transition_activation={
                    "privileged_role_reassignment": privileged_role_reassignment,
                    "delegation_return_and_revocation": True,
                    "cross_command_transfer": False,
                    "activated_plan_replacement": False,
                    "distributed_execution_transfer_or_cancellation": False,
                },
                mission_owner_approval=owner_binding,
                independent_control_approval=control_binding,
                effective_at="2026-07-30T10:00:00Z",
                expires_at="2026-07-30T11:00:00Z",
            )

        provisional = policy(
            placeholder(OWNER_ID, "D"),
            placeholder(CONTROL_ID, "E"),
        )
        selection_sha256 = collaboration_mission_reconfiguration_selection_sha256(provisional)

        def assertion(grant_value, assertion_id, profile_id, operation):
            intent = {
                "mission_id": MISSION_ID,
                "policy_selection_sha256": selection_sha256,
                "principal_profile_id": profile_id,
            }
            return fixture.factory.assertion(
                grant=grant_value,
                assertion_id=assertion_id,
                policy_version=policy_version,
                scope_grant_id=grant_value.grant_id,
                subject=SUBJECT,
                profile_id=profile_id,
                audience=AUDIENCE,
                store_id=fixture.store_id,
                mission_id=MISSION_ID,
                operation=operation,
                operation_intent_sha256=compute_operation_intent_hash(
                    operation,
                    intent,
                ),
            )

        owner_assertion = assertion(
            owner_grant,
            OWNER_ASSERTION_ID,
            OWNER_ID,
            PrincipalOperation.COLLABORATION_POLICY_OWNER_AUTHORIZE,
        )
        control_assertion = assertion(
            control_grant,
            CONTROL_ASSERTION_ID,
            CONTROL_ID,
            PrincipalOperation.COLLABORATION_POLICY_CONTROL_APPROVE,
        )

        def binding(value) -> dict[str, str]:
            return {
                "profile_id": value.profile_id,
                "assertion_id": value.assertion_id,
                "assertion_sha256": value.content_sha256,
            }

        committed = policy(binding(owner_assertion), binding(control_assertion))
        AuthenticatedCollaborationMissionPolicyService(
            fixture.store,
            fixture.registry,
            clock=lambda: fixture.now,
        ).commit(
            committed,
            authority_policy=self.authority,
            mission_owner_assertion=owner_assertion,
            independent_control_assertion=control_assertion,
        )
        return committed

    def _entry(
        self,
        *,
        candidate_id: str = CANDIDATE_ID,
        objective_sha256: str | None = None,
        transition_kind: str = "delegation",
        expires_at: str = "2026-07-30T10:35:00Z",
    ):
        item = self.fixture.source
        return build_collaboration_ownership_chain_entry(
            mission_id=MISSION_ID,
            collaboration_plan_id=self.fixture.plan.plan_id,
            collaboration_plan_sha256=self.fixture.plan.content_sha256,
            work_item_id=item.work_item_id,
            work_item_objective_sha256=(
                collaboration_work_item_objective_sha256(item)
                if objective_sha256 is None
                else objective_sha256
            ),
            planned_owner_id=SOURCE_ID,
            sequence=1,
            owner_epoch=1,
            transition_kind=transition_kind,
            from_owner_id=SOURCE_ID,
            to_owner_id=candidate_id,
            previous_entry_sha256=None,
            reason_code="bounded_delegation",
            requested_at="2026-07-30T10:04:00Z",
            expires_at=expires_at,
            control_role_replacement=False,
            authority_bindings={
                "current_owner_authorization_id": "AUTH-SOURCE-1",
                "proposed_owner_acceptance_id": "ACCEPT-CANDIDATE-1",
                "independent_control_approval_id": "APPROVAL-CONTROL-1",
                "second_control_or_mission_authority_id": None,
            },
        )

    def test_preflight_binds_policy_work_fence_and_chain_without_mutation(self) -> None:
        with closing(sqlite3.connect(self.fixture.path)) as connection:
            counts = (
                connection.execute("SELECT COUNT(*) FROM principal_assertion_uses").fetchone()[0],
                connection.execute(
                    "SELECT COUNT(*) FROM collaboration_work_item_handoffs"
                ).fetchone()[0],
            )
        receipt = self.service.preflight(self._entry()).to_dict()
        replay = self.service.preflight(self._entry()).to_dict()
        self.assertEqual(replay, receipt)
        self.assertEqual(
            receipt["admission_status"],
            "admissible_pending_authenticated_commit",
        )
        self.assertEqual(receipt["authentication_status"], "not_performed")
        self.assertEqual(receipt["runtime_effect"], "none")
        self.assertEqual(receipt["work_fence"]["expected_generation"], 0)
        self.assertEqual(
            receipt["candidate_qualification"]["profile_id"],
            CANDIDATE_ID,
        )
        self.assertEqual(receipt["chain_projection"]["entry_count"], 1)
        body = {
            key: value
            for key, value in receipt.items()
            if key not in {"preflight_id", "preflight_sha256"}
        }
        expected_sha256 = sha256_text(
            canonical_json({"domain": PREFLIGHT_DOMAIN, "preflight": body})
        )
        self.assertEqual(receipt["preflight_sha256"], expected_sha256)
        with closing(sqlite3.connect(self.fixture.path)) as connection:
            self.assertEqual(
                (
                    connection.execute("SELECT COUNT(*) FROM principal_assertion_uses").fetchone()[
                        0
                    ],
                    connection.execute(
                        "SELECT COUNT(*) FROM collaboration_work_item_handoffs"
                    ).fetchone()[0],
                ),
                counts,
            )

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_preflight_matches_published_schema(self) -> None:
        schema = json.loads(PREFLIGHT_SCHEMA_PATH.read_text(encoding="utf-8"))
        schema["properties"]["entry"] = json.loads(ENTRY_SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(self.service.preflight(self._entry()).to_dict())

    def test_stale_objective_and_expired_window_fail_closed(self) -> None:
        with self.assertRaisesRegex(StoreConflictError, "active work item"):
            self.service.preflight(self._entry(objective_sha256="sha256:" + "0" * 64))
        with self.assertRaisesRegex(StoreConflictError, "validity window"):
            self.service.preflight(self._entry(expires_at="2026-07-30T10:04:30Z"))

    def test_cross_command_candidate_and_noninitial_transition_fail_closed(self) -> None:
        with self.assertRaises(PrincipalAuthenticationError):
            self.service.preflight(self._entry(candidate_id=WRONG_COMMAND_ID))
        with self.assertRaisesRegex(StoreConflictError, "initial"):
            self.service.preflight(
                self._entry(
                    candidate_id=CANDIDATE_ID,
                    transition_kind="privileged_reassignment",
                )
            )

    def test_active_lease_fails_before_candidate_admission(self) -> None:
        fixture = self.fixture
        constraints_hash = sha256_text(canonical_json(fixture.mission.to_dict()["constraints"]))
        grant = fixture.factory.grant(
            grant_id="SGR-" + "7" * 32,
            profile_id=OWNER_ID,
            store_id=fixture.store_id,
            mission_id=MISSION_ID,
            mission_context_hash=fixture.stored.context_hash,
            scope_reference=fixture.mission.scope_reference,
            scope_document_hash=fixture.mission.scope_document_hash,
            environment=fixture.mission.environment.value,
            max_action_tier=fixture.mission.max_action_tier.value,
            constraints_hash=constraints_hash,
            operations=[PrincipalOperation.WORK_CLAIM.value],
            policy_version=self.trust_policy_version,
        )
        ScopeGrantAcceptanceService(fixture.store, fixture.registry).accept(grant)
        intent = {
            "expected_generation": 0,
            "mission_id": MISSION_ID,
            "plan_content_sha256": fixture.plan.content_sha256,
            "plan_id": fixture.plan.plan_id,
            "principal_profile_id": OWNER_ID,
            "work_item_id": fixture.readiness.work_item_id,
        }
        assertion = fixture.factory.assertion(
            grant=grant,
            assertion_id="PAS-" + "7" * 32,
            policy_version=self.trust_policy_version,
            scope_grant_id=grant.grant_id,
            subject=SUBJECT,
            profile_id=OWNER_ID,
            audience=AUDIENCE,
            store_id=fixture.store_id,
            mission_id=MISSION_ID,
            operation=PrincipalOperation.WORK_CLAIM,
            operation_intent_sha256=compute_operation_intent_hash(
                PrincipalOperation.WORK_CLAIM,
                intent,
            ),
        )
        fixture.work.claim(
            assertion,
            MISSION_ID,
            fixture.readiness.work_item_id,
            expected_generation=0,
        )
        entry = build_collaboration_ownership_chain_entry(
            mission_id=MISSION_ID,
            collaboration_plan_id=fixture.plan.plan_id,
            collaboration_plan_sha256=fixture.plan.content_sha256,
            work_item_id=fixture.readiness.work_item_id,
            work_item_objective_sha256=(
                collaboration_work_item_objective_sha256(fixture.readiness)
            ),
            planned_owner_id=OWNER_ID,
            sequence=1,
            owner_epoch=1,
            transition_kind="delegation",
            from_owner_id=OWNER_ID,
            to_owner_id=CANDIDATE_ID,
            previous_entry_sha256=None,
            reason_code="bounded_delegation",
            requested_at="2026-07-30T10:04:00Z",
            expires_at="2026-07-30T10:35:00Z",
            control_role_replacement=False,
            authority_bindings={
                "current_owner_authorization_id": "AUTH-OWNER-LEASE",
                "proposed_owner_acceptance_id": "ACCEPT-CANDIDATE-LEASE",
                "independent_control_approval_id": "APPROVAL-CONTROL-LEASE",
                "second_control_or_mission_authority_id": None,
            },
        )
        with self.assertRaisesRegex(StoreConflictError, "Active work item lease"):
            self.service.preflight(entry)


class Phase90CliTests(unittest.TestCase):
    def test_parser_and_legacy_alias_are_closed_and_equal(self) -> None:
        name = "collaboration-ownership-transition-preflight"
        current = command_parser(build_parser(), name)
        legacy = command_parser(legacy_build_parser(), name)
        self.assertEqual(
            required_destinations(current),
            {"ownership_entry", "registry", "store"},
        )
        self.assertEqual(option_strings(legacy), option_strings(current))
        self.assertEqual(
            required_destinations(legacy),
            required_destinations(current),
        )
        for forbidden in (
            "--issuer",
            "--principal-assertion",
            "--private-key",
            "--secret",
            "--signing-key",
            "--subject",
        ):
            self.assertNotIn(forbidden, option_strings(current))

    def test_handler_forwards_loaded_entry_to_read_only_service(self) -> None:
        registry = object()
        entry = object()
        store = object()
        service = Mock()
        receipt = Mock()
        receipt.to_dict.return_value = {
            "schema_version": 1,
            "runtime_effect": "none",
        }
        service.preflight.return_value = receipt
        arguments = (
            "collaboration-ownership-transition-preflight",
            "--store",
            "missions.sqlite3",
            "--registry",
            str(REGISTRY_PATH),
            "--ownership-entry",
            "ownership-entry.json",
        )
        with (
            patch("sunderkey.cli.load_registry", return_value=registry) as loader,
            patch(
                "sunderkey.cli.load_collaboration_ownership_chain_entry",
                return_value=entry,
            ) as load_entry,
            patch("sunderkey.cli.MissionStore", return_value=store) as store_type,
            patch(
                "sunderkey.cli.CollaborationOwnershipTransitionPreflightService",
                return_value=service,
            ) as service_type,
        ):
            output = run_cli(*arguments)
        self.assertEqual(output, receipt.to_dict.return_value)
        self.assertEqual(loader.call_args, call(str(REGISTRY_PATH)))
        self.assertEqual(load_entry.call_args, call("ownership-entry.json"))
        self.assertEqual(store_type.call_args, call("missions.sqlite3"))
        self.assertEqual(service_type.call_args, call(store, registry))
        service.preflight.assert_called_once_with(entry)

    def test_output_cannot_replace_ownership_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            entry_path = Path(temporary) / "ownership-entry.json"
            entry_path.write_text("protected input\n", encoding="utf-8")
            original = entry_path.read_bytes()
            with self.assertRaisesRegex(
                SystemExit,
                "--output must not replace --ownership-entry",
            ):
                run_cli(
                    "collaboration-ownership-transition-preflight",
                    "--store",
                    "missions.sqlite3",
                    "--registry",
                    str(REGISTRY_PATH),
                    "--ownership-entry",
                    str(entry_path),
                    "--output",
                    str(entry_path),
                )
            self.assertEqual(entry_path.read_bytes(), original)

    def test_project_version_is_phase90(self) -> None:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(project["project"]["version"], "0.1.0")


if __name__ == "__main__":
    unittest.main()
