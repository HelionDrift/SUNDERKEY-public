"""Phase 102 privileged ownership reassignment authentication coverage."""

from __future__ import annotations

import ast
import json
import tomllib
import unittest
from dataclasses import replace
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.collaboration import WorkItemKind, build_collaboration_plan
from sunderkey.collaboration_ownership_chain import (
    build_collaboration_ownership_chain_entry,
    collaboration_work_item_objective_sha256,
    validate_collaboration_ownership_chain,
)
from sunderkey.collaboration_ownership_privileged_reassignment_authentication import (
    authenticate_collaboration_ownership_privileged_reassignment,
)
from sunderkey.collaboration_ownership_privileged_reassignment_preflight import (
    CollaborationOwnershipPrivilegedReassignmentPreflight,
)
from sunderkey.errors import PrincipalAuthenticationError
from sunderkey.identity import PrincipalOperation, compute_operation_intent_hash
from sunderkey.mission import MissionRequest
from sunderkey.registry import load_registry

from .test_identity_phase4 import (
    AUDIENCE,
    NOW,
    STORE_ID,
    SUBJECT,
    CredentialFactory,
)
from .test_store import REGISTRY_PATH, mission_data

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "registry/schemas"
MISSION_ID = "MISSION-PHASE102-PRIVILEGED"
READINESS_REPLACEMENT_ID = "AOE-HQ-09"
CONTROL_REPLACEMENT_ID = "AOE-HQ-13"
CONTROL_APPROVER_ID = "AOE-HQ-14"
SECOND_AUTHORITY_ID = "AOE-HQ-15"
CURRENT_OWNER_OPERATION = (
    PrincipalOperation.COLLABORATION_OWNERSHIP_CURRENT_OWNER_AUTHORIZE
)
PROPOSED_OWNER_OPERATION = (
    PrincipalOperation.COLLABORATION_OWNERSHIP_PROPOSED_OWNER_ACCEPT
)
SECOND_AUTHORITY_OPERATION = (
    PrincipalOperation.COLLABORATION_OWNERSHIP_SECOND_AUTHORITY_APPROVE
)


class PrivilegedOwnershipReassignmentAuthenticationPhase102Tests(
    unittest.TestCase
):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)
        raw_mission = mission_data()
        raw_mission["mission_id"] = MISSION_ID
        cls.mission = MissionRequest.from_dict(raw_mission)
        cls.plan = build_collaboration_plan(cls.registry, cls.mission)

    def setUp(self) -> None:
        self.factory = CredentialFactory()

    def _item(self, kind: WorkItemKind):
        return next(item for item in self.plan.work_items if item.kind is kind)

    def _preflight(
        self,
        kind: WorkItemKind,
        proposed_owner_id: str,
        *,
        control_role_replacement: bool,
    ) -> CollaborationOwnershipPrivilegedReassignmentPreflight:
        item = self._item(kind)
        second_id = "PAS-" + "D" * 32 if control_role_replacement else None
        entry = build_collaboration_ownership_chain_entry(
            mission_id=MISSION_ID,
            collaboration_plan_id=self.plan.plan_id,
            collaboration_plan_sha256=self.plan.content_sha256,
            work_item_id=item.work_item_id,
            work_item_objective_sha256=(
                collaboration_work_item_objective_sha256(item)
            ),
            planned_owner_id=item.owner_profile_id,
            sequence=1,
            owner_epoch=1,
            transition_kind="privileged_reassignment",
            from_owner_id=item.owner_profile_id,
            to_owner_id=proposed_owner_id,
            previous_entry_sha256=None,
            reason_code="privileged_role_reassignment",
            requested_at="2026-07-30T10:04:00Z",
            expires_at="2026-07-30T10:35:00Z",
            control_role_replacement=control_role_replacement,
            authority_bindings={
                "current_owner_authorization_id": "PAS-" + "A" * 32,
                "proposed_owner_acceptance_id": "PAS-" + "B" * 32,
                "independent_control_approval_id": "PAS-" + "C" * 32,
                "second_control_or_mission_authority_id": second_id,
            },
        )
        projection = validate_collaboration_ownership_chain(
            (entry,),
            maximum_delegation_depth=3,
        )
        replacement = self.registry.profile(proposed_owner_id)
        return CollaborationOwnershipPrivilegedReassignmentPreflight(
            entry=entry,
            evaluated_at="2026-07-30T10:04:30Z",
            store_id=STORE_ID,
            mission_context_sha256="sha256:" + "1" * 64,
            policy_id="MRP-" + "1" * 32,
            policy_sha256="sha256:" + "2" * 64,
            policy_version=1,
            maximum_delegation_depth=3,
            expected_generation=0,
            previous_transition_id=None,
            expected_lease_expires_at=None,
            work_item_kind=item.kind.value,
            planned_owner_id=item.owner_profile_id,
            current_owner_id=item.owner_profile_id,
            control_role_replacement=control_role_replacement,
            second_authority_required=control_role_replacement,
            required_authority_count=4 if control_role_replacement else 3,
            replacement_profile_id=replacement.id,
            replacement_profile_version=replacement.version,
            replacement_registry_status=replacement.status,
            replacement_profile_kind=replacement.kind.value,
            replacement_category=replacement.category,
            replacement_command_id=replacement.command_id,
            replacement_group_id=replacement.group_id,
            chain_id=projection.chain_id,
            head_entry_id=projection.head_entry_id,
            head_sha256=projection.head_sha256,
            owner_epoch=projection.owner_epoch,
            active_delegation_depth=projection.active_delegation_depth,
            entry_count=projection.entry_count,
        )

    def _credentials(
        self,
        preflight: CollaborationOwnershipPrivilegedReassignmentPreflight,
        *,
        control_profile_id: str,
        second_profile_id: str | None,
    ):
        entry = preflight.entry
        entry_document = entry.to_dict()
        roles = [
            (
                "current",
                entry_document["from_owner_id"],
                "A",
                CURRENT_OWNER_OPERATION,
            ),
            (
                "proposed",
                entry_document["to_owner_id"],
                "B",
                PROPOSED_OWNER_OPERATION,
            ),
            (
                "control",
                control_profile_id,
                "C",
                PrincipalOperation.COLLABORATION_OWNERSHIP_CONTROL_APPROVE,
            ),
        ]
        if second_profile_id is not None:
            roles.append(
                (
                    "second",
                    second_profile_id,
                    "D",
                    SECOND_AUTHORITY_OPERATION,
                )
            )
        policy = self.factory.verified_policy(
            allowed_profiles=sorted(
                {profile_id for _, profile_id, _, _ in roles}
            ),
            allowed_operations=[operation.value for *_, operation in roles],
        )
        grants = {
            name: self.factory.grant(
                grant_id="SGR-" + marker * 32,
                profile_id=profile_id,
                mission_id=MISSION_ID,
                operations=[operation.value],
            )
            for name, profile_id, marker, operation in roles
        }
        scopes = {
            name: self.factory.verify_grant(
                grants[name],
                policy,
                expected_mission_id=MISSION_ID,
                expected_operation=operation,
            )
            for name, _, _, operation in roles
        }
        preflight_document = preflight.to_dict()
        assertions = {}
        for name, profile_id, marker, operation in roles:
            intent = {
                "entry_id": entry.entry_id,
                "entry_sha256": entry.entry_sha256,
                "mission_id": MISSION_ID,
                "preflight_id": preflight_document["preflight_id"],
                "preflight_sha256": preflight_document["preflight_sha256"],
                "principal_profile_id": profile_id,
            }
            assertions[name] = self.factory.assertion(
                grant=grants[name],
                assertion_id="PAS-" + marker * 32,
                scope_grant_id=grants[name].grant_id,
                subject=SUBJECT,
                profile_id=profile_id,
                store_id=STORE_ID,
                mission_id=MISSION_ID,
                operation=operation,
                operation_intent_sha256=compute_operation_intent_hash(
                    operation,
                    intent,
                ),
            )
        return policy, scopes, assertions

    def _authenticate(
        self,
        preflight: CollaborationOwnershipPrivilegedReassignmentPreflight,
        *,
        control_profile_id: str,
        second_profile_id: str | None,
        **overrides,
    ):
        policy, scopes, assertions = self._credentials(
            preflight,
            control_profile_id=control_profile_id,
            second_profile_id=second_profile_id,
        )
        arguments = {
            "current_owner_assertion": assertions["current"],
            "proposed_owner_assertion": assertions["proposed"],
            "independent_control_assertion": assertions["control"],
            "second_authority_assertion": assertions.get("second"),
            "verified_policy": policy,
            "current_owner_scope": scopes["current"],
            "proposed_owner_scope": scopes["proposed"],
            "independent_control_scope": scopes["control"],
            "second_authority_scope": scopes.get("second"),
            "expected_audience": AUDIENCE,
            "expected_store_id": STORE_ID,
            "expected_control_profile_ids": [control_profile_id],
            "expected_second_authority_profile_ids": (
                [] if second_profile_id is None else [second_profile_id]
            ),
            "clock": lambda: NOW,
        }
        arguments.update(overrides)
        return authenticate_collaboration_ownership_privileged_reassignment(
            preflight,
            **arguments,
        )

    def test_three_party_privileged_authentication_binds_exact_roles(self) -> None:
        preflight = self._preflight(
            WorkItemKind.READINESS,
            READINESS_REPLACEMENT_ID,
            control_role_replacement=False,
        )
        authenticated = self._authenticate(
            preflight,
            control_profile_id="AOE-HQ-12",
            second_profile_id=None,
        )
        document = authenticated.to_dict()
        self.assertEqual(
            document["authentication_status"],
            "authenticated_three_party_privileged_reassignment",
        )
        self.assertIsNone(document["second_control_or_mission_authority"])
        self.assertEqual(document["preflight"], preflight.to_dict())
        self.assertTrue(document["authentication_id"].startswith("OPA-"))
        self.assertEqual(document["runtime_effect"], "none")

    def test_control_replacement_authenticates_four_distinct_parties(self) -> None:
        preflight = self._preflight(
            WorkItemKind.CONTROL_REVIEW,
            CONTROL_REPLACEMENT_ID,
            control_role_replacement=True,
        )
        document = self._authenticate(
            preflight,
            control_profile_id=CONTROL_APPROVER_ID,
            second_profile_id=SECOND_AUTHORITY_ID,
        ).to_dict()
        self.assertEqual(
            document["authentication_status"],
            "authenticated_four_party_control_replacement",
        )
        self.assertEqual(
            document["second_control_or_mission_authority"]["profile_id"],
            SECOND_AUTHORITY_ID,
        )
        self.assertEqual(
            document["second_control_or_mission_authority"]["operation"],
            "sunderkey.collaboration.ownership.second-authority-approve.v1",
        )

    def test_fourth_authority_shape_and_membership_fail_closed(self) -> None:
        control_preflight = self._preflight(
            WorkItemKind.CONTROL_REVIEW,
            CONTROL_REPLACEMENT_ID,
            control_role_replacement=True,
        )
        with self.assertRaisesRegex(PrincipalAuthenticationError, "requires"):
            self._authenticate(
                control_preflight,
                control_profile_id=CONTROL_APPROVER_ID,
                second_profile_id=SECOND_AUTHORITY_ID,
                second_authority_assertion=None,
                second_authority_scope=None,
            )
        with self.assertRaisesRegex(PrincipalAuthenticationError, "authorized"):
            self._authenticate(
                control_preflight,
                control_profile_id=CONTROL_APPROVER_ID,
                second_profile_id=SECOND_AUTHORITY_ID,
                expected_second_authority_profile_ids=["AOE-HQ-16"],
            )
        with self.assertRaisesRegex(PrincipalAuthenticationError, "distinct"):
            self._authenticate(
                control_preflight,
                control_profile_id=CONTROL_APPROVER_ID,
                second_profile_id=CONTROL_APPROVER_ID,
            )

        ordinary = self._preflight(
            WorkItemKind.READINESS,
            READINESS_REPLACEMENT_ID,
            control_role_replacement=False,
        )
        with self.assertRaisesRegex(PrincipalAuthenticationError, "fourth"):
            self._authenticate(
                ordinary,
                control_profile_id="AOE-HQ-12",
                second_profile_id=SECOND_AUTHORITY_ID,
            )

    def test_changed_preflight_invalidates_signed_intents(self) -> None:
        preflight = self._preflight(
            WorkItemKind.READINESS,
            READINESS_REPLACEMENT_ID,
            control_role_replacement=False,
        )
        policy, scopes, assertions = self._credentials(
            preflight,
            control_profile_id="AOE-HQ-12",
            second_profile_id=None,
        )
        changed = replace(
            preflight,
            expected_generation=1,
            previous_transition_id="WLT-" + "1" * 32,
        )
        with self.assertRaisesRegex(PrincipalAuthenticationError, "intent"):
            authenticate_collaboration_ownership_privileged_reassignment(
                changed,
                current_owner_assertion=assertions["current"],
                proposed_owner_assertion=assertions["proposed"],
                independent_control_assertion=assertions["control"],
                second_authority_assertion=None,
                verified_policy=policy,
                current_owner_scope=scopes["current"],
                proposed_owner_scope=scopes["proposed"],
                independent_control_scope=scopes["control"],
                second_authority_scope=None,
                expected_audience=AUDIENCE,
                expected_store_id=STORE_ID,
                expected_control_profile_ids=["AOE-HQ-12"],
                expected_second_authority_profile_ids=[],
                clock=lambda: NOW,
            )

    def test_authenticated_wrapper_rejects_direct_replacement(self) -> None:
        preflight = self._preflight(
            WorkItemKind.READINESS,
            READINESS_REPLACEMENT_ID,
            control_role_replacement=False,
        )
        authenticated = self._authenticate(
            preflight,
            control_profile_id="AOE-HQ-12",
            second_profile_id=None,
        )
        with self.assertRaisesRegex(TypeError, "identity"):
            replace(
                authenticated,
                authentication_sha256="sha256:" + "0" * 64,
            )

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_authentication_matches_published_schema(self) -> None:
        preflight = self._preflight(
            WorkItemKind.CONTROL_REVIEW,
            CONTROL_REPLACEMENT_ID,
            control_role_replacement=True,
        )
        document = self._authenticate(
            preflight,
            control_profile_id=CONTROL_APPROVER_ID,
            second_profile_id=SECOND_AUTHORITY_ID,
        ).to_dict()
        authentication_schema = json.loads(
            (
                SCHEMAS
                / "collaboration-ownership-privileged-reassignment-"
                "authentication-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        preflight_schema = json.loads(
            (
                SCHEMAS
                / "collaboration-ownership-privileged-reassignment-"
                "preflight-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        preflight_schema["properties"]["entry"] = json.loads(
            (
                SCHEMAS / "collaboration-ownership-chain-entry-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        authentication_schema["properties"]["preflight"] = preflight_schema
        Draft202012Validator(authentication_schema).validate(document)

    def test_module_has_no_network_storage_or_execution_imports(self) -> None:
        tree = ast.parse(
            (
                ROOT
                / "src/sunderkey/"
                "collaboration_ownership_privileged_reassignment_authentication.py"
            ).read_text(encoding="utf-8")
        )
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported.update(
            str(node.module).split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        )
        self.assertFalse(
            imported
            & {
                "asyncio",
                "http",
                "requests",
                "socket",
                "sqlite3",
                "subprocess",
                "urllib",
            }
        )

    def test_project_version_is_phase102(self) -> None:
        project = tomllib.loads(
            (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )
        self.assertEqual(project["project"]["version"], "0.1.0")


if __name__ == "__main__":
    unittest.main()
