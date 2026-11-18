"""Phase 87 dual-principal mission-policy authentication coverage."""

from __future__ import annotations

import ast
import copy
import json
import unittest
from dataclasses import replace
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.collaboration import WorkItemKind, build_collaboration_plan
from sunderkey.collaboration_mission_policy import (
    build_collaboration_mission_reconfiguration_policy,
    collaboration_mission_reconfiguration_selection_sha256,
)
from sunderkey.collaboration_mission_policy_authentication import (
    authenticate_collaboration_mission_reconfiguration_policy,
)
from sunderkey.collaboration_reconfiguration_policy import (
    load_collaboration_reconfiguration_authority_policy,
)
from sunderkey.errors import PrincipalAuthenticationError
from sunderkey.identity import PrincipalOperation, compute_operation_intent_hash
from sunderkey.mission import MissionRequest
from sunderkey.registry import load_registry

from .test_identity_phase4 import (
    ASSERTION_ID,
    AUDIENCE,
    GRANT_ID,
    MISSION_ID,
    NOW,
    OTHER_ASSERTION_ID,
    OTHER_GRANT_ID,
    STORE_ID,
    SUBJECT,
    CredentialFactory,
)
from .test_store import REGISTRY_PATH, mission_data

ROOT = Path(__file__).resolve().parents[2]
AUTHORITY_PATH = ROOT / "registry" / "collaboration-reconfiguration-policy-d001-d005.json"
SCHEMA_PATH = ROOT / "registry/schemas/collaboration-mission-policy-authentication-v1.schema.json"
MISSION_POLICY_SCHEMA_PATH = (
    ROOT / "registry/schemas/collaboration-mission-reconfiguration-policy-v1.schema.json"
)
OWNER_ID = "AOE-HQ-08"
CONTROL_ID = "AOE-HQ-14"


def binding(profile_id: str, marker: str) -> dict[str, str]:
    return {
        "profile_id": profile_id,
        "assertion_id": "PAS-" + marker * 32,
        "assertion_sha256": "sha256:" + marker.lower() * 64,
    }


class CollaborationMissionPolicyAuthenticationPhase87Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)
        raw_mission = mission_data()
        raw_mission["mission_id"] = MISSION_ID
        cls.mission = MissionRequest.from_dict(raw_mission)
        cls.plan = build_collaboration_plan(cls.registry, cls.mission)
        readiness = tuple(
            item for item in cls.plan.work_items if item.kind is WorkItemKind.READINESS
        )
        assert len(readiness) == 1
        assert readiness[0].owner_profile_id == OWNER_ID
        cls.authority = load_collaboration_reconfiguration_authority_policy(AUTHORITY_PATH)

    def setUp(self) -> None:
        self.factory = CredentialFactory()
        operations = [
            PrincipalOperation.COLLABORATION_POLICY_OWNER_AUTHORIZE.value,
            PrincipalOperation.COLLABORATION_POLICY_CONTROL_APPROVE.value,
        ]
        self.verified_policy = self.factory.verified_policy(
            allowed_profiles=[OWNER_ID, CONTROL_ID],
            allowed_operations=operations,
        )
        self.owner_grant = self.factory.grant(
            grant_id=GRANT_ID,
            profile_id=OWNER_ID,
            mission_id=MISSION_ID,
            operations=[PrincipalOperation.COLLABORATION_POLICY_OWNER_AUTHORIZE.value],
        )
        self.control_grant = self.factory.grant(
            grant_id=OTHER_GRANT_ID,
            profile_id=CONTROL_ID,
            mission_id=MISSION_ID,
            operations=[PrincipalOperation.COLLABORATION_POLICY_CONTROL_APPROVE.value],
        )
        self.owner_scope = self.factory.verify_grant(
            self.owner_grant,
            self.verified_policy,
            expected_mission_id=MISSION_ID,
            expected_operation=(PrincipalOperation.COLLABORATION_POLICY_OWNER_AUTHORIZE),
        )
        self.control_scope = self.factory.verify_grant(
            self.control_grant,
            self.verified_policy,
            expected_mission_id=MISSION_ID,
            expected_operation=(PrincipalOperation.COLLABORATION_POLICY_CONTROL_APPROVE),
        )
        provisional = self._policy(
            binding(OWNER_ID, "A"),
            binding(CONTROL_ID, "B"),
        )
        self.selection_sha256 = collaboration_mission_reconfiguration_selection_sha256(provisional)
        owner_intent = {
            "mission_id": MISSION_ID,
            "policy_selection_sha256": self.selection_sha256,
            "principal_profile_id": OWNER_ID,
        }
        control_intent = {
            "mission_id": MISSION_ID,
            "policy_selection_sha256": self.selection_sha256,
            "principal_profile_id": CONTROL_ID,
        }
        self.owner_assertion = self.factory.assertion(
            grant=self.owner_grant,
            assertion_id=ASSERTION_ID,
            scope_grant_id=GRANT_ID,
            subject=SUBJECT,
            profile_id=OWNER_ID,
            store_id=STORE_ID,
            mission_id=MISSION_ID,
            operation=PrincipalOperation.COLLABORATION_POLICY_OWNER_AUTHORIZE,
            operation_intent_sha256=compute_operation_intent_hash(
                PrincipalOperation.COLLABORATION_POLICY_OWNER_AUTHORIZE,
                owner_intent,
            ),
        )
        self.control_assertion = self.factory.assertion(
            grant=self.control_grant,
            assertion_id=OTHER_ASSERTION_ID,
            scope_grant_id=OTHER_GRANT_ID,
            subject=SUBJECT,
            profile_id=CONTROL_ID,
            store_id=STORE_ID,
            mission_id=MISSION_ID,
            operation=PrincipalOperation.COLLABORATION_POLICY_CONTROL_APPROVE,
            operation_intent_sha256=compute_operation_intent_hash(
                PrincipalOperation.COLLABORATION_POLICY_CONTROL_APPROVE,
                control_intent,
            ),
        )
        self.policy = self._policy(
            self._assertion_binding(self.owner_assertion),
            self._assertion_binding(self.control_assertion),
        )

    def _policy(
        self,
        owner_approval: dict[str, str],
        control_approval: dict[str, str],
        *,
        maximum_delegation_depth: int = 3,
        effective_at: str = "2026-07-30T10:00:00Z",
        expires_at: str = "2026-07-30T11:00:00Z",
    ):
        return build_collaboration_mission_reconfiguration_policy(
            authority_policy=self.authority,
            policy_version=1,
            previous_policy_sha256=None,
            mission_id=MISSION_ID,
            collaboration_plan_id=self.plan.plan_id,
            collaboration_plan_sha256=self.plan.content_sha256,
            maximum_delegation_depth=maximum_delegation_depth,
            reconfiguration_validity_seconds=3600,
            execution_ack_timeout_seconds=300,
            maximum_plan_replacement_items=100,
            transition_activation={
                "privileged_role_reassignment": False,
                "delegation_return_and_revocation": True,
                "cross_command_transfer": False,
                "activated_plan_replacement": False,
                "distributed_execution_transfer_or_cancellation": False,
            },
            mission_owner_approval=owner_approval,
            independent_control_approval=control_approval,
            effective_at=effective_at,
            expires_at=expires_at,
        )

    @staticmethod
    def _assertion_binding(assertion) -> dict[str, str]:
        return {
            "profile_id": assertion.profile_id,
            "assertion_id": assertion.assertion_id,
            "assertion_sha256": assertion.content_sha256,
        }

    def _authenticate(self, **overrides):
        arguments = {
            "authority_policy": self.authority,
            "collaboration_plan": self.plan,
            "mission_owner_assertion": self.owner_assertion,
            "independent_control_assertion": self.control_assertion,
            "verified_policy": self.verified_policy,
            "mission_owner_scope": self.owner_scope,
            "independent_control_scope": self.control_scope,
            "expected_audience": AUDIENCE,
            "expected_store_id": STORE_ID,
            "expected_control_profile_ids": [CONTROL_ID],
            "clock": lambda: NOW,
        }
        arguments.update(overrides)
        return authenticate_collaboration_mission_reconfiguration_policy(
            self.policy,
            **arguments,
        )

    def test_dual_authentication_binds_roles_selection_and_provenance(self) -> None:
        authenticated = self._authenticate()
        document = authenticated.to_dict()
        self.assertEqual(document["authentication_status"], "authenticated_dual_control")
        self.assertEqual(document["runtime_effect"], "none")
        self.assertEqual(document["mission_owner"]["profile_id"], OWNER_ID)
        self.assertEqual(document["independent_control"]["profile_id"], CONTROL_ID)
        self.assertEqual(document["authenticated_at"], "2026-07-30T10:05:00Z")
        self.assertTrue(document["authentication_id"].startswith("MPA-"))
        self.assertEqual(
            collaboration_mission_reconfiguration_selection_sha256(self.policy),
            self.selection_sha256,
        )

    def test_selection_digest_avoids_circular_assertion_binding(self) -> None:
        alternate = self._policy(
            binding(OWNER_ID, "C"),
            binding(CONTROL_ID, "D"),
        )
        self.assertEqual(
            collaboration_mission_reconfiguration_selection_sha256(alternate),
            self.selection_sha256,
        )
        changed = self._policy(
            binding(OWNER_ID, "C"),
            binding(CONTROL_ID, "D"),
            maximum_delegation_depth=4,
        )
        self.assertNotEqual(
            collaboration_mission_reconfiguration_selection_sha256(changed),
            self.selection_sha256,
        )

    def test_wrong_assertion_binding_or_operation_fails_closed(self) -> None:
        changed = copy.deepcopy(self.policy.to_dict())
        changed["approval_bindings"]["independent_control"]["assertion_sha256"] = (
            "sha256:" + "c" * 64
        )
        with self.assertRaisesRegex(PrincipalAuthenticationError, "binding"):
            authenticate_collaboration_mission_reconfiguration_policy(
                self._policy(
                    self._assertion_binding(self.owner_assertion),
                    changed["approval_bindings"]["independent_control"],
                ),
                authority_policy=self.authority,
                collaboration_plan=self.plan,
                mission_owner_assertion=self.owner_assertion,
                independent_control_assertion=self.control_assertion,
                verified_policy=self.verified_policy,
                mission_owner_scope=self.owner_scope,
                independent_control_scope=self.control_scope,
                expected_audience=AUDIENCE,
                expected_store_id=STORE_ID,
                expected_control_profile_ids=[CONTROL_ID],
                clock=lambda: NOW,
            )
        wrong_operation = self.factory.assertion(
            grant=self.control_grant,
            assertion_id=OTHER_ASSERTION_ID,
            scope_grant_id=OTHER_GRANT_ID,
            subject=SUBJECT,
            profile_id=CONTROL_ID,
            mission_id=MISSION_ID,
            operation=PrincipalOperation.COLLABORATION_POLICY_OWNER_AUTHORIZE,
            operation_intent_sha256=self.owner_assertion.operation_intent_sha256,
        )
        wrong_policy = self._policy(
            self._assertion_binding(self.owner_assertion),
            self._assertion_binding(wrong_operation),
        )
        with self.assertRaisesRegex(PrincipalAuthenticationError, "operation"):
            authenticate_collaboration_mission_reconfiguration_policy(
                wrong_policy,
                authority_policy=self.authority,
                collaboration_plan=self.plan,
                mission_owner_assertion=self.owner_assertion,
                independent_control_assertion=wrong_operation,
                verified_policy=self.verified_policy,
                mission_owner_scope=self.owner_scope,
                independent_control_scope=self.control_scope,
                expected_audience=AUDIENCE,
                expected_store_id=STORE_ID,
                expected_control_profile_ids=[CONTROL_ID],
                clock=lambda: NOW,
            )

    def test_control_membership_and_validity_window_fail_closed(self) -> None:
        with self.assertRaisesRegex(PrincipalAuthenticationError, "Control approver"):
            self._authenticate(expected_control_profile_ids=["AOE-HQ-15"])
        expired = self._policy(
            self._assertion_binding(self.owner_assertion),
            self._assertion_binding(self.control_assertion),
            effective_at="2026-07-30T09:00:00Z",
            expires_at="2026-07-30T10:04:59Z",
        )
        with self.assertRaisesRegex(PrincipalAuthenticationError, "validity window"):
            authenticate_collaboration_mission_reconfiguration_policy(
                expired,
                authority_policy=self.authority,
                collaboration_plan=self.plan,
                mission_owner_assertion=self.owner_assertion,
                independent_control_assertion=self.control_assertion,
                verified_policy=self.verified_policy,
                mission_owner_scope=self.owner_scope,
                independent_control_scope=self.control_scope,
                expected_audience=AUDIENCE,
                expected_store_id=STORE_ID,
                expected_control_profile_ids=[CONTROL_ID],
                clock=lambda: NOW,
            )

    def test_authenticated_wrapper_rejects_direct_replacement(self) -> None:
        authenticated = self._authenticate()
        with self.assertRaisesRegex(TypeError, "identity"):
            replace(
                authenticated,
                authentication_sha256="sha256:" + "0" * 64,
            )

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_authentication_matches_published_schema(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        schema["properties"]["mission_policy"] = json.loads(
            MISSION_POLICY_SCHEMA_PATH.read_text(encoding="utf-8")
        )
        Draft202012Validator(schema).validate(self._authenticate().to_dict())

    def test_module_has_no_network_storage_or_execution_imports(self) -> None:
        tree = ast.parse(
            (ROOT / "src/sunderkey/collaboration_mission_policy_authentication.py").read_text(
                encoding="utf-8"
            )
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
            imported & {"asyncio", "http", "requests", "socket", "sqlite3", "subprocess", "urllib"}
        )


if __name__ == "__main__":
    unittest.main()
