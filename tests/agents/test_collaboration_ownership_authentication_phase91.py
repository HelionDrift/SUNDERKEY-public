"""Phase 91 three-principal ownership authentication coverage."""

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
from sunderkey.collaboration_ownership_authentication import (
    authenticate_collaboration_ownership_transition,
)
from sunderkey.collaboration_ownership_chain import (
    build_collaboration_ownership_chain_entry,
    collaboration_work_item_objective_sha256,
    validate_collaboration_ownership_chain,
)
from sunderkey.collaboration_ownership_preflight import (
    CollaborationOwnershipTransitionPreflight,
)
from sunderkey.errors import PrincipalAuthenticationError
from sunderkey.identity import PrincipalOperation, compute_operation_intent_hash
from sunderkey.mission import MissionRequest
from sunderkey.registry import load_registry

from .test_authenticated_work_handoffs_phase18 import (
    CANDIDATE_ID,
    SOURCE_ID,
)
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
MISSION_ID = "MISSION-PHASE91-OWNERSHIP"
CONTROL_ID = "AOE-HQ-14"
CURRENT_GRANT_ID = "SGR-" + "A" * 32
PROPOSED_GRANT_ID = "SGR-" + "B" * 32
CONTROL_GRANT_ID = "SGR-" + "C" * 32
CURRENT_ASSERTION_ID = "PAS-" + "A" * 32
PROPOSED_ASSERTION_ID = "PAS-" + "B" * 32
CONTROL_ASSERTION_ID = "PAS-" + "C" * 32


class CollaborationOwnershipAuthenticationPhase91Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)
        raw_mission = mission_data()
        raw_mission.update(
            {
                "mission_id": MISSION_ID,
                "requested_specialist_ids": [SOURCE_ID, CANDIDATE_ID],
            }
        )
        cls.mission = MissionRequest.from_dict(raw_mission)
        cls.plan = build_collaboration_plan(cls.registry, cls.mission)
        cls.item = next(
            item
            for item in cls.plan.work_items
            if item.kind is WorkItemKind.SPECIALIST_ANALYSIS and item.owner_profile_id == SOURCE_ID
        )
        cls.candidate = cls.registry.profile(CANDIDATE_ID)

    def setUp(self) -> None:
        self.factory = CredentialFactory()
        self.operations = (
            PrincipalOperation.COLLABORATION_OWNERSHIP_CURRENT_OWNER_AUTHORIZE,
            PrincipalOperation.COLLABORATION_OWNERSHIP_PROPOSED_OWNER_ACCEPT,
            PrincipalOperation.COLLABORATION_OWNERSHIP_CONTROL_APPROVE,
        )
        self.verified_policy = self.factory.verified_policy(
            allowed_profiles=[SOURCE_ID, CANDIDATE_ID, CONTROL_ID],
            allowed_operations=[operation.value for operation in self.operations],
        )
        self.grants = {
            "current": self.factory.grant(
                grant_id=CURRENT_GRANT_ID,
                profile_id=SOURCE_ID,
                mission_id=MISSION_ID,
                operations=[self.operations[0].value],
            ),
            "proposed": self.factory.grant(
                grant_id=PROPOSED_GRANT_ID,
                profile_id=CANDIDATE_ID,
                mission_id=MISSION_ID,
                operations=[self.operations[1].value],
            ),
            "control": self.factory.grant(
                grant_id=CONTROL_GRANT_ID,
                profile_id=CONTROL_ID,
                mission_id=MISSION_ID,
                operations=[self.operations[2].value],
            ),
        }
        self.scopes = {
            name: self.factory.verify_grant(
                grant,
                self.verified_policy,
                expected_mission_id=MISSION_ID,
                expected_operation=operation,
            )
            for (name, grant), operation in zip(
                self.grants.items(),
                self.operations,
                strict=True,
            )
        }
        self.preflight = self._preflight()
        preflight_document = self.preflight.to_dict()

        def assertion(
            name: str,
            assertion_id: str,
            profile_id: str,
            operation: PrincipalOperation,
        ):
            entry = self.preflight.entry
            intent = {
                "entry_id": entry.entry_id,
                "entry_sha256": entry.entry_sha256,
                "mission_id": MISSION_ID,
                "preflight_id": preflight_document["preflight_id"],
                "preflight_sha256": preflight_document["preflight_sha256"],
                "principal_profile_id": profile_id,
            }
            grant = self.grants[name]
            return self.factory.assertion(
                grant=grant,
                assertion_id=assertion_id,
                scope_grant_id=grant.grant_id,
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

        self.current_assertion = assertion(
            "current",
            CURRENT_ASSERTION_ID,
            SOURCE_ID,
            self.operations[0],
        )
        self.proposed_assertion = assertion(
            "proposed",
            PROPOSED_ASSERTION_ID,
            CANDIDATE_ID,
            self.operations[1],
        )
        self.control_assertion = assertion(
            "control",
            CONTROL_ASSERTION_ID,
            CONTROL_ID,
            self.operations[2],
        )

    def _preflight(self) -> CollaborationOwnershipTransitionPreflight:
        entry = build_collaboration_ownership_chain_entry(
            mission_id=MISSION_ID,
            collaboration_plan_id=self.plan.plan_id,
            collaboration_plan_sha256=self.plan.content_sha256,
            work_item_id=self.item.work_item_id,
            work_item_objective_sha256=(collaboration_work_item_objective_sha256(self.item)),
            planned_owner_id=SOURCE_ID,
            sequence=1,
            owner_epoch=1,
            transition_kind="delegation",
            from_owner_id=SOURCE_ID,
            to_owner_id=CANDIDATE_ID,
            previous_entry_sha256=None,
            reason_code="bounded_delegation",
            requested_at="2026-07-30T10:04:00Z",
            expires_at="2026-07-30T10:35:00Z",
            control_role_replacement=False,
            authority_bindings={
                "current_owner_authorization_id": CURRENT_ASSERTION_ID,
                "proposed_owner_acceptance_id": PROPOSED_ASSERTION_ID,
                "independent_control_approval_id": CONTROL_ASSERTION_ID,
                "second_control_or_mission_authority_id": None,
            },
        )
        projection = validate_collaboration_ownership_chain(
            (entry,),
            maximum_delegation_depth=3,
        )
        return CollaborationOwnershipTransitionPreflight(
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
            candidate_profile_id=CANDIDATE_ID,
            candidate_profile_version=self.candidate.version,
            candidate_registry_status=self.candidate.status,
            qualification_command_id=str(self.item.command_id),
            qualification_group_id=str(self.item.group_id),
            chain_id=projection.chain_id,
            head_entry_id=projection.head_entry_id,
            head_sha256=projection.head_sha256,
            current_owner_id=projection.current_owner_id,
            owner_epoch=projection.owner_epoch,
            active_delegation_depth=projection.active_delegation_depth,
            entry_count=projection.entry_count,
        )

    def _authenticate(self, **overrides):
        arguments = {
            "current_owner_assertion": self.current_assertion,
            "proposed_owner_assertion": self.proposed_assertion,
            "independent_control_assertion": self.control_assertion,
            "verified_policy": self.verified_policy,
            "current_owner_scope": self.scopes["current"],
            "proposed_owner_scope": self.scopes["proposed"],
            "independent_control_scope": self.scopes["control"],
            "expected_audience": AUDIENCE,
            "expected_store_id": STORE_ID,
            "expected_control_profile_ids": [CONTROL_ID],
            "clock": lambda: NOW,
        }
        arguments.update(overrides)
        return authenticate_collaboration_ownership_transition(
            self.preflight,
            **arguments,
        )

    def test_three_party_authentication_binds_exact_preflight_and_roles(self) -> None:
        authenticated = self._authenticate()
        document = authenticated.to_dict()
        self.assertEqual(
            document["authentication_status"],
            "authenticated_three_party",
        )
        self.assertEqual(document["runtime_effect"], "none")
        self.assertEqual(document["current_owner"]["profile_id"], SOURCE_ID)
        self.assertEqual(
            document["proposed_owner"]["profile_id"],
            CANDIDATE_ID,
        )
        self.assertEqual(
            document["independent_control"]["profile_id"],
            CONTROL_ID,
        )
        self.assertEqual(document["preflight"], self.preflight.to_dict())
        self.assertEqual(document["authenticated_at"], "2026-07-30T10:05:00Z")
        self.assertTrue(document["authentication_id"].startswith("OTA-"))

    def test_wrong_binding_operation_and_control_membership_fail_closed(self) -> None:
        changed = copy.deepcopy(self.preflight.entry.to_dict())
        changed["authority_bindings"]["current_owner_authorization_id"] = "PAS-" + "D" * 32
        changed_entry = build_collaboration_ownership_chain_entry(
            mission_id=changed["mission_id"],
            collaboration_plan_id=changed["collaboration_plan_id"],
            collaboration_plan_sha256=changed["collaboration_plan_sha256"],
            work_item_id=changed["work_item_id"],
            work_item_objective_sha256=changed["work_item_objective_sha256"],
            planned_owner_id=changed["planned_owner_id"],
            sequence=1,
            owner_epoch=1,
            transition_kind="delegation",
            from_owner_id=SOURCE_ID,
            to_owner_id=CANDIDATE_ID,
            previous_entry_sha256=None,
            reason_code=changed["reason_code"],
            requested_at=changed["requested_at"],
            expires_at=changed["expires_at"],
            control_role_replacement=False,
            authority_bindings=changed["authority_bindings"],
        )
        changed_projection = validate_collaboration_ownership_chain(
            (changed_entry,),
            maximum_delegation_depth=3,
        )
        with self.assertRaisesRegex(PrincipalAuthenticationError, "binding"):
            authenticate_collaboration_ownership_transition(
                replace(
                    self.preflight,
                    entry=changed_entry,
                    chain_id=changed_projection.chain_id,
                    head_entry_id=changed_projection.head_entry_id,
                    head_sha256=changed_projection.head_sha256,
                ),
                current_owner_assertion=self.current_assertion,
                proposed_owner_assertion=self.proposed_assertion,
                independent_control_assertion=self.control_assertion,
                verified_policy=self.verified_policy,
                current_owner_scope=self.scopes["current"],
                proposed_owner_scope=self.scopes["proposed"],
                independent_control_scope=self.scopes["control"],
                expected_audience=AUDIENCE,
                expected_store_id=STORE_ID,
                expected_control_profile_ids=[CONTROL_ID],
                clock=lambda: NOW,
            )
        with self.assertRaisesRegex(PrincipalAuthenticationError, "Control approver"):
            self._authenticate(expected_control_profile_ids=["AOE-HQ-15"])

    def test_changed_preflight_digest_invalidates_all_signed_intents(self) -> None:
        changed_preflight = replace(
            self.preflight,
            expected_generation=1,
            previous_transition_id="WLT-" + "1" * 32,
            expected_lease_expires_at="2026-07-30T10:20:00Z",
        )
        with self.assertRaisesRegex(PrincipalAuthenticationError, "intent"):
            authenticate_collaboration_ownership_transition(
                changed_preflight,
                current_owner_assertion=self.current_assertion,
                proposed_owner_assertion=self.proposed_assertion,
                independent_control_assertion=self.control_assertion,
                verified_policy=self.verified_policy,
                current_owner_scope=self.scopes["current"],
                proposed_owner_scope=self.scopes["proposed"],
                independent_control_scope=self.scopes["control"],
                expected_audience=AUDIENCE,
                expected_store_id=STORE_ID,
                expected_control_profile_ids=[CONTROL_ID],
                clock=lambda: NOW,
            )

    def test_expired_transition_and_future_preflight_fail_closed(self) -> None:
        with self.assertRaisesRegex(PrincipalAuthenticationError, "expired"):
            self._authenticate(
                clock=lambda: NOW.replace(minute=36),
            )
        with self.assertRaisesRegex(PrincipalAuthenticationError, "precedes"):
            authenticate_collaboration_ownership_transition(
                replace(self.preflight, evaluated_at="2026-07-30T10:06:00Z"),
                current_owner_assertion=self.current_assertion,
                proposed_owner_assertion=self.proposed_assertion,
                independent_control_assertion=self.control_assertion,
                verified_policy=self.verified_policy,
                current_owner_scope=self.scopes["current"],
                proposed_owner_scope=self.scopes["proposed"],
                independent_control_scope=self.scopes["control"],
                expected_audience=AUDIENCE,
                expected_store_id=STORE_ID,
                expected_control_profile_ids=[CONTROL_ID],
                clock=lambda: NOW,
            )

    def test_authenticated_wrapper_rejects_direct_replacement(self) -> None:
        with self.assertRaisesRegex(TypeError, "identity"):
            replace(
                self._authenticate(),
                authentication_sha256="sha256:" + "0" * 64,
            )

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_authentication_matches_published_schema(self) -> None:
        schema = json.loads(
            (SCHEMAS / "collaboration-ownership-authentication-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        preflight_schema = json.loads(
            (SCHEMAS / "collaboration-ownership-transition-preflight-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        preflight_schema["properties"]["entry"] = json.loads(
            (SCHEMAS / "collaboration-ownership-chain-entry-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        schema["properties"]["preflight"] = preflight_schema
        Draft202012Validator(schema).validate(self._authenticate().to_dict())

    def test_module_has_no_network_storage_or_execution_imports(self) -> None:
        tree = ast.parse(
            (ROOT / "src/sunderkey/collaboration_ownership_authentication.py").read_text(
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


if __name__ == "__main__":
    unittest.main()
