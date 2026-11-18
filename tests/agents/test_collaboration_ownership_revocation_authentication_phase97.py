"""Phase 97 dual-principal ownership revocation authentication coverage."""

from __future__ import annotations

import json
import unittest
from dataclasses import replace
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.collaboration_ownership_chain import (
    apply_collaboration_ownership_revocation,
    build_collaboration_ownership_chain_entry,
    build_collaboration_ownership_revocation,
    validate_collaboration_ownership_chain,
)
from sunderkey.collaboration_ownership_revocation_authentication import (
    authenticate_collaboration_ownership_revocation,
)
from sunderkey.collaboration_ownership_revocation_preflight import (
    CollaborationOwnershipRevocationPreflight,
)
from sunderkey.errors import PrincipalAuthenticationError
from sunderkey.identity import PrincipalOperation, compute_operation_intent_hash

from .test_authenticated_work_handoffs_phase18 import CANDIDATE_ID, SOURCE_ID
from .test_identity_phase4 import (
    AUDIENCE,
    NOW,
    STORE_ID,
    SUBJECT,
    CredentialFactory,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "registry/schemas"
MISSION_ID = "MISSION-PHASE97-REVOCATION"
CONTROL_ID = "AOE-HQ-14"
PLANNED_GRANT_ID = "SGR-" + "F4" * 16
CONTROL_GRANT_ID = "SGR-" + "F5" * 16
PLANNED_ASSERTION_ID = "PAS-" + "F2" * 16
CONTROL_ASSERTION_ID = "PAS-" + "F1" * 16


class CollaborationOwnershipRevocationAuthenticationPhase97Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.factory = CredentialFactory()
        self.operations = (
            PrincipalOperation.COLLABORATION_OWNERSHIP_PROPOSED_OWNER_ACCEPT,
            PrincipalOperation.COLLABORATION_OWNERSHIP_CONTROL_APPROVE,
        )
        self.verified_policy = self.factory.verified_policy(
            allowed_profiles=[SOURCE_ID, CONTROL_ID],
            allowed_operations=[operation.value for operation in self.operations],
        )
        self.grants = {
            "planned": self.factory.grant(
                grant_id=PLANNED_GRANT_ID,
                profile_id=SOURCE_ID,
                mission_id=MISSION_ID,
                operations=[self.operations[0].value],
            ),
            "control": self.factory.grant(
                grant_id=CONTROL_GRANT_ID,
                profile_id=CONTROL_ID,
                mission_id=MISSION_ID,
                operations=[self.operations[1].value],
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
        self.planned_assertion = self._assertion(
            "planned",
            PLANNED_ASSERTION_ID,
            SOURCE_ID,
            self.operations[0],
        )
        self.control_assertion = self._assertion(
            "control",
            CONTROL_ASSERTION_ID,
            CONTROL_ID,
            self.operations[1],
        )

    def _preflight(self) -> CollaborationOwnershipRevocationPreflight:
        first = build_collaboration_ownership_chain_entry(
            mission_id=MISSION_ID,
            collaboration_plan_id="MCP-PHASE97-REVOCATION",
            collaboration_plan_sha256="sha256:" + "1" * 64,
            work_item_id="WIT-PHASE97-REVOCATION",
            work_item_objective_sha256="sha256:" + "2" * 64,
            planned_owner_id=SOURCE_ID,
            sequence=1,
            owner_epoch=1,
            transition_kind="delegation",
            from_owner_id=SOURCE_ID,
            to_owner_id=CANDIDATE_ID,
            previous_entry_sha256=None,
            reason_code="bounded_delegation",
            requested_at="2026-07-30T10:01:00Z",
            expires_at="2026-07-30T10:30:00Z",
            control_role_replacement=False,
            authority_bindings={
                "current_owner_authorization_id": "PAS-" + "A1" * 16,
                "proposed_owner_acceptance_id": "PAS-" + "A2" * 16,
                "independent_control_approval_id": "PAS-" + "A3" * 16,
                "second_control_or_mission_authority_id": None,
            },
        )
        validate_collaboration_ownership_chain(
            (first,),
            maximum_delegation_depth=3,
        )
        revocation = build_collaboration_ownership_revocation(
            head=first,
            independent_control_id=CONTROL_ID,
            independent_control_approval_id=CONTROL_ASSERTION_ID,
            planned_owner_acceptance_id=PLANNED_ASSERTION_ID,
            reason_code="independent_control_revocation",
            requested_at="2026-07-30T10:04:00Z",
            expires_at="2026-07-30T10:25:00Z",
        )
        entry, projection = apply_collaboration_ownership_revocation(
            (first,),
            revocation,
            maximum_delegation_depth=3,
        )
        return CollaborationOwnershipRevocationPreflight(
            revocation=revocation,
            entry=entry,
            evaluated_at="2026-07-30T10:04:30Z",
            store_id=STORE_ID,
            mission_context_sha256="sha256:" + "3" * 64,
            policy_id="MRP-" + "4" * 32,
            policy_sha256="sha256:" + "5" * 64,
            policy_version=1,
            maximum_delegation_depth=3,
            expected_generation=0,
            previous_transition_id=None,
            expected_lease_expires_at=None,
            planned_owner_profile_id=SOURCE_ID,
            planned_owner_profile_version="1.0.0",
            planned_owner_registry_status="qualified",
            qualification_command_id="AOE-GB-D06",
            qualification_group_id="GB",
            chain_id=projection.chain_id,
            head_entry_id=projection.head_entry_id,
            head_sha256=projection.head_sha256,
            current_owner_id=projection.current_owner_id,
            owner_epoch=projection.owner_epoch,
            active_delegation_depth=projection.active_delegation_depth,
            entry_count=projection.entry_count,
        )

    def _assertion(
        self,
        name: str,
        assertion_id: str,
        profile_id: str,
        operation: PrincipalOperation,
    ):
        preflight = self.preflight.to_dict()
        entry = self.preflight.entry
        intent = {
            "entry_id": entry.entry_id,
            "entry_sha256": entry.entry_sha256,
            "mission_id": MISSION_ID,
            "preflight_id": preflight["preflight_id"],
            "preflight_sha256": preflight["preflight_sha256"],
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

    def _authenticate(self, **overrides):
        arguments = {
            "planned_owner_assertion": self.planned_assertion,
            "independent_control_assertion": self.control_assertion,
            "verified_policy": self.verified_policy,
            "planned_owner_scope": self.scopes["planned"],
            "independent_control_scope": self.scopes["control"],
            "expected_audience": AUDIENCE,
            "expected_store_id": STORE_ID,
            "expected_control_profile_ids": [CONTROL_ID],
            "clock": lambda: NOW,
        }
        arguments.update(overrides)
        return authenticate_collaboration_ownership_revocation(
            self.preflight,
            **arguments,
        )

    def test_dual_authentication_binds_exact_preflight_and_roles(self) -> None:
        authenticated = self._authenticate()
        document = authenticated.to_dict()
        self.assertEqual(
            document["authentication_status"],
            "authenticated_dual_party",
        )
        self.assertEqual(document["runtime_effect"], "none")
        self.assertEqual(document["planned_owner"]["profile_id"], SOURCE_ID)
        self.assertEqual(
            document["independent_control"]["profile_id"],
            CONTROL_ID,
        )
        self.assertEqual(document["preflight"], self.preflight.to_dict())
        self.assertEqual(document["authenticated_at"], "2026-07-30T10:05:00Z")
        self.assertTrue(document["authentication_id"].startswith("ORA-"))

    def test_wrong_binding_control_membership_and_role_alias_fail_closed(self) -> None:
        changed_assertion = self._assertion(
            "planned",
            "PAS-" + "F6" * 16,
            SOURCE_ID,
            self.operations[0],
        )
        with self.assertRaisesRegex(PrincipalAuthenticationError, "binding"):
            self._authenticate(planned_owner_assertion=changed_assertion)
        with self.assertRaisesRegex(PrincipalAuthenticationError, "Control approver"):
            self._authenticate(expected_control_profile_ids=["AOE-HQ-15"])
        with self.assertRaisesRegex(PrincipalAuthenticationError, "binding"):
            self._authenticate(independent_control_assertion=self.planned_assertion)

    def test_changed_preflight_invalidates_both_signed_intents(self) -> None:
        changed = replace(
            self.preflight,
            expected_generation=1,
            previous_transition_id="WLT-" + "1" * 32,
            expected_lease_expires_at="2026-07-30T10:20:00Z",
        )
        with self.assertRaisesRegex(PrincipalAuthenticationError, "intent"):
            authenticate_collaboration_ownership_revocation(
                changed,
                planned_owner_assertion=self.planned_assertion,
                independent_control_assertion=self.control_assertion,
                verified_policy=self.verified_policy,
                planned_owner_scope=self.scopes["planned"],
                independent_control_scope=self.scopes["control"],
                expected_audience=AUDIENCE,
                expected_store_id=STORE_ID,
                expected_control_profile_ids=[CONTROL_ID],
                clock=lambda: NOW,
            )

    def test_expired_transition_and_future_preflight_fail_closed(self) -> None:
        with self.assertRaisesRegex(PrincipalAuthenticationError, "expired"):
            self._authenticate(clock=lambda: NOW.replace(minute=26))
        with self.assertRaisesRegex(PrincipalAuthenticationError, "precedes"):
            authenticate_collaboration_ownership_revocation(
                replace(self.preflight, evaluated_at="2026-07-30T10:06:00Z"),
                planned_owner_assertion=self.planned_assertion,
                independent_control_assertion=self.control_assertion,
                verified_policy=self.verified_policy,
                planned_owner_scope=self.scopes["planned"],
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
            (
                SCHEMAS
                / "collaboration-ownership-revocation-authentication-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        schema["properties"]["preflight"] = {"type": "object"}
        Draft202012Validator(schema).validate(self._authenticate().to_dict())

    def test_preflight_projection_tampering_fails_before_signature_checks(self) -> None:
        with self.assertRaises(PrincipalAuthenticationError):
            authenticate_collaboration_ownership_revocation(
                replace(self.preflight, active_delegation_depth=1),
                planned_owner_assertion=self.planned_assertion,
                independent_control_assertion=self.control_assertion,
                verified_policy=self.verified_policy,
                planned_owner_scope=self.scopes["planned"],
                independent_control_scope=self.scopes["control"],
                expected_audience=AUDIENCE,
                expected_store_id=STORE_ID,
                expected_control_profile_ids=[CONTROL_ID],
                clock=lambda: NOW,
            )


if __name__ == "__main__":
    unittest.main()
