"""Phase 86 mission reconfiguration policy coverage."""

from __future__ import annotations

import ast
import copy
import json
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.collaboration_mission_policy import (
    CollaborationMissionReconfigurationPolicy,
    build_collaboration_mission_reconfiguration_policy,
    validate_collaboration_mission_reconfiguration_policy,
)
from sunderkey.collaboration_reconfiguration_policy import (
    load_collaboration_reconfiguration_authority_policy,
)
from sunderkey.errors import CollaborationPlanError

ROOT = Path(__file__).resolve().parents[2]
AUTHORITY_PATH = ROOT / "registry" / "collaboration-reconfiguration-policy-d001-d005.json"
SCHEMA_PATH = (
    ROOT / "registry" / "schemas" / "collaboration-mission-reconfiguration-policy-v1.schema.json"
)
DIGEST_A = "sha256:" + "a" * 64


def assertion(profile_id: str, marker: str) -> dict[str, str]:
    return {
        "profile_id": profile_id,
        "assertion_id": f"PAS-{marker * 32}",
        "assertion_sha256": "sha256:" + marker.lower() * 64,
    }


def activation(**overrides: bool) -> dict[str, bool]:
    result = {
        "privileged_role_reassignment": False,
        "delegation_return_and_revocation": True,
        "cross_command_transfer": False,
        "activated_plan_replacement": False,
        "distributed_execution_transfer_or_cancellation": False,
    }
    result.update(overrides)
    return result


def policy(
    *,
    version: int = 1,
    previous: str | None = None,
    owner: dict[str, str] | None = None,
    control: dict[str, str] | None = None,
    effective_at: str = "2026-08-03T00:00:00Z",
) -> CollaborationMissionReconfigurationPolicy:
    return build_collaboration_mission_reconfiguration_policy(
        authority_policy=load_collaboration_reconfiguration_authority_policy(AUTHORITY_PATH),
        policy_version=version,
        previous_policy_sha256=previous,
        mission_id="MISSION-1",
        collaboration_plan_id="PLAN-1",
        collaboration_plan_sha256=DIGEST_A,
        maximum_delegation_depth=3,
        reconfiguration_validity_seconds=3600,
        execution_ack_timeout_seconds=300,
        maximum_plan_replacement_items=100,
        transition_activation=activation(),
        mission_owner_approval=owner or assertion("PROFILE-MISSION-OWNER", "A"),
        independent_control_approval=control or assertion("PROFILE-CONTROL-1", "B"),
        effective_at=effective_at,
        expires_at="2026-08-04T00:00:00Z",
    )


class CollaborationMissionPolicyPhase86Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.authority = load_collaboration_reconfiguration_authority_policy(AUTHORITY_PATH)

    def test_exact_mission_selection_is_content_addressed_and_inactive(self) -> None:
        selected = policy()
        document = selected.to_dict()
        self.assertEqual(document["selected_parameters"]["maximum_delegation_depth"], 3)
        self.assertTrue(document["transition_activation"]["delegation_return_and_revocation"])
        self.assertEqual(document["authentication_status"], "assertions_pending_verification")
        self.assertEqual(document["runtime_effect"], "none")
        validated = validate_collaboration_mission_reconfiguration_policy(
            selected,
            authority_policy=self.authority,
            expected_mission_id="MISSION-1",
            expected_collaboration_plan_id="PLAN-1",
            expected_collaboration_plan_sha256=DIGEST_A,
        )
        self.assertEqual(validated.policy_sha256, selected.policy_sha256)

    def test_parameter_bounds_and_empty_activation_fail_closed(self) -> None:
        with self.assertRaisesRegex(CollaborationPlanError, "bounds"):
            build_collaboration_mission_reconfiguration_policy(
                authority_policy=self.authority,
                policy_version=1,
                previous_policy_sha256=None,
                mission_id="MISSION-1",
                collaboration_plan_id="PLAN-1",
                collaboration_plan_sha256=DIGEST_A,
                maximum_delegation_depth=9,
                reconfiguration_validity_seconds=3600,
                execution_ack_timeout_seconds=300,
                maximum_plan_replacement_items=100,
                transition_activation=activation(),
                mission_owner_approval=assertion("PROFILE-MISSION-OWNER", "A"),
                independent_control_approval=assertion("PROFILE-CONTROL-1", "B"),
                effective_at="2026-08-03T00:00:00Z",
                expires_at="2026-08-04T00:00:00Z",
            )
        with self.assertRaisesRegex(CollaborationPlanError, "at least one"):
            build_collaboration_mission_reconfiguration_policy(
                authority_policy=self.authority,
                policy_version=1,
                previous_policy_sha256=None,
                mission_id="MISSION-1",
                collaboration_plan_id="PLAN-1",
                collaboration_plan_sha256=DIGEST_A,
                maximum_delegation_depth=3,
                reconfiguration_validity_seconds=3600,
                execution_ack_timeout_seconds=300,
                maximum_plan_replacement_items=100,
                transition_activation={key: False for key in activation()},
                mission_owner_approval=assertion("PROFILE-MISSION-OWNER", "A"),
                independent_control_approval=assertion("PROFILE-CONTROL-1", "B"),
                effective_at="2026-08-03T00:00:00Z",
                expires_at="2026-08-04T00:00:00Z",
            )

    def test_separation_and_content_tampering_fail_closed(self) -> None:
        same_profile = assertion("PROFILE-SAME", "A")
        with self.assertRaisesRegex(CollaborationPlanError, "must be distinct"):
            policy(
                owner=same_profile,
                control={**assertion("PROFILE-SAME", "B")},
            )
        changed = copy.deepcopy(policy().to_dict())
        changed["selected_parameters"]["maximum_delegation_depth"] = 4
        with self.assertRaisesRegex(CollaborationPlanError, "hash"):
            CollaborationMissionReconfigurationPolicy.from_dict(changed)
        invalid_anchor = copy.deepcopy(policy().to_dict())
        invalid_anchor["mission_id"] = "bad mission"
        with self.assertRaisesRegex(CollaborationPlanError, "mission_id"):
            CollaborationMissionReconfigurationPolicy.from_dict(invalid_anchor)

    def test_policy_replacement_requires_exact_monotonic_predecessor(self) -> None:
        first = policy()
        second = policy(
            version=2,
            previous=first.policy_sha256,
            effective_at="2026-08-03T12:00:00Z",
        )
        validated = validate_collaboration_mission_reconfiguration_policy(
            second,
            authority_policy=self.authority,
            expected_mission_id="MISSION-1",
            expected_collaboration_plan_id="PLAN-1",
            expected_collaboration_plan_sha256=DIGEST_A,
            previous_policy=first,
        )
        self.assertEqual(validated.to_dict()["policy_version"], 2)
        with self.assertRaisesRegex(CollaborationPlanError, "predecessor"):
            validate_collaboration_mission_reconfiguration_policy(
                second,
                authority_policy=self.authority,
                expected_mission_id="MISSION-1",
                expected_collaboration_plan_id="PLAN-1",
                expected_collaboration_plan_sha256=DIGEST_A,
            )

    def test_stale_mission_or_plan_binding_fails_closed(self) -> None:
        selected = policy()
        with self.assertRaisesRegex(CollaborationPlanError, "mission binding"):
            validate_collaboration_mission_reconfiguration_policy(
                selected,
                authority_policy=self.authority,
                expected_mission_id="MISSION-2",
                expected_collaboration_plan_id="PLAN-1",
                expected_collaboration_plan_sha256=DIGEST_A,
            )
        with self.assertRaisesRegex(CollaborationPlanError, "collaboration-plan"):
            validate_collaboration_mission_reconfiguration_policy(
                selected,
                authority_policy=self.authority,
                expected_mission_id="MISSION-1",
                expected_collaboration_plan_id="PLAN-2",
                expected_collaboration_plan_sha256=DIGEST_A,
            )

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_policy_matches_published_schema(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(policy().to_dict())

    def test_module_has_no_network_storage_or_execution_imports(self) -> None:
        tree = ast.parse(
            (ROOT / "src/sunderkey/collaboration_mission_policy.py").read_text(encoding="utf-8")
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
