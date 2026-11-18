"""Phase 85 bounded collaboration ownership-chain coverage."""

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

from sunderkey.collaboration_ownership_chain import (
    CollaborationOwnershipChainEntry,
    apply_collaboration_ownership_revocation,
    build_collaboration_ownership_chain_entry,
    build_collaboration_ownership_revocation,
    validate_collaboration_ownership_chain,
)
from sunderkey.errors import CollaborationPlanError

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "registry" / "schemas"
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


def authority_bindings(index: int, *, current: bool = True) -> dict[str, object]:
    return {
        "current_owner_authorization_id": f"AUTH-CURRENT-{index}" if current else None,
        "proposed_owner_acceptance_id": f"ACCEPT-PROPOSED-{index}",
        "independent_control_approval_id": f"APPROVAL-CONTROL-{index}",
        "second_control_or_mission_authority_id": None,
    }


def entry(
    *,
    sequence: int,
    transition_kind: str,
    from_owner: str,
    to_owner: str,
    previous: str | None,
    bindings: dict[str, object] | None = None,
) -> CollaborationOwnershipChainEntry:
    return build_collaboration_ownership_chain_entry(
        mission_id="MISSION-1",
        collaboration_plan_id="PLAN-1",
        collaboration_plan_sha256=DIGEST_A,
        work_item_id="WORK-1",
        work_item_objective_sha256=DIGEST_B,
        planned_owner_id="OWNER-PLANNED",
        sequence=sequence,
        owner_epoch=sequence,
        transition_kind=transition_kind,
        from_owner_id=from_owner,
        to_owner_id=to_owner,
        previous_entry_sha256=previous,
        reason_code="approved_transition",
        requested_at=f"2026-08-02T22:{sequence:02d}:00Z",
        expires_at=f"2026-08-02T23:{sequence:02d}:00Z",
        control_role_replacement=False,
        authority_bindings=bindings or authority_bindings(sequence),
    )


class CollaborationOwnershipChainPhase85Tests(unittest.TestCase):
    def test_bounded_delegation_and_return_are_verified(self) -> None:
        first = entry(
            sequence=1,
            transition_kind="delegation",
            from_owner="OWNER-PLANNED",
            to_owner="OWNER-B",
            previous=None,
        )
        second = entry(
            sequence=2,
            transition_kind="delegation",
            from_owner="OWNER-B",
            to_owner="OWNER-C",
            previous=first.entry_sha256,
        )
        delegated = validate_collaboration_ownership_chain(
            [first, second], maximum_delegation_depth=2
        )
        self.assertEqual(delegated.current_owner_id, "OWNER-C")
        self.assertEqual(delegated.active_delegation_depth, 2)
        returned = entry(
            sequence=3,
            transition_kind="return_to_planned_owner",
            from_owner="OWNER-C",
            to_owner="OWNER-PLANNED",
            previous=second.entry_sha256,
        )
        verified = validate_collaboration_ownership_chain(
            [first, second, returned], maximum_delegation_depth=2
        )
        self.assertEqual(verified.current_owner_id, "OWNER-PLANNED")
        self.assertEqual(verified.active_delegation_depth, 0)

    def test_depth_cycle_and_stale_predecessor_fail_closed(self) -> None:
        first = entry(
            sequence=1,
            transition_kind="delegation",
            from_owner="OWNER-PLANNED",
            to_owner="OWNER-B",
            previous=None,
        )
        second = entry(
            sequence=2,
            transition_kind="delegation",
            from_owner="OWNER-B",
            to_owner="OWNER-C",
            previous=first.entry_sha256,
        )
        with self.assertRaisesRegex(CollaborationPlanError, "depth"):
            validate_collaboration_ownership_chain(
                [first, second], maximum_delegation_depth=1
            )
        cycle = entry(
            sequence=3,
            transition_kind="delegation",
            from_owner="OWNER-C",
            to_owner="OWNER-B",
            previous=second.entry_sha256,
        )
        with self.assertRaisesRegex(CollaborationPlanError, "cycle"):
            validate_collaboration_ownership_chain(
                [first, second, cycle], maximum_delegation_depth=8
            )
        stale = entry(
            sequence=2,
            transition_kind="delegation",
            from_owner="OWNER-B",
            to_owner="OWNER-D",
            previous="sha256:" + "0" * 64,
        )
        with self.assertRaisesRegex(CollaborationPlanError, "predecessor"):
            validate_collaboration_ownership_chain(
                [first, stale], maximum_delegation_depth=8
            )

    def test_control_revocation_restores_planned_owner(self) -> None:
        first = entry(
            sequence=1,
            transition_kind="delegation",
            from_owner="OWNER-PLANNED",
            to_owner="OWNER-B",
            previous=None,
        )
        revocation = build_collaboration_ownership_revocation(
            head=first,
            independent_control_id="CONTROL-1",
            independent_control_approval_id="APPROVAL-CONTROL-REVOCATION",
            planned_owner_acceptance_id="ACCEPT-PLANNED-OWNER",
            reason_code="control_revocation",
            requested_at="2026-08-02T22:30:00Z",
            expires_at="2026-08-02T23:30:00Z",
        )
        revocation_entry, verified = apply_collaboration_ownership_revocation(
            [first], revocation, maximum_delegation_depth=2
        )
        self.assertEqual(revocation_entry.to_dict()["transition_kind"], "control_revocation")
        self.assertEqual(verified.current_owner_id, "OWNER-PLANNED")
        self.assertEqual(verified.active_delegation_depth, 0)

    def test_stale_revocation_and_control_replacement_fail_closed(self) -> None:
        first = entry(
            sequence=1,
            transition_kind="delegation",
            from_owner="OWNER-PLANNED",
            to_owner="OWNER-B",
            previous=None,
        )
        revocation = build_collaboration_ownership_revocation(
            head=first,
            independent_control_id="CONTROL-1",
            independent_control_approval_id="APPROVAL-CONTROL-REVOCATION",
            planned_owner_acceptance_id="ACCEPT-PLANNED-OWNER",
            reason_code="control_revocation",
            requested_at="2026-08-02T22:30:00Z",
            expires_at="2026-08-02T23:30:00Z",
        )
        second = entry(
            sequence=2,
            transition_kind="delegation",
            from_owner="OWNER-B",
            to_owner="OWNER-C",
            previous=first.entry_sha256,
        )
        with self.assertRaisesRegex(CollaborationPlanError, "head is stale"):
            apply_collaboration_ownership_revocation(
                [first, second], revocation, maximum_delegation_depth=2
            )
        with self.assertRaisesRegex(CollaborationPlanError, "second independent"):
            build_collaboration_ownership_chain_entry(
                mission_id="MISSION-1",
                collaboration_plan_id="PLAN-1",
                collaboration_plan_sha256=DIGEST_A,
                work_item_id="WORK-1",
                work_item_objective_sha256=DIGEST_B,
                planned_owner_id="OWNER-PLANNED",
                sequence=1,
                owner_epoch=1,
                transition_kind="privileged_reassignment",
                from_owner_id="OWNER-PLANNED",
                to_owner_id="OWNER-B",
                previous_entry_sha256=None,
                reason_code="control_replacement",
                requested_at="2026-08-02T22:30:00Z",
                expires_at="2026-08-02T23:30:00Z",
                control_role_replacement=True,
                authority_bindings=authority_bindings(1),
            )

    def test_hash_tampering_is_rejected(self) -> None:
        first = entry(
            sequence=1,
            transition_kind="delegation",
            from_owner="OWNER-PLANNED",
            to_owner="OWNER-B",
            previous=None,
        )
        changed = copy.deepcopy(first.to_dict())
        changed["to_owner_id"] = "OWNER-X"
        with self.assertRaisesRegex(CollaborationPlanError, "hash"):
            CollaborationOwnershipChainEntry.from_dict(changed)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_records_match_published_schemas(self) -> None:
        first = entry(
            sequence=1,
            transition_kind="delegation",
            from_owner="OWNER-PLANNED",
            to_owner="OWNER-B",
            previous=None,
        )
        revocation = build_collaboration_ownership_revocation(
            head=first,
            independent_control_id="CONTROL-1",
            independent_control_approval_id="APPROVAL-CONTROL-REVOCATION",
            planned_owner_acceptance_id="ACCEPT-PLANNED-OWNER",
            reason_code="control_revocation",
            requested_at="2026-08-02T22:30:00Z",
            expires_at="2026-08-02T23:30:00Z",
        )
        entry_schema = json.loads(
            (SCHEMAS / "collaboration-ownership-chain-entry-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        revocation_schema = json.loads(
            (SCHEMAS / "collaboration-ownership-revocation-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        Draft202012Validator(entry_schema).validate(first.to_dict())
        Draft202012Validator(revocation_schema).validate(revocation.to_dict())

    def test_module_has_no_network_storage_or_execution_imports(self) -> None:
        tree = ast.parse(
            (ROOT / "src/sunderkey/collaboration_ownership_chain.py").read_text(
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
            & {"asyncio", "http", "requests", "socket", "sqlite3", "subprocess", "urllib"}
        )


if __name__ == "__main__":
    unittest.main()
