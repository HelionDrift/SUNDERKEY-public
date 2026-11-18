"""Phase 101 privileged ownership reassignment preflight coverage."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import tomllib
import unittest
from contextlib import closing
from datetime import timedelta
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.collaboration import WorkItemKind
from sunderkey.collaboration_ownership_chain import (
    build_collaboration_ownership_chain_entry,
    collaboration_work_item_objective_sha256,
)
from sunderkey.collaboration_ownership_privileged_reassignment_preflight import (
    PREFLIGHT_DOMAIN,
    CollaborationOwnershipPrivilegedReassignmentPreflightService,
    load_collaboration_ownership_privileged_reassignment_preflight,
)
from sunderkey.errors import (
    CollaborationPlanError,
    PrincipalAuthenticationError,
    StoreConflictError,
)
from sunderkey.store import canonical_json, format_timestamp, sha256_text

from . import test_collaboration_ownership_preflight_phase90 as phase90

ROOT = Path(__file__).resolve().parents[2]
PREFLIGHT_SCHEMA_PATH = ROOT / (
    "registry/schemas/"
    "collaboration-ownership-privileged-reassignment-preflight-v1.schema.json"
)
ENTRY_SCHEMA_PATH = ROOT / (
    "registry/schemas/collaboration-ownership-chain-entry-v1.schema.json"
)
READINESS_REPLACEMENT_ID = "AOE-HQ-09"
CONTROL_REPLACEMENT_ID = "AOE-HQ-13"


class CollaborationOwnershipPrivilegedReassignmentPreflightPhase101Tests(
    unittest.TestCase
):
    @classmethod
    def setUpClass(cls) -> None:
        phase90.CollaborationOwnershipPreflightPhase90Tests.setUpClass()

    def setUp(self) -> None:
        fixture = phase90.CollaborationOwnershipPreflightPhase90Tests(
            methodName="runTest"
        )
        original_commit_policy = fixture._commit_policy
        fixture._commit_policy = lambda: original_commit_policy(
            privileged_role_reassignment=True
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.base = fixture
        self.fixture = fixture.fixture
        self.service = (
            CollaborationOwnershipPrivilegedReassignmentPreflightService(
                self.fixture.store,
                self.fixture.registry,
                clock=lambda: self.fixture.now,
            )
        )

    def item(self, kind: WorkItemKind):
        return next(item for item in self.fixture.plan.work_items if item.kind is kind)

    def entry(
        self,
        kind: WorkItemKind,
        replacement_id: str,
        *,
        control_role_replacement: bool,
        second_authority_id: str | None,
    ):
        item = self.item(kind)
        return build_collaboration_ownership_chain_entry(
            mission_id=item.mission_id,
            collaboration_plan_id=self.fixture.plan.plan_id,
            collaboration_plan_sha256=self.fixture.plan.content_sha256,
            work_item_id=item.work_item_id,
            work_item_objective_sha256=(
                collaboration_work_item_objective_sha256(item)
            ),
            planned_owner_id=item.owner_profile_id,
            sequence=1,
            owner_epoch=1,
            transition_kind="privileged_reassignment",
            from_owner_id=item.owner_profile_id,
            to_owner_id=replacement_id,
            previous_entry_sha256=None,
            reason_code="privileged_role_reassignment",
            requested_at=format_timestamp(self.fixture.now),
            expires_at=format_timestamp(
                self.fixture.now + timedelta(minutes=20)
            ),
            control_role_replacement=control_role_replacement,
            authority_bindings={
                "current_owner_authorization_id": "PAS-" + "A" * 32,
                "proposed_owner_acceptance_id": "PAS-" + "B" * 32,
                "independent_control_approval_id": "PAS-" + "C" * 32,
                "second_control_or_mission_authority_id": second_authority_id,
            },
        )

    def test_noncontrol_preflight_binds_equivalent_role_without_mutation(self) -> None:
        entry = self.entry(
            WorkItemKind.READINESS,
            READINESS_REPLACEMENT_ID,
            control_role_replacement=False,
            second_authority_id=None,
        )
        with closing(sqlite3.connect(self.fixture.path)) as connection:
            before = (
                connection.execute(
                    "SELECT COUNT(*) FROM collaboration_ownership_chain_entries"
                ).fetchone()[0],
                connection.execute(
                    "SELECT COUNT(*) FROM principal_assertion_uses"
                ).fetchone()[0],
            )
        preflight = self.service.preflight(entry)
        self.assertEqual(self.service.preflight(entry), preflight)
        document = preflight.to_dict()
        self.assertEqual(
            document["admission_status"],
            "admissible_pending_privileged_authenticated_commit",
        )
        self.assertEqual(document["role_binding"]["work_item_kind"], "readiness")
        self.assertFalse(document["role_binding"]["control_role_replacement"])
        self.assertFalse(document["role_binding"]["second_authority_required"])
        self.assertEqual(document["role_binding"]["required_authority_count"], 3)
        self.assertEqual(
            document["replacement_qualification"]["profile_id"],
            READINESS_REPLACEMENT_ID,
        )
        self.assertEqual(
            document["replacement_qualification"]["category"],
            "mission operations",
        )
        body = {
            key: value
            for key, value in document.items()
            if key not in {"preflight_id", "preflight_sha256"}
        }
        self.assertEqual(
            document["preflight_sha256"],
            sha256_text(
                canonical_json({"domain": PREFLIGHT_DOMAIN, "preflight": body})
            ),
        )
        self.assertTrue(document["preflight_id"].startswith("OPF-"))
        with closing(sqlite3.connect(self.fixture.path)) as connection:
            after = (
                connection.execute(
                    "SELECT COUNT(*) FROM collaboration_ownership_chain_entries"
                ).fetchone()[0],
                connection.execute(
                    "SELECT COUNT(*) FROM principal_assertion_uses"
                ).fetchone()[0],
            )
        self.assertEqual(after, before)

    def test_control_replacement_requires_four_authorities(self) -> None:
        preflight = self.service.preflight(
            self.entry(
                WorkItemKind.CONTROL_REVIEW,
                CONTROL_REPLACEMENT_ID,
                control_role_replacement=True,
                second_authority_id="PAS-" + "D" * 32,
            )
        )
        role = preflight.to_dict()["role_binding"]
        self.assertTrue(role["control_role_replacement"])
        self.assertTrue(role["second_authority_required"])
        self.assertEqual(role["required_authority_count"], 4)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_preflight_matches_published_schema(self) -> None:
        schema = json.loads(PREFLIGHT_SCHEMA_PATH.read_text(encoding="utf-8"))
        schema["properties"]["entry"] = json.loads(
            ENTRY_SCHEMA_PATH.read_text(encoding="utf-8")
        )
        Draft202012Validator(schema).validate(
            self.service.preflight(
                self.entry(
                    WorkItemKind.CONTROL_REVIEW,
                    CONTROL_REPLACEMENT_ID,
                    control_role_replacement=True,
                    second_authority_id="PAS-" + "D" * 32,
                )
            ).to_dict()
        )

    def test_role_and_authority_shape_fail_closed(self) -> None:
        with self.assertRaisesRegex(StoreConflictError, "authority shape"):
            self.service.preflight(
                self.entry(
                    WorkItemKind.READINESS,
                    READINESS_REPLACEMENT_ID,
                    control_role_replacement=False,
                    second_authority_id="PAS-" + "D" * 32,
                )
            )
        with self.assertRaisesRegex(StoreConflictError, "authority shape"):
            self.service.preflight(
                self.entry(
                    WorkItemKind.CONTROL_REVIEW,
                    CONTROL_REPLACEMENT_ID,
                    control_role_replacement=False,
                    second_authority_id=None,
                )
            )
        with self.assertRaisesRegex(StoreConflictError, "distinct"):
            item = self.item(WorkItemKind.READINESS)
            duplicate = build_collaboration_ownership_chain_entry(
                mission_id=item.mission_id,
                collaboration_plan_id=self.fixture.plan.plan_id,
                collaboration_plan_sha256=self.fixture.plan.content_sha256,
                work_item_id=item.work_item_id,
                work_item_objective_sha256=(
                    collaboration_work_item_objective_sha256(item)
                ),
                planned_owner_id=item.owner_profile_id,
                sequence=1,
                owner_epoch=1,
                transition_kind="privileged_reassignment",
                from_owner_id=item.owner_profile_id,
                to_owner_id=READINESS_REPLACEMENT_ID,
                previous_entry_sha256=None,
                reason_code="privileged_role_reassignment",
                requested_at=format_timestamp(self.fixture.now),
                expires_at=format_timestamp(
                    self.fixture.now + timedelta(minutes=20)
                ),
                control_role_replacement=False,
                authority_bindings={
                    "current_owner_authorization_id": "PAS-" + "A" * 32,
                    "proposed_owner_acceptance_id": "PAS-" + "A" * 32,
                    "independent_control_approval_id": "PAS-" + "C" * 32,
                    "second_control_or_mission_authority_id": None,
                },
            )
            self.service.preflight(duplicate)

    def test_disabled_policy_and_specialist_item_are_rejected(self) -> None:
        regular = phase90.CollaborationOwnershipPreflightPhase90Tests(
            methodName="runTest"
        )
        regular.setUp()
        self.addCleanup(regular.doCleanups)
        service = CollaborationOwnershipPrivilegedReassignmentPreflightService(
            regular.fixture.store,
            regular.fixture.registry,
            clock=lambda: regular.fixture.now,
        )
        readiness = next(
            item
            for item in regular.fixture.plan.work_items
            if item.kind is WorkItemKind.READINESS
        )
        disabled_entry = build_collaboration_ownership_chain_entry(
            mission_id=readiness.mission_id,
            collaboration_plan_id=regular.fixture.plan.plan_id,
            collaboration_plan_sha256=regular.fixture.plan.content_sha256,
            work_item_id=readiness.work_item_id,
            work_item_objective_sha256=(
                collaboration_work_item_objective_sha256(readiness)
            ),
            planned_owner_id=readiness.owner_profile_id,
            sequence=1,
            owner_epoch=1,
            transition_kind="privileged_reassignment",
            from_owner_id=readiness.owner_profile_id,
            to_owner_id=READINESS_REPLACEMENT_ID,
            previous_entry_sha256=None,
            reason_code="privileged_role_reassignment",
            requested_at=format_timestamp(regular.fixture.now),
            expires_at=format_timestamp(
                regular.fixture.now + timedelta(minutes=20)
            ),
            control_role_replacement=False,
            authority_bindings={
                "current_owner_authorization_id": "PAS-" + "A" * 32,
                "proposed_owner_acceptance_id": "PAS-" + "B" * 32,
                "independent_control_approval_id": "PAS-" + "C" * 32,
                "second_control_or_mission_authority_id": None,
            },
        )
        with self.assertRaisesRegex(StoreConflictError, "does not activate"):
            service.preflight(disabled_entry)

        specialist = self.item(WorkItemKind.SPECIALIST_ANALYSIS)
        specialist_entry = build_collaboration_ownership_chain_entry(
            mission_id=specialist.mission_id,
            collaboration_plan_id=self.fixture.plan.plan_id,
            collaboration_plan_sha256=self.fixture.plan.content_sha256,
            work_item_id=specialist.work_item_id,
            work_item_objective_sha256=(
                collaboration_work_item_objective_sha256(specialist)
            ),
            planned_owner_id=specialist.owner_profile_id,
            sequence=1,
            owner_epoch=1,
            transition_kind="privileged_reassignment",
            from_owner_id=specialist.owner_profile_id,
            to_owner_id=phase90.CANDIDATE_ID,
            previous_entry_sha256=None,
            reason_code="privileged_role_reassignment",
            requested_at=format_timestamp(self.fixture.now),
            expires_at=format_timestamp(
                self.fixture.now + timedelta(minutes=20)
            ),
            control_role_replacement=False,
            authority_bindings={
                "current_owner_authorization_id": "PAS-" + "A" * 32,
                "proposed_owner_acceptance_id": "PAS-" + "B" * 32,
                "independent_control_approval_id": "PAS-" + "C" * 32,
                "second_control_or_mission_authority_id": None,
            },
        )
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "equivalent privileged role",
        ):
            self.service.preflight(specialist_entry)

    def test_loader_rejects_changed_and_duplicate_documents(self) -> None:
        preflight = self.service.preflight(
            self.entry(
                WorkItemKind.READINESS,
                READINESS_REPLACEMENT_ID,
                control_role_replacement=False,
                second_authority_id=None,
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "privileged-preflight.json"
            path.write_text(json.dumps(preflight.to_dict()), encoding="utf-8")
            self.assertEqual(
                load_collaboration_ownership_privileged_reassignment_preflight(
                    path
                ),
                preflight,
            )
            changed = preflight.to_dict()
            changed["role_binding"]["required_authority_count"] = 4
            path.write_text(json.dumps(changed), encoding="utf-8")
            with self.assertRaises(CollaborationPlanError):
                load_collaboration_ownership_privileged_reassignment_preflight(
                    path
                )
            path.write_text(
                '{"schema_version":1,"schema_version":1}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(CollaborationPlanError, "Could not load"):
                load_collaboration_ownership_privileged_reassignment_preflight(
                    path
                )

    def test_project_version_is_phase101(self) -> None:
        project = tomllib.loads(
            (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )
        self.assertEqual(project["project"]["version"], "0.1.0")


if __name__ == "__main__":
    unittest.main()
