from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import unittest
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

from sunderkey.collaboration import (
    CollaborationPlan,
    WorkItemKind,
    build_collaboration_plan,
    load_collaboration_plan,
    validate_collaboration_plan,
)
from sunderkey.errors import CollaborationPlanError
from sunderkey.mission import (
    MissionRequest,
    assemble_joint_mission_cell,
    load_mission_request,
)
from sunderkey.registry import ExpertRegistry, load_registry
from sunderkey.store import SCHEMA_VERSION as STORE_SCHEMA_VERSION
from sunderkey.types import ActionTier, EvidenceLevel, ProfileKind

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = ROOT / "registry" / "army-v1.json"
MISSION_PATH = ROOT / "examples" / "missions" / "internet-api-to-data.json"
PLAN_PATH = ROOT / "examples" / "collaboration" / "internet-api-to-data.json"

EXPECTED_PLAN_ID = "CLP-F878069253CBE5D4D2590A91"
EXPECTED_REGISTRY_SHA256 = (
    "sha256:e5952b36f79737f43c8719e0601740738f2ce9946014c02d0c22be64a44a8c7d"
)
EXPECTED_MISSION_SHA256 = (
    "sha256:e1c21891d9b4fa7e214e6a209f6ad4693ab7671d37dd3283b98d27d05170e875"
)
EXPECTED_CELL_SHA256 = (
    "sha256:2c2c5300b47134eda224de6091d6489920b586bb62093d06cdbec5434ce1c84f"
)
EXPECTED_CONTENT_SHA256 = (
    "sha256:905971ccc793de54748d1aa7ec13b12493b6c7ad3b2700e8af81a26e69a54750"
)


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("ascii")


def canonical_sha256(value: Any) -> str:
    return f"sha256:{hashlib.sha256(canonical_bytes(value)).hexdigest()}"


def recalculate_content_hash(raw: dict[str, Any]) -> None:
    unsigned = {
        key: value
        for key, value in raw.items()
        if key != "content_sha256"
    }
    raw["content_sha256"] = canonical_sha256(unsigned)


class CollaborationPlanPhase6Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)
        cls.mission = load_mission_request(MISSION_PATH)
        cls.cell = assemble_joint_mission_cell(cls.registry, cls.mission)

    def build(self) -> CollaborationPlan:
        return build_collaboration_plan(self.registry, self.mission)

    def items_of_kind(
        self,
        plan: CollaborationPlan,
        kind: WorkItemKind,
    ) -> tuple[Any, ...]:
        return tuple(item for item in plan.work_items if item.kind is kind)

    def test_build_is_byte_identical_and_round_trips(self) -> None:
        first = self.build()
        second = self.build()

        self.assertEqual(
            canonical_bytes(first.to_dict()),
            canonical_bytes(second.to_dict()),
        )
        reopened = CollaborationPlan.from_dict(first.to_dict())
        self.assertEqual(reopened, first)
        self.assertEqual(
            canonical_bytes(reopened.to_dict()),
            canonical_bytes(first.to_dict()),
        )

    def test_file_loader_round_trips_and_rejects_duplicate_keys(
        self,
    ) -> None:
        expected = self.build()
        self.assertEqual(load_collaboration_plan(PLAN_PATH), expected)
        source = PLAN_PATH.read_text(encoding="utf-8")
        cases = {
            "top-level": source.replace(
                "{\n",
                '{\n  "mission_objective": "unreviewed shadow",\n',
                1,
            ),
            "nested": source.replace(
                '"work_items": [\n    {',
                '"work_items": [\n    {\n'
                '      "title": "unreviewed shadow",',
                1,
            ),
        }
        for label, text in cases.items():
            with (
                self.subTest(label=label),
                tempfile.TemporaryDirectory() as directory,
            ):
                self.assertEqual(
                    CollaborationPlan.from_dict(json.loads(text)),
                    expected,
                )
                path = Path(directory) / "duplicate-key-plan.json"
                path.write_text(text, encoding="utf-8")

                with self.assertRaisesRegex(
                    CollaborationPlanError,
                    "Could not read collaboration plan",
                ) as raised:
                    load_collaboration_plan(path)

                self.assertIn(
                    "Duplicate JSON object key",
                    str(raised.exception.__cause__),
                )

    def test_example_has_expected_work_count_and_topology(self) -> None:
        plan = self.build()

        self.assertEqual(len(plan.work_items), 13)
        self.assertEqual(
            [len(layer) for layer in plan.topological_layers],
            [1, 3, 3, 2, 1, 2, 1],
        )
        self.assertEqual(
            {
                kind: len(self.items_of_kind(plan, kind))
                for kind in WorkItemKind
            },
            {
                WorkItemKind.READINESS: 1,
                WorkItemKind.SPECIALIST_ANALYSIS: 3,
                WorkItemKind.DOMAIN_SYNTHESIS: 3,
                WorkItemKind.GROUP_INTEGRATION: 2,
                WorkItemKind.CROSS_SURFACE_INTEGRATION: 1,
                WorkItemKind.CONTROL_REVIEW: 1,
                WorkItemKind.EVIDENCE_REVIEW: 1,
                WorkItemKind.ASSURANCE_REVIEW: 1,
            },
        )

    def test_full_army_plan_covers_all_specialists_and_commands(self) -> None:
        specialist_ids = tuple(
            profile.id
            for profile in self.registry.profiles
            if profile.kind is ProfileKind.SPECIALIST
        )
        mission = MissionRequest.from_dict(
            {
                "schema_version": 1,
                "mission_id": "FULL-ARMY-PLAN-001",
                "objective": (
                    "Coordinate every defined specialist across one "
                    "synthetic full-catalog planning exercise."
                ),
                "environment": "synthetic",
                "requested_specialist_ids": list(specialist_ids),
                "max_action_tier": "R1",
                "required_evidence_level": "E0",
                "scope_reference": "scope://synthetic/full-army-plan",
                "constraints": {
                    "production": False,
                    "third_party": False,
                    "synthetic_data_only": True,
                    "isolated_research_range": False,
                    "max_cell_size": 500,
                },
            }
        )

        plan = build_collaboration_plan(self.registry, mission)
        cell = assemble_joint_mission_cell(self.registry, mission)
        validate_collaboration_plan(self.registry, mission, plan)

        self.assertEqual(len(specialist_ids), 348)
        self.assertEqual(cell.size, 395)
        self.assertEqual(len(plan.work_items), 381)
        self.assertEqual(
            [len(layer) for layer in plan.topological_layers],
            [1, 348, 23, 5, 1, 2, 1],
        )
        self.assertEqual(
            len(
                tuple(
                    item
                    for item in plan.work_items
                    if item.kind is WorkItemKind.DOMAIN_SYNTHESIS
                )
            ),
            23,
        )
        self.assertEqual(
            len(
                tuple(
                    item
                    for item in plan.work_items
                    if item.kind is WorkItemKind.GROUP_INTEGRATION
                )
            ),
            5,
        )
        self.assertEqual(plan.warnings, ())

    def test_each_requested_specialist_owns_exactly_one_work_item(self) -> None:
        specialist_items = self.items_of_kind(
            self.build(),
            WorkItemKind.SPECIALIST_ANALYSIS,
        )

        owners = tuple(item.owner_profile_id for item in specialist_items)
        self.assertEqual(
            set(owners),
            set(self.mission.requested_specialist_ids),
        )
        for specialist_id in self.mission.requested_specialist_ids:
            self.assertEqual(owners.count(specialist_id), 1)

    def test_domain_and_group_dependencies_follow_registry_hierarchy(self) -> None:
        plan = self.build()
        profiles = self.registry.profiles_by_id
        specialist_items = {
            item.owner_profile_id: item
            for item in self.items_of_kind(
                plan,
                WorkItemKind.SPECIALIST_ANALYSIS,
            )
        }
        domain_items = {
            item.command_id: item
            for item in self.items_of_kind(
                plan,
                WorkItemKind.DOMAIN_SYNTHESIS,
            )
        }
        group_items = {
            item.group_id: item
            for item in self.items_of_kind(
                plan,
                WorkItemKind.GROUP_INTEGRATION,
            )
        }
        command_ids = {
            profiles[profile_id].command_id
            for profile_id in self.mission.requested_specialist_ids
        }
        group_ids = {
            self.registry.commands_by_id[command_id].group_id
            for command_id in command_ids
            if command_id is not None
        }

        self.assertEqual(set(domain_items), command_ids)
        self.assertEqual(set(group_items), group_ids)
        self.assertEqual(
            {item.owner_profile_id for item in domain_items.values()},
            set(self.cell.domain_commander_profile_ids),
        )
        self.assertEqual(
            {item.owner_profile_id for item in group_items.values()},
            set(self.cell.group_commander_profile_ids),
        )

        for command_id, item in domain_items.items():
            self.assertIsNotNone(command_id)
            command = self.registry.commands_by_id[command_id]
            selected = {
                profile_id
                for profile_id in self.mission.requested_specialist_ids
                if profiles[profile_id].command_id == command_id
            }
            self.assertEqual(item.owner_profile_id, command.commander_profile_id)
            self.assertEqual(
                set(item.dependency_ids),
                {
                    specialist_items[profile_id].work_item_id
                    for profile_id in selected
                },
            )
            self.assertEqual(
                set(item.supporting_profile_ids),
                selected | {"AOE-HQ-11"},
            )
            self.assertEqual(item.group_id, command.group_id)

        for group_id, item in group_items.items():
            self.assertIsNotNone(group_id)
            group = self.registry.groups_by_id[group_id]
            represented_commands = {
                command_id
                for command_id in command_ids
                if command_id is not None
                and self.registry.commands_by_id[command_id].group_id
                == group_id
            }
            self.assertEqual(item.owner_profile_id, group.commander_profile_id)
            self.assertEqual(
                set(item.dependency_ids),
                {
                    domain_items[command_id].work_item_id
                    for command_id in represented_commands
                },
            )
            self.assertEqual(
                set(item.supporting_profile_ids),
                {
                    self.registry.commands_by_id[
                        command_id
                    ].commander_profile_id
                    for command_id in represented_commands
                }
                | {"AOE-HQ-10"},
            )

    def test_every_assembled_profile_has_a_collaboration_assignment(self) -> None:
        cell_profile_ids = set(self.cell.all_profile_ids)
        referenced_profile_ids: set[str] = set()

        for item in self.build().work_items:
            with self.subTest(work_item_id=item.work_item_id):
                self.assertIn(item.owner_profile_id, cell_profile_ids)
                self.assertLessEqual(
                    set(item.supporting_profile_ids),
                    cell_profile_ids,
                )
                referenced_profile_ids.add(item.owner_profile_id)
                referenced_profile_ids.update(item.supporting_profile_ids)
        self.assertEqual(referenced_profile_ids, cell_profile_ids)

    def test_control_support_ignores_poisoned_specialist_tags(self) -> None:
        specialist_id = self.mission.requested_specialist_ids[0]
        profiles = tuple(
            replace(
                profile,
                category="independent control",
                tags=tuple(
                    sorted(
                        set(profile.tags)
                        | {"independent-control"}
                    )
                ),
            )
            if profile.id == specialist_id
            else profile
            for profile in self.registry.profiles
        )
        poisoned_registry = replace(
            self.registry,
            profiles=profiles,
        )
        poisoned_registry.validate()

        plan = build_collaboration_plan(
            poisoned_registry,
            self.mission,
        )
        control = self.items_of_kind(
            plan,
            WorkItemKind.CONTROL_REVIEW,
        )[0]
        validate_collaboration_plan(
            poisoned_registry,
            self.mission,
            plan,
        )

        self.assertNotIn(
            specialist_id,
            control.supporting_profile_ids,
        )

    def test_fixed_review_owners_require_their_declared_roles(self) -> None:
        for profile_id in ("AOE-HQ-12", "AOE-HQ-18", "AOE-HQ-19"):
            with self.subTest(profile_id=profile_id):
                profiles = tuple(
                    replace(
                        profile,
                        category="mission operations",
                        tags=("shared", "mission-operations"),
                    )
                    if profile.id == profile_id
                    else profile
                    for profile in self.registry.profiles
                )
                poisoned_registry = replace(
                    self.registry,
                    profiles=profiles,
                )
                poisoned_registry.validate()

                with self.assertRaisesRegex(
                    CollaborationPlanError,
                    "invalid semantics",
                ):
                    build_collaboration_plan(
                        poisoned_registry,
                        self.mission,
                    )

    def test_fixed_review_owners_require_their_policy_templates(self) -> None:
        for profile_id in ("AOE-HQ-12", "AOE-HQ-18", "AOE-HQ-19"):
            with self.subTest(profile_id=profile_id):
                profiles = tuple(
                    replace(
                        profile,
                        policy_template="shared-v1",
                    )
                    if profile.id == profile_id
                    else profile
                    for profile in self.registry.profiles
                )
                poisoned_registry = replace(
                    self.registry,
                    profiles=profiles,
                )
                poisoned_registry.validate()

                with self.assertRaisesRegex(
                    CollaborationPlanError,
                    "invalid semantics",
                ):
                    build_collaboration_plan(
                        poisoned_registry,
                        self.mission,
                    )

    def test_control_and_assurance_are_independently_owned(self) -> None:
        plan = self.build()
        control = self.items_of_kind(
            plan,
            WorkItemKind.CONTROL_REVIEW,
        )[0]
        evidence = self.items_of_kind(
            plan,
            WorkItemKind.EVIDENCE_REVIEW,
        )[0]
        assurance = self.items_of_kind(
            plan,
            WorkItemKind.ASSURANCE_REVIEW,
        )[0]
        execution_owners = {
            item.owner_profile_id
            for item in plan.work_items
            if item.kind
            in {
                WorkItemKind.SPECIALIST_ANALYSIS,
                WorkItemKind.DOMAIN_SYNTHESIS,
                WorkItemKind.GROUP_INTEGRATION,
                WorkItemKind.CROSS_SURFACE_INTEGRATION,
            }
        }

        self.assertEqual(control.owner_profile_id, "AOE-HQ-12")
        self.assertEqual(assurance.owner_profile_id, "AOE-HQ-19")
        self.assertNotEqual(
            control.owner_profile_id,
            assurance.owner_profile_id,
        )
        self.assertNotIn(
            control.owner_profile_id,
            assurance.supporting_profile_ids,
        )
        self.assertNotIn(
            assurance.owner_profile_id,
            control.supporting_profile_ids,
        )
        self.assertNotIn(control.owner_profile_id, execution_owners)
        self.assertNotIn(assurance.owner_profile_id, execution_owners)
        self.assertEqual(
            set(assurance.dependency_ids),
            {control.work_item_id, evidence.work_item_id},
        )

    def test_specialist_work_respects_example_tier_and_evidence(self) -> None:
        for item in self.items_of_kind(
            self.build(),
            WorkItemKind.SPECIALIST_ANALYSIS,
        ):
            with self.subTest(work_item_id=item.work_item_id):
                self.assertIs(item.action_tier_ceiling, ActionTier.R2)
                self.assertIs(
                    item.required_evidence_level,
                    EvidenceLevel.E3,
                )

    def test_plan_has_stable_provenance_hashes_and_identifiers(self) -> None:
        plan = self.build()

        self.assertEqual(
            plan.registry_sha256,
            canonical_sha256(self.registry.to_dict()),
        )
        raw_registry = json.loads(
            REGISTRY_PATH.read_text(encoding="utf-8")
        )
        self.assertEqual(
            plan.registry_sha256,
            canonical_sha256(raw_registry),
        )
        self.assertEqual(
            plan.mission_sha256,
            canonical_sha256(self.mission.to_dict()),
        )
        self.assertEqual(
            plan.joint_mission_cell_sha256,
            canonical_sha256(self.cell.to_dict()),
        )
        self.assertEqual(
            plan.content_sha256,
            canonical_sha256(plan.unsigned_dict()),
        )
        self.assertEqual(plan.plan_id, EXPECTED_PLAN_ID)
        self.assertEqual(plan.registry_sha256, EXPECTED_REGISTRY_SHA256)
        self.assertEqual(plan.mission_sha256, EXPECTED_MISSION_SHA256)
        self.assertEqual(
            plan.joint_mission_cell_sha256,
            EXPECTED_CELL_SHA256,
        )
        self.assertEqual(plan.content_sha256, EXPECTED_CONTENT_SHA256)
        self.assertEqual(
            plan.mission_objective,
            self.mission.objective,
        )

    def test_work_item_identity_is_local_to_a_content_bound_plan(self) -> None:
        original = self.build()
        revised_mission = replace(
            self.mission,
            objective=(
                "Review a different common objective with the same "
                "mission ID and specialist set."
            ),
        )
        revised = build_collaboration_plan(
            self.registry,
            revised_mission,
        )

        self.assertNotEqual(original.plan_id, revised.plan_id)
        self.assertNotEqual(
            original.content_sha256,
            revised.content_sha256,
        )
        self.assertEqual(
            tuple(item.work_item_id for item in original.work_items),
            tuple(item.work_item_id for item in revised.work_items),
        )
        self.assertNotEqual(
            original.mission_objective,
            revised.mission_objective,
        )

    def test_plan_preserves_valid_multiline_and_long_mission_text(self) -> None:
        objective = "Primary objective\n" + ("A" * 4097)
        scope_reference = "scope://reviewed/multiline\r\n" + ("B" * 2049)
        mission_raw = self.mission.to_dict()
        mission_raw["objective"] = objective
        mission_raw["scope_reference"] = scope_reference
        mission = MissionRequest.from_dict(mission_raw)

        plan = build_collaboration_plan(self.registry, mission)

        self.assertEqual(plan.mission_objective, objective)
        self.assertEqual(plan.scope_reference, scope_reference)
        self.assertEqual(CollaborationPlan.from_dict(plan.to_dict()), plan)
        validate_collaboration_plan(self.registry, mission, plan)

    def test_plan_preserves_valid_multiline_and_long_registry_text(self) -> None:
        selected_id = self.mission.requested_specialist_ids[0]
        selected_profile = self.registry.profile(selected_id)
        self.assertIsNotNone(selected_profile.command_id)
        registry_raw = copy.deepcopy(self.registry.to_dict())
        registry_raw["catalog_id"] = "SUNDERKEY\nCATALOG"
        registry_raw["catalog_version"] = "1.0\r\nreviewed"
        for profile in registry_raw["profiles"]:
            if profile["id"] == selected_id:
                profile["name"] = "Specialist\ncontinued"
                profile["mission"] = "Role mission\n" + ("C" * 4097)
                break
        for command in registry_raw["commands"]:
            if command["id"] == selected_profile.command_id:
                command["name"] = "Command\ncontinued"
                command["mission"] = "Command mission\r\ncontinued"
                command["outputs"] = "Domain output\n" + ("D" * 4097)
                break
        registry = ExpertRegistry.from_dict(registry_raw)

        plan = build_collaboration_plan(registry, self.mission)
        specialist_item = next(
            item
            for item in plan.work_items
            if item.owner_profile_id == selected_id
        )
        domain_item = next(
            item
            for item in plan.work_items
            if item.command_id == selected_profile.command_id
            and item.kind is WorkItemKind.DOMAIN_SYNTHESIS
        )

        self.assertEqual(plan.registry_catalog_id, "SUNDERKEY\nCATALOG")
        self.assertEqual(plan.registry_catalog_version, "1.0\r\nreviewed")
        self.assertIn("\n", specialist_item.title)
        self.assertGreater(len(specialist_item.role_mission), 4096)
        self.assertIn("\r\n", domain_item.role_mission)
        self.assertGreater(len(domain_item.deliverable), 4096)
        self.assertEqual(CollaborationPlan.from_dict(plan.to_dict()), plan)
        validate_collaboration_plan(registry, self.mission, plan)

    def test_direct_source_dataclasses_are_revalidated_strictly(self) -> None:
        invalid_missions = (
            replace(self.mission, schema_version=True),
            replace(self.mission, schema_version=1.0),
            replace(self.mission, schema_version=2),
            replace(
                self.mission,
                requested_specialist_ids=(
                    self.mission.requested_specialist_ids[0],
                    self.mission.requested_specialist_ids[0],
                ),
            ),
        )
        for mission in invalid_missions:
            with (
                self.subTest(mission=mission),
                self.assertRaises(CollaborationPlanError),
            ):
                build_collaboration_plan(self.registry, mission)

        invalid_registries = (
            replace(self.registry, schema_version=True),
            replace(self.registry, schema_version=1.0),
            replace(self.registry, schema_version=2),
        )
        for registry in invalid_registries:
            with (
                self.subTest(registry=registry.schema_version),
                self.assertRaises(CollaborationPlanError),
            ):
                build_collaboration_plan(registry, self.mission)

    def test_unknown_fields_are_rejected_at_both_contract_levels(self) -> None:
        top_level = self.build().to_dict()
        top_level["unsupported"] = "value"
        with self.assertRaisesRegex(
            CollaborationPlanError,
            "unsupported fields",
        ):
            CollaborationPlan.from_dict(top_level)

        nested = self.build().to_dict()
        nested["work_items"][0]["unsupported"] = "value"
        with self.assertRaisesRegex(
            CollaborationPlanError,
            "unsupported fields",
        ):
            CollaborationPlan.from_dict(nested)

    def test_bool_and_float_integer_fields_are_rejected(self) -> None:
        cases = (
            ("plan schema bool", ("schema_version",), True),
            ("plan schema float", ("schema_version",), 1.0),
            (
                "work schema bool",
                ("work_items", 0, "schema_version"),
                True,
            ),
            (
                "work schema float",
                ("work_items", 0, "schema_version"),
                1.0,
            ),
            ("work layer bool", ("work_items", 0, "layer"), True),
            ("work layer float", ("work_items", 0, "layer"), 0.0),
        )
        for label, path, invalid in cases:
            with self.subTest(label=label):
                raw = self.build().to_dict()
                target: Any = raw
                for component in path[:-1]:
                    target = target[component]
                target[path[-1]] = invalid

                with self.assertRaises(CollaborationPlanError):
                    CollaborationPlan.from_dict(raw)

    def test_duplicate_ids_and_relationships_are_rejected(self) -> None:
        duplicate_item = self.build().to_dict()
        duplicate_item["work_items"].append(
            copy.deepcopy(duplicate_item["work_items"][0])
        )
        with self.assertRaisesRegex(
            CollaborationPlanError,
            "duplicate work_item_id",
        ):
            CollaborationPlan.from_dict(duplicate_item)

        duplicate_support = self.build().to_dict()
        specialist = duplicate_support["work_items"][1]
        specialist["supporting_profile_ids"].append(
            specialist["supporting_profile_ids"][0]
        )
        with self.assertRaisesRegex(CollaborationPlanError, "duplicates"):
            CollaborationPlan.from_dict(duplicate_support)

        duplicate_dependency = self.build().to_dict()
        specialist = duplicate_dependency["work_items"][1]
        specialist["dependency_ids"].append(
            specialist["dependency_ids"][0]
        )
        with self.assertRaisesRegex(CollaborationPlanError, "duplicates"):
            CollaborationPlan.from_dict(duplicate_dependency)

    def test_owner_cannot_also_be_a_supporter(self) -> None:
        raw = self.build().to_dict()
        specialist = raw["work_items"][1]
        specialist["supporting_profile_ids"].append(
            specialist["owner_profile_id"]
        )

        with self.assertRaisesRegex(
            CollaborationPlanError,
            "owner cannot also be a supporting profile",
        ):
            CollaborationPlan.from_dict(raw)

    def test_unknown_and_self_dependencies_are_rejected(self) -> None:
        unknown = self.build().to_dict()
        unknown["work_items"][1]["dependency_ids"] = [
            "WIT-UNKNOWN-0000000000000000"
        ]
        with self.assertRaisesRegex(
            CollaborationPlanError,
            "unknown dependencies",
        ):
            CollaborationPlan.from_dict(unknown)

        self_dependency = self.build().to_dict()
        readiness = self_dependency["work_items"][0]
        readiness["dependency_ids"] = [readiness["work_item_id"]]
        with self.assertRaisesRegex(
            CollaborationPlanError,
            "cannot depend on itself",
        ):
            CollaborationPlan.from_dict(self_dependency)

    def test_dependency_cycles_are_rejected(self) -> None:
        raw = self.build().to_dict()
        readiness = raw["work_items"][0]
        assurance = raw["work_items"][-1]
        readiness["dependency_ids"] = [assurance["work_item_id"]]

        with self.assertRaisesRegex(
            CollaborationPlanError,
            "contains a cycle",
        ):
            CollaborationPlan.from_dict(raw)

    def test_semantic_tampering_with_recalculated_hash_is_rejected(self) -> None:
        raw = self.build().to_dict()
        specialists = [
            item
            for item in raw["work_items"]
            if item["kind"] == WorkItemKind.SPECIALIST_ANALYSIS.value
        ]
        specialists[0]["owner_profile_id"] = specialists[1][
            "owner_profile_id"
        ]
        recalculate_content_hash(raw)

        tampered = CollaborationPlan.from_dict(raw)
        self.assertEqual(
            tampered.content_sha256,
            canonical_sha256(tampered.unsigned_dict()),
        )
        with self.assertRaisesRegex(
            CollaborationPlanError,
            "does not match the registry and mission",
        ):
            validate_collaboration_plan(
                self.registry,
                self.mission,
                tampered,
            )

    def test_planning_does_not_change_store_schema_or_create_state(self) -> None:
        self.assertEqual(STORE_SCHEMA_VERSION, 39)
        registry_before = asdict(self.registry)
        mission_before = self.mission.to_dict()

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_path = Path(temporary_directory)
            original_directory = Path.cwd()
            try:
                os.chdir(temporary_path)
                before = tuple(temporary_path.rglob("*"))
                first = self.build()
                second = self.build()
                after = tuple(temporary_path.rglob("*"))
            finally:
                os.chdir(original_directory)

        self.assertEqual(before, ())
        self.assertEqual(after, ())
        self.assertEqual(first, second)
        self.assertEqual(asdict(self.registry), registry_before)
        self.assertEqual(self.mission.to_dict(), mission_before)


if __name__ == "__main__":
    unittest.main()
