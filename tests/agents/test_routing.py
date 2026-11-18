from __future__ import annotations

import copy
import json
import unittest
from dataclasses import replace
from pathlib import Path

from sunderkey.errors import RoutingError
from sunderkey.registry import load_registry
from sunderkey.routing import (
    CapabilityCatalog,
    RoutingPolicy,
    RoutingRequest,
    load_capability_catalog,
    load_routing_policy,
    load_routing_request,
    route_mission,
)
from sunderkey.types import ProfileKind

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = ROOT / "registry" / "army-v1.json"
CAPABILITY_PATH = ROOT / "registry" / "capabilities-pilot-v1.json"
POLICY_PATH = ROOT / "registry" / "routing-policy-pilot-v1.json"
EXAMPLE_PATH = ROOT / "examples" / "routing" / "internet-api-to-data.json"
CAPABILITY_SCHEMA_PATH = (
    ROOT / "registry" / "schemas" / "capability-catalog.schema.json"
)
POLICY_SCHEMA_PATH = (
    ROOT / "registry" / "schemas" / "routing-policy.schema.json"
)
REQUEST_SCHEMA_PATH = (
    ROOT / "registry" / "schemas" / "routing-request.schema.json"
)


class CapabilityRoutingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)
        cls.catalog = load_capability_catalog(CAPABILITY_PATH, cls.registry)
        cls.policy = load_routing_policy(POLICY_PATH, cls.catalog)
        cls.example_raw = json.loads(EXAMPLE_PATH.read_text(encoding="utf-8"))

    def request_from_example(self, **mission_changes: object) -> RoutingRequest:
        raw = copy.deepcopy(self.example_raw)
        raw["mission"].update(mission_changes)
        return RoutingRequest.from_dict(raw)

    def test_catalog_maps_exactly_all_twenty_pilot_specialists(self) -> None:
        pilot_ids = {
            profile.id
            for profile in self.registry.profiles
            if profile.kind is ProfileKind.SPECIALIST and profile.pilot
        }
        assignment_ids = set(self.catalog.assignments_by_profile_id)

        self.assertEqual(len(pilot_ids), 20)
        self.assertEqual(assignment_ids, pilot_ids)
        self.assertTrue(
            all(
                self.registry.profiles_by_id[profile_id].status == "qualified"
                for profile_id in assignment_ids
            )
        )

    def test_example_routes_to_three_narrow_specialists(self) -> None:
        request = load_routing_request(EXAMPLE_PATH)
        decision = route_mission(
            self.registry,
            self.catalog,
            self.policy,
            request,
        )

        self.assertEqual(
            decision.selected_specialist_ids,
            (
                "AOE-GA-D03-S13",
                "AOE-GB-D06-S09",
                "AOE-GB-D07-S01",
            ),
        )
        self.assertEqual(
            decision.mission_request.requested_specialist_ids,
            decision.selected_specialist_ids,
        )
        self.assertEqual(decision.joint_mission_cell.size, 19)
        self.assertEqual(decision.status, "routed")
        self.assertEqual(decision.warnings, ())

    def test_output_is_bound_to_catalog_and_policy_versions(self) -> None:
        decision = route_mission(
            self.registry,
            self.catalog,
            self.policy,
            load_routing_request(EXAMPLE_PATH),
        )
        output = decision.to_dict()

        self.assertEqual(
            output["capability_catalog"],
            {
                "id": "sunderkey-pilot-capabilities",
                "version": "1.0.0",
                "sha256": self.catalog.canonical_sha256,
            },
        )
        self.assertEqual(
            output["routing_policy"],
            {
                "id": "sunderkey-pilot-qualified-routing",
                "version": "1.0.0",
                "sha256": self.policy.canonical_sha256,
            },
        )
        self.assertRegex(
            output["capability_catalog"]["sha256"],
            r"^sha256:[0-9a-f]{64}$",
        )
        self.assertRegex(
            output["routing_policy"]["sha256"],
            r"^sha256:[0-9a-f]{64}$",
        )
        self.assertEqual(
            output["mission_request"]["requested_specialist_ids"],
            list(decision.selected_specialist_ids),
        )
        self.assertEqual(
            output["joint_mission_cell"]["size"],
            decision.joint_mission_cell.size,
        )

    def test_required_capabilities_are_primary_when_primary_is_eligible(self) -> None:
        raw = copy.deepcopy(self.example_raw)
        raw["required_capability_ids"] = [
            "identity.authorization.rbac-abac-rebac"
        ]
        request = RoutingRequest.from_dict(raw)

        decision = route_mission(
            self.registry,
            self.catalog,
            self.policy,
            request,
        )

        self.assertEqual(
            decision.selected_specialist_ids,
            ("AOE-GA-D03-S13",),
        )
        coverage = decision.capability_coverage[0]
        self.assertEqual(coverage.matches[0].match_type, "primary")

    def test_supporting_match_is_used_only_when_primary_is_excluded(self) -> None:
        raw = copy.deepcopy(self.example_raw)
        raw["required_capability_ids"] = [
            "identity.authorization.rbac-abac-rebac"
        ]
        raw["excluded_specialist_ids"] = ["AOE-GA-D03-S13"]
        request = RoutingRequest.from_dict(raw)

        decision = route_mission(
            self.registry,
            self.catalog,
            self.policy,
            request,
        )

        self.assertEqual(
            decision.selected_specialist_ids,
            ("AOE-GB-D05-S12",),
        )
        self.assertEqual(
            decision.capability_coverage[0].matches[0].match_type,
            "supporting",
        )

    def test_preference_breaks_equal_supporting_match_rank(self) -> None:
        raw = copy.deepcopy(self.example_raw)
        raw["required_capability_ids"] = [
            "identity.authorization.rbac-abac-rebac"
        ]
        raw["excluded_specialist_ids"] = ["AOE-GA-D03-S13"]
        raw["preferred_specialist_ids"] = ["AOE-GB-D06-S09"]
        request = RoutingRequest.from_dict(raw)

        decision = route_mission(
            self.registry,
            self.catalog,
            self.policy,
            request,
        )

        self.assertEqual(
            decision.selected_specialist_ids,
            ("AOE-GB-D06-S09",),
        )

    def test_supporting_fallback_can_be_disabled_by_policy(self) -> None:
        raw = copy.deepcopy(self.example_raw)
        raw["required_capability_ids"] = [
            "identity.authorization.rbac-abac-rebac"
        ]
        raw["excluded_specialist_ids"] = ["AOE-GA-D03-S13"]
        request = RoutingRequest.from_dict(raw)
        policy = replace(self.policy, allow_supporting_matches=False)

        with self.assertRaisesRegex(RoutingError, "No eligible pilot specialist"):
            route_mission(
                self.registry,
                self.catalog,
                policy,
                request,
            )

    def test_disabled_supporting_matches_do_not_affect_scoring(self) -> None:
        raw = copy.deepcopy(self.example_raw)
        raw["required_capability_ids"] = ["data.relational-database"]
        raw["optional_capability_ids"] = [
            "identity.authorization.rbac-abac-rebac"
        ]
        request = RoutingRequest.from_dict(raw)
        assignments = tuple(
            replace(
                assignment,
                primary_capability_ids=tuple(
                    sorted(
                        assignment.primary_capability_ids
                        + ("data.relational-database",)
                    )
                ),
            )
            if assignment.profile_id == "AOE-GE-D23-S14"
            else assignment
            for assignment in self.catalog.profile_assignments
        )
        catalog = replace(self.catalog, profile_assignments=assignments)

        disabled = route_mission(
            self.registry,
            catalog,
            replace(self.policy, allow_supporting_matches=False),
            request,
        )
        enabled = route_mission(
            self.registry,
            catalog,
            replace(self.policy, allow_supporting_matches=True),
            request,
        )

        self.assertEqual(
            disabled.selected_specialist_ids,
            ("AOE-GB-D07-S01",),
        )
        self.assertTrue(
            all(
                step.score.optional_supporting_coverage == 0
                for step in disabled.selection_steps
            )
        )
        self.assertEqual(
            enabled.selected_specialist_ids,
            ("AOE-GE-D23-S14",),
        )
        self.assertEqual(
            enabled.selection_steps[0].score.optional_supporting_coverage,
            1,
        )

    def test_optional_capability_does_not_add_a_specialist(self) -> None:
        raw = copy.deepcopy(self.example_raw)
        raw["required_capability_ids"] = ["data.relational-database"]
        raw["optional_capability_ids"] = [
            "identity.authorization.rbac-abac-rebac"
        ]
        request = RoutingRequest.from_dict(raw)

        decision = route_mission(
            self.registry,
            self.catalog,
            self.policy,
            request,
        )

        self.assertEqual(
            decision.selected_specialist_ids,
            ("AOE-GB-D07-S01",),
        )
        optional = next(
            item
            for item in decision.capability_coverage
            if not item.required
        )
        self.assertEqual(optional.matches, ())

    def test_input_order_does_not_change_the_decision(self) -> None:
        first_raw = copy.deepcopy(self.example_raw)
        second_raw = copy.deepcopy(self.example_raw)
        second_raw["required_capability_ids"].reverse()

        first = route_mission(
            self.registry,
            self.catalog,
            self.policy,
            RoutingRequest.from_dict(first_raw),
        )
        second = route_mission(
            self.registry,
            self.catalog,
            self.policy,
            RoutingRequest.from_dict(second_raw),
        )

        self.assertEqual(first.to_dict(), second.to_dict())

    def test_objective_prose_does_not_change_selection(self) -> None:
        first_raw = copy.deepcopy(self.example_raw)
        second_raw = copy.deepcopy(self.example_raw)
        second_raw["mission"]["objective"] = (
            "Text is descriptive and is not a capability-routing input."
        )

        first = route_mission(
            self.registry,
            self.catalog,
            self.policy,
            RoutingRequest.from_dict(first_raw),
        )
        second = route_mission(
            self.registry,
            self.catalog,
            self.policy,
            RoutingRequest.from_dict(second_raw),
        )

        self.assertEqual(
            first.selected_specialist_ids,
            second.selected_specialist_ids,
        )
        self.assertEqual(first.selection_steps, second.selection_steps)

    def test_reordered_catalog_is_normalized(self) -> None:
        raw = json.loads(CAPABILITY_PATH.read_text(encoding="utf-8"))
        raw["capabilities"].reverse()
        raw["profile_assignments"].reverse()

        reordered = CapabilityCatalog.from_dict(raw, self.registry)

        self.assertEqual(reordered.capabilities, self.catalog.capabilities)
        self.assertEqual(
            reordered.profile_assignments,
            self.catalog.profile_assignments,
        )
        self.assertEqual(
            reordered.canonical_sha256,
            self.catalog.canonical_sha256,
        )

    def test_route_boundary_revalidates_direct_policy_objects(self) -> None:
        request = load_routing_request(EXAMPLE_PATH)
        invalid_policies = (
            (
                replace(self.policy, schema_version=2),
                "schema_version must be 1",
            ),
            (
                replace(self.policy, max_specialists=0),
                "must be a positive integer",
            ),
            (
                replace(
                    self.policy,
                    allowed_statuses=("qualified", "qualified"),
                ),
                "duplicate values",
            ),
        )

        for invalid_policy, message in invalid_policies:
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(RoutingError, message),
            ):
                route_mission(
                    self.registry,
                    self.catalog,
                    invalid_policy,
                    request,
                )

    def test_route_boundary_revalidates_direct_request_objects(self) -> None:
        request = load_routing_request(EXAMPLE_PATH)
        invalid_requests = (
            (
                replace(request, schema_version=2),
                "schema_version must be 1",
            ),
            (
                replace(request, required_capability_ids=()),
                "must not be empty",
            ),
            (
                replace(
                    request,
                    mission_template=replace(
                        request.mission_template,
                        schema_version=2,
                    ),
                ),
                "mission schema_version must be the integer 1",
            ),
            (
                replace(
                    request,
                    pinned_specialist_ids=("AOE-GB-D06-S09",),
                    excluded_specialist_ids=("AOE-GB-D06-S09",),
                ),
                "both pinned and excluded",
            ),
        )

        for invalid_request, message in invalid_requests:
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(RoutingError, message),
            ):
                route_mission(
                    self.registry,
                    self.catalog,
                    self.policy,
                    invalid_request,
                )

    def test_routing_request_constraint_defaults_match_runtime(self) -> None:
        raw = copy.deepcopy(self.example_raw)
        raw["mission"]["constraints"] = {}

        request = RoutingRequest.from_dict(raw)
        decision = route_mission(
            self.registry,
            self.catalog,
            self.policy,
            request,
        )

        self.assertFalse(request.mission_template.constraints.production)
        self.assertFalse(request.mission_template.constraints.third_party)
        self.assertFalse(
            request.mission_template.constraints.synthetic_data_only
        )
        self.assertFalse(
            request.mission_template.constraints.isolated_research_range
        )
        self.assertEqual(request.mission_template.constraints.max_cell_size, 20)
        self.assertEqual(decision.status, "routed")

    def test_routing_preserves_scope_document_hash(self) -> None:
        raw = copy.deepcopy(self.example_raw)
        expected = "sha256:" + ("b" * 64)
        raw["mission"]["scope_document_hash"] = expected

        request = RoutingRequest.from_dict(raw)
        decision = route_mission(
            self.registry,
            self.catalog,
            self.policy,
            request,
        )

        self.assertEqual(request.mission_template.scope_document_hash, expected)
        self.assertEqual(decision.mission_request.scope_document_hash, expected)
        self.assertEqual(
            decision.to_dict()["mission_request"]["scope_document_hash"],
            expected,
        )

    def test_non_semantic_versions_are_supported_consistently(self) -> None:
        catalog_raw = json.loads(CAPABILITY_PATH.read_text(encoding="utf-8"))
        catalog_raw["catalog_version"] = "pilot-v1"
        catalog = CapabilityCatalog.from_dict(catalog_raw, self.registry)
        policy_raw = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        policy_raw["policy_version"] = "pilot-v1"
        policy_raw["capability_catalog_version"] = "pilot-v1"

        policy = RoutingPolicy.from_dict(policy_raw, catalog)

        self.assertEqual(catalog.catalog_version, "pilot-v1")
        self.assertEqual(policy.policy_version, "pilot-v1")

    def test_routing_schemas_match_runtime_defaults_and_versions(self) -> None:
        capability_schema = json.loads(
            CAPABILITY_SCHEMA_PATH.read_text(encoding="utf-8")
        )
        policy_schema = json.loads(
            POLICY_SCHEMA_PATH.read_text(encoding="utf-8")
        )
        request_schema = json.loads(
            REQUEST_SCHEMA_PATH.read_text(encoding="utf-8")
        )

        self.assertEqual(
            capability_schema["properties"]["catalog_version"],
            {"$ref": "#/$defs/asciiText"},
        )
        self.assertEqual(
            capability_schema["properties"]["expert_catalog_version"],
            {"$ref": "#/$defs/asciiText"},
        )
        self.assertEqual(
            policy_schema["properties"]["policy_version"],
            {"$ref": "#/$defs/asciiText"},
        )
        self.assertEqual(
            policy_schema["properties"]["capability_catalog_version"],
            {"$ref": "#/$defs/asciiText"},
        )
        constraints = request_schema["$defs"]["missionTemplate"][
            "properties"
        ]["constraints"]
        self.assertNotIn("required", constraints)
        self.assertEqual(
            constraints["properties"]["production"]["default"],
            False,
        )
        self.assertEqual(
            constraints["properties"]["max_cell_size"]["default"],
            20,
        )

    def test_unknown_capability_fails_closed(self) -> None:
        raw = copy.deepcopy(self.example_raw)
        raw["required_capability_ids"] = ["api.unknown-capability"]
        request = RoutingRequest.from_dict(raw)

        with self.assertRaisesRegex(RoutingError, "unknown capabilities"):
            route_mission(
                self.registry,
                self.catalog,
                self.policy,
                request,
            )

    def test_empty_capabilities_do_not_trigger_prose_inference(self) -> None:
        raw = copy.deepcopy(self.example_raw)
        raw["required_capability_ids"] = []
        raw["mission"]["objective"] = "Test API object authorization."

        with self.assertRaisesRegex(RoutingError, "must not be empty"):
            RoutingRequest.from_dict(raw)

    def test_pinned_and_excluded_profile_conflict_is_rejected(self) -> None:
        raw = copy.deepcopy(self.example_raw)
        raw["pinned_specialist_ids"] = ["AOE-GB-D06-S09"]
        raw["excluded_specialist_ids"] = ["AOE-GB-D06-S09"]

        with self.assertRaisesRegex(RoutingError, "both pinned and excluded"):
            RoutingRequest.from_dict(raw)

    def test_policy_rejects_action_tier_above_pilot_autonomy(self) -> None:
        request = self.request_from_example(max_action_tier="R3")

        with self.assertRaisesRegex(RoutingError, "No eligible pilot specialist"):
            route_mission(
                self.registry,
                self.catalog,
                self.policy,
                request,
            )

    def test_policy_rejects_production_environment(self) -> None:
        raw = copy.deepcopy(self.example_raw)
        raw["mission"]["environment"] = "production"
        raw["mission"]["constraints"]["production"] = True
        raw["mission"]["constraints"]["synthetic_data_only"] = False
        request = RoutingRequest.from_dict(raw)

        with self.assertRaisesRegex(RoutingError, "not allowed by routing policy"):
            route_mission(
                self.registry,
                self.catalog,
                self.policy,
                request,
            )

    def test_effective_cell_size_is_a_hard_limit(self) -> None:
        raw = copy.deepcopy(self.example_raw)
        raw["required_capability_ids"] = ["data.relational-database"]
        request = RoutingRequest.from_dict(raw)
        policy = replace(self.policy, max_cell_size=13)

        with self.assertRaisesRegex(RoutingError, "cell-size limit"):
            route_mission(
                self.registry,
                self.catalog,
                policy,
                request,
            )

    def test_catalog_version_mismatch_fails_closed(self) -> None:
        catalog = replace(self.catalog, expert_catalog_version="9.0.0")

        with self.assertRaisesRegex(RoutingError, "does not match the registry"):
            route_mission(
                self.registry,
                catalog,
                self.policy,
                load_routing_request(EXAMPLE_PATH),
            )

    def test_routing_request_rejects_non_ascii_text(self) -> None:
        raw = copy.deepcopy(self.example_raw)
        raw["mission"]["objective"] += chr(0x200B)

        with self.assertRaisesRegex(RoutingError, "disallowed character"):
            RoutingRequest.from_dict(raw)


if __name__ == "__main__":
    unittest.main()
