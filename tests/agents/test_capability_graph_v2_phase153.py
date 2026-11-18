"""Phase 153 Army v2 collaborative capability graph coverage."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from scripts.build_capability_graph_v2 import build_catalog, build_schema, load_json
from sunderkey.army_expansion import load_army_expansion_roadmap
from sunderkey.attack_vectors import load_attack_vector_catalog
from sunderkey.capability_graph_v2 import validate_capability_graph_v2
from sunderkey.errors import RoutingError
from sunderkey.registry import load_registry
from sunderkey.routing import CapabilityCatalog, load_capability_catalog

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_DIR = ROOT / "registry"
BASELINE_REGISTRY_PATH = REGISTRY_DIR / "army-v1.json"
REGISTRY_PATH = REGISTRY_DIR / "army-v2.json"
BASELINE_PATH = REGISTRY_DIR / "capabilities-army-v1.json"
TARGET_PATH = REGISTRY_DIR / "capabilities-army-v2.json"
VECTOR_PATH = REGISTRY_DIR / "attack-vectors-v2.json"
ROADMAP_PATH = REGISTRY_DIR / "army-expansion-roadmap-v1.json"
SCHEMA_SOURCE_PATH = REGISTRY_DIR / "schemas" / "capability-catalog.schema.json"
SCHEMA_PATH = REGISTRY_DIR / "schemas" / "capability-catalog-v2.schema.json"


class CapabilityGraphV2Phase153Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.baseline_registry = load_registry(BASELINE_REGISTRY_PATH)
        cls.registry = load_registry(REGISTRY_PATH)
        cls.baseline = load_capability_catalog(BASELINE_PATH, cls.baseline_registry)
        cls.target = load_capability_catalog(TARGET_PATH, cls.registry)
        cls.roadmap = load_army_expansion_roadmap(ROADMAP_PATH)
        cls.vectors = load_attack_vector_catalog(
            VECTOR_PATH,
            cls.registry,
            cls.roadmap,
        )
        cls.report = validate_capability_graph_v2(
            cls.baseline_registry,
            cls.baseline,
            cls.target,
            cls.registry,
            cls.vectors,
        )

    def test_checked_graph_and_schema_match_deterministic_builder(self) -> None:
        expected = CapabilityCatalog.from_dict(
            build_catalog(
                load_json(REGISTRY_PATH),
                load_json(BASELINE_PATH),
                load_json(VECTOR_PATH),
            ),
            self.registry,
        )
        self.assertEqual(
            TARGET_PATH.read_text(encoding="utf-8"),
            json.dumps(expected.to_dict(), ensure_ascii=True, indent=2) + "\n",
        )
        expected_schema = build_schema(load_json(SCHEMA_SOURCE_PATH))
        self.assertEqual(
            SCHEMA_PATH.read_text(encoding="utf-8"),
            json.dumps(expected_schema, ensure_ascii=True, indent=2) + "\n",
        )

    def test_graph_has_complete_primary_and_supporting_coverage(self) -> None:
        self.assertEqual(len(self.target.capabilities), 391)
        self.assertEqual(len(self.target.profile_assignments), 391)
        for assignment in self.target.profile_assignments:
            with self.subTest(profile=assignment.profile_id):
                self.assertEqual(len(assignment.primary_capability_ids), 1)
                self.assertEqual(len(assignment.supporting_capability_ids), 2)
                self.assertFalse(
                    set(assignment.primary_capability_ids)
                    & set(assignment.supporting_capability_ids)
                )

    def test_all_v1_capability_definitions_and_primaries_are_preserved(self) -> None:
        baseline_definitions = {
            item.id: item.to_dict() for item in self.baseline.capabilities
        }
        target_definitions = {item.id: item.to_dict() for item in self.target.capabilities}
        self.assertEqual(
            {item: target_definitions[item] for item in baseline_definitions},
            baseline_definitions,
        )
        for profile_id, assignment in self.baseline.assignments_by_profile_id.items():
            self.assertEqual(
                self.target.assignments_by_profile_id[profile_id].primary_capability_ids,
                assignment.primary_capability_ids,
            )

    def test_vector_collaboration_becomes_supporting_capability_edges(self) -> None:
        assignment = self.target.assignments_by_profile_id["AOE-GB-D06-S09"]
        self.assertEqual(assignment.primary_capability_ids, ("api.authorization.object-level",))
        self.assertEqual(
            assignment.supporting_capability_ids,
            ("api.authorization.function-level", "army.gb.d06.s08"),
        )

        restoration = self.target.assignments_by_profile_id["AOE-GD-D24-S06"]
        self.assertEqual(
            restoration.supporting_capability_ids,
            ("army.gd.d24.s05", "army.gd.d24.s07"),
        )

    def test_report_is_content_addressed_and_has_no_routing_effect(self) -> None:
        document = self.report.to_dict()
        self.assertEqual(document["report_id"], "CGR-A0E25CD81DB3E26C845B4F1B4284D181")
        self.assertEqual(document["preserved_capability_count"], 348)
        self.assertEqual(document["capability_count"], 391)
        self.assertEqual(document["supporting_edge_count"], 782)
        self.assertEqual(document["routing_policy_status"], "not_created")
        self.assertEqual(document["qualification_effect"], "none")
        self.assertEqual(document["routing_effect"], "none")
        self.assertEqual(document["execution_effect"], "none")

    def test_closed_schema_accepts_the_checked_graph(self) -> None:
        if Draft202012Validator is None:
            self.skipTest("jsonschema is not installed")
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(self.target.to_dict())

    def test_primary_mutation_and_support_edge_drift_fail_closed(self) -> None:
        changed = copy.deepcopy(self.target.to_dict())
        changed["profile_assignments"][0]["primary_capability_ids"] = [
            changed["profile_assignments"][1]["primary_capability_ids"][0]
        ]
        with self.assertRaises((RoutingError, KeyError)):
            candidate = CapabilityCatalog.from_dict(changed, self.registry)
            validate_capability_graph_v2(
                self.baseline_registry,
                self.baseline,
                candidate,
                self.registry,
                self.vectors,
            )

        changed = copy.deepcopy(self.target.to_dict())
        changed["profile_assignments"][0]["supporting_capability_ids"] = [
            "army.ga.d01.s04"
        ]
        candidate = CapabilityCatalog.from_dict(changed, self.registry)
        with self.assertRaisesRegex(RoutingError, "supporting edges"):
            validate_capability_graph_v2(
                self.baseline_registry,
                self.baseline,
                candidate,
                self.registry,
                self.vectors,
            )


if __name__ == "__main__":
    unittest.main()
