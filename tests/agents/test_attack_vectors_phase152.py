"""Phase 152 Army v2 attack-vector taxonomy coverage."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from scripts.build_attack_vector_catalog_v2 import build_catalog, load_json
from sunderkey.army_expansion import load_army_expansion_roadmap
from sunderkey.attack_vectors import AttackVectorCatalog, load_attack_vector_catalog
from sunderkey.errors import RegistryError
from sunderkey.registry import load_registry

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_DIR = ROOT / "registry"
ARMY_PATH = REGISTRY_DIR / "army-v2.json"
ROADMAP_PATH = REGISTRY_DIR / "army-expansion-roadmap-v1.json"
CATALOG_PATH = REGISTRY_DIR / "attack-vectors-v2.json"
SCHEMA_PATH = REGISTRY_DIR / "schemas" / "attack-vector-catalog-v2.schema.json"


class AttackVectorsPhase152Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(ARMY_PATH)
        cls.roadmap = load_army_expansion_roadmap(ROADMAP_PATH)
        cls.catalog = load_attack_vector_catalog(
            CATALOG_PATH,
            cls.registry,
            cls.roadmap,
        )
        cls.vectors = {item.vector_id: item for item in cls.catalog.vectors}

    def test_checked_catalog_matches_deterministic_builder(self) -> None:
        raw = build_catalog(load_json(ARMY_PATH), load_json(ROADMAP_PATH))
        expected = AttackVectorCatalog.from_dict(raw, self.registry, self.roadmap)
        self.assertEqual(self.catalog, expected)
        self.assertEqual(
            CATALOG_PATH.read_text(encoding="utf-8"),
            json.dumps(expected.to_dict(), ensure_ascii=True, indent=2) + "\n",
        )

    def test_every_specialist_has_one_primary_vector_and_collaborators(self) -> None:
        self.assertEqual(len(self.catalog.vectors), 391)
        primary_ids = [item.primary_specialist_id for item in self.catalog.vectors]
        self.assertEqual(len(primary_ids), len(set(primary_ids)))
        self.assertEqual(self.catalog.coverage_summary["specialists_without_primary_vector"], 0)
        for vector in self.catalog.vectors:
            with self.subTest(vector=vector.vector_id):
                self.assertGreaterEqual(len(vector.supporting_specialist_ids), 1)
                self.assertNotIn(vector.primary_specialist_id, vector.supporting_specialist_ids)
                self.assertGreaterEqual(len(vector.standards_mappings), 1)

    def test_exact_api_and_agentic_crosswalks_are_narrow(self) -> None:
        bola = self.vectors["AV-GB-D06-S09-01"].standards_mappings[0]
        self.assertEqual(bola.source_id, "owasp-api-security")
        self.assertEqual(bola.reference_id, "API1:2023")
        self.assertEqual(bola.relationship, "exact_risk")

        goal_hijack = self.vectors["AV-GD-D20-S19-01"].standards_mappings[0]
        self.assertEqual(goal_hijack.source_id, "owasp-agentic")
        self.assertEqual(goal_hijack.source_version, "2026")
        self.assertEqual(goal_hijack.reference_id, "ASI01")
        self.assertEqual(goal_hijack.relationship, "exact_risk")

        broad_connector = self.vectors["AV-GB-D06-S16-01"].standards_mappings[0]
        self.assertEqual(broad_connector.relationship, "related_technique")
        self.assertEqual(self.catalog.coverage_summary["exact_external_mapping_count"], 10)

    def test_contextual_attack_mappings_do_not_claim_exact_techniques(self) -> None:
        passive_osint = self.vectors["AV-GA-D01-S01-01"].standards_mappings[0]
        self.assertEqual(passive_osint.source_id, "mitre-attack")
        self.assertEqual(passive_osint.reference_id, "enterprise:TA0043")
        self.assertEqual(passive_osint.relationship, "contextual_tactic")
        self.assertIn("not claimed", passive_osint.rationale)

    def test_high_consequence_vectors_bind_restoration_validation(self) -> None:
        for vector_id in (
            "AV-GD-D19-S19-01",
            "AV-GD-D24-S06-01",
            "AV-GD-D25-S11-01",
        ):
            with self.subTest(vector=vector_id):
                vector = self.vectors[vector_id]
                self.assertEqual(vector.independent_validator_id, "AOE-HQ-33")
                self.assertTrue(
                    any("AOE-HQ-33" in item for item in vector.cleanup_and_restoration)
                )

    def test_action_tiers_cannot_exceed_profile_limits(self) -> None:
        vector = self.vectors["AV-GD-D25-S12-01"]
        profile = self.registry.profiles_by_id[vector.primary_specialist_id]
        self.assertEqual(profile.max_autonomous_tier.value, "R2")
        self.assertEqual(vector.allowed_action_tiers, ("R0", "R1", "R2"))

    def test_catalog_is_schema_valid_content_addressed_and_non_operational(self) -> None:
        document = self.catalog.to_dict()
        self.assertEqual(
            self.catalog.catalog_sha256,
            "sha256:a153f425076b03adc015fbee20a938add68cc4af3202741534327a61706e1b1b",
        )
        self.assertEqual(document["catalog_status"], "coverage_anchor_baseline")
        self.assertEqual(document["operational_effect"], "none")
        if Draft202012Validator is not None:
            schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
            Draft202012Validator(schema).validate(document)

    def test_tampered_hash_source_version_and_self_support_fail_closed(self) -> None:
        changed = copy.deepcopy(self.catalog.to_dict())
        changed["limitations"][0] = "Changed limitation"
        with self.assertRaisesRegex(RegistryError, "hash does not match"):
            AttackVectorCatalog.from_dict(changed, self.registry, self.roadmap)

        changed = copy.deepcopy(self.catalog.to_dict())
        changed["vectors"][0]["standards_mappings"][0]["source_version"] = "0"
        with self.assertRaisesRegex(RegistryError, "version is unbound"):
            AttackVectorCatalog.from_dict(changed, self.registry, self.roadmap)

        changed = copy.deepcopy(self.catalog.to_dict())
        changed["vectors"][0]["supporting_specialist_ids"][0] = changed["vectors"][0][
            "primary_specialist_id"
        ]
        with self.assertRaisesRegex(RegistryError, "cannot support itself"):
            AttackVectorCatalog.from_dict(changed, self.registry, self.roadmap)


if __name__ == "__main__":
    unittest.main()
