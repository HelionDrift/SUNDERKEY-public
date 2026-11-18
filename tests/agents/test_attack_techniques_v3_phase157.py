"""Phase 157 infrastructure-independent attack-technique catalog v3 tests."""

from __future__ import annotations

import copy
import importlib.util
import json
import re
import unittest
from pathlib import Path

from sunderkey.attack_techniques_v3 import (
    CATALOG_DOMAIN,
    EFFECT_FIELDS,
    REFERENCE_PROFILES,
    AttackTechniqueCatalog,
    canonical_sha256,
    load_attack_technique_catalog_v3,
)
from sunderkey.errors import RegistryError

ROOT = Path(__file__).resolve().parents[2]
CATALOG_PATH = ROOT / "registry" / "attack-techniques-reference-v3.json"
SCHEMA_PATH = ROOT / "registry" / "schemas" / "attack-technique-catalog-v3.schema.json"
BUILDER_PATH = ROOT / "scripts" / "build_attack_techniques_v3.py"


def load_builder():
    spec = importlib.util.spec_from_file_location("build_attack_techniques_v3", BUILDER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load attack-technique builder")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rehash_technique(value: dict) -> None:
    value.pop("technique_sha256", None)
    value["technique_sha256"] = canonical_sha256(
        {"domain": f"{CATALOG_DOMAIN}.technique", "technique": value}
    )


def rehash_catalog(value: dict) -> None:
    value.pop("catalog_sha256", None)
    value["catalog_sha256"] = canonical_sha256({"domain": CATALOG_DOMAIN, "catalog": value})


class AttackTechniquesV3Phase157Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.builder = load_builder()
        cls.catalog = load_attack_technique_catalog_v3(CATALOG_PATH)
        cls.document = cls.catalog.to_dict()

    def test_checked_artifacts_match_deterministic_builder_and_schema(self) -> None:
        expected_catalog = self.builder.build_catalog()
        expected_schema = self.builder.build_schema()
        self.assertEqual(self.document, expected_catalog)
        self.assertEqual(
            CATALOG_PATH.read_text(encoding="utf-8"),
            json.dumps(expected_catalog, ensure_ascii=True, indent=2) + "\n",
        )
        self.assertEqual(
            SCHEMA_PATH.read_text(encoding="utf-8"),
            json.dumps(expected_schema, ensure_ascii=True, indent=2) + "\n",
        )
        try:
            from jsonschema import Draft202012Validator
        except ImportError:
            self.skipTest("jsonschema is not installed")
        Draft202012Validator.check_schema(expected_schema)
        Draft202012Validator(expected_schema).validate(self.document)

    def test_each_reference_profile_has_three_concrete_records(self) -> None:
        self.assertEqual(len(self.catalog.techniques), 18)
        self.assertEqual(self.catalog.coverage_summary["reference_profile_count"], 6)
        self.assertEqual(self.catalog.coverage_summary["unique_mechanic_count"], 18)
        for profile_id, _, vector_id, family in REFERENCE_PROFILES:
            records = [item for item in self.catalog.techniques if item.profile_id == profile_id]
            with self.subTest(profile_id=profile_id):
                self.assertEqual(len(records), 3)
                self.assertTrue(all(item.vector_id == vector_id for item in records))
                self.assertTrue(all(item.family == family for item in records))
                for item in records:
                    self.assertGreaterEqual(len(item.prerequisites), 2)
                    self.assertGreaterEqual(len(item.observables), 2)
                    self.assertGreaterEqual(len(item.safe_proof), 2)
                    self.assertGreaterEqual(len(item.negative_controls), 2)
                    self.assertGreaterEqual(len(item.cleanup_and_restoration), 2)
                    self.assertGreaterEqual(len(item.blind_spots), 2)

    def test_source_releases_are_pinned_and_mappings_are_primary(self) -> None:
        expected = {
            "iec-62443-3-3": "IEC 62443-3-3:2013",
            "mitre-attack-enterprise": "19.2",
            "owasp-api-security": "2023",
        }
        self.assertEqual(
            {item.source_id: item.source_version for item in self.catalog.standards_sources},
            expected,
        )
        for source in self.catalog.standards_sources:
            self.assertRegex(source.release_date, r"^20[0-9]{2}-[01][0-9]-[0-3][0-9]$")
            self.assertNotRegex(source.source_version.lower(), r"latest|current|rolling|stable")
        for technique in self.catalog.techniques:
            self.assertGreaterEqual(len(technique.standards_mappings), 1)

    def test_catalog_is_non_operational_and_contains_no_forbidden_markers(self) -> None:
        for field in EFFECT_FIELDS:
            self.assertEqual(self.document[field], "none")
        for technique in self.catalog.techniques:
            for field in EFFECT_FIELDS:
                self.assertEqual(getattr(technique, field), "none")
        rendered = CATALOG_PATH.read_text(encoding="utf-8")
        self.assertNotIn("\u2013", rendered)
        self.assertNotIn("\u2014", rendered)
        self.assertNotRegex(rendered, re.compile(r"\b(?:https?://)?(?:localhost|127\.0\.0\.1)\b"))

    def test_duplicate_ids_and_hash_drift_fail_closed(self) -> None:
        duplicate = copy.deepcopy(self.document)
        duplicate["techniques"].append(copy.deepcopy(duplicate["techniques"][0]))
        duplicate["coverage_summary"]["technique_count"] += 1
        duplicate["coverage_summary"]["mapped_technique_count"] += 1
        duplicate["coverage_summary"]["non_operational_technique_count"] += 1
        rehash_catalog(duplicate)
        with self.assertRaisesRegex(RegistryError, "IDs are not unique"):
            AttackTechniqueCatalog.from_dict(duplicate)

        drift = copy.deepcopy(self.document)
        drift["limitations"][0] = "Changed without updating the content address."
        with self.assertRaisesRegex(RegistryError, "hash does not match"):
            AttackTechniqueCatalog.from_dict(drift)

    def test_bad_mappings_and_missing_source_pins_fail_closed(self) -> None:
        bad_mapping = copy.deepcopy(self.document)
        bad_mapping["techniques"][0]["standards_mappings"][0]["reference_id"] = "T0000"
        rehash_technique(bad_mapping["techniques"][0])
        rehash_catalog(bad_mapping)
        with self.assertRaisesRegex(RegistryError, "mapping reference is invalid"):
            AttackTechniqueCatalog.from_dict(bad_mapping)

        missing_pin = copy.deepcopy(self.document)
        missing_pin["standards_sources"][0].pop("release_date")
        rehash_catalog(missing_pin)
        with self.assertRaisesRegex(RegistryError, "fields are invalid"):
            AttackTechniqueCatalog.from_dict(missing_pin)

        rolling = copy.deepcopy(self.document)
        rolling["standards_sources"][0]["source_version"] = "rolling"
        rehash_catalog(rolling)
        with self.assertRaisesRegex(RegistryError, "version is not pinned"):
            AttackTechniqueCatalog.from_dict(rolling)

        changed_pin = copy.deepcopy(self.document)
        for source in changed_pin["standards_sources"]:
            if source["source_id"] == "mitre-attack-enterprise":
                source["source_version"] = "19.3"
        for technique in changed_pin["techniques"]:
            changed = False
            for mapping in technique["standards_mappings"]:
                if mapping["source_id"] == "mitre-attack-enterprise":
                    mapping["source_version"] = "19.3"
                    changed = True
            if changed:
                rehash_technique(technique)
        rehash_catalog(changed_pin)
        with self.assertRaisesRegex(RegistryError, "source pin is invalid"):
            AttackTechniqueCatalog.from_dict(changed_pin)

    def test_generic_repeated_mechanics_and_invalid_effects_fail_closed(self) -> None:
        repeated = copy.deepcopy(self.document)
        repeated["techniques"][1]["mechanic"] = repeated["techniques"][0]["mechanic"]
        rehash_technique(repeated["techniques"][1])
        rehash_catalog(repeated)
        with self.assertRaisesRegex(RegistryError, "generic repeated mechanics"):
            AttackTechniqueCatalog.from_dict(repeated)

        invalid_effect = copy.deepcopy(self.document)
        invalid_effect["techniques"][0]["execution_effect"] = "execute"
        rehash_technique(invalid_effect["techniques"][0])
        rehash_catalog(invalid_effect)
        with self.assertRaisesRegex(RegistryError, "effect fields must all be none"):
            AttackTechniqueCatalog.from_dict(invalid_effect)


if __name__ == "__main__":
    unittest.main()
