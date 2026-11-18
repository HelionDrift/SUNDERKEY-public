"""Phase 154 vector-bound Army v2 qualification plan coverage."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from scripts.build_qualification_plans_v2 import (
    build_plan_schema,
    build_plans,
    build_standard,
    build_standard_schema,
    load_json,
)
from sunderkey.army_expansion import load_army_expansion_roadmap
from sunderkey.attack_vectors import load_attack_vector_catalog
from sunderkey.errors import QualificationError
from sunderkey.qualification import _canonical_sha256, load_qualification_standard
from sunderkey.qualification_plans_v2 import (
    CATALOG_DOMAIN,
    QualificationPlanCatalogV2,
    load_qualification_plan_catalog_v2,
)
from sunderkey.registry import load_registry
from sunderkey.routing import load_capability_catalog

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_DIR = ROOT / "registry"
REGISTRY_PATH = REGISTRY_DIR / "army-v2.json"
CAPABILITIES_PATH = REGISTRY_DIR / "capabilities-army-v2.json"
VECTORS_PATH = REGISTRY_DIR / "attack-vectors-v2.json"
ROADMAP_PATH = REGISTRY_DIR / "army-expansion-roadmap-v1.json"
STANDARD_SOURCE_PATH = REGISTRY_DIR / "qualification-standard-v1.json"
STANDARD_PATH = REGISTRY_DIR / "qualification-standard-v2.json"
STANDARD_SCHEMA_SOURCE_PATH = REGISTRY_DIR / "schemas" / "qualification-standard.schema.json"
STANDARD_SCHEMA_PATH = REGISTRY_DIR / "schemas" / "qualification-standard-v2.schema.json"
PLANS_PATH = REGISTRY_DIR / "qualification-plans-army-v2.json"
PLANS_SCHEMA_PATH = REGISTRY_DIR / "schemas" / "qualification-plan-catalog-v2.schema.json"


class QualificationPlansV2Phase154Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry_document = load_json(REGISTRY_PATH)
        cls.capabilities_document = load_json(CAPABILITIES_PATH)
        cls.vectors_document = load_json(VECTORS_PATH)
        cls.registry = load_registry(REGISTRY_PATH)
        cls.capabilities = load_capability_catalog(CAPABILITIES_PATH, cls.registry)
        cls.roadmap = load_army_expansion_roadmap(ROADMAP_PATH)
        cls.vectors = load_attack_vector_catalog(
            VECTORS_PATH,
            cls.registry,
            cls.roadmap,
        )
        cls.standard = load_qualification_standard(
            STANDARD_PATH,
            cls.registry,
            cls.capabilities,
        )
        cls.catalog = load_qualification_plan_catalog_v2(
            PLANS_PATH,
            cls.registry,
            cls.capabilities,
            cls.vectors,
            cls.standard,
        )

    def load_changed(self, document: dict[str, object]) -> None:
        document["catalog_sha256"] = _canonical_sha256(
            {
                "domain": CATALOG_DOMAIN,
                "catalog": {
                    key: value for key, value in document.items() if key != "catalog_sha256"
                },
            }
        )
        QualificationPlanCatalogV2.from_dict(
            document,
            self.registry,
            self.capabilities,
            self.vectors,
            self.standard,
        )

    def test_checked_artifacts_match_deterministic_builder(self) -> None:
        expected_standard = build_standard(
            load_json(STANDARD_SOURCE_PATH),
            self.registry_document,
            self.capabilities_document,
        )
        expected_plans = QualificationPlanCatalogV2.from_dict(
            build_plans(
                self.registry_document,
                self.capabilities_document,
                self.vectors_document,
                expected_standard,
            ),
            self.registry,
            self.capabilities,
            self.vectors,
            self.standard,
        )
        self.assertEqual(
            STANDARD_PATH.read_text(encoding="utf-8"),
            json.dumps(self.standard.to_dict(), ensure_ascii=True, indent=2) + "\n",
        )
        self.assertEqual(
            PLANS_PATH.read_text(encoding="utf-8"),
            json.dumps(expected_plans.to_dict(), ensure_ascii=True, indent=2) + "\n",
        )
        self.assertEqual(
            STANDARD_SCHEMA_PATH.read_text(encoding="utf-8"),
            json.dumps(
                build_standard_schema(load_json(STANDARD_SCHEMA_SOURCE_PATH)),
                ensure_ascii=True,
                indent=2,
            )
            + "\n",
        )
        self.assertEqual(
            PLANS_SCHEMA_PATH.read_text(encoding="utf-8"),
            json.dumps(build_plan_schema(), ensure_ascii=True, indent=2) + "\n",
        )

    def test_catalog_covers_every_specialist_without_qualification_effect(self) -> None:
        document = self.catalog.to_dict()
        self.assertEqual(len(document["profile_plans"]), 391)
        self.assertEqual(document["plan_status"], "defined_unexecuted")
        self.assertEqual(document["qualification_effect"], "none")
        self.assertEqual(
            document["catalog_sha256"],
            "sha256:9938bfb9e69b5f01ffa1716d288dedac2520d16cc50b6717485e4f692482de6c",
        )
        self.assertEqual(set(document["coverage_summary"].values()), {391})

    def test_api_plan_has_exact_vector_and_collaboration_bindings(self) -> None:
        plans = {item["profile_id"]: item for item in self.catalog.to_dict()["profile_plans"]}
        plan = plans["AOE-GB-D06-S09"]
        self.assertEqual(plan["vector_id"], "AV-GB-D06-S09-01")
        self.assertEqual(
            plan["primary_capability_ids"],
            ["api.authorization.object-level"],
        )
        self.assertEqual(
            plan["supporting_capability_ids"],
            ["api.authorization.function-level", "army.gb.d06.s08"],
        )
        self.assertEqual(plan["independent_validator_id"], "AOE-HQ-34")
        self.assertEqual(plan["allowed_action_tiers"], ["R0", "R1", "R2"])
        self.assertEqual(len(plan["required_scenario_variants"]), 6)
        self.assertEqual(len(plan["critical_failures"]), 7)

    def test_new_command_plans_bind_human_safety_and_restoration_control(self) -> None:
        plans = {item["profile_id"]: item for item in self.catalog.to_dict()["profile_plans"]}
        for profile_id in ("AOE-GD-D24-S06", "AOE-GD-D25-S01"):
            with self.subTest(profile=profile_id):
                plan = plans[profile_id]
                self.assertEqual(plan["independent_validator_id"], "AOE-HQ-33")
                self.assertTrue(
                    any("residual effects" in item for item in plan["cleanup_and_restoration"])
                )
                self.assertTrue(any("stop condition" in item for item in plan["critical_failures"]))

    def test_closed_schemas_accept_checked_artifacts(self) -> None:
        if Draft202012Validator is None:
            self.skipTest("jsonschema is not installed")
        Draft202012Validator(json.loads(STANDARD_SCHEMA_PATH.read_text(encoding="utf-8"))).validate(
            self.standard.to_dict()
        )
        Draft202012Validator(json.loads(PLANS_SCHEMA_PATH.read_text(encoding="utf-8"))).validate(
            self.catalog.to_dict()
        )

    def test_vector_support_and_validator_drift_fail_closed(self) -> None:
        for field, replacement in (
            ("vector_id", "AV-GA-D01-S02-01"),
            ("supporting_capability_ids", ["army.ga.d01.s04"]),
            ("independent_validator_id", "AOE-HQ-33"),
            ("allowed_action_tiers", ["R0"]),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.catalog.to_dict())
                changed["profile_plans"][0][field] = replacement
                with self.assertRaisesRegex(QualificationError, "not vector-bound"):
                    self.load_changed(changed)

    def test_evidence_and_critical_failure_drift_fail_closed(self) -> None:
        changed = copy.deepcopy(self.catalog.to_dict())
        changed["profile_plans"][0]["required_evidence"] = ["Unsupported evidence."]
        with self.assertRaisesRegex(QualificationError, "not vector-bound"):
            self.load_changed(changed)

        changed = copy.deepcopy(self.catalog.to_dict())
        changed["profile_plans"][0]["critical_failures"] = [
            "Failure one.",
            "Failure two.",
            "Failure three.",
            "Failure four.",
        ]
        with self.assertRaisesRegex(QualificationError, "lacks critical failures"):
            self.load_changed(changed)

    def test_reordering_and_stale_hash_fail_closed(self) -> None:
        changed = copy.deepcopy(self.catalog.to_dict())
        changed["profile_plans"][0], changed["profile_plans"][1] = (
            changed["profile_plans"][1],
            changed["profile_plans"][0],
        )
        with self.assertRaisesRegex(QualificationError, "do not cover"):
            self.load_changed(changed)

        changed = copy.deepcopy(self.catalog.to_dict())
        changed["limitations"][0] = "Changed limitation."
        with self.assertRaisesRegex(QualificationError, "hash does not match"):
            QualificationPlanCatalogV2.from_dict(
                changed,
                self.registry,
                self.capabilities,
                self.vectors,
                self.standard,
            )


if __name__ == "__main__":
    unittest.main()
