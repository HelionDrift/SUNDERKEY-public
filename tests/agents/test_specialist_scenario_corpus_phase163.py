"""Phase 163 deterministic specialist qualification scenario corpus tests."""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import sunderkey
import sunderkey.specialist_scenario_corpus as scenario_corpus_module

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.specialist_scenario_corpus import (
    CORPUS_DOMAIN,
    SOURCE_SPECS,
    VARIANT_DEFINITIONS,
    ScenarioCorpusLimits,
    SpecialistScenarioCorpusError,
    build_specialist_scenario_corpus,
    validate_specialist_scenario_corpus,
)

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_DIR = ROOT / "registry"
SCHEMA_PATH = REGISTRY_DIR / "schemas" / "specialist-scenario-corpus-v1.schema.json"


def canonical_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def rehash_catalog(document: dict[str, object], domain: str) -> None:
    body = copy.deepcopy(document)
    body.pop("catalog_sha256", None)
    document["catalog_sha256"] = canonical_sha256({"domain": domain, "catalog": body})


class SpecialistScenarioCorpusPhase163Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.corpus = build_specialist_scenario_corpus(REGISTRY_DIR)
        cls.document = cls.corpus.to_dict()

    def test_public_package_exports_are_available(self) -> None:
        self.assertIs(
            sunderkey.build_specialist_scenario_corpus,
            build_specialist_scenario_corpus,
        )
        self.assertIs(
            sunderkey.validate_specialist_scenario_corpus,
            validate_specialist_scenario_corpus,
        )

    def copy_sources(self, destination: Path) -> None:
        for _, artifact_name, _, _ in SOURCE_SPECS:
            shutil.copyfile(REGISTRY_DIR / artifact_name, destination / artifact_name)

    def test_current_sources_support_all_specialists_and_variants(self) -> None:
        coverage = self.document["coverage_summary"]
        self.assertEqual(coverage["specialist_profile_count"], 391)
        self.assertEqual(coverage["eligible_profile_count"], 391)
        self.assertEqual(coverage["gap_profile_count"], 0)
        self.assertEqual(coverage["required_variants_per_profile"], 6)
        self.assertEqual(coverage["expected_scenario_count"], 2346)
        self.assertEqual(coverage["scenario_count"], 2346)
        self.assertEqual(coverage["missing_scenario_count"], 0)
        self.assertEqual(coverage["gap_reason_counts"], {})
        self.assertTrue(coverage["complete"])
        self.assertEqual(self.document["corpus_status"], "complete")
        self.assertEqual(self.document["gaps"], [])

    def test_every_profile_has_each_variant_once(self) -> None:
        by_profile: dict[str, set[str]] = {}
        for scenario in self.document["scenarios"]:
            by_profile.setdefault(scenario["profile_id"], set()).add(scenario["variant_id"])
        expected = {item["variant_id"] for item in VARIANT_DEFINITIONS}
        self.assertEqual(len(by_profile), 391)
        self.assertTrue(all(variants == expected for variants in by_profile.values()))

    def test_api_negative_control_has_exact_reviewed_bindings(self) -> None:
        scenario = next(
            item
            for item in self.document["scenarios"]
            if item["profile_id"] == "AOE-GB-D06-S09" and item["variant_id"] == "negative_control"
        )
        self.assertEqual(scenario["vector_id"], "AV-GB-D06-S09-01")
        self.assertEqual(scenario["primary_capability_ids"], ["api.authorization.object-level"])
        self.assertEqual(
            scenario["supporting_capability_ids"],
            ["api.authorization.function-level", "army.gb.d06.s08"],
        )
        self.assertEqual(scenario["independent_validator_ids"], ["AOE-HQ-34"])
        self.assertEqual(
            scenario["commander_binding"],
            {
                "command_id": "AOE-GB-D06",
                "commander_profile_id": "AOE-GB-D06-CMD",
                "group_commander_profile_id": "AOE-HQ-04",
                "work_package_id": "IWP2-AOE-GB-D06-S09",
            },
        )
        self.assertEqual(
            scenario["action_tier"],
            {
                "allowed_action_tiers": ["R0", "R1", "R2"],
                "maximum_permitted_action_tier": "R2",
            },
        )
        self.assertIn(
            "qualification.proof.negative-control",
            scenario["safe_proof_identifiers"],
        )

    def test_source_hashes_are_exact_raw_and_canonical_bindings(self) -> None:
        bindings = self.document["source_bindings"]
        self.assertEqual([item["source_role"] for item in bindings], [x[0] for x in SOURCE_SPECS])
        for binding in bindings:
            payload = (REGISTRY_DIR / binding["artifact_name"]).read_bytes()
            self.assertEqual(
                binding["content_sha256"],
                f"sha256:{hashlib.sha256(payload).hexdigest()}",
            )
            self.assertEqual(
                binding["canonical_sha256"],
                canonical_sha256(json.loads(payload.decode("utf-8"))),
            )
        source_hashes = {item["source_role"]: item["content_sha256"] for item in bindings}
        self.assertTrue(
            all(
                scenario["source_binding_sha256s"] == source_hashes
                for scenario in self.document["scenarios"]
            )
        )

    def test_ids_are_unique_content_addresses_and_output_is_canonical(self) -> None:
        validate_specialist_scenario_corpus(self.document)
        scenario_ids = [item["scenario_id"] for item in self.document["scenarios"]]
        self.assertEqual(len(scenario_ids), len(set(scenario_ids)))
        self.assertEqual(
            self.corpus.document_json,
            json.dumps(
                self.document,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ),
        )
        body = dict(self.document)
        body.pop("corpus_id")
        body.pop("corpus_sha256")
        self.assertEqual(
            self.document["corpus_sha256"],
            canonical_sha256({"domain": CORPUS_DOMAIN, "corpus": body}),
        )

    def test_repeated_build_is_byte_identical(self) -> None:
        rebuilt = build_specialist_scenario_corpus(REGISTRY_DIR)
        self.assertEqual(rebuilt.corpus_id, self.corpus.corpus_id)
        self.assertEqual(rebuilt.corpus_sha256, self.corpus.corpus_sha256)
        self.assertEqual(rebuilt.document_json, self.corpus.document_json)

    def test_scenarios_are_non_operational_and_cannot_change_state(self) -> None:
        forbidden_fields = {
            "exploit_payload",
            "target_instruction",
            "credential",
            "endpoint",
            "request_template",
        }
        for scenario in self.document["scenarios"]:
            self.assertTrue(forbidden_fields.isdisjoint(scenario))
            self.assertEqual(scenario["qualification_effect"], "none")
            self.assertEqual(scenario["routing_effect"], "none")
            self.assertEqual(scenario["authority_effect"], "none")
            self.assertEqual(scenario["execution_effect"], "none")

    def test_valid_missing_plan_is_preserved_as_exact_gap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            self.copy_sources(temporary)

            plans_path = temporary / "qualification-plans-army-v2.json"
            plans = json.loads(plans_path.read_text(encoding="utf-8"))
            missing_profile = "AOE-GA-D01-S01"
            plans["profile_plans"] = [
                item for item in plans["profile_plans"] if item["profile_id"] != missing_profile
            ]
            rehash_catalog(plans, "sunderkey.qualification-plans-v2.v1")
            plans_path.write_text(json.dumps(plans, ensure_ascii=True, indent=2) + "\n")

            blueprints_path = temporary / "candidate-blueprints-army-v2.json"
            blueprints = json.loads(blueprints_path.read_text(encoding="utf-8"))
            blueprints["qualification_plan_catalog_sha256"] = plans["catalog_sha256"]
            rehash_catalog(blueprints, "sunderkey.candidate-blueprint-catalog.v2")
            blueprints_path.write_text(json.dumps(blueprints, ensure_ascii=True, indent=2) + "\n")

            packages_path = temporary / "implementation-work-packages-v2.json"
            packages = json.loads(packages_path.read_text(encoding="utf-8"))
            packages["qualification_plan_catalog_sha256"] = plans["catalog_sha256"]
            packages["blueprint_catalog_sha256"] = blueprints["catalog_sha256"]
            rehash_catalog(packages, "sunderkey.implementation-work-packages.v2")
            packages_path.write_text(json.dumps(packages, ensure_ascii=True, indent=2) + "\n")

            corpus = build_specialist_scenario_corpus(temporary).to_dict()
            self.assertEqual(corpus["corpus_status"], "gaps_preserved")
            self.assertEqual(corpus["coverage_summary"]["eligible_profile_count"], 390)
            self.assertEqual(corpus["coverage_summary"]["gap_profile_count"], 1)
            self.assertEqual(corpus["coverage_summary"]["scenario_count"], 2340)
            self.assertEqual(corpus["coverage_summary"]["missing_scenario_count"], 6)
            self.assertEqual(
                corpus["coverage_summary"]["gap_reason_counts"],
                {"missing_qualification_plan": 1},
            )
            self.assertEqual(
                corpus["gaps"],
                [
                    {
                        "profile_id": missing_profile,
                        "reason_codes": ["missing_qualification_plan"],
                    }
                ],
            )

    def test_tampered_declared_catalog_hash_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            self.copy_sources(temporary)
            vectors_path = temporary / "attack-vectors-v2.json"
            vectors = json.loads(vectors_path.read_text(encoding="utf-8"))
            vectors["vectors"][0]["description"] = "Tampered description."
            vectors_path.write_text(json.dumps(vectors, ensure_ascii=True, indent=2) + "\n")
            with self.assertRaisesRegex(
                SpecialistScenarioCorpusError,
                "declared catalog hash does not match content",
            ):
                build_specialist_scenario_corpus(temporary)

    def test_resource_limits_fail_before_corpus_generation(self) -> None:
        limits = ScenarioCorpusLimits(maximum_total_source_bytes=1)
        with self.assertRaisesRegex(SpecialistScenarioCorpusError, "exceed total byte limit"):
            build_specialist_scenario_corpus(REGISTRY_DIR, limits=limits)

    def test_source_read_rejects_nonregular_and_replaced_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.json"
            replacement = Path(directory) / "replacement.json"
            source.write_text("{}", encoding="utf-8")
            replacement.write_text("{}", encoding="utf-8")
            limits = ScenarioCorpusLimits(maximum_source_bytes=16)

            with patch.object(
                Path,
                "lstat",
                return_value=SimpleNamespace(st_mode=stat.S_IFIFO, st_size=0),
            ):
                with self.assertRaisesRegex(SpecialistScenarioCorpusError, "regular file"):
                    scenario_corpus_module._read_source(source, limits)

            original_open = scenario_corpus_module.os.open
            flags_seen: list[int] = []

            def open_replacement(path, flags, *args, **kwargs):
                flags_seen.append(flags)
                if Path(path) == source:
                    return original_open(replacement, flags, *args, **kwargs)
                return original_open(path, flags, *args, **kwargs)

            with patch.object(scenario_corpus_module.os, "open", side_effect=open_replacement):
                with self.assertRaisesRegex(SpecialistScenarioCorpusError, "changed while opening"):
                    scenario_corpus_module._read_source(source, limits)
            if getattr(scenario_corpus_module.os, "O_NONBLOCK", 0):
                self.assertTrue(flags_seen[0] & scenario_corpus_module.os.O_NONBLOCK)
            if getattr(scenario_corpus_module.os, "O_NOFOLLOW", 0):
                self.assertTrue(flags_seen[0] & scenario_corpus_module.os.O_NOFOLLOW)

    def test_source_read_is_bounded_and_detects_path_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.json"
            source.write_text("{}", encoding="utf-8")
            limits = ScenarioCorpusLimits(maximum_source_bytes=16)

            with patch.object(scenario_corpus_module.os, "open", side_effect=AssertionError):
                with self.assertRaisesRegex(SpecialistScenarioCorpusError, "exceeds byte limit"):
                    scenario_corpus_module._read_source(
                        source, ScenarioCorpusLimits(maximum_source_bytes=1)
                    )

            original_fdopen = scenario_corpus_module.os.fdopen

            def grow_before_read(descriptor, *args, **kwargs):
                with source.open("ab") as stream:
                    stream.write(b"x" * 40)
                return original_fdopen(descriptor, *args, **kwargs)

            with patch.object(scenario_corpus_module.os, "fdopen", side_effect=grow_before_read):
                with self.assertRaisesRegex(SpecialistScenarioCorpusError, "exceeds byte limit"):
                    scenario_corpus_module._read_source(source, limits)

            source.write_text("{}", encoding="utf-8")
            original_lstat = Path.lstat
            inspections = 0

            def changed_metadata(path, *args, **kwargs):
                nonlocal inspections
                metadata = original_lstat(path, *args, **kwargs)
                if Path(path) != source:
                    return metadata
                inspections += 1
                if inspections == 2:
                    return SimpleNamespace(
                        st_mode=metadata.st_mode,
                        st_dev=metadata.st_dev,
                        st_ino=metadata.st_ino,
                        st_size=metadata.st_size,
                        st_mtime_ns=metadata.st_mtime_ns + 1,
                    )
                return metadata

            with patch.object(Path, "lstat", side_effect=changed_metadata, autospec=True):
                with self.assertRaisesRegex(SpecialistScenarioCorpusError, "changed while reading"):
                    scenario_corpus_module._read_source(source, limits)

    def test_mutated_scenario_content_address_fails_validation(self) -> None:
        changed = copy.deepcopy(self.document)
        changed["scenarios"][0]["expected_disposition"] = "changed"
        with self.assertRaisesRegex(SpecialistScenarioCorpusError, "content address"):
            validate_specialist_scenario_corpus(changed)

    def test_closed_schema_accepts_generated_corpus(self) -> None:
        if Draft202012Validator is None:
            self.skipTest("jsonschema is not installed")
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(self.document)


if __name__ == "__main__":
    unittest.main()
