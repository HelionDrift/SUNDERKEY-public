"""Bounded consistency checks for the closed offline specialist registration."""

from __future__ import annotations

import ast
import json
import unittest
from collections import Counter
from pathlib import Path
from unittest.mock import patch

from sunderkey import offline_specialist_components as specialist


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "src/sunderkey/offline_specialist_components.py"
CATALOG = ROOT / specialist.CATALOG_PATH
PACKAGES = ROOT / "registry/implementation-work-packages-v2.json"


def _dispatch_branches() -> list[tuple[str, ast.If]]:
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "run_offline_specialist_component"
    )
    branches: list[tuple[str, ast.If]] = []
    for node in ast.walk(function):
        if not isinstance(node, ast.If) or not isinstance(node.test, ast.Compare):
            continue
        comparison = node.test
        if (
            isinstance(comparison.left, ast.Name)
            and comparison.left.id == "component_id"
            and len(comparison.ops) == 1
            and isinstance(comparison.ops[0], ast.Eq)
            and len(comparison.comparators) == 1
            and isinstance(comparison.comparators[0], ast.Constant)
            and isinstance(comparison.comparators[0].value, str)
        ):
            branches.append((comparison.comparators[0].value, node))
    return branches


class OfflineSpecialistRegistrationConsistencyTests(unittest.TestCase):
    def test_every_registered_component_has_one_imported_analysis_dispatch(self) -> None:
        tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        import_origins = {
            alias.asname or alias.name: f"src/sunderkey/{node.module}.py"
            for node in tree.body
            if isinstance(node, ast.ImportFrom) and node.level == 1 and node.module
            for alias in node.names
        }
        branches = _dispatch_branches()
        registered = {item[3]: item[4] for item in specialist.COMPONENTS}
        self.assertEqual(len(registered), len(specialist.COMPONENTS))
        self.assertEqual(Counter(component_id for component_id, _ in branches),
                         Counter({component_id: 1 for component_id in registered}))
        for component_id, branch in branches:
            with self.subTest(component_id=component_id):
                assignments = [
                    node for node in branch.body
                    if isinstance(node, ast.Assign)
                    and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)
                    and node.targets[0].id == "analysis"
                ]
                self.assertEqual(len(assignments), 1)
                call = assignments[0].value
                self.assertIsInstance(call, ast.Call)
                self.assertIsInstance(call.func, ast.Name)
                self.assertEqual(import_origins.get(call.func.id), registered[component_id])

    def test_catalog_descriptors_match_registration_and_work_packages(self) -> None:
        catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
        packages = json.loads(PACKAGES.read_text(encoding="utf-8"))["packages"]
        by_profile = {package["profile_id"]: package for package in packages}
        descriptors = catalog["components"]
        self.assertEqual(len(descriptors), len(specialist.COMPONENTS))
        self.assertEqual(len({item["component_id"] for item in descriptors}), len(descriptors))
        self.assertEqual(
            [item["component_id"] for item in descriptors],
            [item[3] for item in specialist.COMPONENTS],
        )
        self.assertEqual(set(specialist.PROFILE_DEFAULT_COMPONENTS),
                         {item["profile_id"] for item in descriptors})
        for profile_id, component_id in specialist.PROFILE_DEFAULT_COMPONENTS.items():
            self.assertIn(
                (profile_id, component_id),
                {(item["profile_id"], item["component_id"]) for item in descriptors},
            )
        bound_paths = {item["path"] for item in catalog["sources"]}
        self.assertTrue(set(specialist.INTEGRATION_PATHS) <= bound_paths)
        for row, descriptor in zip(specialist.COMPONENTS, descriptors, strict=True):
            profile_id, capability, wave, component_id, module, test, guide = row
            with self.subTest(component_id=component_id):
                package = by_profile[profile_id]
                self.assertEqual(
                    (
                        descriptor["profile_id"],
                        descriptor["primary_capability_id"],
                        descriptor["scheduled_wave_id"],
                        descriptor["component_id"],
                        descriptor["implementation_path"],
                        descriptor["test_path"],
                        descriptor["guide_path"],
                    ),
                    row,
                )
                self.assertIn(capability, package["primary_capability_ids"])
                self.assertEqual(wave, package["scheduled_wave_id"])
                for key in (
                    "package_id", "profile_name", "priority_sequence",
                    "commander_profile_id", "independent_validator_id",
                    "vector_id", "blueprint_sha256",
                ):
                    self.assertEqual(descriptor[key], package[key])
                self.assertIn(module, bound_paths)
                self.assertIn(test, bound_paths)
                self.assertIn(guide, bound_paths)
                for path in (module, test, guide):
                    self.assertTrue((ROOT / path).is_file(), path)

    def test_each_component_has_exactly_one_bound_inert_example(self) -> None:
        catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
        source_paths = [item["path"] for item in catalog["sources"]]
        self.assertEqual(len(source_paths), len(set(source_paths)))
        bound_paths = set(source_paths)
        example_paths = sorted(ROOT.glob("examples/*-component.json"))
        fixture_paths = {path.relative_to(ROOT).as_posix() for path in example_paths}
        registered = {item[3] for item in specialist.COMPONENTS}
        declared_examples = [
            path for path in specialist.INTEGRATION_PATHS
            if path.startswith("examples/") and path.endswith("-component.json")
        ]
        self.assertEqual(len(declared_examples), len(set(declared_examples)))
        bound_examples = {
            path for path in bound_paths
            if path.startswith("examples/") and path.endswith("-component.json")
        }
        self.assertEqual(set(declared_examples), fixture_paths)
        self.assertEqual(bound_examples, fixture_paths)
        resolved: list[str] = []
        for path in example_paths:
            relative = path.relative_to(ROOT).as_posix()
            with self.subTest(fixture=relative):
                request = specialist.load_offline_specialist_component_request(path)
                profile_id = request["profile_id"]
                component_id = request.get(
                    "component_id", specialist.PROFILE_DEFAULT_COMPONENTS.get(profile_id)
                )
                self.assertIn(component_id, registered)
                self.assertEqual(request["schema_version"], 1)
                self.assertIn(request["environment"], ("synthetic", "supplied_inert_data"))
                self.assertEqual(request["action_tier"], "R0")
                self.assertIs(request["dry_run"], True)
                self.assertEqual(request["credential_refs"], [])
                self.assertEqual(
                    request["resources"],
                    {"network": [], "filesystem": [], "process": [], "credential": []},
                )
                self.assertIsInstance(request["payload"], dict)
                resolved.append(component_id)
        self.assertEqual(
            Counter(resolved), Counter({component_id: 1 for component_id in registered})
        )

    def test_legacy_example_mutation_invalidates_catalog_and_dispatch(self) -> None:
        catalog = specialist.build_offline_specialist_component_catalog(repository_root=ROOT)
        original_read = specialist._read_source
        for relative in (
            "examples/offline-agent-resource-budget-component.json",
            "examples/offline-workspace-external-sharing-component.json",
        ):
            with self.subTest(fixture=relative):
                self.assertIn(relative, specialist.INTEGRATION_PATHS)
                request = specialist.load_offline_specialist_component_request(ROOT / relative)

                def changed_read(repository_root: str | Path, path: str) -> bytes:
                    content = original_read(repository_root, path)
                    return content + b"\n" if path == relative else content

                with patch.object(specialist, "_read_source", side_effect=changed_read):
                    with self.assertRaises(specialist.OfflineSpecialistComponentError):
                        specialist.OfflineSpecialistComponentCatalog.from_dict(
                            catalog.to_dict(), repository_root=ROOT
                        )
                    with self.assertRaises(specialist.OfflineSpecialistComponentError):
                        specialist.run_offline_specialist_component(
                            request, catalog=catalog, repository_root=ROOT
                        )

    def test_representative_fixture_replay_has_no_operational_effect(self) -> None:
        catalog = specialist.build_offline_specialist_component_catalog(repository_root=ROOT)
        for name in (
            "offline-mqtt-topic-component.json",
            "offline-vehicle-service-declarations-component.json",
        ):
            with self.subTest(fixture=name):
                request = specialist.load_offline_specialist_component_request(
                    ROOT / "examples" / name
                )
                result = specialist.run_offline_specialist_component(
                    request, catalog=catalog, repository_root=ROOT
                )
                self.assertEqual(result["component"]["profile_id"], request["profile_id"])
                self.assertEqual(result["operational_effects"], specialist.EFFECTS)
                self.assertIs(result["full_candidate_assembled"], False)
                self.assertIs(result["positive_use_approved"], False)
                self.assertEqual(
                    specialist.verify_offline_specialist_component_result(
                        result, request=request, catalog=catalog, repository_root=ROOT
                    ),
                    result,
                )


if __name__ == "__main__":
    unittest.main()
