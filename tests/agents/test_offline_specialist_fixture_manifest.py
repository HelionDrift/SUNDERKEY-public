"""Negative checks for the lightweight specialist fixture preflight."""

from __future__ import annotations

import unittest

from scripts.check_offline_specialist_fixture_manifest import check_fixture_manifest


class SpecialistFixtureManifestTests(unittest.TestCase):
    def test_matching_fixture_sets(self) -> None:
        self.assertEqual(
            check_fixture_manifest(
                fixture_paths={"examples/one-component.json"},
                declared_paths=["examples/one-component.json"],
                bound_paths=["examples/one-component.json"],
            ),
            1,
        )

    def test_missing_declaration_and_binding_fail(self) -> None:
        with self.assertRaisesRegex(ValueError, "declarations differ"):
            check_fixture_manifest(
                fixture_paths={"examples/one-component.json"},
                declared_paths=[],
                bound_paths=["examples/one-component.json"],
            )
        with self.assertRaisesRegex(ValueError, "bindings differ"):
            check_fixture_manifest(
                fixture_paths={"examples/one-component.json"},
                declared_paths=["examples/one-component.json"],
                bound_paths=[],
            )

    def test_duplicate_declarations_and_bindings_fail(self) -> None:
        fixture = "examples/one-component.json"
        with self.assertRaisesRegex(ValueError, "declarations contain duplicates"):
            check_fixture_manifest(
                fixture_paths={fixture}, declared_paths=[fixture, fixture], bound_paths=[fixture]
            )
        with self.assertRaisesRegex(ValueError, "bindings contain duplicates"):
            check_fixture_manifest(
                fixture_paths={fixture}, declared_paths=[fixture], bound_paths=[fixture, fixture]
            )


if __name__ == "__main__":
    unittest.main()
