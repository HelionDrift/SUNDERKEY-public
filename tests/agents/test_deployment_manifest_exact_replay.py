"""Exact native JSON replay for checked deployment descriptions."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path
from typing import Any

from sunderkey.deployment_manifests import (
    BOUNDARY_EFFECTS,
    PROFILE_DOMAIN,
    DeploymentManifest,
    DeploymentManifestBundle,
    DeploymentManifestError,
    build_deployment_manifest_bundle,
    canonical_json,
    canonical_sha256,
    parse_deployment_manifest_bundle,
)

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "registry" / "deployment-manifest-bundle-v1.json"
PROFILE_GOLDENS = (
    (
        "high_availability_postgresql",
        "DMF-3D36910CC3AE22FAA060DE283F1F9982",
        "sha256:3d36910cc3ae22faa060de283f1f9982d61dd1e59ca1bc64a5aed483741ba746",
    ),
    (
        "local_sqlite_asgi",
        "DMF-B3B52CD78E315C3050DC47AC7F29A8DA",
        "sha256:b3b52cd78e315c3050dc47ac7f29a8dabc9b2416e08bd134359da551790c6017",
    ),
    (
        "single_node_postgresql",
        "DMF-6009E540B20B45B6D7CC26FEAF02F002",
        "sha256:6009e540b20b45b6d7cc26feaf02f002fc7b5289707da8d081fe23a178968288",
    ),
)


def _numeric_paths(value: Any, path: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    if type(value) in (bool, int):
        return [path]
    if type(value) is dict:
        return [
            found for key, item in value.items() for found in _numeric_paths(item, (*path, key))
        ]
    if type(value) is list:
        return [
            found
            for index, item in enumerate(value)
            for found in _numeric_paths(item, (*path, index))
        ]
    return []


def _set_alias(raw: dict[str, Any], path: tuple[Any, ...]) -> None:
    parent: Any = raw
    for key in path[:-1]:
        parent = parent[key]
    original = parent[path[-1]]
    parent[path[-1]] = int(original) if type(original) is bool else float(original)


def _readdress_profile(raw: dict[str, Any]) -> None:
    body = {key: value for key, value in raw.items() if key not in {"profile_id", "profile_sha256"}}
    digest = canonical_sha256({"content": body, "domain": PROFILE_DOMAIN})
    raw["profile_id"] = "DMF-" + digest[7:39].upper()
    raw["profile_sha256"] = digest


class DeploymentManifestExactReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.bundle = build_deployment_manifest_bundle()

    def test_original_bundle_profiles_and_checked_bytes_remain_exact(self) -> None:
        self.assertEqual(self.bundle.bundle_id, "DMB-3D8C8D4CACA83A3520B7A23B20B43FCB")
        self.assertEqual(
            self.bundle.bundle_sha256,
            "sha256:3d8c8d4caca83a3520b7a23b20b43fcb3006f4007d398ec7b9dd10839594401f",
        )
        self.assertEqual(
            tuple(
                (item.profile_type, item.profile_id, item.profile_sha256)
                for item in self.bundle.profiles
            ),
            PROFILE_GOLDENS,
        )
        self.assertEqual(
            hashlib.sha256(REGISTRY.read_bytes()).hexdigest(),
            "280887047ab55f589e7095d6d2ebfca49dc5eae826dfd2e4d735a41833b905ec",
        )
        self.assertEqual(json.loads(REGISTRY.read_text(encoding="ascii")), self.bundle.to_dict())
        self.assertEqual(DeploymentManifestBundle.from_dict(self.bundle.to_dict()), self.bundle)
        self.assertEqual(parse_deployment_manifest_bundle(self.bundle.document_json), self.bundle)
        for profile in self.bundle.profiles:
            self.assertEqual(DeploymentManifest.from_dict(profile.to_dict()), profile)

    def test_native_metadata_aliases_reject_both_bundle_entrypoints(self) -> None:
        for field, aliases in (
            ("schema_version", (True, 1.0)),
            ("repository_manifest_publication_complete", (1, 1.0)),
            ("external_qualification_complete", (0, 0.0)),
            ("live_deployment_performed", (0, 0.0)),
        ):
            for alias in aliases:
                changed = copy.deepcopy(self.bundle.to_dict())
                changed[field] = alias
                document = canonical_json(changed)
                self.assertNotEqual(document, self.bundle.document_json)
                for entrypoint in ("mapping", "canonical_text"):
                    with self.subTest(field=field, alias=alias, entrypoint=entrypoint):
                        with self.assertRaises(DeploymentManifestError):
                            if entrypoint == "mapping":
                                DeploymentManifestBundle.from_dict(changed)
                            else:
                                parse_deployment_manifest_bundle(document)

    def test_coherently_readdressed_numeric_profile_aliases_fail_template_replay(self) -> None:
        for profile in self.bundle.profiles:
            original = profile.to_dict()
            paths = _numeric_paths(original)
            self.assertGreater(len(paths), 20)
            for path in paths:
                changed = copy.deepcopy(original)
                _set_alias(changed, path)
                _readdress_profile(changed)
                self.assertNotEqual(changed["profile_sha256"], profile.profile_sha256)
                with self.subTest(profile=profile.profile_type, path=path):
                    with self.assertRaisesRegex(DeploymentManifestError, "checked template"):
                        DeploymentManifest.from_dict(changed)

    def test_old_profile_addresses_still_reject_changed_native_bytes(self) -> None:
        for profile in self.bundle.profiles:
            changed = copy.deepcopy(profile.to_dict())
            changed["services"][0]["run_as_non_root"] = 1
            with self.subTest(profile=profile.profile_type):
                with self.assertRaises(DeploymentManifestError):
                    DeploymentManifest.from_dict(changed)

    def test_mapping_order_is_not_a_content_change_and_inputs_are_not_mutated(self) -> None:
        for original in (self.bundle.to_dict(), *(item.to_dict() for item in self.bundle.profiles)):
            reordered = dict(reversed(tuple(original.items())))
            before = copy.deepcopy(reordered)
            if "bundle_id" in original:
                parsed = DeploymentManifestBundle.from_dict(reordered)
            else:
                parsed = DeploymentManifest.from_dict(reordered)
            self.assertEqual(canonical_json(parsed.to_dict()), canonical_json(original))
            self.assertEqual(canonical_json(reordered), canonical_json(before))

    def test_array_order_unknown_fields_and_positive_effects_remain_rejected(self) -> None:
        mutations = (
            lambda raw: raw["profiles"].reverse(),
            lambda raw: raw.update({"unselected": "value"}),
            lambda raw: raw.update({"external_qualification_complete": True}),
            lambda raw: raw.update({"live_deployment_performed": True}),
            lambda raw: raw["effects"].update({"network": "performed"}),
        )
        for index, mutate in enumerate(mutations):
            changed = copy.deepcopy(self.bundle.to_dict())
            mutate(changed)
            with self.subTest(mutation=index):
                with self.assertRaises(DeploymentManifestError):
                    DeploymentManifestBundle.from_dict(changed)

    def test_round_trips_remain_descriptions_not_external_observations(self) -> None:
        parsed = parse_deployment_manifest_bundle(self.bundle.document_json)
        raw = parsed.to_dict()
        self.assertEqual(raw["effects"], BOUNDARY_EFFECTS)
        self.assertIs(raw["repository_manifest_publication_complete"], True)
        self.assertIs(raw["external_qualification_complete"], False)
        self.assertIs(raw["live_deployment_performed"], False)
        self.assertEqual(raw["status"], "repository_complete_infrastructure_blocked")
        for profile in raw["profiles"]:
            self.assertEqual(profile["effects"], BOUNDARY_EFFECTS)
            self.assertEqual(
                profile["status"], "repository_manifest_complete_infrastructure_blocked"
            )


if __name__ == "__main__":
    unittest.main()
