"""Phase 170 repository-only deployment manifest tests."""

from __future__ import annotations

import ast
import copy
import json
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

import sunderkey
from sunderkey.deployment_manifests import (
    BOUNDARY_EFFECTS,
    DeploymentManifestBundle,
    DeploymentManifestError,
    build_deployment_manifest_bundle,
    parse_deployment_manifest_bundle,
)

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "src" / "sunderkey" / "deployment_manifests.py"
REGISTRY = ROOT / "registry" / "deployment-manifest-bundle-v1.json"
SCHEMA = ROOT / "registry" / "schemas" / "deployment-manifest-bundle-v1.schema.json"
DOC = ROOT / "docs" / "deployment-manifests.md"


class DeploymentManifestPhase170Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.bundle = build_deployment_manifest_bundle()
        cls.checked = json.loads(REGISTRY.read_text(encoding="utf-8"))

    def profile(self, profile_type: str) -> dict:
        return next(
            item
            for item in self.bundle.to_dict()["profiles"]
            if item["profile_type"] == profile_type
        )

    def test_bundle_is_deterministic_content_addressed_and_round_trips(self) -> None:
        second = build_deployment_manifest_bundle()
        self.assertEqual(second, self.bundle)
        self.assertEqual(second.document_json, self.bundle.document_json)
        self.assertEqual(DeploymentManifestBundle.from_dict(self.bundle.to_dict()), self.bundle)
        self.assertEqual(parse_deployment_manifest_bundle(self.bundle.document_json), self.bundle)
        self.assertRegex(self.bundle.bundle_id, r"^DMB-[0-9A-F]{32}$")
        self.assertRegex(self.bundle.bundle_sha256, r"^sha256:[0-9a-f]{64}$")

    def test_checked_bundle_is_exact_builder_output(self) -> None:
        self.assertEqual(self.checked, self.bundle.to_dict())
        expected_text = (
            json.dumps(self.bundle.to_dict(), indent=2, sort_keys=True, ensure_ascii=True) + "\n"
        )
        self.assertEqual(REGISTRY.read_text(encoding="ascii"), expected_text)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_checked_bundle_validates_against_schema(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(self.checked)

    def test_three_profiles_cover_local_single_node_and_ha(self) -> None:
        profiles = self.bundle.to_dict()["profiles"]
        self.assertEqual(
            [item["profile_type"] for item in profiles],
            [
                "high_availability_postgresql",
                "local_sqlite_asgi",
                "single_node_postgresql",
            ],
        )
        self.assertEqual(len({item["profile_id"] for item in profiles}), 3)
        self.assertEqual(len({item["profile_sha256"] for item in profiles}), 3)

    def test_images_versions_digests_identities_and_secret_refs_are_exact(self) -> None:
        for profile in self.bundle.to_dict()["profiles"]:
            for image in profile["images"]:
                self.assertEqual(image["image_reference"].rsplit("@", 1)[1], image["image_digest"])
                self.assertNotIn(":latest", image["image_reference"])
                self.assertRegex(image["exact_version"], r"^[0-9]+(?:\.[0-9]+){1,3}")
            for service in profile["services"]:
                self.assertTrue(service["service_identity"].startswith("service:"))
                self.assertTrue(service["run_as_non_root"])
                self.assertFalse(service["writable_root_filesystem"])
            for secret_ref in profile["secrets"]:
                self.assertTrue(secret_ref.startswith("secretref:"))

    def test_local_profile_is_loopback_sqlite_and_default_deny(self) -> None:
        profile = self.profile("local_sqlite_asgi")
        self.assertEqual(profile["storage"]["backend"], "sqlite")
        self.assertEqual(profile["runtime"]["api_adapter"], "in_process_asgi")
        self.assertEqual(profile["network"]["ingress_mode"], "loopback_only")
        self.assertEqual(profile["network"]["egress_mode"], "deny_all")
        self.assertFalse(profile["network"]["public_ingress"])
        self.assertEqual(profile["capacity"]["maximum_worker_concurrency"], 1)
        self.assertEqual(profile["secrets"], [])

    def test_single_node_profile_requires_postgresql_tls_proxy_and_backups(self) -> None:
        profile = self.profile("single_node_postgresql")
        self.assertEqual(profile["storage"]["backend"], "postgresql")
        self.assertEqual(profile["network"]["ingress_mode"], "tls_only")
        self.assertEqual(profile["network"]["egress_mode"], "default_deny_allowlist_proxy")
        self.assertEqual(profile["network"]["internal_service_tls"], "mutual_tls_required")
        self.assertTrue(profile["backup"]["point_in_time_recovery_required"])
        self.assertTrue(profile["backup"]["restore_drill_required"])
        self.assertFalse(profile["migration"]["automatic_migration"])

    def test_ha_profile_requires_quorum_fencing_replicas_and_same_region(self) -> None:
        profile = self.profile("high_availability_postgresql")
        self.assertEqual(profile["storage"]["persistent_volume_count"], 3)
        self.assertEqual(profile["capacity"]["database_replicas"], 3)
        self.assertEqual(profile["capacity"]["scheduler_replicas"], 3)
        self.assertTrue(profile["fencing"]["ha_coordination_required"])
        self.assertEqual(profile["fencing"]["minimum_voters"], 3)
        self.assertTrue(profile["fencing"]["fail_closed_on_ambiguity"])
        self.assertEqual(profile["regional_custody"]["cross_region_transfer_default"], "deny")
        self.assertEqual(profile["regional_custody"]["regional_replication"], "same_region_only")

    def test_contract_boundaries_and_external_evidence_are_explicit(self) -> None:
        required_modules = {
            "sunderkey.deployment_profile_contracts",
            "sunderkey.egress_proxy_contracts",
            "sunderkey.ha_coordination_contracts",
            "sunderkey.health_state_contracts",
            "sunderkey.persistence_port_contracts.postgresql",
            "sunderkey.persistence_port_contracts.sqlite",
            "sunderkey.postgresql_runtime_adapter",
            "sunderkey.regional_custody_contracts",
        }
        for profile in self.bundle.to_dict()["profiles"]:
            self.assertEqual(
                {item["module"] for item in profile["contract_bindings"]}, required_modules
            )
            self.assertIn("rollback_drill_receipt", profile["required_external_evidence"])
            self.assertIn(
                "runtime_image_signature_verification", profile["required_external_evidence"]
            )
            self.assertEqual(profile["effects"], BOUNDARY_EFFECTS)

    def test_repository_completion_never_claims_deployment_or_qualification(self) -> None:
        raw = self.bundle.to_dict()
        self.assertTrue(raw["repository_manifest_publication_complete"])
        self.assertFalse(raw["live_deployment_performed"])
        self.assertFalse(raw["external_qualification_complete"])
        self.assertEqual(raw["status"], "repository_complete_infrastructure_blocked")
        self.assertEqual(raw["effects"], BOUNDARY_EFFECTS)
        for profile in raw["profiles"]:
            self.assertEqual(
                profile["status"], "repository_manifest_complete_infrastructure_blocked"
            )

    def test_tampering_and_noncanonical_documents_fail_closed(self) -> None:
        changed = copy.deepcopy(self.checked)
        changed["profiles"][0]["capacity"]["database_replicas"] = 2
        with self.assertRaisesRegex(DeploymentManifestError, "checked template"):
            DeploymentManifestBundle.from_dict(changed)

        changed = copy.deepcopy(self.checked)
        changed["profiles"][0]["images"][0]["image_reference"] = (
            "registry.sunderkey.invalid/sunderkey/api:latest"
        )
        with self.assertRaises(DeploymentManifestError):
            DeploymentManifestBundle.from_dict(changed)

        with self.assertRaisesRegex(DeploymentManifestError, "not canonical"):
            parse_deployment_manifest_bundle(json.dumps(self.checked, indent=2))

    def test_module_has_no_runtime_or_host_effect_surface(self) -> None:
        tree = ast.parse(MODULE.read_text(encoding="utf-8"))
        forbidden_imports = {
            "asyncio",
            "docker",
            "kubernetes",
            "os",
            "pathlib",
            "requests",
            "socket",
            "subprocess",
            "urllib",
        }
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertTrue(imported.isdisjoint(forbidden_imports))
        source = MODULE.read_text(encoding="utf-8")
        for forbidden in ("kubectl", "docker run", "podman run", "create_connection"):
            self.assertNotIn(forbidden, source.lower())

    def test_documentation_exists_and_preserves_the_boundary(self) -> None:
        text = DOC.read_text(encoding="utf-8")
        self.assertIn("local SQLite and ASGI", text)
        self.assertIn("single-node PostgreSQL", text)
        self.assertIn("high-availability PostgreSQL", text)
        self.assertIn("does not deploy", text)
        self.assertIn("infrastructure-blocked", text)

    def test_public_package_exports_deployment_manifest_boundary(self) -> None:
        self.assertIs(
            sunderkey.build_deployment_manifest_bundle,
            build_deployment_manifest_bundle,
        )
        self.assertIs(
            sunderkey.parse_deployment_manifest_bundle,
            parse_deployment_manifest_bundle,
        )
        self.assertIs(sunderkey.DeploymentManifestBundle, DeploymentManifestBundle)


if __name__ == "__main__":
    unittest.main()
