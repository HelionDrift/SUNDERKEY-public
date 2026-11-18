"""Synthetic checks for declared D014 self-managed database host intent."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path

from sunderkey.deployment_manifests import DeploymentManifestBundle
from sunderkey.gcp_self_managed_postgresql import (
    GcpSelfManagedPostgresqlError,
    review_gcp_self_managed_postgresql_hosts,
    verify_gcp_self_managed_postgresql_host_review,
)
from sunderkey.production_deployment_decision_dossier import (
    load_production_deployment_decision_dossier,
)

ROOT = Path(__file__).resolve().parents[2]


def _declaration() -> dict:
    return {
        "project_id": "sunder-test-project",
        "region": "us-west3",
        "database_service_identity_ref": "principalref:synthetic-database-service",
        "nodes": [
            {
                "instance_id": f"synthetic-db-{suffix}",
                "zone": f"us-west3-{suffix}",
                "data_volume_ref": f"volref:synthetic-db-{suffix}",
            }
            for suffix in "abc"
        ],
    }


class GcpSelfManagedPostgresqlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dossier = load_production_deployment_decision_dossier(
            ROOT / "registry/production-deployment-decision-dossier-d014.json"
        )
        cls.bundle = DeploymentManifestBundle.from_dict(
            json.loads((ROOT / "registry/deployment-manifest-bundle-v1.json").read_text("utf-8"))
        )

    def review(self, declaration: dict) -> dict:
        return review_gcp_self_managed_postgresql_hosts(
            declaration, dossier=self.dossier, bundle=self.bundle
        )

    def test_three_declared_nodes_are_a_stable_offline_review_not_acceptance(self) -> None:
        original = _declaration()
        result = self.review(original)
        reordered = copy.deepcopy(original)
        reordered["nodes"].reverse()
        self.assertEqual(result, self.review(reordered))
        self.assertEqual(result["option_id"], "self_managed_quorum_postgresql")
        self.assertEqual(result["zone_count"], 3)
        self.assertEqual(result["identity_assurance"], "operator_asserted_unsigned")
        self.assertEqual(result["status"], "valid_for_offline_topology_review_only")
        self.assertTrue(result["review_id"].startswith("GSP-"))
        covered = {
            key: value
            for key, value in result.items()
            if key not in {"review_id", "review_sha256"}
        }
        digest = "sha256:" + hashlib.sha256(
            json.dumps(
                {
                    "domain": "sunderkey.gcp-self-managed-postgresql-host-review.v1",
                    "review": covered,
                },
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
        ).hexdigest()
        self.assertEqual(result["review_sha256"], digest)
        self.assertEqual(result["review_id"], "GSP-" + digest[7:39].upper())
        self.assertEqual(result["source"]["dossier_id"], self.dossier.dossier_id)
        self.assertEqual(result["source"]["manifest_bundle_id"], self.bundle.bundle_id)
        self.assertFalse(result["network_call_performed"])
        self.assertTrue(all(value == "none" for value in result["effects"].values()))
        self.assertIn("signed_host_and_database_acceptance_missing", result["blocker_codes"])
        self.assertIn(
            "database_election_replication_and_writer_fencing_unverified",
            result["blocker_codes"],
        )

    def test_two_zone_intent_remains_explicitly_incomplete(self) -> None:
        declaration = _declaration()
        declaration["nodes"][2]["zone"] = "us-west3-b"
        result = self.review(declaration)
        self.assertEqual(result["zone_count"], 2)
        self.assertIn("three_zone_distribution_unproven", result["blocker_codes"])

    def test_exact_count_and_unique_node_resources_are_required(self) -> None:
        for mutation in ("two_nodes", "duplicate_instance", "duplicate_volume"):
            with self.subTest(mutation=mutation):
                declaration = _declaration()
                if mutation == "two_nodes":
                    declaration["nodes"].pop()
                elif mutation == "duplicate_instance":
                    declaration["nodes"][2]["instance_id"] = declaration["nodes"][1]["instance_id"]
                else:
                    declaration["nodes"][2]["data_volume_ref"] = declaration["nodes"][1][
                        "data_volume_ref"
                    ]
                with self.assertRaises(GcpSelfManagedPostgresqlError):
                    self.review(declaration)

    def test_wrong_region_zone_project_or_reference_fails(self) -> None:
        for field, value in (
            ("region", "us-west2"),
            ("project_id", "INVALID"),
            ("database_service_identity_ref", "secretref:database-password"),
        ):
            with self.subTest(field=field):
                declaration = _declaration()
                declaration[field] = value
                with self.assertRaises(GcpSelfManagedPostgresqlError):
                    self.review(declaration)
        declaration = _declaration()
        declaration["nodes"][0]["zone"] = "us-central1-a"
        with self.assertRaises(GcpSelfManagedPostgresqlError):
            self.review(declaration)
        declaration = _declaration()
        declaration["nodes"][0]["data_volume_ref"] = "secretref:volume-token"
        with self.assertRaises(GcpSelfManagedPostgresqlError):
            self.review(declaration)

    def test_extra_fields_cannot_turn_review_into_a_cloud_sql_or_credential_plan(self) -> None:
        for field, value in (
            ("cloud_sql_instances", []),
            ("credential", "secretref:database-password"),
            ("deployment_approved", True),
        ):
            with self.subTest(field=field):
                declaration = _declaration()
                declaration[field] = value
                with self.assertRaises(GcpSelfManagedPostgresqlError):
                    self.review(declaration)
        declaration = _declaration()
        declaration["nodes"][0]["primary"] = True
        with self.assertRaises(GcpSelfManagedPostgresqlError):
            self.review(declaration)

    def test_non_native_values_and_wrong_sources_fail_closed(self) -> None:
        wrong_collection = {**_declaration(), "nodes": tuple(_declaration()["nodes"])}
        for invalid in (None, [], "{}", wrong_collection):
            with self.subTest(invalid_type=type(invalid).__name__):
                with self.assertRaises(GcpSelfManagedPostgresqlError):
                    self.review(invalid)

        class EqualRegion:
            def __ne__(self, other: object) -> bool:
                return False

        disguised_region = {**_declaration(), "region": EqualRegion()}
        with self.assertRaises(GcpSelfManagedPostgresqlError):
            self.review(disguised_region)

        with self.assertRaises(GcpSelfManagedPostgresqlError):
            review_gcp_self_managed_postgresql_hosts(
                _declaration(), dossier=object(), bundle=self.bundle
            )
        with self.assertRaises(GcpSelfManagedPostgresqlError):
            review_gcp_self_managed_postgresql_hosts(
                _declaration(), dossier=self.dossier, bundle=object()
            )

    def test_stored_review_replays_exact_sources_and_rejects_tampering(self) -> None:
        review = self.review(_declaration())
        self.assertEqual(
            verify_gcp_self_managed_postgresql_host_review(
                review, dossier=self.dossier, bundle=self.bundle
            ),
            review,
        )
        for field, value in (
            ("review_sha256", "sha256:" + "0" * 64),
            ("network_call_performed", 0),
            ("blocker_codes", tuple(review["blocker_codes"])),
            ("identity_assurance", "authenticated"),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(review)
                changed[field] = value
                with self.assertRaises(GcpSelfManagedPostgresqlError):
                    verify_gcp_self_managed_postgresql_host_review(
                        changed, dossier=self.dossier, bundle=self.bundle
                    )
        changed = copy.deepcopy(review)
        changed["declaration"]["nodes"][0]["zone"] = "us-west3-b"
        with self.assertRaises(GcpSelfManagedPostgresqlError):
            verify_gcp_self_managed_postgresql_host_review(
                changed, dossier=self.dossier, bundle=self.bundle
            )


if __name__ == "__main__":
    unittest.main()
