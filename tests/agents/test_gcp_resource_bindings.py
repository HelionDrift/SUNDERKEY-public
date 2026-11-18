"""Declared GCP coordinates cannot imply provider authenticity or deployment authority."""

from __future__ import annotations

import ast
import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator

from scripts.check_gcp_resource_bindings import main, read_planning_object
import sunderkey.gcp_resource_bindings as resource
from sunderkey.deployment_profile_contracts import build_standard_profile
from sunderkey.gcp_resource_bindings import (
    MAX_PLAN_BYTES,
    GcpResourceBindingError,
    GcpResourceBindingPlan,
    _address,
    build_gcp_resource_binding_plan,
    parse_gcp_planning_json,
    parse_gcp_source_json,
    verify_gcp_resource_binding_plan,
)
from sunderkey.production_deployment_decision_dossier import (
    load_production_deployment_decision_dossier,
)
from sunderkey.regional_custody_contracts import TenantRegionBinding

ROOT = Path(__file__).resolve().parents[2]
DOSSIER = ROOT / "registry/production-deployment-decision-dossier-d014.json"
PROJECT = "sunderkey-synthetic"
KEY_PREFIX = f"projects/{PROJECT}/locations/us-west3/keyRings/synthetic/cryptoKeys/"


def synthetic_inputs() -> dict:
    return {
        "provider": "gcp",
        "primary_region": "us-west3",
        "recovery_region": None,
        "projects": [{"project_id": PROJECT, "project_number": "123456789012"}],
        "service_accounts": [
            {
                "service_identity_ref": "principalref:synthetic-custody",
                "project_id": PROJECT,
                "account_id": "synthetic-custody",
                "unique_id": "123456789012345678901",
            }
        ],
        "kms_key_versions": [
            {
                "key_ref": "keyref:synthetic-encryption",
                "resource_name": KEY_PREFIX + "encryption/cryptoKeyVersions/1",
                "purpose": "ENCRYPT_DECRYPT",
                "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
                "protection_level": "SOFTWARE",
            },
            {
                "key_ref": "keyref:synthetic-signing",
                "resource_name": KEY_PREFIX + "signing/cryptoKeyVersions/2",
                "purpose": "ASYMMETRIC_SIGN",
                "algorithm": "EC_SIGN_ED25519",
                "protection_level": "SOFTWARE",
            },
        ],
        "gcs_buckets": [
            {
                "storage_ref": "storeref:encrypted-local-evidence",
                "project_id": PROJECT,
                "bucket_name": "sunderkey-synthetic-evidence",
                "location": "us-west3",
                "encryption_key_ref": "keyref:synthetic-encryption",
            }
        ],
        "cloud_sql_instances": [
            {
                "database_ref": "componentref:synthetic-postgresql",
                "project_id": PROJECT,
                "instance_id": "synthetic-postgresql",
                "region": "us-west3",
                "primary_zone": "us-west3-a",
                "secondary_zone": "us-west3-b",
            }
        ],
    }


class GcpResourceBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sources = {
            "dossier": load_production_deployment_decision_dossier(DOSSIER),
            "deployment_profile": build_standard_profile("managed_service"),
            "regional_binding": TenantRegionBinding(
                "tenantref:synthetic",
                "policyref:synthetic",
                "sha256:" + "1" * 64,
                "1.0.0",
                "us-west3",
                ("us-west3",),
                ("us-west3",),
                "keyref:synthetic-encryption",
                "2026-09-27T12:00:00Z",
            ),
        }
        self.inputs = synthetic_inputs()

    def plan(self, inputs: dict | None = None) -> GcpResourceBindingPlan:
        return build_gcp_resource_binding_plan(
            self.inputs if inputs is None else inputs, **self.sources
        )

    def test_deterministic_round_trip_and_source_verification(self) -> None:
        plan = self.plan()
        self.assertEqual(plan, self.plan(copy.deepcopy(self.inputs)))
        self.assertEqual(plan, GcpResourceBindingPlan.from_json(json.dumps(plan.to_dict())))
        result = verify_gcp_resource_binding_plan(plan, **self.sources)
        self.assertEqual(result["status"], "valid_for_offline_planning_only")
        self.assertEqual(
            result["source_integrity"], "supplied_records_revalidated_not_authenticated"
        )
        self.assertIs(result["network_call_performed"], False)
        self.assertEqual(set(result["effects"].values()), {"none"})
        self.assertIn("managed_sql_manifest_mapping_required", result["blocker_codes"])
        self.assertIn("authenticated_d014_selection_required", result["blocker_codes"])
        self.assertIn("recovery_region_unselected", result["blocker_codes"])

    def test_json_schema_agrees_on_metadata_and_native_coordinate_boundaries(self) -> None:
        schema = json.loads(
            (ROOT / "registry/schemas/gcp-resource-binding-plan-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        positive = self.plan().to_dict()
        validator.validate(positive)
        for field, value in (
            ("schema_version", True),
            ("provider", "azure"),
            ("recovery_region", "us-west1"),
            ("primary_region", "global"),
            ("validation_scope", "live_configuration_verified"),
        ):
            raw = copy.deepcopy(positive)
            raw[field] = value
            with self.subTest(field=field):
                self.assertTrue(list(validator.iter_errors(raw)))
        for field, value in (("purpose", []), ("protection_level", "HSM")):
            raw = copy.deepcopy(positive)
            raw["kms_key_versions"][1][field] = value
            self.assertTrue(list(validator.iter_errors(raw)))

    def test_missing_extra_fields_and_unsupported_primitives_fail_closed(self) -> None:
        for mutation in (
            lambda raw: raw.pop("recovery_region"),
            lambda raw: raw.update({"credentials": "not-permitted"}),
            lambda raw: raw.update({"recovery_region": "us-west1"}),
            lambda raw: raw.update({"primary_region": "US"}),
            lambda raw: raw.update({"primary_region": "us-west1"}),
            lambda raw: raw.update({"projects": ()}),
            lambda raw: raw["projects"][0].update({"project_number": 123}),
            lambda raw: raw["projects"][0].update({"project_number": True}),
            lambda raw: raw["projects"][0].update({"project_number": "0123"}),
            lambda raw: raw["projects"][0].update({"project_number": "0"}),
            lambda raw: raw["projects"][0].update({"project_number": float("nan")}),
            lambda raw: raw["projects"][0].update({"project_id": "../unsafe"}),
            lambda raw: raw["projects"][0].update({"project_id": "google-test"}),
            lambda raw: raw["projects"][0].update({"project_id": "ssl-synthetic"}),
            lambda raw: raw["projects"].append(dict(raw["projects"][0])),
            lambda raw: raw["projects"].append(
                {"project_id": "another-project", "project_number": "123456789012"}
            ),
        ):
            raw = copy.deepcopy(self.inputs)
            mutation(raw)
            with self.subTest(raw=repr(raw)[:100]), self.assertRaises(GcpResourceBindingError):
                self.plan(raw)

    def test_key_purpose_protection_location_and_version_pins(self) -> None:
        for field, value in (
            ("purpose", {}),
            ("algorithm", []),
            ("protection_level", []),
            ("resource_name", KEY_PREFIX + "signing"),
            ("resource_name", KEY_PREFIX + "signing/cryptoKeyVersions/latest"),
            ("resource_name", KEY_PREFIX + "signing/cryptoKeyVersions/0"),
            ("resource_name", KEY_PREFIX + "signing/cryptoKeyVersions/02"),
            (
                "resource_name",
                KEY_PREFIX.replace("us-west3", "global") + "signing/cryptoKeyVersions/2",
            ),
            (
                "resource_name",
                KEY_PREFIX.replace(PROJECT, "another-project") + "signing/cryptoKeyVersions/2",
            ),
            ("resource_name", KEY_PREFIX + "../signing/cryptoKeyVersions/2"),
            ("algorithm", "EC_SIGN_P256_SHA256"),
            ("protection_level", "HSM"),
        ):
            raw = copy.deepcopy(self.inputs)
            raw["kms_key_versions"][1][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(GcpResourceBindingError):
                self.plan(raw)
        raw = copy.deepcopy(self.inputs)
        raw["kms_key_versions"][1]["resource_name"] = KEY_PREFIX + "encryption/cryptoKeyVersions/2"
        with self.assertRaises(GcpResourceBindingError):
            self.plan(raw)

    def test_bucket_subset_location_key_binding_and_duplicate_coordinates(self) -> None:
        for field, value in (
            ("location", "US"),
            ("location", "us-west3-a"),
            ("project_id", "another-project"),
            ("bucket_name", "not.supported"),
            ("bucket_name", "not_supported"),
            ("bucket_name", "goog-synthetic"),
            ("bucket_name", "test-g00gle-bucket"),
            ("bucket_name", "bucket/unsafe"),
            ("encryption_key_ref", "keyref:synthetic-signing"),
            ("encryption_key_ref", "keyref:unknown"),
        ):
            raw = copy.deepcopy(self.inputs)
            raw["gcs_buckets"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(GcpResourceBindingError):
                self.plan(raw)
        raw = copy.deepcopy(self.inputs)
        raw["gcs_buckets"].append({**raw["gcs_buckets"][0], "storage_ref": "storeref:another"})
        with self.assertRaises(GcpResourceBindingError):
            self.plan(raw)

    def test_sql_coordinates_cannot_claim_ha_or_fallback(self) -> None:
        for field, value in (
            ("region", "us-west1"),
            ("primary_zone", "us-west1-a"),
            ("primary_zone", []),
            ("secondary_zone", []),
            ("secondary_zone", "us-west3-a"),
            ("instance_id", "postgresql://" + "user:secret@host"),
            ("instance_id", "a" * 98),
        ):
            raw = copy.deepcopy(self.inputs)
            raw["cloud_sql_instances"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(GcpResourceBindingError):
                self.plan(raw)
        self.inputs["cloud_sql_instances"][0]["secondary_zone"] = None
        result = verify_gcp_resource_binding_plan(self.plan(), **self.sources)
        self.assertIn("managed_sql_manifest_mapping_required", result["blocker_codes"])

    def test_service_account_recreation_changes_plan_identity(self) -> None:
        before = self.plan()
        self.inputs["service_accounts"][0]["unique_id"] = "123456789012345678902"
        self.assertNotEqual(before.to_dict()["plan_sha256"], self.plan().to_dict()["plan_sha256"])
        self.inputs["service_accounts"][0]["email"] = "redundant@untrusted.example"
        with self.assertRaises(GcpResourceBindingError):
            self.plan()

    def test_rotation_keeps_immutable_key_profile_and_rejects_protection_substitution(self) -> None:
        rotated = copy.deepcopy(self.inputs["kms_key_versions"][0])
        rotated["key_ref"] = "keyref:synthetic-encryption-previous"
        rotated["resource_name"] = KEY_PREFIX + "encryption/cryptoKeyVersions/2"
        self.inputs["kms_key_versions"].append(rotated)
        self.plan()
        rotated["protection_level"] = "HSM"
        with self.assertRaises(GcpResourceBindingError):
            self.plan()

    def test_rehashed_plan_escalation_source_substitution_and_wrapper_mutation_reject(self) -> None:
        before = self.plan()
        for field, value in (
            ("schema_version", True),
            ("identity_assurance", "authenticated"),
            ("validation_scope", "live_configuration_verified"),
            ("effects", {**before.to_dict()["effects"], "deployment": "allowed"}),
        ):
            raw = before.to_dict()
            raw[field] = value
            body = {key: item for key, item in raw.items() if key not in {"plan_id", "plan_sha256"}}
            raw["plan_id"], raw["plan_sha256"] = _address(body)
            with self.subTest(field=field), self.assertRaises(GcpResourceBindingError):
                GcpResourceBindingPlan.from_dict(raw)
        raw = before.to_dict()
        raw["source_bindings"]["regional_binding"] = {
            "id": "TRB-" + "0" * 32,
            "sha256": "sha256:" + "0" * 64,
        }
        body = {key: item for key, item in raw.items() if key not in {"plan_id", "plan_sha256"}}
        raw["plan_id"], raw["plan_sha256"] = _address(body)
        rebound = GcpResourceBindingPlan.from_dict(raw)
        with self.assertRaises(GcpResourceBindingError):
            verify_gcp_resource_binding_plan(rebound, **self.sources)
        object.__setattr__(before, "document_json", before.document_json + " ")
        with self.assertRaises(GcpResourceBindingError):
            before.to_dict()

    def test_source_mutation_and_incompatible_tenant_region_fail(self) -> None:
        object.__setattr__(self.sources["regional_binding"], "home_region", "us-west1")
        with self.assertRaises(GcpResourceBindingError):
            self.plan()
        self.setUp()
        object.__setattr__(
            self.sources["deployment_profile"], "profile_sha256", "sha256:" + "0" * 64
        )
        with self.assertRaises(GcpResourceBindingError):
            self.plan()

    def test_partial_inventory_retains_missing_coordinate_and_external_blockers(self) -> None:
        for field in ("service_accounts", "kms_key_versions", "gcs_buckets", "cloud_sql_instances"):
            self.inputs[field] = []
        result = verify_gcp_resource_binding_plan(self.plan(), **self.sources)
        self.assertTrue(
            {
                "service_identity_coordinates_missing",
                "profile_evidence_store_coordinates_missing",
                "tenant_encryption_coordinates_missing",
                "database_coordinates_missing",
            }.issubset(result["blocker_codes"])
        )

    def test_source_collection_limits_are_not_coordinate_row_limits(self) -> None:
        for count in (129, 256):
            with self.subTest(count=count):
                profile = replace(
                    self.sources["deployment_profile"],
                    tool_allowlist=tuple(f"toolref:synthetic-{index}" for index in range(count)),
                )
                self.sources["deployment_profile"] = profile
                parsed = parse_gcp_source_json(json.dumps(profile.to_dict()))
                self.assertEqual(len(parsed["tool_allowlist"]), count)
                self.plan()
        oversized = copy.deepcopy(self.inputs)
        oversized["projects"] = [dict(oversized["projects"][0])] * 129
        with self.assertRaises(GcpResourceBindingError):
            parse_gcp_planning_json(json.dumps(oversized))

    def test_aggregate_native_dag_budget_rejects_before_json_encoding(self) -> None:
        shared = ["x"] * 128
        for _ in range(7):
            shared = [shared] * 128
        raw = copy.deepcopy(self.inputs)
        raw["projects"] = shared
        with patch("sunderkey.gcp_resource_bindings.json.dumps") as encoder:
            with self.assertRaisesRegex(GcpResourceBindingError, "aggregate byte"):
                self.plan(raw)
            encoder.assert_not_called()
        with patch("sunderkey.gcp_resource_bindings.json.dumps") as encoder:
            with self.assertRaisesRegex(GcpResourceBindingError, "aggregate byte"):
                resource._canonical({"schema_version": 1, "items": shared}, max_items=None)
            encoder.assert_not_called()

    def test_native_cycles_huge_ints_and_strings_reject_before_encoding(self) -> None:
        cyclic = []
        cyclic.append(cyclic)
        oversized_int = 1 << (MAX_PLAN_BYTES * 4)
        for value in (cyclic, oversized_int, -oversized_int, "x" * MAX_PLAN_BYTES):
            with self.subTest(family=type(value).__name__):
                with patch("sunderkey.gcp_resource_bindings.json.dumps") as encoder:
                    with self.assertRaises(GcpResourceBindingError):
                        resource._canonical(value)
                    encoder.assert_not_called()

    def test_aggregate_size_counts_escaping_punctuation_and_preserves_valid_bytes(self) -> None:
        samples = (
            {"quoted\"key": [None, True, False, -123, "\\\""]},
            [[], {}, {"": ""}],
            [["shared"], ["shared"]],
        )
        for value in samples:
            expected = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            with self.subTest(value=value):
                self.assertEqual(resource._canonical(value), expected)
                with patch("sunderkey.gcp_resource_bindings.MAX_PLAN_BYTES", len(expected)):
                    self.assertEqual(resource._canonical(value), expected)
                with patch("sunderkey.gcp_resource_bindings.MAX_PLAN_BYTES", len(expected) - 1):
                    with patch("sunderkey.gcp_resource_bindings.json.dumps") as encoder:
                        with self.assertRaisesRegex(GcpResourceBindingError, "aggregate byte"):
                            resource._canonical(value)
                        encoder.assert_not_called()
        with patch("sunderkey.gcp_resource_bindings.MAX_PLAN_BYTES", 64):
            self.assertEqual(len(resource._canonical("\\" * 31)), 64)
            with patch("sunderkey.gcp_resource_bindings.json.dumps") as encoder:
                with self.assertRaisesRegex(GcpResourceBindingError, "aggregate byte"):
                    resource._canonical("\\" * 32)
                encoder.assert_not_called()
        shared = ["shared"]
        self.assertEqual(resource._canonical([shared, shared]), '[["shared"],["shared"]]')


    def test_source_metadata_is_checked_before_existing_parser_normalization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            objects = {
                "input": self.inputs,
                "dossier": self.sources["dossier"].to_dict(),
                "deployment-profile": self.sources["deployment_profile"].to_dict(),
                "regional-binding": self.sources["regional_binding"].to_dict(),
            }
            args = []
            for name, raw in objects.items():
                path = base / (name + ".json")
                path.write_text(json.dumps(raw), encoding="utf-8")
                args.extend(["--" + name, str(path)])
            for name in ("dossier", "deployment-profile", "regional-binding"):
                for alias in (True, 1.0):
                    with self.subTest(source=name, alias=alias):
                        malformed = {**objects[name], "schema_version": alias}
                        path = base / (name + ".json")
                        path.write_text(json.dumps(malformed), encoding="utf-8")
                        with self.assertRaises(GcpResourceBindingError):
                            read_planning_object(path, source=True)
                        with redirect_stdout(io.StringIO()):
                            self.assertEqual(main(args), 2)
                        path.write_text(json.dumps(objects[name]), encoding="utf-8")

    def test_duplicate_nonfinite_unicode_and_oversize_json_are_rejected(self) -> None:
        for text in (
            '{"provider":"gcp","provider":"gcp"}',
            '{"number":NaN}',
            '{"text":"\\ud800"}',
            "{" + " " * MAX_PLAN_BYTES + "}",
        ):
            with self.subTest(text=text[:60]), self.assertRaises(GcpResourceBindingError):
                parse_gcp_planning_json(text)

        class StringSubclass(str):
            pass

        self.inputs["projects"][0]["project_id"] = StringSubclass(PROJECT)
        with self.assertRaises(GcpResourceBindingError):
            self.plan()

    def test_validate_only_cli_requires_explicit_files_and_preserves_every_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            objects = {
                "input": self.inputs,
                "dossier": self.sources["dossier"].to_dict(),
                "deployment-profile": self.sources["deployment_profile"].to_dict(),
                "regional-binding": self.sources["regional_binding"].to_dict(),
            }
            args: list[str] = []
            before: dict[Path, bytes] = {}
            for name, raw in objects.items():
                path = base / (name + ".json")
                path.write_text(json.dumps(raw), encoding="utf-8")
                before[path] = path.read_bytes()
                args.extend(["--" + name, str(path)])
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(main(args), 0)
            result = json.loads(output.getvalue())
            self.assertEqual(result["status"], "valid_for_offline_planning_only")
            self.assertEqual({path: path.read_bytes() for path in before}, before)
            self.assertEqual(set(base.iterdir()), set(before))
            (base / "input.json").write_text(
                '{"credentials":"raw-secret-synthetic"}', encoding="utf-8"
            )
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(main(args), 2)
            self.assertNotIn("raw-secret-synthetic", output.getvalue())
            (base / "input.json").write_bytes(b"x" * (MAX_PLAN_BYTES + 1))
            with self.assertRaises(GcpResourceBindingError):
                read_planning_object(base / "input.json")

    def test_module_has_no_cloud_environment_file_or_signing_client(self) -> None:
        tree = ast.parse(
            (ROOT / "src/sunderkey/gcp_resource_bindings.py").read_text(encoding="utf-8")
        )
        imports = {
            item.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for item in node.names
        }
        self.assertEqual(imports, {"hashlib", "json", "re"})


if __name__ == "__main__":
    unittest.main()
