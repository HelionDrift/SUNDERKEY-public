"""Supplied OCI image and layer declaration checks."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_oci_image_layers import (
    OciImageLayersError,
    analyze_supplied_oci_image_layers,
    component_fixture,
    verify_supplied_oci_image_layers,
    verify_supplied_oci_image_layers_bytes,
)


class OciImageLayersTests(unittest.TestCase):
    def test_consistent_supplied_metadata_is_inert_and_replayable(self) -> None:
        model = component_fixture()
        report = analyze_supplied_oci_image_layers(model)
        body = report.to_dict()
        self.assertEqual(body["disposition"], "supplied_oci_metadata_consistent")
        self.assertEqual(body["layer_count"], 1)
        self.assertEqual(body["candidate_count"], 0)
        self.assertEqual(body["layer_rows"][0]["diff_id"], model["configuration"]["diff_ids"][0])
        self.assertNotEqual(
            body["layer_rows"][0]["diff_id"], body["layer_rows"][0]["descriptor"]["digest"]
        )
        self.assertFalse(body["registry_contacted"])
        self.assertFalse(body["blob_bytes_verified"])
        self.assertFalse(body["layer_decompressed"])
        self.assertFalse(body["filesystem_overlay_applied"])
        self.assertFalse(body["runtime_executed"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_oci_image_layers(report, model=model).to_json(), report.to_json()
        )
        self.assertEqual(
            verify_supplied_oci_image_layers_bytes(
                report.to_json().encode("ascii"), model=model
            ).to_json(), report.to_json()
        )

    def test_manifest_config_layer_and_history_mismatches(self) -> None:
        cases = (
            ("manifest_schema_version_not_two", "manifest", "schema_version", 3),
            (
                "config_media_type_conflict", "configuration", "media_type",
                "application/vnd.example.config",
            ),
            ("rootfs_type_not_layers", "configuration", "rootfs_type", "other"),
            ("diff_id_layer_count_mismatch", "configuration", "diff_ids", []),
            ("history_layer_count_mismatch", "configuration", "history", [{"empty_layer": True}]),
        )
        for issue, section, field, replacement in cases:
            with self.subTest(issue=issue):
                model = component_fixture()
                model[section][field] = replacement
                body = analyze_supplied_oci_image_layers(model).to_dict()
                self.assertIn(issue, {row["issue"] for row in body["mismatches"]})
                self.assertEqual(body["disposition"], "candidate_supplied_oci_metadata_mismatch")
                self.assertGreater(body["candidate_count"], 0)

    def test_unknown_media_and_incomplete_inventory_do_not_promote(self) -> None:
        model = component_fixture()
        model["manifest"]["layers"][0]["media_type"] = "application/vnd.example.layer"
        body = analyze_supplied_oci_image_layers(model).to_dict()
        self.assertEqual(body["disposition"], "unknown")
        self.assertEqual(body["unsupported_media_type_count"], 1)
        model["manifest"]["layers"][0]["media_type"] = "application/vnd.oci.image.layer.v1.tar"
        model["configuration"]["diff_ids"].clear()
        model["inventory_complete"] = False
        body = analyze_supplied_oci_image_layers(model).to_dict()
        self.assertEqual(body["disposition"], "unknown")
        self.assertEqual(body["candidate_count"], 0)
        self.assertTrue(body["mismatches"])
        self.assertEqual(body["unknown_count"], 1)

    def test_empty_layer_set_and_absent_optional_history(self) -> None:
        model = component_fixture()
        model["manifest"]["layers"] = []
        model["configuration"]["diff_ids"] = []
        model["configuration"]["history"] = None
        body = analyze_supplied_oci_image_layers(model).to_dict()
        self.assertEqual(body["disposition"], "supplied_oci_metadata_consistent")
        self.assertEqual(body["layer_count"], 0)
        self.assertIsNone(body["history_count"])

    def test_closed_bounds_and_native_types(self) -> None:
        model = component_fixture()
        model["manifest"]["config"]["size"] = True
        with self.assertRaises(OciImageLayersError):
            analyze_supplied_oci_image_layers(model)
        model = component_fixture()
        model["configuration"]["diff_ids"] = ["sha512:abc"]
        with self.assertRaises(OciImageLayersError):
            analyze_supplied_oci_image_layers(model)
        model = component_fixture()
        model["manifest"]["extra"] = 1
        with self.assertRaises(ValueError):
            analyze_supplied_oci_image_layers(model)
        model = component_fixture()
        model["manifest"]["layers"] *= 65
        with self.assertRaises(ValueError):
            analyze_supplied_oci_image_layers(model)

    def test_original_replay_rejects_changes_and_forged_exports(self) -> None:
        model = component_fixture()
        report = analyze_supplied_oci_image_layers(model)
        changed = copy.deepcopy(model)
        changed["manifest"]["layers"][0]["size"] += 1
        with self.assertRaises(OciImageLayersError):
            verify_supplied_oci_image_layers(report, model=changed)
        with self.assertRaises(OciImageLayersError):
            verify_supplied_oci_image_layers(report.to_dict(), model=model)
        with self.assertRaises(OciImageLayersError):
            verify_supplied_oci_image_layers_bytes(b"{}", model=model)
        duplicated = report.to_json().replace(
            '"schema_version":1', '"schema_version":1,"schema_version":1', 1
        )
        with self.assertRaises(ValueError):
            verify_supplied_oci_image_layers_bytes(duplicated.encode("ascii"), model=model)


if __name__ == "__main__":
    unittest.main()
