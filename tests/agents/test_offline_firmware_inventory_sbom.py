"""Bounded supplied firmware inventory and SBOM claim reconciliation tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_firmware_inventory_sbom import (
    FirmwareInventorySbomError,
    analyze_supplied_firmware_inventory_sbom,
    component_fixture,
    verify_supplied_firmware_inventory_sbom,
    verify_supplied_firmware_inventory_sbom_bytes,
)


class FirmwareInventorySbomTests(unittest.TestCase):
    def test_version_difference_is_inert_and_replayable(self) -> None:
        model = component_fixture()
        report = analyze_supplied_firmware_inventory_sbom(model)
        body = report.to_dict()
        self.assertEqual(body["disposition"], "candidate_supplied_claim_mismatch")
        self.assertEqual(body["rows"][0]["comparison"], "version_differs")
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["unknown_count"], 0)
        for flag in (
            "source_authenticated", "firmware_acquired", "firmware_unpacked",
            "sbom_parsed", "component_bytes_hashed", "device_contacted",
            "finding_claimed", "full_candidate_assembled", "positive_use_approved",
            "qualification_claimed",
        ):
            self.assertFalse(body[flag], flag)
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_firmware_inventory_sbom(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            verify_supplied_firmware_inventory_sbom_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_missing_and_digest_claims_are_distinguished(self) -> None:
        model = component_fixture()
        model["firmware_inventory"].append({
            "component_id": "inventory-only",
            "version": "3.0",
            "sha256": "sha256:" + "2" * 64,
        })
        model["sbom_claims"].append({
            "component_id": "sbom-only",
            "version": "4.0",
            "sha256": "sha256:" + "3" * 64,
        })
        model["sbom_claims"][0]["version"] = "2.0"
        model["sbom_claims"][0]["sha256"] = "sha256:" + "4" * 64
        body = analyze_supplied_firmware_inventory_sbom(model).to_dict()
        self.assertEqual(
            [(row["component_id"], row["comparison"]) for row in body["rows"]],
            [
                ("controller-runtime", "digest_differs"),
                ("inventory-only", "inventory_only"),
                ("sbom-only", "sbom_only"),
            ],
        )
        self.assertEqual(body["candidate_count"], 3)

    def test_incomplete_claims_are_unknown_even_when_values_differ(self) -> None:
        model = component_fixture()
        model["sbom_complete"] = False
        body = analyze_supplied_firmware_inventory_sbom(model).to_dict()
        self.assertEqual(body["disposition"], "unknown_incomplete_supplied_claims")
        self.assertEqual(body["candidate_count"], 0)
        self.assertEqual(body["unknown_count"], 1)
        model["sbom_complete"] = True
        model["sbom_claims"][0]["version"] = "2.0"
        body = analyze_supplied_firmware_inventory_sbom(model).to_dict()
        self.assertEqual(body["disposition"], "supplied_claims_match")
        model["inventory_complete"] = False
        model["firmware_inventory"] = []
        model["sbom_claims"] = []
        body = analyze_supplied_firmware_inventory_sbom(model).to_dict()
        self.assertEqual(body["disposition"], "unknown_incomplete_supplied_claims")
        self.assertEqual(body["candidate_count"], 0)

    def test_closed_native_claims_and_bounds(self) -> None:
        model = component_fixture()
        model["firmware_inventory"].append(copy.deepcopy(model["firmware_inventory"][0]))
        with self.assertRaises(FirmwareInventorySbomError):
            analyze_supplied_firmware_inventory_sbom(model)
        for field, invalid in (
            ("schema_version", True),
            ("inventory_complete", 1),
        ):
            with self.subTest(field=field):
                model = component_fixture()
                model[field] = invalid
                with self.assertRaises(ValueError):
                    analyze_supplied_firmware_inventory_sbom(model)
        for invalid in ("sha256:" + "A" * 64, "sha256:abc", 5):
            with self.subTest(digest=invalid):
                model = component_fixture()
                model["sbom_claims"][0]["sha256"] = invalid
                with self.assertRaises(FirmwareInventorySbomError):
                    analyze_supplied_firmware_inventory_sbom(model)
        model = component_fixture()
        model["sbom_claims"][0]["extra"] = True
        with self.assertRaises(ValueError):
            analyze_supplied_firmware_inventory_sbom(model)
        model = component_fixture()
        model["firmware_inventory"] *= 129
        with self.assertRaises(ValueError):
            analyze_supplied_firmware_inventory_sbom(model)
        model = component_fixture()
        model["firmware_inventory"] = []
        model["sbom_claims"] = []
        with self.assertRaises(FirmwareInventorySbomError):
            analyze_supplied_firmware_inventory_sbom(model)

    def test_original_model_replay_rejects_changed_claims_and_forgery(self) -> None:
        model = component_fixture()
        report = analyze_supplied_firmware_inventory_sbom(model)
        changed = copy.deepcopy(model)
        changed["sbom_claims"][0]["version"] = "2.0"
        with self.assertRaises(FirmwareInventorySbomError):
            verify_supplied_firmware_inventory_sbom(report, model=changed)
        with self.assertRaises(FirmwareInventorySbomError):
            verify_supplied_firmware_inventory_sbom(report.to_dict(), model=model)
        with self.assertRaises(FirmwareInventorySbomError):
            verify_supplied_firmware_inventory_sbom_bytes(b"{}", model=model)
        with self.assertRaises(ValueError):
            verify_supplied_firmware_inventory_sbom_bytes(
                b'{"schema_version":1,"schema_version":1}', model=model
            )


if __name__ == "__main__":
    unittest.main()
