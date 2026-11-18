"""Supplied OCI registry signature binding declaration checks."""

from __future__ import annotations

import copy
import json
import unittest

from sunderkey.offline_oci_registry_signature_bindings import (
    OciRegistrySignatureBindingsError,
    analyze_supplied_oci_registry_signature_bindings,
    component_fixture,
    verify_supplied_oci_registry_signature_bindings,
    verify_supplied_oci_registry_signature_bindings_bytes,
)


class OciRegistrySignatureBindingsTests(unittest.TestCase):
    def test_matching_supplied_binding_is_inert_and_replayable(self) -> None:
        model = component_fixture()
        report = analyze_supplied_oci_registry_signature_bindings(model)
        body = report.to_dict()
        self.assertEqual(body["disposition"], "supplied_binding_consistent")
        self.assertEqual(body["signature_record_count"], 1)
        self.assertTrue(body["signature_rows"][0]["subject_match"])
        self.assertEqual(body["candidate_count"], 0)
        self.assertFalse(body["registry_contacted"])
        self.assertFalse(body["cryptographic_signature_verified"])
        self.assertFalse(body["signer_identity_verified"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_oci_registry_signature_bindings(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            verify_supplied_oci_registry_signature_bindings_bytes(
                report.to_json().encode("ascii"), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_candidate_binding_conflicts_are_only_about_supplied_values(self) -> None:
        model = component_fixture()
        model["signatures"][0]["subject_digest"] = "sha256:" + "c" * 64
        model["signatures"][0]["repository"] = "other/service"
        body = analyze_supplied_oci_registry_signature_bindings(model).to_dict()
        self.assertEqual(body["disposition"], "candidate_supplied_binding_mismatch")
        self.assertEqual(body["candidate_count"], 2)
        self.assertEqual(
            {row["issue"] for row in body["mismatches"]},
            {"subject_digest_mismatch", "repository_mismatch"},
        )

    def test_incomplete_and_empty_inventories_do_not_promote(self) -> None:
        model = component_fixture()
        model["inventory_complete"] = False
        model["signatures"][0]["subject_digest"] = "sha256:" + "c" * 64
        body = analyze_supplied_oci_registry_signature_bindings(model).to_dict()
        self.assertEqual(body["disposition"], "unknown")
        self.assertEqual(body["candidate_count"], 0)
        self.assertEqual(body["mismatches"], [])
        self.assertIsNone(body["signature_rows"][0]["subject_match"])
        self.assertIsNone(body["signature_rows"][0]["repository_match"])
        self.assertEqual(body["signature_rows"][0]["status"], "unknown")
        model = component_fixture()
        model["signatures"] = []
        self.assertEqual(
            analyze_supplied_oci_registry_signature_bindings(model).to_dict()["disposition"],
            "unknown",
        )

    def test_closed_bounds_and_native_types(self) -> None:
        cases = []
        model = component_fixture()
        model["schema_version"] = True
        cases.append(model)
        model = component_fixture()
        model["inventory_complete"] = 1
        cases.append(model)
        model = component_fixture()
        model["signatures"][0]["subject_digest"] = "sha512:abcd"
        cases.append(model)
        model = component_fixture()
        model["signatures"][0]["extra"] = "x"
        cases.append(model)
        model = component_fixture()
        model["signatures"] *= 65
        cases.append(model)
        model = component_fixture()
        model["signatures"].append(copy.deepcopy(model["signatures"][0]))
        cases.append(model)
        for model in cases:
            with self.subTest(model=model), self.assertRaises(ValueError):
                analyze_supplied_oci_registry_signature_bindings(model)

    def test_original_replay_rejects_changes_and_forged_exports(self) -> None:
        model = component_fixture()
        report = analyze_supplied_oci_registry_signature_bindings(model)
        changed = copy.deepcopy(model)
        changed["registry"]["manifest_digest"] = "sha256:" + "d" * 64
        with self.assertRaises(OciRegistrySignatureBindingsError):
            verify_supplied_oci_registry_signature_bindings(report, model=changed)
        with self.assertRaises(OciRegistrySignatureBindingsError):
            verify_supplied_oci_registry_signature_bindings(report.to_dict(), model=model)
        tampered = report.to_dict()
        tampered["candidate_count"] = 4
        with self.assertRaises(OciRegistrySignatureBindingsError):
            verify_supplied_oci_registry_signature_bindings_bytes(
                json.dumps(tampered).encode("ascii"), model=model
            )
        duplicated = report.to_json().replace(
            '"schema_version":1', '"schema_version":1,"schema_version":1', 1
        )
        with self.assertRaises(ValueError):
            verify_supplied_oci_registry_signature_bindings_bytes(
                duplicated.encode("ascii"), model=model
            )


if __name__ == "__main__":
    unittest.main()
