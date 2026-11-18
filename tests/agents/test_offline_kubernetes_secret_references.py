"""Inert supplied Kubernetes Secret and ConfigMap reference tests."""

from __future__ import annotations

import copy
import json
import unittest

from sunderkey.offline_kubernetes_secret_references import (
    KubernetesSecretReferencesError,
    KubernetesSecretReferencesReport,
    analyze_supplied_kubernetes_secret_references,
    analyze_supplied_kubernetes_secret_references_bytes,
    component_fixture,
    verify_supplied_kubernetes_secret_references,
    verify_supplied_kubernetes_secret_references_bytes,
)


class KubernetesSecretReferencesTests(unittest.TestCase):
    def test_dotted_tls_secret_key_is_a_bounded_metadata_name(self) -> None:
        model = component_fixture()
        model["objects"][0]["object_kind"] = "secret"
        model["objects"][0]["keys"] = ["tls.crt"]
        model["references"][0]["object_kind"] = "secret"
        model["references"][0]["key_name"] = "tls.crt"
        body = analyze_supplied_kubernetes_secret_references(model).to_dict()
        self.assertEqual(body["candidate_count"], 0)
        self.assertIsNone(body["reference_rows"][0]["expected_resolution"])
        model["references"][0]["key_name"] = "tls/crt"
        with self.assertRaises(KubernetesSecretReferencesError):
            analyze_supplied_kubernetes_secret_references(model)

    def test_candidate_is_only_a_supplied_reference_contradiction(self) -> None:
        model = component_fixture()
        report = analyze_supplied_kubernetes_secret_references(model)
        body = report.to_dict()
        self.assertEqual(body["profile_id"], "AOE-GC-D15-S09")
        self.assertEqual(body["wave_id"], "IW2-011")
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["reference_rows"][0]["reason"], "declared_required_key_absent")
        self.assertFalse(body["api_contacted"])
        self.assertFalse(body["secret_values_accepted"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            analyze_supplied_kubernetes_secret_references_bytes(
                model_bytes=json.dumps(model).encode("ascii")
            ).to_json(), report.to_json()
        )
        self.assertEqual(
            verify_supplied_kubernetes_secret_references(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            verify_supplied_kubernetes_secret_references_bytes(
                report.to_json().encode("ascii"), model=model
            ).to_json(), report.to_json(),
        )

    def test_absent_object_optional_and_incomplete_are_unknown_when_needed(self) -> None:
        model = component_fixture()
        model["objects"] = []
        body = analyze_supplied_kubernetes_secret_references(model).to_dict()
        self.assertEqual(body["reference_rows"][0]["reason"], "declared_required_object_absent")
        self.assertEqual(body["candidate_count"], 1)
        model["inventory_complete"] = False
        body = analyze_supplied_kubernetes_secret_references(model).to_dict()
        self.assertEqual(body["candidate_count"], 0)
        self.assertIsNone(body["reference_rows"][0]["expected_resolution"])
        self.assertEqual(body["reference_rows"][0]["disposition"], "unknown")
        model["inventory_complete"] = True
        model["references"][0]["optional"] = True
        self.assertEqual(
            analyze_supplied_kubernetes_secret_references(model).to_dict()["candidate_count"], 0
        )
        for field in ("context_complete", "observation_complete"):
            changed = component_fixture()
            changed["references"][0][field] = False
            self.assertEqual(
                analyze_supplied_kubernetes_secret_references(changed).to_dict()["candidate_count"],
                0,
            )

    def test_closed_source_rejects_values_and_exact_types(self) -> None:
        for field in ("data", "stringData", "value"):
            model = component_fixture()
            model["objects"][0][field] = "raw-secret-value"
            with self.subTest(field=field), self.assertRaises(ValueError):
                analyze_supplied_kubernetes_secret_references(model)
        for field, value in (("inventory_complete", 1), ("schema_version", True)):
            model = component_fixture()
            model[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                analyze_supplied_kubernetes_secret_references(model)
        model = component_fixture()
        model["references"][0]["optional"] = 0
        with self.assertRaises(ValueError):
            analyze_supplied_kubernetes_secret_references(model)
        model = component_fixture()
        model["objects"][0]["keys"] = ["mode", "mode"]
        with self.assertRaises(ValueError):
            analyze_supplied_kubernetes_secret_references(model)

    def test_replay_and_export_forgery_fail_closed(self) -> None:
        model = component_fixture()
        report = analyze_supplied_kubernetes_secret_references(model)
        original_json = report.to_json()
        model["objects"][0]["metadata_complete"] = False
        self.assertEqual(report.to_json(), original_json)
        model = component_fixture()
        changed = copy.deepcopy(model)
        changed["objects"][0]["keys"].append("endpoint")
        with self.assertRaises(KubernetesSecretReferencesError):
            verify_supplied_kubernetes_secret_references(report, model=changed)
        with self.assertRaises(KubernetesSecretReferencesError):
            verify_supplied_kubernetes_secret_references(report.to_dict(), model=model)
        class SubReport(KubernetesSecretReferencesReport):
            pass

        with self.assertRaises(KubernetesSecretReferencesError):
            verify_supplied_kubernetes_secret_references(
                SubReport._owned(report.to_dict()), model=model
            )
        with self.assertRaises(ValueError):
            verify_supplied_kubernetes_secret_references_bytes(b"{}", model=model)
        forged = report.to_dict()
        forged["candidate_count"] = 0
        with self.assertRaises(KubernetesSecretReferencesError):
            verify_supplied_kubernetes_secret_references_bytes(
                json.dumps(forged).encode("ascii"), model=model
            )
        with self.assertRaises(KubernetesSecretReferencesError):
            KubernetesSecretReferencesReport({})
        duplicate = report.to_json().replace(
            '"schema_version":1', '"schema_version":1,"schema_version":1', 1
        )
        with self.assertRaises(ValueError):
            verify_supplied_kubernetes_secret_references_bytes(
                duplicate.encode("ascii"), model=model
            )


if __name__ == "__main__":
    unittest.main()
