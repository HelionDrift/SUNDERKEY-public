"""Inert supplied Kubernetes API authentication context tests."""

from __future__ import annotations

import copy
import json
import unittest

from sunderkey.offline_kubernetes_api_authentication import (
    KubernetesApiAuthenticationError,
    KubernetesApiAuthenticationReport,
    analyze_supplied_kubernetes_api_authentication,
    analyze_supplied_kubernetes_api_authentication_bytes,
    component_fixture,
    verify_supplied_kubernetes_api_authentication,
    verify_supplied_kubernetes_api_authentication_bytes,
)


class KubernetesApiAuthenticationTests(unittest.TestCase):
    def test_candidate_is_only_a_supplied_contradiction(self) -> None:
        model = component_fixture()
        report = analyze_supplied_kubernetes_api_authentication(model)
        body = report.to_dict()
        self.assertEqual(body["profile_id"], "AOE-GC-D15-S03")
        self.assertEqual(body["wave_id"], "IW2-005")
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["request_rows"][0]["reason"], "declared_expired_credential")
        self.assertFalse(body["api_contacted"])
        self.assertFalse(body["credential_bytes_accepted"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            analyze_supplied_kubernetes_api_authentication_bytes(
                model_bytes=json.dumps(model).encode("ascii")
            ).to_json(), report.to_json()
        )
        self.assertEqual(
            verify_supplied_kubernetes_api_authentication(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            verify_supplied_kubernetes_api_authentication_bytes(
                report.to_json().encode("ascii"), model=model
            ).to_json(), report.to_json(),
        )

    def test_other_explicit_contradictions_and_unknown_premises(self) -> None:
        model = component_fixture()
        model["credentials"][0]["validity"] = "expired"
        self.assertEqual(
            analyze_supplied_kubernetes_api_authentication(model).to_dict()["request_rows"][0]["reason"],
            "declared_expired_credential",
        )
        model["credentials"][0]["validity"] = "valid"
        model["requests"][0]["expected_principal_id"] = "other-sa"
        body = analyze_supplied_kubernetes_api_authentication(model).to_dict()
        self.assertEqual(body["request_rows"][0]["reason"], "declared_principal_mismatch")
        self.assertIsNone(body["request_rows"][0]["expected_authentication"])
        self.assertEqual(body["candidate_count"], 0)
        model["requests"][0]["expected_principal_id"] = "team-a-sa"
        model["requests"][0]["audience_id"] = "api-b"
        body = analyze_supplied_kubernetes_api_authentication(model).to_dict()
        self.assertEqual(body["request_rows"][0]["reason"], "declared_audience_mismatch")
        self.assertIsNone(body["request_rows"][0]["expected_authentication"])
        self.assertEqual(body["candidate_count"], 0)
        model["inventory_complete"] = False
        body = analyze_supplied_kubernetes_api_authentication(model).to_dict()
        self.assertEqual(body["candidate_count"], 0)
        self.assertEqual(body["request_rows"][0]["disposition"], "unknown")
        self.assertIsNone(body["request_rows"][0]["expected_authentication"])
        for field in ("context_complete", "observation_complete"):
            changed = component_fixture()
            changed["requests"][0][field] = False
            self.assertEqual(
                analyze_supplied_kubernetes_api_authentication(changed).to_dict()["candidate_count"],
                0,
            )

    def test_closed_source_rejects_raw_credentials_and_exact_types(self) -> None:
        for field, value in (("token", "eyJabc"), ("private_key", "raw"), ("kubeconfig", "raw")):
            model = component_fixture()
            model["credentials"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                analyze_supplied_kubernetes_api_authentication(model)
        for field, value in (("inventory_complete", 1), ("schema_version", True)):
            model = component_fixture()
            model[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                analyze_supplied_kubernetes_api_authentication(model)
        model = component_fixture()
        model["credentials"][0]["metadata_complete"] = 1
        with self.assertRaises(ValueError):
            analyze_supplied_kubernetes_api_authentication(model)
        model = component_fixture()
        model["requests"] *= 129
        with self.assertRaises(ValueError):
            analyze_supplied_kubernetes_api_authentication(model)

    def test_replay_and_export_forgery_fail_closed(self) -> None:
        model = component_fixture()
        report = analyze_supplied_kubernetes_api_authentication(model)
        original_json = report.to_json()
        model["credentials"][0]["validity"] = "unknown"
        self.assertEqual(report.to_json(), original_json)
        model = component_fixture()
        changed = copy.deepcopy(model)
        changed["requests"][0]["supplied_outcome"] = "rejected"
        with self.assertRaises(KubernetesApiAuthenticationError):
            verify_supplied_kubernetes_api_authentication(report, model=changed)
        with self.assertRaises(KubernetesApiAuthenticationError):
            verify_supplied_kubernetes_api_authentication(report.to_dict(), model=model)
        class SubReport(KubernetesApiAuthenticationReport):
            pass

        with self.assertRaises(KubernetesApiAuthenticationError):
            verify_supplied_kubernetes_api_authentication(
                SubReport._owned(report.to_dict()), model=model
            )
        with self.assertRaises(ValueError):
            verify_supplied_kubernetes_api_authentication_bytes(b"{}", model=model)
        forged = report.to_dict()
        forged["candidate_count"] = 0
        with self.assertRaises(KubernetesApiAuthenticationError):
            verify_supplied_kubernetes_api_authentication_bytes(
                json.dumps(forged).encode("ascii"), model=model
            )
        with self.assertRaises(KubernetesApiAuthenticationError):
            KubernetesApiAuthenticationReport({})
        duplicate = report.to_json().replace(
            '"schema_version":1', '"schema_version":1,"schema_version":1', 1
        )
        with self.assertRaises(ValueError):
            verify_supplied_kubernetes_api_authentication_bytes(
                duplicate.encode("ascii"), model=model
            )


if __name__ == "__main__":
    unittest.main()
