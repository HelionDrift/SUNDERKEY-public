"""Synthetic mesh trust projection and original-source replay tests."""

from __future__ import annotations

import copy
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_service_mesh_trust as mesh

ERROR = mesh.ServiceMeshTrustAnalysisError


def fixture() -> dict:
    return mesh.component_fixture()


def analyze(model: dict) -> dict:
    return mesh.analyze_supplied_service_mesh_trust(model).to_dict()


def observation(model: dict, flow_id: str = "deny-allowed") -> dict:
    return next(row for row in analyze(model)["flow_observations"] if row["flow_id"] == flow_id)


class ServiceMeshTrustTests(unittest.TestCase):
    def deny_before_hash(self, model: dict) -> None:
        with patch.object(mesh, "_address") as address:
            with self.assertRaises(ERROR):
                mesh.analyze_supplied_service_mesh_trust(model)
            address.assert_not_called()

    def test_fixture_projection_effects_and_original_replay(self):
        source = fixture()
        report = mesh.analyze_supplied_service_mesh_trust(source)
        document = report.to_dict()
        self.assertEqual(document["profile_id"], "AOE-GB-D06-S08")
        self.assertEqual(document["blueprint_sha256"], mesh.BLUEPRINT_SHA256)
        self.assertEqual(document["candidate_count"], 1)
        self.assertEqual(document["unknown_count"], 1)
        self.assertEqual(
            [row["outcome"] for row in document["flow_observations"]],
            [
                "candidate_declared_deny_allowed_contradiction",
                "matches_declared_policy",
                "unknown",
            ],
        )
        self.assertEqual(document["flow_observations"][0]["expected_outcome"], "deny")
        self.assertIn("sidecar_path_not_proven", document["flow_observations"][2]["uncertainty"])
        self.assertEqual(set(document["effects"].values()), {"none"})
        self.assertTrue(all(value is False for value in document["flags"].values()))
        self.assertEqual(
            report.to_json(), mesh.analyze_supplied_service_mesh_trust(source).to_json()
        )
        detached = mesh.ServiceMeshTrustAnalysis.from_json(report.to_json())
        self.assertEqual(
            mesh.verify_supplied_service_mesh_trust_analysis(detached, model=source).to_json(),
            report.to_json(),
        )
        source["flows"][0]["observed_outcome"] = "denied"
        self.assertEqual(document["candidate_count"], 1)
        with self.assertRaises(ERROR):
            mesh.verify_supplied_service_mesh_trust_analysis(report, model=source)

    def test_exact_identity_policy_and_strict_plaintext(self):
        source = fixture()
        source["policies"][0]["allowed_identities"] = ["spiffe://demo/client"]
        self.assertEqual(observation(source)["expected_outcome"], "allow")
        self.assertEqual(observation(source)["outcome"], "matches_declared_policy")
        source["flows"][0]["observed_outcome"] = "denied"
        self.assertEqual(observation(source)["outcome"], "declared_allow_denied_contradiction")
        self.assertEqual(analyze(source)["candidate_count"], 0)
        source["policies"][0]["allowed_identities"] = ["spiffe://demo/client-extra"]
        self.assertEqual(observation(source)["expected_outcome"], "deny")
        source["flows"][0]["observed_outcome"] = "allowed"
        self.assertEqual(
            observation(source)["outcome"], "candidate_declared_deny_allowed_contradiction"
        )
        source["flows"][0]["transport"] = "plaintext"
        source["flows"][0]["identity_binding_complete"] = False
        source["flows"][0]["presented_identity"] = "unknown"
        self.assertEqual(observation(source)["expected_outcome"], "deny")

    def test_unknown_mesh_modes_and_paths_never_create_candidate(self):
        cases = (
            (
                "permissive",
                lambda x: x["policies"][0].update(mtls_mode="permissive"),
                "non_strict_or_unknown_mtls_mode",
            ),
            (
                "disabled",
                lambda x: x["policies"][0].update(mtls_mode="disabled"),
                "non_strict_or_unknown_mtls_mode",
            ),
            ("policy", lambda x: x["policies"][0].update(complete=False), "policy_incomplete"),
            ("route", lambda x: x["routes"][0].update(complete=False), "route_incomplete"),
            (
                "source_absent",
                lambda x: x["workloads"][0].update(sidecar_present=False),
                "sidecar_absent",
            ),
            (
                "destination_absent",
                lambda x: x["workloads"][1].update(sidecar_present=False),
                "sidecar_absent",
            ),
            (
                "sidecar_incomplete",
                lambda x: x["workloads"][1].update(sidecar_complete=False),
                "sidecar_semantics_incomplete",
            ),
            (
                "source_bypass",
                lambda x: x["flows"][0].update(source_path="bypass"),
                "sidecar_path_not_proven",
            ),
            (
                "destination_bypass",
                lambda x: x["flows"][0].update(destination_path="bypass"),
                "sidecar_path_not_proven",
            ),
            ("transport", lambda x: x["flows"][0].update(transport="unknown"), "transport_unknown"),
            (
                "outcome",
                lambda x: x["flows"][0].update(observed_outcome="unknown"),
                "observation_incomplete",
            ),
            (
                "identity_binding",
                lambda x: x["flows"][0].update(identity_binding_complete=False),
                "identity_binding_incomplete",
            ),
            (
                "identity_mismatch",
                lambda x: x["flows"][0].update(presented_identity="spiffe://demo/other"),
                "presented_identity_mismatch",
            ),
            (
                "identity_rule",
                lambda x: x["policies"][0].update(identity_rule="unknown", allowed_identities=[]),
                "identity_rule_unknown",
            ),
        )
        for name, change, reason in cases:
            with self.subTest(name=name):
                source = fixture()
                change(source)
                row = observation(source)
                self.assertEqual(row["outcome"], "unknown")
                self.assertIn(reason, row["uncertainty"])

    def test_route_and_identity_false_positive_guards(self):
        source = fixture()
        source["flows"][0]["presented_identity"] = "spiffe://demo/server"
        self.assertEqual(observation(source)["outcome"], "unknown")
        source = fixture()
        source["policies"][0]["identity_rule"] = "allow_any"
        source["policies"][0]["allowed_identities"] = []
        self.assertEqual(observation(source)["expected_outcome"], "allow")
        self.assertEqual(observation(source)["outcome"], "matches_declared_policy")
        source["routes"][0]["service_id"] = "wrong"
        self.deny_before_hash(source)

    def test_unknown_identity_cannot_support_mtls_policy_contradiction(self):
        source = fixture()
        source["workloads"][0]["identity"] = "unknown"
        source["flows"][0]["presented_identity"] = "unknown"
        self.deny_before_hash(source)
        source = fixture()
        source["flows"][0]["presented_identity"] = "unknown"
        row = observation(source)
        self.assertEqual(row["outcome"], "unknown")
        self.assertIn("presented_identity_unknown", row["uncertainty"])
        source["flows"][0]["transport"] = "plaintext"
        self.assertEqual(observation(source)["expected_outcome"], "deny")

    def test_closed_types_references_and_no_rule_widening(self):
        changes = (
            lambda x: x.update(extra=True),
            lambda x: x.update(schema_version=True),
            lambda x: x["workloads"][0].update(sidecar_present=1),
            lambda x: x["workloads"][0].update(identity="spiffe://demo/client?query"),
            lambda x: x["workloads"][0].update(workload_id="server"),
            lambda x: x["routes"][0].update(destination_id="missing"),
            lambda x: x["routes"][0].update(policy_id="missing"),
            lambda x: x["routes"][0].update(complete=1),
            lambda x: x["policies"][0].update(mtls_mode="auto"),
            lambda x: x["policies"][0].update(identity_rule="regex"),
            lambda x: x["policies"][0].update(allowed_identities=["spiffe://demo/server"] * 2),
            lambda x: x["flows"][0].update(source_id="missing"),
            lambda x: x["flows"][0].update(route_id="missing"),
            lambda x: x["flows"][0].update(source_path="ambient"),
            lambda x: x["flows"][0].update(observation_complete=1),
            lambda x: x["flows"].reverse(),
        )
        for change in changes:
            source = fixture()
            change(source)
            with self.subTest(source=source):
                self.deny_before_hash(source)

    def test_bytes_duplicate_keys_fractional_and_report_forgery(self):
        source = fixture()
        raw = json.dumps(source, sort_keys=True, separators=(",", ":")).encode("ascii")
        direct = mesh.analyze_supplied_service_mesh_trust(source)
        self.assertEqual(
            mesh.analyze_supplied_service_mesh_trust_bytes(model_bytes=raw).to_json(),
            direct.to_json(),
        )
        for data in (
            b'{"schema_version":1,"schema_version":1}',
            raw.replace(b'"schema_version":1', b'"schema_version":1.0'),
            raw + b"x",
            b"\xff",
        ):
            with self.subTest(data=data[:40]):
                with self.assertRaises(ERROR):
                    mesh.analyze_supplied_service_mesh_trust_bytes(model_bytes=data)
        forged = copy.deepcopy(direct.to_dict())
        forged["candidate_count"] = 0
        with self.assertRaises(ERROR):
            mesh.ServiceMeshTrustAnalysis.from_dict(forged)
        forged = copy.deepcopy(direct.to_dict())
        forged["source_model"]["policies"][0]["mtls_mode"] = "permissive"
        with self.assertRaises(ERROR):
            mesh.ServiceMeshTrustAnalysis.from_dict(forged)
        with self.assertRaises(ERROR):
            mesh.verify_supplied_service_mesh_trust_analysis(direct.to_dict(), model=source)

    def test_native_cycle_and_bounds(self):
        source = fixture()
        source["cycle"] = source
        self.deny_before_hash(source)
        source = fixture()
        source["flows"] = source["flows"] * (mesh.MAX_FLOWS + 1)
        self.deny_before_hash(source)
        source = fixture()
        source["flows"][0]["flow_id"] = "x" * (mesh.MAX_STRING_BYTES + 1)
        self.deny_before_hash(source)


if __name__ == "__main__":
    unittest.main()
