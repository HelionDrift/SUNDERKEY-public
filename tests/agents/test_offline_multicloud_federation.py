"""Synthetic cross-provider federation projection and source replay tests."""

from __future__ import annotations

import copy
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_multicloud_federation as federation

ERROR = federation.MulticloudFederationAnalysisError


def fixture() -> dict:
    return federation.component_fixture()


def analyze(model: dict) -> dict:
    return federation.analyze_supplied_multicloud_federation(model).to_dict()


def row(model: dict, exchange_id: str = "deny-issued") -> dict:
    return next(
        item
        for item in analyze(model)["exchange_observations"]
        if item["exchange_id"] == exchange_id
    )


class MulticloudFederationTests(unittest.TestCase):
    def deny_before_hash(self, model: dict) -> None:
        with patch.object(federation, "_address") as address:
            with self.assertRaises(ERROR):
                federation.analyze_supplied_multicloud_federation(model)
            address.assert_not_called()

    def test_fixture_replay_and_no_effects(self):
        model = fixture()
        report = federation.analyze_supplied_multicloud_federation(model)
        document = report.to_dict()
        self.assertEqual(document["profile_id"], "AOE-GC-D14-S09")
        self.assertEqual(document["blueprint_sha256"], federation.BLUEPRINT_SHA256)
        self.assertEqual(document["independent_validator_id"], "AOE-HQ-19")
        self.assertEqual(document["candidate_count"], 1)
        self.assertEqual(document["unknown_count"], 2)
        self.assertEqual(
            [item["outcome"] for item in document["exchange_observations"]],
            [
                "candidate_declared_deny_issued_contradiction",
                "unknown",
                "unknown",
            ],
        )
        self.assertEqual(
            document["exchange_observations"][0]["mismatched_declarations"], ["audience_id"]
        )
        self.assertEqual(set(document["effects"].values()), {"none"})
        self.assertTrue(all(value is False for value in document["flags"].values()))
        self.assertEqual(
            report.to_json(), federation.analyze_supplied_multicloud_federation(model).to_json()
        )
        parsed = federation.MulticloudFederationAnalysis.from_json(report.to_json())
        self.assertEqual(
            federation.verify_supplied_multicloud_federation_analysis(
                parsed, model=model
            ).to_json(),
            report.to_json(),
        )
        model["trusts"][0]["audience_id"] = "audience-other"
        with self.assertRaises(ERROR):
            federation.verify_supplied_multicloud_federation_analysis(report, model=model)

    def test_exact_cross_provider_identity_and_disabled_trust(self):
        model = fixture()
        exchange = model["exchanges"][0]
        exchange["audience_id"] = "audience-b"
        self.assertEqual(row(model)["outcome"], "unknown")
        self.assertIn("unmodeled_issuance_conditions", row(model)["uncertainty"])
        exchange["subject_id"] = "workload-a.extra"
        self.assertEqual(row(model)["mismatched_declarations"], ["subject_id"])
        exchange["subject_id"] = "workload-a"
        exchange["source_tenant"] = "aws-account-other"
        self.assertEqual(row(model)["mismatched_declarations"], ["source_tenant"])
        exchange["source_tenant"] = "aws-account-a"
        model["trusts"][0]["enabled"] = False
        self.assertEqual(row(model)["mismatched_declarations"], ["trust_disabled"])
        exchange["supplied_outcome"] = "denied"
        self.assertEqual(row(model)["outcome"], "matches_declared_trust")
        self.assertEqual(analyze(model)["candidate_count"], 1)

    def test_declared_failed_assertion_and_no_guaranteed_issuance(self):
        model = fixture()
        model["exchanges"][0]["audience_id"] = "audience-b"
        model["exchanges"][0]["assertion_disposition"] = "failed"
        self.assertEqual(row(model)["expected_outcome"], "deny")
        self.assertIn("assertion_failed", row(model)["mismatched_declarations"])
        model["exchanges"][0]["assertion_disposition"] = "declared_verified"
        model["exchanges"][0]["supplied_outcome"] = "denied"
        self.assertEqual(row(model)["outcome"], "unknown")
        self.assertIn("unmodeled_issuance_conditions", row(model)["uncertainty"])
        self.assertEqual(analyze(model)["candidate_count"], 0)

    def test_unknown_incomplete_premises_never_candidate(self):
        cases = (
            (
                "contract",
                lambda x: x["trusts"][0].update(contract_complete=False),
                "trust_contract_incomplete",
            ),
            (
                "context",
                lambda x: x["exchanges"][0].update(context_complete=False),
                "exchange_context_incomplete",
            ),
            (
                "observation",
                lambda x: x["exchanges"][0].update(supplied_outcome="unknown"),
                "exchange_observation_incomplete",
            ),
            (
                "assertion",
                lambda x: x["exchanges"][0].update(assertion_disposition="unknown"),
                "assertion_disposition_unknown",
            ),
            (
                "issuer",
                lambda x: x["exchanges"][0].update(issuer_id="unknown"),
                "issuer_id_unknown",
            ),
            (
                "target",
                lambda x: x["exchanges"][0].update(target_tenant="unknown"),
                "target_tenant_unknown",
            ),
        )
        for name, change, reason in cases:
            with self.subTest(name=name):
                model = fixture()
                change(model)
                observed = row(model)
                self.assertEqual(observed["outcome"], "unknown")
                self.assertIn(reason, observed["uncertainty"])

    def test_closed_types_references_and_provider_boundaries(self):
        changes = (
            lambda x: x.update(extra=True),
            lambda x: x.update(schema_version=True),
            lambda x: x["trusts"][0].update(source_provider="other"),
            lambda x: x["trusts"][0].update(target_provider="aws"),
            lambda x: x["trusts"][0].update(enabled=1),
            lambda x: x["trusts"][0].update(contract_complete=1),
            lambda x: x["exchanges"][0].update(trust_id="missing"),
            lambda x: x["exchanges"][0].update(target_provider="aws"),
            lambda x: x["exchanges"][0].update(assertion_disposition="token"),
            lambda x: x["exchanges"][0].update(context_complete=1),
            lambda x: x["exchanges"][0].update(observation_complete=1),
            lambda x: x["exchanges"].reverse(),
        )
        for change in changes:
            model = fixture()
            change(model)
            with self.subTest(model=model):
                self.deny_before_hash(model)

    def test_raw_bytes_and_forged_report(self):
        model = fixture()
        raw = json.dumps(model, sort_keys=True, separators=(",", ":")).encode("ascii")
        report = federation.analyze_supplied_multicloud_federation(model)
        self.assertEqual(
            federation.analyze_supplied_multicloud_federation_bytes(model_bytes=raw).to_json(),
            report.to_json(),
        )
        for data in (
            b'{"schema_version":1,"schema_version":1}',
            raw.replace(b'"schema_version":1', b'"schema_version":1.0'),
            raw + b"x",
            b"\xff",
        ):
            with self.subTest(data=data[:40]):
                with self.assertRaises(ERROR):
                    federation.analyze_supplied_multicloud_federation_bytes(model_bytes=data)
        forged = copy.deepcopy(report.to_dict())
        forged["candidate_count"] = 0
        with self.assertRaises(ERROR):
            federation.MulticloudFederationAnalysis.from_dict(forged)
        forged = copy.deepcopy(report.to_dict())
        forged["source_model"]["trusts"][0]["audience_id"] = "audience-other"
        with self.assertRaises(ERROR):
            federation.MulticloudFederationAnalysis.from_dict(forged)
        with self.assertRaises(ERROR):
            federation.verify_supplied_multicloud_federation_analysis(report.to_dict(), model=model)

    def test_native_cycle_and_bounds(self):
        model = fixture()
        model["cycle"] = model
        self.deny_before_hash(model)
        model = fixture()
        model["exchanges"] = model["exchanges"] * (federation.MAX_EXCHANGES + 1)
        self.deny_before_hash(model)
        model = fixture()
        model["exchanges"][0]["exchange_id"] = "x" * (federation.MAX_STRING_BYTES + 1)
        self.deny_before_hash(model)


if __name__ == "__main__":
    unittest.main()
