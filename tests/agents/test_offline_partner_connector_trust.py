"""Synthetic partner connector trust projection and replay controls."""

from __future__ import annotations

import copy
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_partner_connector_trust as connector

ERROR = connector.PartnerConnectorTrustAnalysisError


def fixture() -> dict:
    return connector.component_fixture()


def analyze(model: dict) -> dict:
    return connector.analyze_supplied_partner_connector_trust(model).to_dict()


def observation(model: dict, transfer_id: str = "allowed-contradiction") -> dict:
    return next(
        row for row in analyze(model)["transfer_observations"] if row["transfer_id"] == transfer_id
    )


class PartnerConnectorTrustTests(unittest.TestCase):
    def deny_before_hash(self, model: dict) -> None:
        with patch.object(connector, "_address") as address:
            with self.assertRaises(ERROR):
                connector.analyze_supplied_partner_connector_trust(model)
            address.assert_not_called()

    def test_fixture_determinism_effects_and_original_replay(self):
        source = fixture()
        report = connector.analyze_supplied_partner_connector_trust(source)
        document = report.to_dict()
        self.assertEqual(document["profile_id"], "AOE-GB-D06-S16")
        self.assertEqual(document["blueprint_sha256"], connector.BLUEPRINT_SHA256)
        self.assertEqual(document["candidate_count"], 1)
        self.assertEqual(document["unknown_count"], 1)
        self.assertEqual(
            [row["outcome"] for row in document["transfer_observations"]],
            [
                "candidate_declared_deny_allowed_contradiction",
                "matches_declared_policy",
                "unknown",
            ],
        )
        self.assertEqual(
            document["transfer_observations"][0]["violated_declarations"],
            ["partner_mismatch"],
        )
        self.assertEqual(set(document["effects"].values()), {"none"})
        self.assertTrue(all(value is False for value in document["flags"].values()))
        self.assertEqual(
            report.to_json(), connector.analyze_supplied_partner_connector_trust(source).to_json()
        )
        detached = connector.PartnerConnectorTrustAnalysis.from_json(report.to_json())
        self.assertEqual(
            connector.verify_supplied_partner_connector_trust_analysis(
                detached, model=source
            ).to_json(),
            report.to_json(),
        )
        source["connectors"][0]["partner_id"] = "partner-b"
        self.assertEqual(document["candidate_count"], 1)
        with self.assertRaises(ERROR):
            connector.verify_supplied_partner_connector_trust_analysis(report, model=source)

    def test_exact_identity_scope_partner_and_data_class_guards(self):
        source = fixture()
        transfer = source["transfers"][0]
        transfer["destination_partner_id"] = "partner-a"
        self.assertEqual(observation(source)["outcome"], "matches_declared_policy")
        transfer["presented_identity"] = "connector-orders-extra"
        self.assertEqual(observation(source)["violated_declarations"], ["identity_mismatch"])
        transfer["presented_identity"] = "connector-orders"
        transfer["required_scope"] = "orders.read.extra"
        self.assertEqual(observation(source)["violated_declarations"], ["scope_not_granted"])
        transfer["required_scope"] = "orders.read"
        transfer["data_class"] = "restricted"
        self.assertEqual(observation(source)["violated_declarations"], ["data_class_not_allowed"])
        transfer["observed_outcome"] = "denied"
        self.assertEqual(observation(source)["outcome"], "matches_declared_policy")
        self.assertEqual(analyze(source)["candidate_count"], 0)

    def test_allow_denied_is_not_security_bypass_candidate(self):
        source = fixture()
        transfer = source["transfers"][0]
        transfer["destination_partner_id"] = "partner-a"
        transfer["observed_outcome"] = "denied"
        row = observation(source)
        self.assertEqual(row["expected_outcome"], "allow")
        self.assertEqual(row["outcome"], "declared_allow_denied_contradiction")
        self.assertEqual(analyze(source)["candidate_count"], 0)

    def test_unknowns_never_become_candidate(self):
        cases = (
            ("disabled", lambda x: x["connectors"][0].update(enabled=False), "connector_disabled"),
            (
                "policy",
                lambda x: x["connectors"][0].update(policy_complete=False),
                "connector_policy_incomplete",
            ),
            (
                "context",
                lambda x: x["transfers"][0].update(context_complete=False),
                "transfer_context_incomplete",
            ),
            (
                "observation",
                lambda x: x["transfers"][0].update(observed_outcome="unknown"),
                "transfer_observation_incomplete",
            ),
            (
                "direction",
                lambda x: x["transfers"][0].update(direction="unknown"),
                "transfer_direction_unknown",
            ),
            (
                "identity",
                lambda x: x["transfers"][0].update(presented_identity="unknown"),
                "presented_identity_unknown",
            ),
            (
                "partner",
                lambda x: x["transfers"][0].update(destination_partner_id="unknown"),
                "destination_partner_id_unknown",
            ),
            (
                "scope",
                lambda x: x["transfers"][0].update(required_scope="unknown"),
                "required_scope_unknown",
            ),
            (
                "class",
                lambda x: x["transfers"][0].update(data_class="unknown"),
                "data_class_unknown",
            ),
        )
        for name, change, reason in cases:
            with self.subTest(name=name):
                source = fixture()
                change(source)
                row = observation(source)
                self.assertEqual(row["outcome"], "unknown")
                self.assertIn(reason, row["uncertainty"])

    def test_closed_types_references_and_no_widening(self):
        changes = (
            lambda x: x.update(extra=True),
            lambda x: x.update(schema_version=True),
            lambda x: x["connectors"][0].update(connector_kind="other"),
            lambda x: x["connectors"][0].update(enabled=1),
            lambda x: x["connectors"][0].update(policy_complete=1),
            lambda x: x["connectors"][0].update(allowed_scopes=["orders.*"]),
            lambda x: x["connectors"][0].update(allowed_scopes=["orders.read"] * 2),
            lambda x: x["connectors"][0].update(allowed_data_classes=["internal"] * 2),
            lambda x: x["transfers"][0].update(connector_id="other"),
            lambda x: x["transfers"][0].update(direction="inbound"),
            lambda x: x["transfers"][0].update(context_complete=1),
            lambda x: x["transfers"][0].update(observation_complete=1),
            lambda x: x["transfers"][0].update(data_class="bad class"),
            lambda x: x["transfers"].reverse(),
        )
        for change in changes:
            source = fixture()
            change(source)
            with self.subTest(source=source):
                self.deny_before_hash(source)

    def test_bytes_duplicate_keys_fractions_and_report_forgery(self):
        source = fixture()
        raw = json.dumps(source, sort_keys=True, separators=(",", ":")).encode("ascii")
        direct = connector.analyze_supplied_partner_connector_trust(source)
        self.assertEqual(
            connector.analyze_supplied_partner_connector_trust_bytes(model_bytes=raw).to_json(),
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
                    connector.analyze_supplied_partner_connector_trust_bytes(model_bytes=data)
        forged = copy.deepcopy(direct.to_dict())
        forged["candidate_count"] = 0
        with self.assertRaises(ERROR):
            connector.PartnerConnectorTrustAnalysis.from_dict(forged)
        forged = copy.deepcopy(direct.to_dict())
        forged["source_model"]["connectors"][0]["partner_id"] = "partner-b"
        with self.assertRaises(ERROR):
            connector.PartnerConnectorTrustAnalysis.from_dict(forged)
        with self.assertRaises(ERROR):
            connector.verify_supplied_partner_connector_trust_analysis(
                direct.to_dict(), model=source
            )

    def test_native_cycles_and_bounds(self):
        source = fixture()
        source["cycle"] = source
        self.deny_before_hash(source)
        source = fixture()
        source["transfers"] = source["transfers"] * (connector.MAX_TRANSFERS + 1)
        self.deny_before_hash(source)
        source = fixture()
        source["transfers"][0]["transfer_id"] = "x" * (connector.MAX_STRING_BYTES + 1)
        self.deny_before_hash(source)


if __name__ == "__main__":
    unittest.main()
