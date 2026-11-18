"""Synthetic source-bound tests for declared webhook receiver policy."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_webhook_callback_trust as webhook


def encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def readdress(document: dict) -> dict:
    changed = copy.deepcopy(document)
    body = {
        key: value for key, value in changed.items() if key not in {"report_id", "report_sha256"}
    }
    digest = hashlib.sha256(encoded({"domain": webhook.DOMAIN, "analysis": body})).hexdigest()
    changed["report_id"] = "WCT-" + digest[:32].upper()
    changed["report_sha256"] = "sha256:" + digest
    return changed


class BytesAlias(bytes):
    pass


class StringAlias(str):
    pass


class DictAlias(dict):
    pass


class ReportAlias(webhook.WebhookCallbackTrustReport):
    pass


class OfflineWebhookCallbackTrustTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = webhook.component_fixture()
        self.source_id = "synthetic:webhook"

    def analyze(self, model=None) -> webhook.WebhookCallbackTrustReport:
        return webhook.analyze_webhook_callback_trust(
            source_content=encoded(self.model if model is None else model),
            source_id=self.source_id,
        )

    def test_fixture_source_replay_and_no_effects(self) -> None:
        content = encoded(self.model)
        report = self.analyze().to_dict()
        self.assertEqual(report["profile_id"], "AOE-GB-D06-S06")
        self.assertEqual(report["capability_id"], "army.gb.d06.s06")
        self.assertEqual(
            report["source"]["sha256"], "sha256:" + hashlib.sha256(content).hexdigest()
        )
        projections = {p["delivery_id"]: p for p in report["projections"]}
        self.assertEqual(projections["delivery-fresh"]["expected_decision"], "accept")
        self.assertEqual(projections["delivery-fresh"]["assessment"], "declared_consistent")
        self.assertEqual(projections["delivery-replay"]["basis"], "replay_event_id")
        self.assertEqual(
            projections["delivery-replay"]["assessment"], "candidate_policy_contradiction"
        )
        self.assertEqual(report["summary"]["delivery_count"], 2)
        self.assertFalse(report["signature_verified_live"])
        self.assertFalse(report["callback_performed"])
        self.assertFalse(report["finding_claimed"])
        self.assertTrue(all(value == "none" for value in report["effects"].values()))

    def test_source_destination_and_complete_missing_policy(self) -> None:
        model = copy.deepcopy(self.model)
        model["deliveries"] = [model["deliveries"][0]]
        model["deliveries"][0]["producer_id"] = "other-service"
        p = self.analyze(model).to_dict()["projections"][0]
        self.assertEqual((p["expected_decision"], p["basis"]), ("reject", "producer_not_allowed"))
        model["deliveries"][0]["producer_id"] = "billing-service"
        model["deliveries"][0]["receiver_id"] = "unlisted-hook"
        p = self.analyze(model).to_dict()["projections"][0]
        self.assertEqual((p["expected_decision"], p["basis"]), ("reject", "no_receiver_policy"))
        model["policy_complete"] = False
        p = self.analyze(model).to_dict()["projections"][0]
        self.assertEqual((p["expected_decision"], p["assessment"]), ("unknown", "unknown"))

    def test_signature_disposition_is_declared_not_cryptographic(self) -> None:
        model = copy.deepcopy(self.model)
        model["deliveries"] = [model["deliveries"][0]]
        for disposition, expected, basis in (
            ("failed", "reject", "signature_not_verified"),
            ("not_checked", "reject", "signature_not_verified"),
            ("unknown", "unknown", "unknown_signature"),
            ("verified", "accept", "all_declared_checks_pass"),
        ):
            model["deliveries"][0]["signature_disposition"] = disposition
            with self.subTest(disposition=disposition):
                p = self.analyze(model).to_dict()["projections"][0]
                self.assertEqual((p["expected_decision"], p["basis"]), (expected, basis))
        model["receivers"][0]["signature_required"] = False
        model["deliveries"][0]["signature_disposition"] = "unknown"
        p = self.analyze(model).to_dict()["projections"][0]
        self.assertEqual(p["expected_decision"], "accept")

    def test_replay_context_is_receiver_scoped_and_not_observation_order(self) -> None:
        model = copy.deepcopy(self.model)
        model["deliveries"] = [model["deliveries"][1]]
        model["prior_acceptances"][0]["receiver_id"] = "other-hook"
        p = self.analyze(model).to_dict()["projections"][0]
        self.assertEqual(p["expected_decision"], "accept")
        model = copy.deepcopy(self.model)
        model["receivers"][0]["replay_key"] = "idempotency_key"
        p = {p["delivery_id"]: p for p in self.analyze(model).to_dict()["projections"]}
        self.assertEqual(p["delivery-replay"]["basis"], "replay_idempotency_key")
        model["deliveries"][1]["idempotency_key_id"] = None
        p = {p["delivery_id"]: p for p in self.analyze(model).to_dict()["projections"]}
        self.assertEqual(p["delivery-replay"]["basis"], "missing_idempotency_key")
        self.assertEqual(p["delivery-replay"]["assessment"], "unknown")
        model["receivers"][0]["replay_key"] = "none"
        p = {p["delivery_id"]: p for p in self.analyze(model).to_dict()["projections"]}
        self.assertEqual(p["delivery-replay"]["expected_decision"], "accept")

    def test_age_boundary_staleness_and_missing_age(self) -> None:
        model = copy.deepcopy(self.model)
        model["deliveries"] = [model["deliveries"][0]]
        for age, expected, basis in (
            (300, "accept", "all_declared_checks_pass"),
            (301, "reject", "stale_event"),
            (None, "unknown", "unknown_age"),
        ):
            model["deliveries"][0]["age_seconds"] = age
            with self.subTest(age=age):
                p = self.analyze(model).to_dict()["projections"][0]
                self.assertEqual((p["expected_decision"], p["basis"]), (expected, basis))
        model["receivers"][0]["max_age_seconds"] = None
        p = self.analyze(model).to_dict()["projections"][0]
        self.assertEqual(p["expected_decision"], "accept")

    def test_known_denial_wins_over_unrelated_unknown_premises(self) -> None:
        model = copy.deepcopy(self.model)
        model["deliveries"] = [model["deliveries"][0]]
        model["deliveries"][0]["signature_disposition"] = "unknown"
        model["deliveries"][0]["age_seconds"] = None
        model["deliveries"][0]["producer_id"] = "unlisted"
        p = self.analyze(model).to_dict()["projections"][0]
        self.assertEqual((p["expected_decision"], p["basis"]), ("reject", "producer_not_allowed"))
        model["deliveries"][0]["producer_id"] = "billing-service"
        model["deliveries"][0]["event_id"] = "evt-old"
        p = self.analyze(model).to_dict()["projections"][0]
        self.assertEqual((p["expected_decision"], p["basis"]), ("reject", "replay_event_id"))

    def test_incomplete_context_and_unknown_outcome_do_not_claim_result(self) -> None:
        for flag in ("facts_complete", "policy_complete"):
            model = copy.deepcopy(self.model)
            model[flag] = False
            with self.subTest(flag=flag):
                projections = self.analyze(model).to_dict()["projections"]
                self.assertTrue(all(p["expected_decision"] == "unknown" for p in projections))
                self.assertTrue(all(p["assessment"] == "unknown" for p in projections))
        model = copy.deepcopy(self.model)
        model["deliveries"] = [model["deliveries"][0]]
        model["deliveries"][0]["receiver_outcome"] = "unknown"
        p = self.analyze(model).to_dict()["projections"][0]
        self.assertEqual((p["expected_decision"], p["assessment"]), ("accept", "unknown"))

    def test_exact_source_replay_rejects_readdressed_report(self) -> None:
        report = self.analyze()
        self.assertEqual(
            webhook.verify_webhook_callback_trust(
                report,
                source_content=encoded(self.model),
                source_id=self.source_id,
            ),
            report,
        )
        changed = copy.deepcopy(self.model)
        changed["deliveries"][1]["receiver_outcome"] = "rejected"
        with self.assertRaises(webhook.WebhookCallbackTrustError):
            webhook.verify_webhook_callback_trust(
                report,
                source_content=encoded(changed),
                source_id=self.source_id,
            )
        forged = report.to_dict()
        forged["projections"][0]["expected_decision"] = "reject"
        parsed = webhook.WebhookCallbackTrustReport.from_json(
            encoded(readdress(forged)).decode("ascii")
        )
        with self.assertRaises(webhook.WebhookCallbackTrustError):
            webhook.verify_webhook_callback_trust(
                parsed,
                source_content=encoded(self.model),
                source_id=self.source_id,
            )

    def test_direct_report_construction_rejects_effect_claims(self) -> None:
        report = self.analyze()
        self.assertEqual(webhook.WebhookCallbackTrustReport(report.to_json()), report)
        with self.assertRaises(webhook.WebhookCallbackTrustError):
            webhook.WebhookCallbackTrustReport(" " + report.to_json())
        for section, key, value in (
            (None, "finding_claimed", True),
            (None, "signature_verified_live", True),
            ("effects", "network", "used"),
        ):
            forged = report.to_dict()
            if section is None:
                forged[key] = value
            else:
                forged[section][key] = value
            changed = encoded(readdress(forged)).decode("ascii")
            with self.assertRaises(webhook.WebhookCallbackTrustError):
                webhook.WebhookCallbackTrustReport.from_json(changed)
            damaged = webhook.WebhookCallbackTrustReport(report.to_json())
            object.__setattr__(damaged, "_json", changed)
            with self.assertRaises(webhook.WebhookCallbackTrustError):
                damaged.to_json()

    def test_native_adapter_detached_fixture_and_family(self) -> None:
        native = {"source_id": self.source_id, "source": copy.deepcopy(self.model)}
        report = webhook.analyze_supplied_webhook_callback_trust(native)
        self.assertEqual(report, self.analyze())
        native["source"]["deliveries"][0]["age_seconds"] = 301
        self.assertNotEqual(report, webhook.analyze_supplied_webhook_callback_trust(native))
        for invalid in (
            {"source": self.model},
            {"source_id": self.source_id, "source": self.model, "extra": False},
            {"source_id": StringAlias(self.source_id), "source": self.model},
            {"source_id": self.source_id, "source": []},
            DictAlias({"source_id": self.source_id, "source": self.model}),
        ):
            with (
                self.subTest(invalid=invalid),
                self.assertRaises(webhook.WebhookCallbackTrustError),
            ):
                webhook.analyze_supplied_webhook_callback_trust(invalid)
        fixture = webhook.component_fixture()
        fixture["receivers"][0]["receiver_id"] = "mutated"
        self.assertEqual(webhook.component_fixture()["receivers"][0]["receiver_id"], "billing-hook")
        with self.assertRaises(webhook.WebhookCallbackTrustError):
            webhook.verify_webhook_callback_trust(
                ReportAlias(report.to_json()),
                source_content=encoded(self.model),
                source_id=self.source_id,
            )

    def test_closed_schema_and_duplicate_prior_records(self) -> None:
        invalid = []
        extra = copy.deepcopy(self.model)
        extra["callback_url"] = "https://example.invalid"
        invalid.append(extra)
        for section in ("receivers", "prior_acceptances", "deliveries"):
            candidate = copy.deepcopy(self.model)
            candidate[section].append(copy.deepcopy(candidate[section][0]))
            invalid.append(candidate)
        duplicate_key = copy.deepcopy(self.model)
        duplicate_key["prior_acceptances"].append(
            {
                "receiver_id": "billing-hook",
                "event_id": "different-event",
                "idempotency_key_id": "key-old",
            }
        )
        invalid.append(duplicate_key)
        for section, field, value in (
            ("receivers", "signature_required", 1),
            ("receivers", "replay_key", "timestamp"),
            ("receivers", "max_age_seconds", -1),
            ("receivers", "max_age_seconds", True),
            ("receivers", "allowed_producer_ids", ["billing-service", "billing-service"]),
            ("deliveries", "signature_disposition", "trusted"),
            ("deliveries", "receiver_outcome", "delivered"),
            ("deliveries", "age_seconds", -1),
            ("deliveries", "age_seconds", 1.5),
        ):
            candidate = copy.deepcopy(self.model)
            candidate[section][0][field] = value
            invalid.append(candidate)
        for field, value in (
            ("facts_complete", 1),
            ("policy_complete", "yes"),
            ("schema_version", "v2"),
        ):
            candidate = copy.deepcopy(self.model)
            candidate[field] = value
            invalid.append(candidate)
        for candidate in invalid:
            with (
                self.subTest(candidate=candidate),
                self.assertRaises(webhook.WebhookCallbackTrustError),
            ):
                self.analyze(candidate)

    def test_duplicate_keys_resource_bounds_and_no_side_effects(self) -> None:
        bad = [
            b'{"schema_version":"v1","schema_version":"v1"}',
            b'{"receivers":[{"receiver_id":"a","receiver_id":"b"}]}',
            b'{"x":NaN}',
            b'{"x":1.3}',
            b'{"x":9223372036854775808}',
            b"\xff",
            b"[" * (webhook.MAX_DEPTH + 1) + b"0" + b"]" * (webhook.MAX_DEPTH + 1),
            b" " * (webhook.MAX_SOURCE_BYTES + 1),
        ]
        for source in bad:
            with (
                self.subTest(source=source[:32]),
                self.assertRaises(webhook.WebhookCallbackTrustError),
            ):
                webhook.analyze_webhook_callback_trust(
                    source_content=source, source_id=self.source_id
                )
        for source, identity in (
            (BytesAlias(encoded(self.model)), self.source_id),
            (encoded(self.model), StringAlias(self.source_id)),
            (encoded(self.model), "https://not-a-source"),
        ):
            with self.assertRaises(webhook.WebhookCallbackTrustError):
                webhook.analyze_webhook_callback_trust(source_content=source, source_id=identity)
        report = self.analyze()
        with patch("socket.create_connection", side_effect=AssertionError("network attempt")):
            with patch("subprocess.run", side_effect=AssertionError("process attempt")):
                self.assertEqual(
                    webhook.verify_webhook_callback_trust(
                        report,
                        source_content=encoded(self.model),
                        source_id=self.source_id,
                    ),
                    report,
                )

    def test_determinism_and_empty_delivery_projection(self) -> None:
        report = self.analyze()
        self.assertEqual(report.to_json(), self.analyze().to_json())
        self.assertEqual(
            webhook.WebhookCallbackTrustReport.from_json("\n" + report.to_json() + "\n"), report
        )
        reversed_model = copy.deepcopy(self.model)
        reversed_model["deliveries"].reverse()
        self.assertEqual(
            self.analyze(reversed_model).to_dict()["projections"], report.to_dict()["projections"]
        )
        self.assertNotEqual(self.analyze(reversed_model).to_json(), report.to_json())
        model = copy.deepcopy(self.model)
        model["deliveries"] = []
        self.assertEqual(self.analyze(model).to_dict()["projections"], [])
        model = copy.deepcopy(self.model)
        model["receivers"] = [
            {**model["receivers"][0], "receiver_id": f"receiver-{index}"}
            for index in range(webhook.MAX_RECEIVERS + 1)
        ]
        with self.assertRaises(webhook.WebhookCallbackTrustError):
            self.analyze(model)


if __name__ == "__main__":
    unittest.main()
