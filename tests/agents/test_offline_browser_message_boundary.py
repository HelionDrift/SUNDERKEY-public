"""Synthetic browser message boundary projection and replay tests."""

from __future__ import annotations

import copy
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_browser_message_boundary as boundary

ERROR = boundary.BrowserMessageBoundaryAnalysisError


def fixture() -> dict:
    return boundary.component_fixture()


def analyze(model: dict) -> dict:
    return boundary.analyze_supplied_browser_message_boundary(model).to_dict()


def observation(model: dict, message_id: str = "candidate") -> dict:
    return next(
        item for item in analyze(model)["message_observations"] if item["message_id"] == message_id
    )


class BrowserMessageBoundaryTests(unittest.TestCase):
    def deny_before_hash(self, model: dict) -> None:
        with patch.object(boundary, "_address") as address:
            with self.assertRaises(ERROR):
                boundary.analyze_supplied_browser_message_boundary(model)
            address.assert_not_called()

    def test_fixture_is_source_bound_nonqualifying_and_deterministic(self):
        source = fixture()
        report = boundary.analyze_supplied_browser_message_boundary(source)
        document = report.to_dict()
        self.assertEqual(document["profile_id"], "AOE-GB-D05-S15")
        self.assertEqual(document["blueprint_sha256"], boundary.BLUEPRINT_SHA256)
        self.assertEqual(document["candidate_count"], 1)
        self.assertEqual(document["unknown_count"], 1)
        self.assertEqual(
            [item["outcome"] for item in document["message_observations"]],
            [
                "candidate_cross_origin_message_without_check",
                "accepted_by_declared_policy",
                "not_delivered_under_supplied_model",
                "unknown",
            ],
        )
        self.assertIn("opaque_sender_origin", document["message_observations"][-1]["uncertainty"])
        self.assertEqual(set(document["effects"].values()), {"none"})
        self.assertTrue(all(value is False for value in document["flags"].values()))
        self.assertEqual(
            report.to_json(), boundary.analyze_supplied_browser_message_boundary(source).to_json()
        )
        detached = boundary.BrowserMessageBoundaryAnalysis.from_json(report.to_json())
        self.assertEqual(
            boundary.verify_supplied_browser_message_boundary_analysis(
                detached, model=source
            ).to_json(),
            report.to_json(),
        )
        source["messages"][0]["payload_trust"] = "trusted"
        self.assertEqual(document["candidate_count"], 1)
        with self.assertRaises(ERROR):
            boundary.verify_supplied_browser_message_boundary_analysis(report, model=source)

    def test_false_positive_guards_for_exact_origin_target_and_same_origin(self):
        source = fixture()
        source["messages"][0]["sender_origin"] = "https://app.example"
        self.assertEqual(
            observation(source)["outcome"], "accepted_same_origin_under_supplied_model"
        )
        source["messages"][0]["sender_origin"] = "https://other.example"
        source["messages"][0]["target_origin"] = "https://app.example.evil.example"
        self.assertEqual(observation(source)["outcome"], "not_delivered_under_supplied_model")
        source["messages"][0]["target_origin"] = "https://app.example:8443"
        self.assertEqual(observation(source)["outcome"], "not_delivered_under_supplied_model")
        source["messages"][0]["target_origin"] = "*"
        self.assertEqual(
            observation(source)["outcome"], "candidate_cross_origin_message_without_check"
        )
        source["messages"][0]["payload_trust"] = "trusted"
        self.assertEqual(observation(source)["outcome"], "accepted_under_supplied_model")
        source["messages"][0]["payload_trust"] = "untrusted"
        source["listeners"][1]["handler_sensitive"] = False
        self.assertEqual(observation(source)["outcome"], "accepted_under_supplied_model")

    def test_exact_allowlist_never_uses_suffix_or_prefix_matching(self):
        source = fixture()
        source["messages"][1]["sender_origin"] = "https://partner.example.evil.example"
        self.assertEqual(
            observation(source, "checked-partner")["outcome"], "rejected_by_declared_policy"
        )
        source["messages"][1]["sender_origin"] = "https://evilpartner.example"
        self.assertEqual(
            observation(source, "checked-partner")["outcome"], "rejected_by_declared_policy"
        )
        source["messages"][1]["sender_origin"] = "https://partner.example:8443"
        self.assertEqual(
            observation(source, "checked-partner")["outcome"], "rejected_by_declared_policy"
        )
        source["messages"][1]["sender_origin"] = "https://partner.example"
        self.assertEqual(
            observation(source, "checked-partner")["outcome"], "accepted_by_declared_policy"
        )

    def test_unknowns_never_promote_to_candidate(self):
        cases = (
            ("global_origins", lambda x: x.update(origins_complete=False), "origins_incomplete"),
            (
                "listener_semantics",
                lambda x: x["listeners"][1].update(semantics_complete=False),
                "listener_semantics_incomplete",
            ),
            (
                "message_context",
                lambda x: x["messages"][0].update(context_complete=False),
                "message_context_incomplete",
            ),
            (
                "opaque_origin",
                lambda x: x["messages"][0].update(sender_origin="null"),
                "opaque_sender_origin",
            ),
            (
                "unknown_target",
                lambda x: x["messages"][0].update(target_origin="unknown"),
                "target_origin_unknown",
            ),
            (
                "unknown_payload",
                lambda x: x["messages"][0].update(payload_trust="unknown"),
                "payload_trust_unknown",
            ),
            (
                "unknown_rule",
                lambda x: x["listeners"][1].update(origin_rule="unknown"),
                "listener_origin_rule_unknown",
            ),
        )
        for name, change, reason in cases:
            with self.subTest(name=name):
                source = fixture()
                change(source)
                row = observation(source)
                self.assertEqual(row["outcome"], "unknown")
                self.assertIn(reason, row["uncertainty"])

    def test_unsupported_origin_grammar_denied_before_hash(self):
        invalid_origins = (
            "https://app.example/",
            "https://app.example/path",
            "https://app.example?x=1",
            "https://user@app.example",
            "HTTPS://app.example",
            "https://App.example",
            "https://app.example:443",
            "http://app.example:80",
            "https://app.example:0001",
            "https://app.example:65536",
            "https://app..example",
            "https://app.example.",
            "https://*.example",
            "https://[::1]",
            "file://app.example",
            "null",
            "https://app.example#fragment",
            "https://app.example\\@evil.example",
        )
        for origin in invalid_origins:
            with self.subTest(origin=origin):
                source = fixture()
                source["listeners"][0]["receiver_origin"] = origin
                self.deny_before_hash(source)

    def test_closed_model_exact_types_references_sort_and_no_widening(self):
        changes = (
            lambda x: x.update(extra=True),
            lambda x: x.update(schema_version=True),
            lambda x: x.update(origins_complete=1),
            lambda x: x["listeners"][0].update(origin_rule="suffix"),
            lambda x: x["listeners"][0].update(
                accepted_origins=["https://partner.example", "https://partner.example"]
            ),
            lambda x: x["listeners"][1].update(accepted_origins=["https://partner.example"]),
            lambda x: x["listeners"][0].update(handler_sensitive=1),
            lambda x: x["messages"][0].update(listener_id="missing"),
            lambda x: x["messages"][0].update(context_complete=1),
            lambda x: x["messages"][0].update(target_origin="null"),
            lambda x: x["messages"][0].update(payload_trust="maybe"),
            lambda x: x["messages"][0].update(message_id="bad id"),
            lambda x: x["messages"].reverse(),
        )
        for change in changes:
            source = fixture()
            change(source)
            with self.subTest(source=source):
                self.deny_before_hash(source)

    def test_bytes_duplicate_keys_numeric_fractions_and_report_forgery_rejected(self):
        source = fixture()
        raw = json.dumps(source, sort_keys=True, separators=(",", ":")).encode("ascii")
        direct = boundary.analyze_supplied_browser_message_boundary(source)
        self.assertEqual(
            boundary.analyze_supplied_browser_message_boundary_bytes(model_bytes=raw).to_json(),
            direct.to_json(),
        )
        bad = (
            b'{"schema_version":1,"schema_version":1}',
            raw.replace(b'"schema_version":1', b'"schema_version":1.0'),
            raw + b"x",
            b"\xff",
        )
        for data in bad:
            with self.subTest(data=data[:40]):
                with self.assertRaises(ERROR):
                    boundary.analyze_supplied_browser_message_boundary_bytes(model_bytes=data)
        document = direct.to_dict()
        forged = copy.deepcopy(document)
        forged["candidate_count"] = 2
        with self.assertRaises(ERROR):
            boundary.BrowserMessageBoundaryAnalysis.from_dict(forged)
        forged = copy.deepcopy(document)
        forged["source_model"]["listeners"][1]["origin_rule"] = "exact_allowlist"
        with self.assertRaises(ERROR):
            boundary.BrowserMessageBoundaryAnalysis.from_dict(forged)
        with self.assertRaises(ERROR):
            boundary.verify_supplied_browser_message_boundary_analysis(document, model=source)

    def test_native_cycle_and_bounded_inputs(self):
        source = fixture()
        source["cycle"] = source
        self.deny_before_hash(source)
        source = fixture()
        source["messages"] = source["messages"] * (boundary.MAX_MESSAGES + 1)
        self.deny_before_hash(source)
        source = fixture()
        source["messages"][0]["message_id"] = "x" * (boundary.MAX_STRING_BYTES + 1)
        self.deny_before_hash(source)


if __name__ == "__main__":
    unittest.main()
