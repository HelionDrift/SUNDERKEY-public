"""Synthetic deep-link WebView bridge-origin projection and replay tests."""

from __future__ import annotations

import copy
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_webview_bridge_origin as boundary

ERROR = boundary.WebViewBridgeOriginAnalysisError


def fixture() -> dict:
    return boundary.component_fixture()


def analyze(model: dict) -> dict:
    return boundary.analyze_supplied_webview_bridge_origin(model).to_dict()


def observation(model: dict, entry_id: str = "candidate") -> dict:
    return next(row for row in analyze(model)["entry_observations"] if row["entry_id"] == entry_id)


class WebViewBridgeOriginTests(unittest.TestCase):
    def deny_before_hash(self, model: dict) -> None:
        with patch.object(boundary, "_address") as address:
            with self.assertRaises(ERROR):
                boundary.analyze_supplied_webview_bridge_origin(model)
            address.assert_not_called()

    def test_fixture_source_bound_nonqualifying_and_deterministic(self):
        source = fixture()
        report = boundary.analyze_supplied_webview_bridge_origin(source)
        document = report.to_dict()
        self.assertEqual(document["profile_id"], "AOE-GB-D08-S12")
        self.assertEqual(document["wave_id"], "IW2-016")
        self.assertEqual(document["blueprint_sha256"], boundary.BLUEPRINT_SHA256)
        self.assertEqual(document["entry_count"], 5)
        self.assertEqual(document["candidate_count"], 1)
        self.assertEqual(document["unknown_count"], 1)
        self.assertEqual(
            [row["outcome"] for row in document["entry_observations"]],
            [
                "candidate_supplied_bridge_trust_conflict",
                "declared_bridge_origin_denied",
                "outside_declared_webview_surface",
                "consistent_with_declared_trust_policy",
                "unknown",
            ],
        )
        self.assertEqual(set(document["effects"].values()), {"none"})
        self.assertTrue(all(value is False for value in document["flags"].values()))
        self.assertEqual(
            report.to_json(), boundary.analyze_supplied_webview_bridge_origin(source).to_json()
        )
        detached = boundary.WebViewBridgeOriginAnalysis.from_json(report.to_json())
        self.assertEqual(
            boundary.verify_supplied_webview_bridge_origin_analysis(
                detached, model=source
            ).to_json(),
            report.to_json(),
        )
        source["surfaces"][0]["trusted_only_bridge_required"] = False
        self.assertEqual(document["candidate_count"], 1)
        with self.assertRaises(ERROR):
            boundary.verify_supplied_webview_bridge_origin_analysis(report, model=source)

    def test_explicit_reachability_and_policy_premises_gate_candidate(self):
        cases = (
            (lambda x: x.update(surfaces_complete=False), "surfaces_incomplete"),
            (
                lambda x: x["surfaces"][0].update(trusted_origins_complete=False),
                "trusted_origins_incomplete",
            ),
            (lambda x: x["surfaces"][0].update(policy_complete=False), "bridge_policy_incomplete"),
            (
                lambda x: x["entries"][0].update(reachability_complete=False),
                "reachability_incomplete",
            ),
            (lambda x: x["entries"][0].update(context_complete=False), "entry_context_incomplete"),
            (
                lambda x: x["entries"][0].update(bridge_exposure_complete=False),
                "entry_bridge_exposure_incomplete",
            ),
            (lambda x: x["entries"][0].update(reachability="unknown"), "reachability_unknown"),
            (lambda x: x["entries"][0].update(entry_kind="unknown"), "entry_kind_unknown"),
            (lambda x: x["entries"][0].update(target_surface="unknown"), "target_surface_unknown"),
            (lambda x: x["entries"][0].update(entry_origin="unknown"), "entry_origin_unknown"),
        )
        for change, reason in cases:
            source = fixture()
            change(source)
            with self.subTest(reason=reason):
                row = observation(source)
                self.assertEqual(row["outcome"], "unknown")
                self.assertIn(reason, row["uncertainty"])

    def test_wildcard_dynamic_and_unknown_rule_abstain(self):
        for rule in ("wildcard", "dynamic", "unknown"):
            source = fixture()
            source["surfaces"][0]["bridge_origin_rule"] = rule
            source["surfaces"][0]["allowed_origins"] = []
            with self.subTest(rule=rule):
                self.assertEqual(observation(source)["outcome"], "unknown")

    def test_non_candidates_for_unreachable_non_webview_internal_and_nonprivileged(self):
        changes = (
            (lambda x: x["entries"][0].update(reachability="unreachable"), "declared_unreachable"),
            (
                lambda x: x["entries"][0].update(target_surface="external_browser"),
                "outside_declared_webview_surface",
            ),
            (
                lambda x: x["entries"][0].update(entry_kind="internal_navigation"),
                "not_external_deep_link_under_supplied_model",
            ),
            (
                lambda x: x["entries"][0].update(bridge_exposed=False),
                "no_declared_privileged_bridge",
            ),
            (
                lambda x: x["surfaces"][0].update(trusted_only_bridge_required=False),
                "consistent_with_declared_trust_policy",
            ),
        )
        for change, expected in changes:
            source = fixture()
            change(source)
            with self.subTest(expected=expected):
                self.assertEqual(observation(source)["outcome"], expected)
        source = fixture()
        source["surfaces"][0]["privileged_bridge_exposed"] = False
        for entry in source["entries"]:
            entry["bridge_exposed"] = False
        self.assertEqual(observation(source)["outcome"], "no_declared_privileged_bridge")

    def test_exact_origin_equality_and_no_suffix_widening(self):
        source = fixture()
        source["entries"][0]["entry_origin"] = "https://untrusted.example.evil.example"
        self.assertEqual(observation(source)["outcome"], "declared_bridge_origin_denied")
        source["entries"][0]["entry_origin"] = "https://untrusted.example:8443"
        self.assertEqual(observation(source)["outcome"], "declared_bridge_origin_denied")
        source["entries"][0]["entry_origin"] = "https://untrusted.example"
        self.assertEqual(observation(source)["outcome"], "candidate_supplied_bridge_trust_conflict")

    def test_invalid_origin_grammar_and_closed_types_denied_before_hash(self):
        invalid_origins = (
            "https://app.example/",
            "https://app.example/path",
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
            "file://app.example",
            "https://app.example#fragment",
        )
        for origin in invalid_origins:
            source = fixture()
            source["entries"][0]["entry_origin"] = origin
            with self.subTest(origin=origin):
                self.deny_before_hash(source)
        changes = (
            lambda x: x.update(extra=True),
            lambda x: x.update(schema_version=True),
            lambda x: x.update(surfaces_complete=1),
            lambda x: x["surfaces"][0].update(bridge_origin_rule="regex"),
            lambda x: x["surfaces"][0].update(
                allowed_origins=["https://app.example", "https://app.example"]
            ),
            lambda x: x["surfaces"][0].update(trusted_only_bridge_required=1),
            lambda x: x["surfaces"][0].update(policy_complete=1),
            lambda x: x["surfaces"][0].update(privileged_bridge_exposed=False),
            lambda x: x["entries"][0].update(surface_id="missing"),
            lambda x: x["entries"][0].update(reachability_complete=1),
            lambda x: x["entries"][0].update(bridge_exposed=1),
            lambda x: x["entries"][0].update(bridge_exposure_complete=1),
            lambda x: x["entries"][0].pop("bridge_exposure_complete"),
            lambda x: x["entries"][0].update(entry_id="bad id"),
            lambda x: x["entries"].reverse(),
        )
        for change in changes:
            source = fixture()
            change(source)
            with self.subTest(source=source):
                self.deny_before_hash(source)

    def test_raw_json_and_report_forgery_rejected(self):
        source = fixture()
        raw = json.dumps(source, sort_keys=True, separators=(",", ":")).encode("ascii")
        direct = boundary.analyze_supplied_webview_bridge_origin(source)
        self.assertEqual(
            boundary.analyze_supplied_webview_bridge_origin_bytes(model_bytes=raw).to_json(),
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
                    boundary.analyze_supplied_webview_bridge_origin_bytes(model_bytes=data)
        forged = copy.deepcopy(direct.to_dict())
        forged["candidate_count"] = 2
        with self.assertRaises(ERROR):
            boundary.WebViewBridgeOriginAnalysis.from_dict(forged)
        forged = copy.deepcopy(direct.to_dict())
        forged["source_model"]["entries"][0]["reachability"] = "unreachable"
        with self.assertRaises(ERROR):
            boundary.WebViewBridgeOriginAnalysis.from_dict(forged)

    def test_native_cycle_and_bounded_inputs(self):
        source = fixture()
        source["cycle"] = source
        self.deny_before_hash(source)
        source = fixture()
        source["entries"] = source["entries"] * (boundary.MAX_ENTRIES + 1)
        self.deny_before_hash(source)
        source = fixture()
        source["entries"][0]["entry_id"] = "x" * (boundary.MAX_STRING_BYTES + 1)
        self.deny_before_hash(source)


if __name__ == "__main__":
    unittest.main()
