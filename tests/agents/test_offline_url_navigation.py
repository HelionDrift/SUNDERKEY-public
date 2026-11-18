"""Synthetic HTTPS transition, refusal and exact replay controls."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_url_navigation as navigation

ERROR = navigation.UrlNavigationAnalysisError


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def model(*locations, base="https://App.Example.invalid:443/start/index#old"):
    return {
        "schema_version": 1,
        "base_url": base,
        "hops": [
            {"hop_id": f"hop-{index}", "location": location}
            for index, location in enumerate(locations)
        ],
    }


def report(*locations, base="https://App.Example.invalid:443/start/index#old"):
    return navigation.analyze_supplied_url_navigation(model(*locations, base=base)).to_dict()


def readdress(document):
    body = copy.deepcopy(document)
    body.pop("analysis_id", None)
    body.pop("analysis_sha256", None)
    digest = hashlib.sha256(
        b"sunderkey.offline-url-navigation.v1\n" + canonical(body).encode("ascii")
    ).hexdigest()
    return {
        **body,
        "analysis_id": "HNP-" + digest[:32].upper(),
        "analysis_sha256": "sha256:" + digest,
    }


class UrlNavigationTests(unittest.TestCase):
    def deny_before_hash(self, source):
        with patch.object(navigation, "_address") as address:
            with self.assertRaises(ERROR):
                navigation.analyze_supplied_url_navigation(source)
            address.assert_not_called()

    def test_fixture_literal_addresses_and_transition_chain(self):
        source = navigation.component_fixture()
        document = navigation.analyze_supplied_url_navigation(source).to_dict()
        self.assertEqual(document["analysis_id"], "HNP-951FCED8A00F3E724CB31E129B6E201F")
        self.assertEqual(
            document["analysis_sha256"],
            "sha256:951fced8a00f3e724cb31e129b6e201f3328e1091abba60dd15bd243794aa9d6",
        )
        self.assertEqual(
            document["source_model_sha256"],
            "sha256:faff2ccbb60175a7bba0f62aa9be0e49f0614f49c5cbf8df35d011d20b093891",
        )
        self.assertEqual(document["profile_id"], "AOE-GB-D05-S05")
        self.assertEqual(document["blueprint_sha256"], navigation.BLUEPRINT_SHA256)
        self.assertEqual(
            document["base_projection"],
            {
                "url": "https://app.example.invalid/start/index",
                "origin": "https://app.example.invalid",
                "authority": "app.example.invalid",
            },
        )
        self.assertEqual(
            [row["to_url"] for row in document["hop_observations"]],
            [
                "https://app.example.invalid/next?x=1",
                "https://cdn.example.invalid:8443/view",
                "https://cdn.example.invalid:8443/view",
            ],
        )
        self.assertEqual(
            [row["origin_changed"] for row in document["hop_observations"]],
            [False, True, False],
        )
        self.assertEqual(
            [row["fragment_present"] for row in document["hop_observations"]],
            [False, True, True],
        )
        self.assertEqual(
            (
                document["projected_hop_count"],
                document["refused_hop_count"],
                document["unprocessed_hop_count"],
            ),
            (3, 0, 0),
        )
        self.assertEqual(set(document["effects"].values()), {"none"})
        self.assertTrue(all(value is False for value in document["flags"].values()))

    def test_absolute_scheme_relative_port_and_host_case(self):
        document = report(
            "HTTPS://APP.EXAMPLE.INVALID:443/upper",
            "//App.Example.Invalid:8443/port",
            "https://app.example.invalid/again",
        )
        rows = document["hop_observations"]
        self.assertEqual([row["authority_changed"] for row in rows], [False, True, True])
        self.assertEqual(
            [row["to_authority"] for row in rows],
            [
                "app.example.invalid",
                "app.example.invalid:8443",
                "app.example.invalid",
            ],
        )
        self.assertEqual([row["status"] for row in rows], ["projected"] * 3)

    def test_relative_root_query_and_fragment_forms(self):
        document = report("child", "/root", "?x=1", "#part", "#")
        rows = document["hop_observations"]
        self.assertEqual(
            [row["location_kind"] for row in rows],
            [
                "path_relative",
                "root_relative",
                "query_relative",
                "fragment_relative",
                "fragment_relative",
            ],
        )
        self.assertEqual(
            [row["to_url"] for row in rows],
            [
                "https://app.example.invalid/start/child",
                "https://app.example.invalid/root",
                "https://app.example.invalid/root?x=1",
                "https://app.example.invalid/root?x=1",
                "https://app.example.invalid/root?x=1",
            ],
        )
        self.assertTrue(all(row["origin_changed"] is False for row in rows))

    def test_unsafe_and_ambiguous_hops_are_refused_without_continuation(self):
        cases = (
            ("https://user:secret@evil.example.invalid/x", "userinfo_or_at_sign_ambiguous"),
            ("http://evil.example.invalid/x", "scheme_not_https"),
            ("javascript:alert(1)", "scheme_not_https"),
            ("https:evil.example.invalid", "ambiguous_scheme_form"),
            ("///evil.example.invalid/x", "ambiguous_leading_slashes"),
            ("https:\\evil.example.invalid/x", "backslash_ambiguous"),
            ("https://exa%2fmple.invalid/x", "percent_encoding_ambiguous"),
            ("/safe%2Funsafe", "percent_encoding_ambiguous"),
            ("https://xn--bcher-kva.example/x", "idna_label_ambiguous"),
            ("https://[::1]/x", "unsupported_url_character"),
            ("https://127.0.0.1/x", "numeric_or_ambiguous_host"),
            ("https://example.invalid./x", "ambiguous_host"),
            ("https://example.invalid:0443/x", "noncanonical_port"),
            ("https://example.invalid:0/x", "invalid_port"),
            ("https://example.invalid:/x", "invalid_port"),
            ("https://example.invalid:65536/x", "invalid_port"),
            ("https://example.invalid//x", "ambiguous_path_slashes"),
            ("/x#one#two", "ambiguous_fragment_delimiter"),
        )
        for location, reason in cases:
            with self.subTest(location=location):
                document = report("/safe", location, "/never")
                self.assertEqual(document["projected_hop_count"], 1)
                self.assertEqual(document["refused_hop_count"], 1)
                self.assertEqual(document["unprocessed_hop_count"], 1)
                self.assertEqual(len(document["hop_observations"]), 2)
                row = document["hop_observations"][1]
                self.assertEqual(row["status"], "refused")
                self.assertEqual(row["refusal_reason"], reason)
                self.assertIsNone(row["to_url"])
                self.assertIsNone(row["origin_changed"])

    def test_non_ascii_rejected_at_exact_native_boundary(self):
        for location in ("/café", "https://bücher.example/x"):
            self.deny_before_hash(model(location))
            raw = canonical(model(location))
            with self.assertRaises(ERROR):
                navigation.analyze_supplied_url_navigation_bytes(model_bytes=raw.encode("ascii"))

    def test_invalid_base_fails_before_hash(self):
        for base in (
            "http://app.example.invalid/start",
            "https://user:secret@app.example.invalid/start",
            "https://xn--bcher-kva.example/start",
            "https://app.example.invalid:0443/start",
            "https://app.example.invalid/%2F",
            "https://[::1]/start",
            "//app.example.invalid/start",
        ):
            self.deny_before_hash(model("/safe", base=base))

    def test_roundtrip_detachment_and_original_binding(self):
        source = navigation.component_fixture()
        original = copy.deepcopy(source)
        report_object = navigation.analyze_supplied_url_navigation(source)
        expected = report_object.to_json()
        for rebuilt in (
            navigation.UrlNavigationAnalysis.from_dict(report_object.to_dict()),
            navigation.UrlNavigationAnalysis.from_json(expected),
            navigation.analyze_supplied_url_navigation_bytes(
                model_bytes=canonical(source).encode("ascii")
            ),
            navigation.verify_supplied_url_navigation_analysis(report_object, model=source),
        ):
            self.assertEqual(rebuilt.to_json(), expected)
        self.assertEqual(report_object.analysis_id, report_object.to_dict()["analysis_id"])
        self.assertEqual(report_object.analysis_sha256, report_object.to_dict()["analysis_sha256"])
        source["hops"][0]["location"] = "/changed"
        exported = report_object.to_dict()
        exported["hop_observations"].clear()
        self.assertEqual(report_object.to_json(), expected)
        with self.assertRaises(ERROR):
            navigation.verify_supplied_url_navigation_analysis(report_object, model=source)
        self.assertEqual(
            navigation.verify_supplied_url_navigation_analysis(
                report_object, model=original
            ).to_json(),
            expected,
        )

    def test_closed_shapes_duplicate_hops_and_native_aliases(self):
        source = model("/one")
        for version in (True, 1.0, "1", None, 0, 2):
            self.deny_before_hash({**source, "schema_version": version})
        self.deny_before_hash({**source, "extra": None})
        self.deny_before_hash({**source, "hops": []})
        self.deny_before_hash({**source, "hops": [source["hops"][0]] * 2})
        for field in ("hop_id", "location"):
            changed = copy.deepcopy(source)
            changed["hops"][0].pop(field)
            self.deny_before_hash(changed)
        for location in (True, None, [], {}, 1, "", "x" * 1025):
            self.deny_before_hash(model(location))
        for identity in ("", "bad space", "x" * 129, True, 1):
            changed = copy.deepcopy(source)
            changed["hops"][0]["hop_id"] = identity
            self.deny_before_hash(changed)

        class Mapping(dict):
            def items(self):
                raise AssertionError("Subclass hook reached")

        self.deny_before_hash(Mapping(source))

    def test_max_hops_order_and_one_more(self):
        source = model(*[f"/path-{i}" for i in range(32)])
        document = navigation.analyze_supplied_url_navigation(source).to_dict()
        self.assertEqual(document["projected_hop_count"], 32)
        self.assertEqual(
            [row["hop_id"] for row in document["hop_observations"]], [f"hop-{i}" for i in range(32)]
        )
        self.deny_before_hash(model(*[f"/path-{i}" for i in range(33)]))

    def test_raw_duplicate_members_lexical_limits_and_exact_bytes(self):
        source = canonical(model("/one"))
        for raw in (
            source.replace('"schema_version":1', '"schema_version":1,"schema_version":1'),
            source.replace('"location":"/one"', '"location":"/one","location":"/two"'),
            source.replace('"schema_version":1', '"schema_version":01'),
            source.replace('"schema_version":1', '"schema_version":1.0'),
            '"' + "x" * 1025 + '"',
            '"' + "\\u0078" * 1025 + '"',
            '"\\u00e4"',
            "[" * 16 + "0" + "]" * 16,
            "9" * 20000,
        ):
            with patch.object(navigation, "_address") as address, self.assertRaises(ERROR):
                navigation.analyze_supplied_url_navigation_bytes(model_bytes=raw.encode("ascii"))
            address.assert_not_called()

        class Bytes(bytes):
            pass

        for content in (b"", b"\xff", "{}", bytearray(b"{}"), memoryview(b"{}"), Bytes(b"{}")):
            with self.assertRaises(ERROR):
                navigation.analyze_supplied_url_navigation_bytes(model_bytes=content)
        expected = navigation.analyze_supplied_url_navigation(model("/one")).to_json()
        for raw in (json.dumps(model("/one"), indent=2), source.replace("hop-0", "\\u0068op-0")):
            self.assertEqual(
                navigation.analyze_supplied_url_navigation_bytes(
                    model_bytes=raw.encode("ascii")
                ).to_json(),
                expected,
            )

    def test_cycles_depth_native_and_work_bounds(self):
        cycle = []
        cycle.append(cycle)
        nested = 0
        for _ in range(16):
            nested = [nested]
        for value in (cycle, nested, [None] * 32768, ["\\" * 1024] * 600):
            with patch.object(navigation.json, "dumps") as serializer:
                self.deny_before_hash(value)
                serializer.assert_not_called()
        with patch.object(navigation, "MAX_WORK", 1):
            self.deny_before_hash(model("/one"))

    def test_cohashed_projection_and_effect_promotion_rejected(self):
        document = navigation.analyze_supplied_url_navigation(
            navigation.component_fixture()
        ).to_dict()
        for field, value in (
            ("origin_changed", False),
            ("to_authority", "app.example.invalid"),
            ("to_url", "https://evil.example.invalid/"),
            ("status", "verified_open_redirect"),
        ):
            changed = copy.deepcopy(document)
            changed["hop_observations"][1][field] = value
            with self.assertRaises(ERROR):
                navigation.UrlNavigationAnalysis.from_dict(readdress(changed))
        for section, field, value in (
            ("flags", "open_redirect_verified", True),
            ("effects", "network", "invoked"),
            ("bounds", "hops", 33),
        ):
            changed = copy.deepcopy(document)
            changed[section][field] = value
            with self.assertRaises(ERROR):
                navigation.UrlNavigationAnalysis.from_json(canonical(readdress(changed)))
        changed = copy.deepcopy(document)
        changed["source_model_sha256"] = "sha256:" + "a" * 64
        with self.assertRaises(ERROR):
            navigation.UrlNavigationAnalysis.from_dict(readdress(changed))

    def test_mutated_wrapper_foreign_report_and_no_io_paths(self):
        report_object = navigation.analyze_supplied_url_navigation(navigation.component_fixture())
        forged = report_object.to_dict()
        forged["hop_observations"][0]["origin_changed"] = True
        object.__setattr__(report_object, "_document_json", canonical(readdress(forged)))
        with self.assertRaises(ERROR):
            report_object.to_dict()
        for foreign in ({}, None, "{}", object()):
            with self.assertRaises(ERROR):
                navigation.verify_supplied_url_navigation_analysis(foreign, model=model("/one"))
        with (
            patch("builtins.open", side_effect=AssertionError("filesystem access")),
            patch("socket.socket", side_effect=AssertionError("network access")),
            patch("subprocess.Popen", side_effect=AssertionError("process access")),
        ):
            self.assertEqual(report("/one")["projected_hop_count"], 1)


if __name__ == "__main__":
    unittest.main()
