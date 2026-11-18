"""Genuine MQTT supplied arithmetic, independent finite oracles and boundary controls."""

from __future__ import annotations

import copy
import hashlib
import itertools
import json
import unittest
from dataclasses import FrozenInstanceError
from unittest.mock import patch

from sunderkey import offline_mqtt_topic_analysis as m


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _model(filters=(), topics=(), matches=(), overlaps=()):
    return {
        "schema_version": 1,
        "protocol_version": "3.1.1",
        "filters": [
            {"filter_id": f"f{index}", "topic_filter": text} for index, text in enumerate(filters)
        ],
        "topics": [
            {"topic_id": f"t{index}", "topic_name": text} for index, text in enumerate(topics)
        ],
        "match_queries": [
            {"query_id": f"m{index}", "filter_id": f"f{left}", "topic_id": f"t{right}"}
            for index, (left, right) in enumerate(matches)
        ],
        "overlap_queries": [
            {
                "query_id": f"o{index}",
                "left_filter_id": f"f{left}",
                "right_filter_id": f"f{right}",
            }
            for index, (left, right) in enumerate(overlaps)
        ],
    }


def _reference_match(pattern, topic):
    """Separate recursive definition, with no production compiler or matcher call."""
    if not topic or (topic[0] == "$" and pattern[0] in "+#"):
        return False
    pattern_parts = pattern.split("/")
    topic_parts = topic.split("/")

    def consume(left, right):
        if not left:
            return not right
        if left[0] == "#":
            return True
        if not right:
            return False
        return (left[0] == "+" or left[0] == right[0]) and consume(left[1:], right[1:])

    return consume(pattern_parts, topic_parts)


def _readdress(document):
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = (
        "sha256:"
        + hashlib.sha256(
            m.DOMAIN.encode("ascii") + b"\n" + _canonical(body).encode("ascii")
        ).hexdigest()
    )
    document["analysis_sha256"] = digest
    document["analysis_id"] = "MQT-" + digest[7:39].upper()
    return document


def _recorded_work(operation):
    maximum = 0
    original = m._Budget.charge

    def observe(self, amount):
        nonlocal maximum
        original(self, amount)
        maximum = max(maximum, self.used)

    with patch.object(m._Budget, "charge", observe):
        operation()
    return maximum


class MqttTopicAnalysisTests(unittest.TestCase):
    def analyze(self, model=None):
        return m.analyze_supplied_mqtt_topics(m.component_fixture() if model is None else model)

    def results(self, patterns, topics):
        pairs = list(itertools.product(range(len(patterns)), range(len(topics))))
        document = self.analyze(_model(patterns, topics, pairs)).to_dict()
        return {row["query_id"]: row["matches"] for row in document["match_results"]}

    def overlap(self, left, right):
        return self.analyze(_model((left, right), overlaps=((0, 1),))).to_dict()["overlap_results"][
            0
        ]

    def deny_before_hash(self, operation):
        with patch.object(m, "_digest") as digest:
            with self.assertRaises(m.MqttTopicAnalysisError):
                operation()
            digest.assert_not_called()

    def test_public_fixture_has_genuine_literal_addresses_and_mathematical_rows(self):
        report = self.analyze()
        document = report.to_dict()
        self.assertEqual(document["analysis_id"], "MQT-34556B64BB2AE71B5D849A8FC97EFBCC")
        self.assertEqual(
            document["analysis_sha256"],
            "sha256:34556b64bb2ae71b5d849a8fc97efbcc1d88751acecb0aa094723683c1f93c6b",
        )
        self.assertEqual(
            document["source_model_sha256"],
            "sha256:dc26a19e9917004244bf1a298cc4e92d8a903d588162f4b9b706d12f2aad4959",
        )
        self.assertEqual(
            {row["query_id"]: row["matches"] for row in document["match_results"]},
            {
                "sensor-a": True,
                "empty-level": True,
                "parent": True,
                "wildcard-system": False,
                "literal-system": True,
                "unicode": True,
            },
        )
        overlaps = {row["query_id"]: row for row in document["overlap_results"]}
        self.assertEqual(overlaps["sensors"]["witness_topic"], "sensors//temperature")
        self.assertEqual(overlaps["system-root"]["status"], "disjoint")
        self.assertEqual(overlaps["system-self"]["witness_topic"], "$SYS")

    def test_original_army_ownership_and_all_effects_are_nonqualifying(self):
        document = self.analyze().to_dict()
        self.assertEqual(document["profile_id"], "AOE-GD-D18-S15")
        self.assertEqual(document["capability_id"], "army.gd.d18.s15")
        self.assertEqual(document["wave_id"], "IW2-019")
        self.assertEqual(document["commander_profile_id"], "AOE-GD-D18-CMD")
        self.assertEqual(document["group_commander_profile_id"], "AOE-HQ-06")
        self.assertEqual(document["independent_validator_id"], "AOE-HQ-33")
        self.assertEqual(set(document["effects"].values()), {"none"})
        self.assertEqual(set(document["claims"].values()), {False})

    def test_native_bytes_raw_utf8_and_escaped_input_share_canonical_projection(self):
        model = m.component_fixture()
        expected = self.analyze(model).to_json()
        for ensure_ascii in (False, True):
            content = json.dumps(model, indent=2, ensure_ascii=ensure_ascii).encode("utf-8")
            report = m.analyze_supplied_mqtt_topics_bytes(model_bytes=content)
            self.assertEqual(report.to_json(), expected)

    def test_constructor_parsers_exports_and_original_verifier_roundtrip(self):
        model = m.component_fixture()
        report = self.analyze(model)
        document = report.to_dict()
        text = report.to_json()
        for other in (
            m.MqttTopicAnalysis(text),
            m.MqttTopicAnalysis.from_json(text),
            m.MqttTopicAnalysis.from_dict(document),
            m.verify_supplied_mqtt_topic_analysis(report, model=model),
        ):
            self.assertEqual(other.to_json(), text)
        with self.assertRaises(FrozenInstanceError):
            report.document_json = "{}"

    def test_sources_exports_and_public_fixtures_are_fresh_and_detached(self):
        model = m.component_fixture()
        report = self.analyze(model)
        before = report.to_json()
        model["filters"][0]["topic_filter"] = "other"
        exported = report.to_dict()
        exported["source_model"]["filters"].clear()
        exported["match_results"].clear()
        fresh = m.component_fixture()
        fresh["overlap_queries"].clear()
        self.assertEqual(report.to_json(), before)
        self.assertEqual(len(m.component_fixture()["overlap_queries"]), 3)

    def test_empty_declared_sets_and_query_sets_have_no_fabricated_assessment(self):
        document = self.analyze(_model()).to_dict()
        self.assertEqual(document["match_results"], [])
        self.assertEqual(document["overlap_results"], [])
        self.assertEqual(document["unicode_cautions"], [])

    def test_plus_consumes_exactly_one_level_including_an_empty_level(self):
        topics = ("a", "a/", "a/b", "a/b/c", "/", "/a")
        results = self.results(("a/+", "+/+", "+"), topics)
        expected = (
            (False, True, True, False, False, False),
            (False, True, True, False, True, True),
            (True, False, False, False, False, False),
        )
        for index, flags in enumerate(expected):
            for offset, flag in enumerate(flags):
                self.assertIs(results[f"m{index * len(topics) + offset}"], flag)

    def test_terminal_hash_includes_parent_and_any_descendant_levels(self):
        topics = ("a", "a/", "a/b", "a//b", "ab", "/", "b")
        results = self.results(("a/#", "#"), topics)
        for index, flag in enumerate((True, True, True, True, False, False, False)):
            self.assertIs(results[f"m{index}"], flag)
        self.assertTrue(all(results[f"m{7 + index}"] for index in range(7)))

    def test_root_wildcards_exclude_dollar_but_nonroot_dollar_is_literal(self):
        patterns = ("#", "+/status", "$SYS/#", "a/+", "a/#", "/#")
        topics = ("$SYS", "$SYS/status", "a/$SYS", "/$SYS")
        results = self.results(patterns, topics)
        for left, right in itertools.product(range(len(patterns)), range(len(topics))):
            self.assertIs(
                results[f"m{left * len(topics) + right}"],
                _reference_match(patterns[left], topics[right]),
            )

    def test_leading_trailing_and_adjacent_separators_remain_significant(self):
        topics = ("a", "/a", "a/", "a//b", "/", "//")
        results = self.results(topics, topics)
        for left, right in itertools.product(range(len(topics)), repeat=2):
            self.assertIs(results[f"m{left * len(topics) + right}"], left == right)

    def test_exact_case_unicode_and_no_normalization_are_preserved(self):
        patterns = ("Cafe", "caf\u00e9", "cafe\u0301", "\ufeffa", "a")
        topics = ("Cafe", "cafe", "caf\u00e9", "cafe\u0301", "\ufeffa", "a")
        results = self.results(patterns, topics)
        for left, right in itertools.product(range(len(patterns)), range(len(topics))):
            self.assertIs(
                results[f"m{left * len(topics) + right}"], patterns[left] == topics[right]
            )

    def test_controls_and_noncharacters_are_cautions_not_universal_invalidity(self):
        for text in ("a\t", "a\x7f", "a\x85", "a\ufdd0", "a\uffff", "a\U0010ffff"):
            with self.subTest(text=repr(text)):
                document = self.analyze(_model((text,), (text,), ((0, 0),))).to_dict()
                self.assertTrue(document["match_results"][0]["matches"])
                self.assertEqual(len(document["unicode_cautions"]), 2)
        document = self.analyze(_model(("\ufeffa",), ("\ufeffa",), ((0, 0),))).to_dict()
        self.assertEqual(document["unicode_cautions"], [])

    def test_supplementary_unicode_escape_pairs_and_raw_utf8_are_identical(self):
        model = _model(("a\U0001f600/+",), ("a\U0001f600/",), ((0, 0),), ((0, 0),))
        text = _canonical(model)
        self.assertIn("\\ud83d\\ude00", text)
        native = self.analyze(model)
        raw = m.analyze_supplied_mqtt_topics_bytes(model_bytes=text.encode("ascii"))
        self.assertEqual(raw.to_json(), native.to_json())

    def test_mqtt5_shared_subscription_spelling_is_not_reinterpreted(self):
        document = self.analyze(
            _model(("$share/workers/a/#",), ("a/b", "$share/workers/a/b"), ((0, 0), (0, 1)))
        ).to_dict()
        self.assertEqual([row["matches"] for row in document["match_results"]], [False, True])

    def test_overlap_returns_witnesses_checked_by_independent_definition(self):
        pairs = (
            ("#", "+"),
            ("a/#", "a"),
            ("a/+", "a/#"),
            ("/#", "+/#"),
            ("+/+", "/"),
            ("$SYS/#", "$SYS/+"),
            ("a/+/c", "+/b/+"),
        )
        for left, right in pairs:
            with self.subTest(left=left, right=right):
                row = self.overlap(left, right)
                self.assertEqual(row["status"], "overlap_witness")
                self.assertTrue(_reference_match(left, row["witness_topic"]))
                self.assertTrue(_reference_match(right, row["witness_topic"]))
                self.assertEqual(
                    row["minimum_witness_utf8_bytes"], len(row["witness_topic"].encode("utf-8"))
                )

    def test_symbolic_root_empty_topic_corner_cases_have_legal_witnesses(self):
        for left, right, status, witness in (
            ("#", "#", "overlap_witness", "a"),
            ("/#", "+", "disjoint", None),
            ("/#", "+/#", "overlap_witness", "/"),
            ("/#", "/#", "overlap_witness", "/"),
            ("+", "+", "overlap_witness", "a"),
        ):
            with self.subTest(left=left, right=right):
                row = self.overlap(left, right)
                self.assertEqual((row["status"], row["witness_topic"]), (status, witness))

    def test_proven_disjointness_includes_root_dollar_length_and_literal_conflicts(self):
        for left, right in (
            ("#", "$SYS/#"),
            ("+/+", "$SYS/+"),
            ("a", "b"),
            ("a/+", "a"),
            ("a/b", "a/c/#"),
            ("/a", "a/+"),
        ):
            with self.subTest(left=left, right=right):
                row = self.overlap(left, right)
                self.assertEqual(row["status"], "disjoint")
                self.assertIsNone(row["witness_topic"])

    def test_unbounded_language_overlap_is_not_called_disjoint_when_witness_is_too_wide(self):
        left = "a" * 3000 + "/+"
        right = "+/" + "b" * 3000
        row = self.overlap(left, right)
        self.assertEqual(row["status"], "no_witness_within_software_topic_bounds")
        self.assertIsNone(row["witness_topic"])
        self.assertEqual(row["minimum_witness_utf8_bytes"], 6001)

    def test_minimal_bounded_overlap_witness_byte_boundary_is_exact(self):
        for right_length, status in (
            (2047, "overlap_witness"),
            (2048, "no_witness_within_software_topic_bounds"),
        ):
            row = self.overlap("a" * 2048 + "/+", "+/" + "b" * right_length)
            self.assertEqual(row["status"], status)
            if row["witness_topic"] is not None:
                self.assertEqual(len(row["witness_topic"].encode("utf-8")), 4096)

    def test_independent_finite_alphabet_matcher_oracle(self):
        patterns = (
            "#",
            "+",
            "a",
            "b",
            "$SYS",
            "/",
            "+/+",
            "a/#",
            "b/#",
            "$SYS/#",
            "/#",
            "//",
            "a/+",
            "+/a",
            "+/+/#",
            "a/+/b",
            "+/b",
            "/a",
            "a/",
            "a//",
            "$SYS/+",
            "a/$SYS",
            "+/+/+",
            "//+",
            "//#",
        )
        topics = [
            "/".join(parts)
            for size in (1, 2, 3)
            for parts in itertools.product(("", "a", "b", "$SYS"), repeat=size)
            if "/".join(parts)
        ]
        pairs = list(itertools.product(range(len(patterns)), range(len(topics))))
        checked = 0
        for start in range(0, len(pairs), m.MAX_MATCH_QUERIES):
            chunk = pairs[start : start + m.MAX_MATCH_QUERIES]
            document = self.analyze(_model(patterns, topics, chunk)).to_dict()
            actual = {row["query_id"]: row["matches"] for row in document["match_results"]}
            for index, (left, right) in enumerate(chunk):
                self.assertIs(actual[f"m{index}"], _reference_match(patterns[left], topics[right]))
                checked += 1
        self.assertEqual(checked, 2075)

    def test_independent_symbolic_overlap_oracle_enumerates_a_complete_small_alphabet(self):
        patterns = (
            "#",
            "+",
            "a",
            "b",
            "$SYS",
            "/",
            "+/+",
            "a/#",
            "b/#",
            "$SYS/#",
            "/#",
            "//",
            "a/+",
            "+/a",
            "+/+/#",
            "a/+/b",
            "+/b",
            "/a",
            "a/",
            "a//",
            "$SYS/+",
            "a/$SYS",
            "+/+/+",
            "//+",
            "//#",
        )
        topics = [
            "/".join(parts)
            for size in (1, 2, 3)
            for parts in itertools.product(("", "a", "b", "$SYS"), repeat=size)
            if "/".join(parts)
        ]
        pairs = list(itertools.product(range(len(patterns)), repeat=2))
        checked = 0
        for start in range(0, len(pairs), m.MAX_OVERLAP_QUERIES):
            chunk = pairs[start : start + m.MAX_OVERLAP_QUERIES]
            document = self.analyze(_model(patterns, overlaps=chunk)).to_dict()
            actual = {row["query_id"]: row for row in document["overlap_results"]}
            for index, (left, right) in enumerate(chunk):
                row = actual[f"o{index}"]
                exists = any(
                    _reference_match(patterns[left], topic)
                    and _reference_match(patterns[right], topic)
                    for topic in topics
                )
                self.assertEqual(row["status"], "overlap_witness" if exists else "disjoint")
                if exists:
                    self.assertTrue(_reference_match(patterns[left], row["witness_topic"]))
                    self.assertTrue(_reference_match(patterns[right], row["witness_topic"]))
                checked += 1
        self.assertEqual(checked, 625)

    def test_overlap_is_symmetric_and_input_permutations_preserve_semantic_rows(self):
        model = m.component_fixture()
        before = self.analyze(model).to_dict()
        for field in ("filters", "topics", "match_queries", "overlap_queries"):
            model[field].reverse()
        after = self.analyze(model).to_dict()
        self.assertEqual(after["match_results"], before["match_results"])
        self.assertEqual(after["overlap_results"], before["overlap_results"])
        self.assertNotEqual(after["source_model_sha256"], before["source_model_sha256"])
        for left, right in (("a/#", "+/b"), ("/#", "+/#"), ("#", "$SYS/#")):
            a, b = self.overlap(left, right), self.overlap(right, left)
            for key in ("status", "witness_topic", "minimum_witness_utf8_bytes"):
                self.assertEqual(a[key], b[key])

    def test_duplicate_source_and_query_ids_and_dangling_references_reject(self):
        model = m.component_fixture()
        cases = []
        for field in ("filters", "topics", "match_queries", "overlap_queries"):
            changed = copy.deepcopy(model)
            changed[field].append(copy.deepcopy(changed[field][0]))
            cases.append(changed)
        changed = copy.deepcopy(model)
        changed["overlap_queries"][0]["query_id"] = changed["match_queries"][0]["query_id"]
        cases.append(changed)
        for field, reference in (
            ("match_queries", "filter_id"),
            ("match_queries", "topic_id"),
            ("overlap_queries", "left_filter_id"),
            ("overlap_queries", "right_filter_id"),
        ):
            changed = copy.deepcopy(model)
            changed[field][0][reference] = "missing"
            cases.append(changed)
        for changed in cases:
            self.deny_before_hash(lambda changed=changed: self.analyze(changed))

    def test_identical_text_under_distinct_source_ids_is_not_ambiguous(self):
        document = self.analyze(
            _model(("a/#", "a/#"), ("a", "a"), ((0, 0), (1, 1)), ((0, 1),))
        ).to_dict()
        self.assertTrue(all(row["matches"] for row in document["match_results"]))
        self.assertEqual(document["overlap_results"][0]["witness_topic"], "a")

    def test_schema_protocol_fields_and_identifiers_require_exact_native_values(self):
        model = m.component_fixture()
        for value in (True, False, 1.0, "1", None, 0, 2):
            changed = copy.deepcopy(model)
            changed["schema_version"] = value
            self.deny_before_hash(lambda changed=changed: self.analyze(changed))
        for value in (3.1, True, "5.0", None):
            changed = copy.deepcopy(model)
            changed["protocol_version"] = value
            self.deny_before_hash(lambda changed=changed: self.analyze(changed))
        for value in ("", "a" * 65, "contains space", "\u00e9", True, None):
            changed = copy.deepcopy(model)
            changed["filters"][0]["filter_id"] = value
            self.deny_before_hash(lambda changed=changed: self.analyze(changed))
        changed = copy.deepcopy(model)
        changed["extra"] = "not closed"
        self.deny_before_hash(lambda: self.analyze(changed))

    def test_native_json_aliases_cycles_and_shared_occurrences_are_bounded(self):
        for value in ((), set(), 1.0, b"{}", None, True):
            self.deny_before_hash(lambda value=value: m.analyze_supplied_mqtt_topics(value))
        model = m.component_fixture()
        model["filters"].append(model)
        self.deny_before_hash(lambda: self.analyze(model))
        shared = ["a" * 1024] * 128
        self.deny_before_hash(lambda: self.analyze({"repeated": [shared] * 16}))

    def test_each_native_array_rejects_null_int_bool_before_len_or_expansion(self):
        for field in ("filters", "topics", "match_queries", "overlap_queries"):
            for value in (None, 1, True, (), {}):
                with self.subTest(field=field, value=repr(value)):
                    model = m.component_fixture()
                    model[field] = value
                    self.deny_before_hash(lambda model=model: self.analyze(model))

    def test_invalid_filter_grammar_and_invalid_topic_wildcards_reject(self):
        for pattern in ("", "a+", "+a", "a/#/b", "a#", "##", "a/+#", "#/a"):
            self.deny_before_hash(lambda pattern=pattern: self.analyze(_model((pattern,))))
        for topic in ("", "+", "#", "a/+/b", "a#"):
            self.deny_before_hash(lambda topic=topic: self.analyze(_model(topics=(topic,))))

    def test_nul_surrogate_and_ill_formed_utf8_reject_before_hash(self):
        for text in ("a\x00", "a\ud800", "a\udfff"):
            self.deny_before_hash(lambda text=text: self.analyze(_model((text,))))
        for content in (b"\xff", b'"\xc0\x80"', b'"\xed\xa0\x80"', b'"\xf4\x90\x80\x80"'):
            self.deny_before_hash(
                lambda content=content: m.analyze_supplied_mqtt_topics_bytes(model_bytes=content)
            )

    def test_raw_unpaired_surrogates_and_oversize_decoded_strings_deny_before_decoder(self):
        raw_values = (
            '"\\ud800"',
            '"\\udc00"',
            '"\\ud800\\u0061"',
            '"\\u0000"',
            '"' + "\\u00e9" * 2049 + '"',
        )
        for content in raw_values:
            with patch.object(m.json, "loads") as decoder, patch.object(m, "_digest") as digest:
                with self.assertRaises(m.MqttTopicAnalysisError):
                    m.analyze_supplied_mqtt_topics_bytes(model_bytes=content.encode("ascii"))
                decoder.assert_not_called()
                digest.assert_not_called()

    def test_raw_duplicate_keys_at_every_level_reject(self):
        content = _canonical(m.component_fixture())
        cases = (
            content.replace('"schema_version":1', '"schema_version":1,"schema_version":1'),
            content.replace('"filter_id":"sensor"', '"filter_id":"sensor","filter_id":"other"'),
            '{"a":{"b":1,"b":1}}',
        )
        for text in cases:
            self.deny_before_hash(
                lambda text=text: m.analyze_supplied_mqtt_topics_bytes(
                    model_bytes=text.encode("ascii")
                )
            )

    def test_raw_depth_nodes_and_integer_lexical_cost_deny_before_decoder(self):
        cases = (
            "[" * 16 + "0" + "]" * 16,
            "[" + ",".join("0" for _ in range(m.MAX_MODEL_NODES)) + "]",
            "9" * 21,
            "9223372036854775808",
            "-9223372036854775809",
            "--1",
            "1.0",
            "NaN",
        )
        for text in cases:
            with patch.object(m.json, "loads") as decoder, patch.object(m, "_digest") as digest:
                with self.assertRaises(m.MqttTopicAnalysisError):
                    m.analyze_supplied_mqtt_topics_bytes(model_bytes=text.encode("ascii"))
                decoder.assert_not_called()
                digest.assert_not_called()

    def test_raw_integer_extremes_and_lexical_depth_boundary_are_native_then_closed(self):
        for text in ("9223372036854775807", "-9223372036854775808", "[" * 15 + "0" + "]" * 15):
            real_decoder = m.json.loads
            with patch.object(m.json, "loads", wraps=real_decoder) as decoder:
                self.deny_before_hash(
                    lambda text=text: m.analyze_supplied_mqtt_topics_bytes(
                        model_bytes=text.encode("ascii")
                    )
                )
                self.assertEqual(decoder.call_count, 1)

    def test_native_final_primitive_and_escaped_byte_bounds_are_exact(self):
        for value in (None, False, True, 1):
            budget = m._Budget()
            _, size, _ = m._capture(value, budget)
            with self.assertRaises(m.MqttTopicAnalysisError):
                m._capture(value, m._Budget(), byte_limit=size - 1)
            self.assertEqual(m._capture(value, m._Budget(), byte_limit=size)[1], size)
        text = "\U0001f600" * 1024
        self.assertEqual(m._capture(text, m._Budget())[1], 12 * 1024 + 2)
        self.deny_before_hash(lambda: self.analyze(_model((text + "a",))))

    def test_native_raw_model_byte_and_wrong_input_families_reject(self):
        for content in (b"", bytearray(b"{}"), "{}", b" " * (m.MAX_MODEL_BYTES + 1)):
            self.deny_before_hash(
                lambda content=content: m.analyze_supplied_mqtt_topics_bytes(model_bytes=content)
            )
        for text in ("", " " * (m.MAX_REPORT_BYTES + 1), None, b"{}"):
            self.deny_before_hash(lambda text=text: m.MqttTopicAnalysis.from_json(text))

    def test_utf8_and_level_software_boundaries_are_not_fabricated_protocol_findings(self):
        for text in ("a" * 4096, "\u00e9" * 2048, "/".join("a" for _ in range(64))):
            document = self.analyze(_model((text,), (text,), ((0, 0),))).to_dict()
            self.assertTrue(document["match_results"][0]["matches"])
        for text in ("a" * 4097, "\u00e9" * 2049, "/".join("a" for _ in range(65))):
            self.deny_before_hash(lambda text=text: self.analyze(_model((text,))))

    def test_array_and_explicit_pair_ceilings_deny_before_hash(self):
        for field, limit in (
            ("filters", m.MAX_FILTERS),
            ("topics", m.MAX_TOPICS),
            ("match_queries", m.MAX_MATCH_QUERIES),
            ("overlap_queries", m.MAX_OVERLAP_QUERIES),
        ):
            model = m.component_fixture()
            model[field] = model[field][:1] * (limit + 1)
            self.deny_before_hash(lambda model=model: self.analyze(model))

    def test_real_retained_node_ceiling_rejects_valid_bounded_source_before_any_digest(self):
        model = _model(
            ("a",) * 128,
            ("a",) * 128,
            tuple((index % 128, index % 128) for index in range(512)),
            tuple((index % 128, (index + 1) % 128) for index in range(256)),
        )
        owned, size, nodes = m._capture(model, m._Budget())
        m._validated(owned, m._Budget())
        self.assertLessEqual(size, m.MAX_MODEL_BYTES)
        self.assertLessEqual(nodes, m.MAX_MODEL_NODES)
        self.deny_before_hash(lambda: self.analyze(model))
        self.deny_before_hash(
            lambda: m.analyze_supplied_mqtt_topics_bytes(
                model_bytes=_canonical(model).encode("ascii")
            )
        )

    def test_real_retained_byte_ceiling_rejects_valid_source_before_any_digest(self):
        model = _model(("a" * 4096,), overlaps=((0, 0),) * 256)
        owned, size, _ = m._capture(model, m._Budget())
        m._validated(owned, m._Budget())
        self.assertLess(size, m.MAX_MODEL_BYTES)
        self.deny_before_hash(lambda: self.analyze(model))
        self.deny_before_hash(
            lambda: m.analyze_supplied_mqtt_topics_bytes(
                model_bytes=_canonical(model).encode("ascii")
            )
        )

    def test_real_separate_original_work_ceiling_denies_before_any_digest(self):
        text = "a" * 4096
        model = _model((text,) * 40, (text,), ((0, 0),) * 512, ((0, 0),) * 120)
        report = self.analyze(model)
        document = report.to_dict()
        self.assertLess(len(_canonical(model)), m.MAX_MODEL_BYTES)
        self.assertLess(len(_canonical(document)), m.MAX_REPORT_BYTES)
        self.deny_before_hash(lambda: m.verify_supplied_mqtt_topic_analysis(report, model=model))

    def test_each_public_operation_funds_exact_cumulative_work_before_any_digest(self):
        model = m.component_fixture()
        report = self.analyze(model)
        document = report.to_dict()
        text = report.to_json()
        operations = (
            lambda: self.analyze(model),
            lambda: m.analyze_supplied_mqtt_topics_bytes(
                model_bytes=_canonical(model).encode("ascii")
            ),
            lambda: m.MqttTopicAnalysis(text),
            lambda: m.MqttTopicAnalysis.from_dict(document),
            lambda: m.MqttTopicAnalysis.from_json(text),
            report.to_dict,
            report.to_json,
            lambda: m.verify_supplied_mqtt_topic_analysis(report, model=model),
        )
        original = m._Budget.charge
        for operation in operations:
            needed = _recorded_work(operation)
            for adjustment in (-1, 0):
                limit = needed + adjustment

                def capped(self, amount, limit=limit):
                    if amount > limit - self.used:
                        raise m.MqttTopicAnalysisError("Test-observed exact work ceiling exceeded")
                    original(self, amount)

                with (
                    self.subTest(operation=operations.index(operation), adjustment=adjustment),
                    patch.object(m._Budget, "charge", capped),
                ):
                    if adjustment < 0:
                        self.deny_before_hash(operation)
                    else:
                        operation()

    def test_cohashed_false_matches_witnesses_and_disjointness_reject_full_replay(self):
        document = self.analyze().to_dict()
        cases = []
        changed = copy.deepcopy(document)
        changed["match_results"][0]["matches"] = not changed["match_results"][0]["matches"]
        cases.append(changed)
        changed = copy.deepcopy(document)
        changed["overlap_results"][0]["witness_topic"] = "other"
        cases.append(changed)
        changed = copy.deepcopy(document)
        changed["overlap_results"][0].update(m._overlap_row("disjoint"))
        cases.append(changed)
        changed = copy.deepcopy(document)
        changed["overlap_results"][1].update(
            m._overlap_row("overlap_witness", witness="$SYS", minimum_bytes=4, levels=1)
        )
        cases.append(changed)
        for changed in cases:
            readdressed = _readdress(changed)
            with self.assertRaises(m.MqttTopicAnalysisError):
                m.MqttTopicAnalysis.from_dict(readdressed)
            with self.assertRaises(m.MqttTopicAnalysisError):
                m.MqttTopicAnalysis.from_json(_canonical(readdressed))

    def test_cohashed_native_scalar_aliases_and_promoted_effects_are_rejected(self):
        baseline = self.analyze().to_dict()
        cases = []
        for value in (1, 1.0):
            changed = copy.deepcopy(baseline)
            changed["match_results"][0]["matches"] = value
            cases.append(changed)
        changed = copy.deepcopy(baseline)
        changed["effects"]["authority"] = "granted"
        cases.append(changed)
        changed = copy.deepcopy(baseline)
        changed["claims"]["broker_behavior_proven"] = True
        cases.append(changed)
        changed = copy.deepcopy(baseline)
        changed["source_model"]["schema_version"] = True
        changed["source_model_sha256"] = (
            "sha256:"
            + hashlib.sha256(
                m.MODEL_DOMAIN.encode("ascii")
                + b"\n"
                + _canonical(changed["source_model"]).encode("ascii")
            ).hexdigest()
        )
        cases.append(changed)
        for changed in cases:
            with self.assertRaises(m.MqttTopicAnalysisError):
                m.MqttTopicAnalysis.from_dict(_readdress(changed))

    def test_valid_alternate_source_is_not_verification_against_the_original(self):
        original = m.component_fixture()
        alternate = copy.deepcopy(original)
        alternate["filters"][0]["topic_filter"] = "other/#"
        report = self.analyze(alternate)
        self.assertEqual(
            m.MqttTopicAnalysis.from_json(report.to_json()).to_json(), report.to_json()
        )
        with self.assertRaises(m.MqttTopicAnalysisError):
            m.verify_supplied_mqtt_topic_analysis(report, model=original)

    def test_cohashed_source_substitution_cannot_preserve_original_results(self):
        document = self.analyze().to_dict()
        document["source_model"]["filters"][0]["topic_filter"] = "other/#"
        document["source_model_sha256"] = (
            "sha256:"
            + hashlib.sha256(
                m.MODEL_DOMAIN.encode("ascii")
                + b"\n"
                + _canonical(document["source_model"]).encode("ascii")
            ).hexdigest()
        )
        with self.assertRaises(m.MqttTopicAnalysisError):
            m.MqttTopicAnalysis.from_dict(_readdress(document))

    def test_missing_slots_wrong_wrappers_and_readdressed_wrapper_mutation_deny(self):
        missing = object.__new__(m.MqttTopicAnalysis)
        for operation in (
            missing.to_dict,
            missing.to_json,
            lambda: m.verify_supplied_mqtt_topic_analysis(missing, model=m.component_fixture()),
        ):
            self.deny_before_hash(operation)
        for value in ({}, None, True, "{}"):
            self.deny_before_hash(
                lambda value=value: m.verify_supplied_mqtt_topic_analysis(
                    value, model=m.component_fixture()
                )
            )
        report = self.analyze()
        false = report.to_dict()
        false["match_results"][0]["matches"] = not false["match_results"][0]["matches"]
        object.__setattr__(report, "document_json", _canonical(_readdress(false)))
        for operation in (
            report.to_dict,
            report.to_json,
            lambda: m.verify_supplied_mqtt_topic_analysis(report, model=m.component_fixture()),
        ):
            with self.assertRaises(m.MqttTopicAnalysisError):
                operation()

    def test_report_json_is_exact_canonical_and_hash_or_field_tamper_rejects(self):
        document = self.analyze().to_dict()
        for text in (
            json.dumps(document, indent=2),
            _canonical(document) + "\n",
            _canonical(document).replace('"schema_version":1', '"schema_version":1.0'),
        ):
            with self.assertRaises(m.MqttTopicAnalysisError):
                m.MqttTopicAnalysis.from_json(text)
        for field in ("analysis_id", "analysis_sha256", "source_model_sha256"):
            changed = copy.deepcopy(document)
            changed[field] = "invalid"
            with self.assertRaises(m.MqttTopicAnalysisError):
                m.MqttTopicAnalysis.from_dict(changed)
        changed = copy.deepcopy(document)
        changed["extra"] = "closed"
        with self.assertRaises(m.MqttTopicAnalysisError):
            m.MqttTopicAnalysis.from_dict(_readdress(changed))


if __name__ == "__main__":
    unittest.main()
