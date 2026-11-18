from __future__ import annotations

import copy
import hashlib
import itertools
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_android_component_analysis as android

ERROR = android.AndroidComponentAnalysisError


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def component(**changes):
    value = {
        "component_id": "synthetic-component",
        "kind": "activity",
        "enabled": None,
        "exported": None,
        "has_intent_filters": False,
    }
    value.update(changes)
    return value


def model(components=None, **changes):
    value = {
        "schema_version": 1,
        "source_id": "synthetic-merged",
        "projection_complete": True,
        "target_sdk": 31,
        "application_enabled": None,
        "components": [component()] if components is None else components,
    }
    value.update(changes)
    return value


def observe(**changes):
    return android.analyze_supplied_android_components(model([component(**changes)])).to_dict()[
        "component_observations"
    ][0]


def readdress(document):
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = hashlib.sha256(
        ("sunderkey.offline-android-component-analysis.v1\n" + canonical(body)).encode("ascii")
    ).hexdigest()
    document["analysis_id"] = "ACD-" + digest[:32].upper()
    document["analysis_sha256"] = "sha256:" + digest
    return document


class AndroidComponentAnalysisTests(unittest.TestCase):
    def deny_before_hash(self, supplied):
        with (
            patch.object(android, "_address") as address,
            patch.object(android.hashlib, "sha256") as digest,
            self.assertRaises(ERROR),
        ):
            android.analyze_supplied_android_components(supplied)
        address.assert_not_called()
        digest.assert_not_called()

    def deny_before_decoder(self, content):
        with (
            patch.object(android.json, "loads") as decoder,
            patch.object(android, "_address") as address,
            self.assertRaises(ERROR),
        ):
            android.AndroidComponentAnalysis.from_json(content)
        decoder.assert_not_called()
        address.assert_not_called()

    def test_fresh_synthetic_fixture_has_exact_declared_outcomes(self):
        fixture = android.component_fixture()
        other = android.component_fixture()
        self.assertEqual(fixture, other)
        self.assertIsNot(fixture, other)
        self.assertIsNot(fixture["components"], other["components"])
        document = android.analyze_supplied_android_components(fixture).to_dict()
        self.assertEqual(
            [row["outcome"] for row in document["component_observations"]],
            [
                "declaration_subset_resolved",
                "missing_required_exported_declaration",
                "declaration_subset_resolved",
            ],
        )
        self.assertEqual(
            [row["declared_enabled"] for row in document["component_observations"]],
            [True, False, True],
        )
        self.assertEqual(
            [row["declared_exported"] for row in document["component_observations"]],
            [False, None, False],
        )

    def test_literal_fixture_addresses_and_independent_address_oracle(self):
        source = android.component_fixture()
        result = android.analyze_supplied_android_components(source).to_dict()
        source_digest = hashlib.sha256(
            ("sunderkey.offline-android-component-model.v1\n" + canonical(source)).encode("ascii")
        ).hexdigest()
        self.assertEqual(result["source_model_sha256"], "sha256:" + source_digest)
        self.assertEqual(readdress(copy.deepcopy(result)), result)
        # Literal identities are pinned from the first authorized benign fixture run.
        self.assertEqual(result["analysis_id"], "ACD-94DF8096C55E2BC435527108C195B381")
        self.assertEqual(
            result["analysis_sha256"],
            "sha256:94df8096c55e2bc435527108c195b381ead53cdeafaa3a455cc067388524cc1b",
        )
        self.assertEqual(
            result["source_model_sha256"],
            "sha256:0332d9f1e5a655b95ab8b2f55affdef5cb27b6dafa8769ea308acd83e764aa26",
        )

    def test_public_native_json_and_bytes_roundtrip_and_separate_source_replay(self):
        source = android.component_fixture()
        report = android.analyze_supplied_android_components(source)
        text = report.to_json()
        for replay in (
            android.AndroidComponentAnalysis(report.to_dict()),
            android.AndroidComponentAnalysis.from_dict(report.to_dict()),
            android.AndroidComponentAnalysis.from_json(text),
            android.analyze_supplied_android_components_bytes(
                model_bytes=canonical(source).encode()
            ),
            android.verify_supplied_android_component_analysis(report, model=source),
        ):
            self.assertEqual(replay.to_json(), text)
            self.assertIs(type(replay), android.AndroidComponentAnalysis)

    def test_nullable_enabled_and_exported_independent_truth_table(self):
        # Table lookup, rather than sharing the analyzer's branch conditions.
        default_enabled = {None: True, False: False, True: True}
        for sdk, application in itertools.product(
            (None, 1, 30, 31, 32, 2147483647), (None, False, True)
        ):
            inputs = []
            expected = []
            for index, (kind, enabled, exported, filters) in enumerate(
                itertools.product(
                    ("activity", "service", "receiver"),
                    (None, False, True),
                    (None, False, True),
                    (False, True),
                )
            ):
                inputs.append(
                    component(
                        component_id=f"truth-{index}",
                        kind=kind,
                        enabled=enabled,
                        exported=exported,
                        has_intent_filters=filters,
                    )
                )
                declared_enabled = default_enabled[application] and default_enabled[enabled]
                if exported in (False, True):
                    effective = exported
                    outcome = "declaration_subset_resolved"
                    satisfied = True
                elif filters is False:
                    effective, outcome, satisfied = False, "declaration_subset_resolved", True
                else:
                    table = {
                        None: (None, "unassessed", None),
                        "legacy": (True, "declaration_subset_resolved", True),
                        "modern": (None, "missing_required_exported_declaration", False),
                    }
                    band = None if sdk is None else ("legacy" if sdk < 31 else "modern")
                    effective, outcome, satisfied = table[band]
                required = False if not filters else (None if sdk is None else sdk >= 31)
                combined = (
                    declared_enabled and effective
                    if outcome == "declaration_subset_resolved"
                    else None
                )
                expected.append(
                    (declared_enabled, effective, outcome, satisfied, required, combined)
                )
            rows = android.analyze_supplied_android_components(
                model(inputs, target_sdk=sdk, application_enabled=application)
            ).to_dict()["component_observations"]
            self.assertEqual(len(rows), len(expected))
            for row, values in zip(rows, expected, strict=True):
                with self.subTest(
                    sdk=sdk, application=application, component_id=row["component_id"]
                ):
                    self.assertEqual(
                        tuple(
                            row[field]
                            for field in (
                                "declared_enabled",
                                "declared_exported",
                                "outcome",
                                "explicit_exported_requirement_satisfied",
                                "requires_explicit_exported",
                                "declared_enabled_and_exported",
                            )
                        ),
                        values,
                    )

    def test_sdk31_filter_requirement_is_not_disabled_away(self):
        for kind, app, own in itertools.product(
            ("activity", "service", "receiver"), (None, False, True), (None, False, True)
        ):
            source = model(
                [component(kind=kind, enabled=own, exported=None, has_intent_filters=True)],
                application_enabled=app,
            )
            row = android.analyze_supplied_android_components(source).to_dict()[
                "component_observations"
            ][0]
            self.assertEqual(row["outcome"], "missing_required_exported_declaration")
            self.assertIs(row["requires_explicit_exported"], True)
            self.assertIs(row["explicit_exported_requirement_satisfied"], False)
            self.assertIsNone(row["declared_exported"])
            self.assertIsNone(row["declared_enabled_and_exported"])

    def test_sdk30_and31_exact_threshold(self):
        for sdk, effective, status in (
            (1, True, "declaration_subset_resolved"),
            (30, True, "declaration_subset_resolved"),
            (31, None, "missing_required_exported_declaration"),
            (2147483647, None, "missing_required_exported_declaration"),
        ):
            row = android.analyze_supplied_android_components(
                model([component(has_intent_filters=True)], target_sdk=sdk)
            ).to_dict()["component_observations"][0]
            self.assertIs(row["declared_exported"], effective)
            self.assertEqual(row["outcome"], status)

    def test_explicit_false_never_becomes_a_true_default(self):
        for kind, sdk, filters in itertools.product(
            ("activity", "service", "receiver"), (None, 30, 31), (False, True)
        ):
            row = android.analyze_supplied_android_components(
                model(
                    [component(kind=kind, exported=False, has_intent_filters=filters)],
                    target_sdk=sdk,
                )
            ).to_dict()["component_observations"][0]
            self.assertIs(row["declared_exported"], False)
            self.assertEqual(row["exported_resolution"], "explicit_attribute")
            self.assertEqual(row["outcome"], "declaration_subset_resolved")

    def test_enabled_conjunction_and_descriptive_default_flags(self):
        for app, own in itertools.product((None, False, True), repeat=2):
            row = android.analyze_supplied_android_components(
                model([component(enabled=own, exported=True)], application_enabled=app)
            ).to_dict()["component_observations"][0]
            self.assertIs(row["application_enabled_defaulted"], app is None)
            self.assertIs(row["component_enabled_defaulted"], own is None)
            self.assertIs(row["declared_enabled"], not any(value is False for value in (app, own)))
            self.assertEqual(row["declared_enabled_and_exported"], row["declared_enabled"])

    def test_unknown_sdk_does_not_guess_missing_filter_exported(self):
        row = android.analyze_supplied_android_components(
            model([component(has_intent_filters=True)], target_sdk=None)
        ).to_dict()["component_observations"][0]
        self.assertEqual(row["outcome"], "unassessed")
        self.assertEqual(row["reasons"], ["target_sdk_unavailable_for_filter_default"])
        for field in (
            "declared_exported",
            "requires_explicit_exported",
            "explicit_exported_requirement_satisfied",
            "declared_enabled_and_exported",
        ):
            self.assertIsNone(row[field])

    def test_unknown_sdk_can_preserve_explicit_or_no_filter_declarations(self):
        for exported, filters in ((None, False), (True, False), (False, True), (True, True)):
            row = android.analyze_supplied_android_components(
                model([component(exported=exported, has_intent_filters=filters)], target_sdk=None)
            ).to_dict()["component_observations"][0]
            self.assertEqual(row["outcome"], "declaration_subset_resolved")
            self.assertIs(row["declared_exported"], False if exported is None else exported)
            self.assertIs(row["explicit_exported_requirement_satisfied"], True)

    def test_incomplete_projection_globally_withholds_derived_declarations(self):
        for sdk, app, own, exported, filters in itertools.product(
            (None, 30, 31),
            (None, False, True),
            (None, False, True),
            (None, False, True),
            (False, True),
        ):
            row = android.analyze_supplied_android_components(
                model(
                    [component(enabled=own, exported=exported, has_intent_filters=filters)],
                    projection_complete=False,
                    target_sdk=sdk,
                    application_enabled=app,
                )
            ).to_dict()["component_observations"][0]
            for field in (
                "declared_enabled",
                "declared_exported",
                "requires_explicit_exported",
                "explicit_exported_requirement_satisfied",
                "declared_enabled_and_exported",
            ):
                self.assertIsNone(row[field])
            self.assertEqual(row["outcome"], "unassessed")
            self.assertEqual(row["reasons"], ["merged_projection_incomplete"])
            self.assertIs(row["exported_attribute"], exported)

    def test_empty_declared_projection_is_content_not_installability(self):
        result = android.analyze_supplied_android_components(model([])).to_dict()
        self.assertEqual(result["component_count"], 0)
        self.assertEqual(result["component_observations"], [])
        self.assertIs(result["flags"]["installability_verified"], False)

    def test_source_and_component_identity_are_opaque_not_class_inference(self):
        source = model(
            [component(component_id="not-a.class:retained-id")], source_id="source:fixture-1"
        )
        result = android.analyze_supplied_android_components(source).to_dict()
        self.assertEqual(result["source_model"], source)
        self.assertEqual(
            result["component_observations"][0]["component_id"], "not-a.class:retained-id"
        )
        for field, bad in (("source_id", "x" * 129), ("source_id", "bad space")):
            self.deny_before_hash(model(**{field: bad}))
        for bad in ("", "x" * 129, "bad space", "../relative"):
            self.deny_before_hash(model([component(component_id=bad)]))

    def test_duplicate_identity_is_denied_even_for_different_kinds(self):
        self.deny_before_hash(model([component(), component(kind="service")]))

    def test_unknown_alias_provider_and_native_kind_shapes_fail_closed(self):
        for kind in (
            "provider",
            "activity-alias",
            "dynamic_receiver",
            "unknown",
            [],
            {},
            True,
            None,
        ):
            self.deny_before_hash(model([component(kind=kind)]))

    def test_closed_fields_and_missing_fields_fail_before_hash(self):
        base = model()
        for name in base:
            incomplete = copy.deepcopy(base)
            incomplete.pop(name)
            self.deny_before_hash(incomplete)
        for name in component():
            incomplete = component()
            incomplete.pop(name)
            self.deny_before_hash(model([incomplete]))
        for extra in (
            "permissions",
            "apk_path",
            "platform_sdk",
            "aliases",
            "credentials",
            "callback",
        ):
            self.deny_before_hash(model(**{extra: None}))
            self.deny_before_hash(model([component(**{extra: None})]))

    def test_boolean_aliases_are_not_coerced(self):
        for invalid in (0, 1, 0.0, 1.0, "true", "false", [], {}):
            self.deny_before_hash(model(application_enabled=invalid))
            self.deny_before_hash(model(projection_complete=invalid))
            for name in ("enabled", "exported", "has_intent_filters"):
                self.deny_before_hash(model([component(**{name: invalid})]))
        self.deny_before_hash(model(projection_complete=None))
        self.deny_before_hash(model([component(has_intent_filters=None)]))

    def test_schema_and_sdk_integer_aliases_limits_are_native(self):
        for invalid in (True, False, 1.0, "1", None, 0, 2):
            self.deny_before_hash(model(schema_version=invalid))
        for invalid in (True, False, 31.0, "31", -1, 0, 2147483648, 2**63, -(2**63) - 1):
            self.deny_before_hash(model(target_sdk=invalid))
        self.deny_before_hash(model(target_sdk=2**5000))

    def test_exact_native_collections_and_scalar_subclasses_before_copy(self):
        class Text(str):
            def __str__(self):
                raise AssertionError("String normalization hook reached")

        class Number(int):
            def __str__(self):
                raise AssertionError("Number normalization hook reached")

        class Mapping(dict):
            def items(self):
                raise AssertionError("Mapping hook reached")

        class Sequence(list):
            def __iter__(self):
                raise AssertionError("Sequence hook reached")

        for source in (
            Mapping(model()),
            model(Sequence([component()])),
            model([Mapping(component())]),
            model(source_id=Text("synthetic")),
            model(target_sdk=Number(31)),
            model([component(kind=Text("activity"))]),
            model(tuple([component()])),
        ):
            with patch.object(android.json, "dumps") as serializer:
                self.deny_before_hash(source)
            serializer.assert_not_called()

    def test_native_cycle_dag_depth_nodes_strings_and_escape_cost_before_copy(self):
        cycle = []
        cycle.append(cycle)
        deep = None
        for _ in range(16):
            deep = [deep]
        shared = ["x" * 512] * 128
        for source in (cycle, deep, [shared] * 40, [None] * 32768, ['"' * 512] * 1100):
            with patch.object(android.json, "dumps") as serializer:
                self.deny_before_hash(source)
            serializer.assert_not_called()
        for source in (
            model(source_id="x" * 513),
            model(source_id=chr(127)),
            model(source_id="e\u0301"),
        ):
            with patch.object(android.json, "dumps") as serializer:
                self.deny_before_hash(source)
            serializer.assert_not_called()

    def test_component_count_and_cumulative_output_limits_are_not_declaration_findings(self):
        self.deny_before_hash(model([component(component_id=f"c-{i}") for i in range(1025)]))
        # This genuine native model fits input limits but its complete rows exceed
        # the retained-output node ceiling, before any model or result digest.
        large = model([component(component_id=f"c-{i}") for i in range(1024)])
        self.assertLess(len(canonical(large)), android.MAX_DOCUMENT_BYTES)
        self.assertLess(android._measure(large)[1], android.MAX_NATIVE_NODES)
        self.deny_before_hash(large)

    def test_report_identity_fields_and_row_retention_are_budgeted_before_hash(self):
        source = android.component_fixture()
        report = android.analyze_supplied_android_components(source)
        full_size = len(report.to_json())
        self.assertGreater(full_size, len(canonical(source)))
        with patch.object(android, "MAX_DOCUMENT_BYTES", full_size - 1):
            self.deny_before_hash(source)
        many = model([component(component_id=f"row-{i}") for i in range(100)])
        with patch.object(android, "MAX_DOCUMENT_BYTES", len(canonical(many)) + 1):
            self.deny_before_hash(many)

    def test_final_replay_export_equality_work_reserved_before_first_hash(self):
        source = android.component_fixture()
        charges = []
        original = android._Work.charge

        def measured(self, amount):
            original(self, amount)
            charges.append(self.count)

        with patch.object(android._Work, "charge", measured):
            report = android.analyze_supplied_android_components(source)
            text = report.to_json()
        exact = max(charges)
        for operation in (
            lambda: android.analyze_supplied_android_components(source),
            report.to_json,
            lambda: android.AndroidComponentAnalysis.from_json(text),
        ):
            with (
                patch.object(android, "MAX_WORK", exact - 1),
                patch.object(android, "_address") as address,
                patch.object(android.hashlib, "sha256") as digest,
                self.assertRaisesRegex(ERROR, "work bound"),
            ):
                operation()
            address.assert_not_called()
            digest.assert_not_called()
        with patch.object(android, "MAX_WORK", exact):
            self.assertEqual(android.analyze_supplied_android_components(source).to_json(), text)
            self.assertEqual(android.AndroidComponentAnalysis.from_json(text).to_json(), text)
        with (
            patch.object(android, "MAX_WORK", 1),
            patch.object(android.json, "dumps") as serializer,
        ):
            self.deny_before_hash(source)
        serializer.assert_not_called()

    def test_raw_integer_lexical_bounds_precede_decoder(self):
        for token in (
            "--1",
            "---1",
            "--0",
            "01",
            "-01",
            "+1",
            "1.0",
            "1e0",
            "NaN",
            "Infinity",
            "9223372036854775808",
            "-9223372036854775809",
            "9" * 20000,
        ):
            self.deny_before_decoder('{"schema_version":' + token + ',"components":[]}')

    def test_raw_scalar_depth_nodes_escaped_strings_bytes_precede_decoder(self):
        for scalar in ("0", "true", "null", '"text"'):
            self.deny_before_decoder("[" * 16 + scalar + "]" * 16)
        for text in (
            '"' + "x" * 513 + '"',
            '"' + "\\u0078" * 513 + '"',
            '"\\u007f"',
            '"\\ud800"',
            '"\\n"',
            " " * 1048577,
            "[" + ",".join(["null"] * 32768) + "]",
        ):
            self.deny_before_decoder(text)

    def test_duplicate_raw_keys_malformed_documents_bool_aliases(self):
        text = canonical(model())
        for content in (
            text.replace('"schema_version":1', '"schema_version":1,"schema_version":1'),
            text.replace('"exported":null', '"exported":null,"exported":null'),
            text.replace('"exported":null', '"exported":0'),
            text.replace('"schema_version":1', '"schema_version":true'),
            "{]",
            "null",
            "[]",
            "{}",
            text[:-1],
        ):
            with patch.object(android, "_address") as address, self.assertRaises(ERROR):
                android.analyze_supplied_android_components_bytes(model_bytes=content.encode())
            address.assert_not_called()

    def test_native_bytes_family_and_ascii_contract_before_decode(self):
        class Bytes(bytes):
            pass

        for content in (
            None,
            "{}",
            b"",
            b"\xff",
            bytearray(b"{}"),
            memoryview(b"{}"),
            Bytes(b"{}"),
            b" " * 1048577,
        ):
            with patch.object(android.json, "loads") as decoder, self.assertRaises(ERROR):
                android.analyze_supplied_android_components_bytes(model_bytes=content)
            decoder.assert_not_called()

    def test_equivalent_raw_json_spelling_preserves_model_identity(self):
        source = android.component_fixture()
        expected = android.analyze_supplied_android_components(source).to_json()
        for text in (
            json.dumps(source, indent=2),
            canonical(source).replace("synthetic", "\\u0073ynthetic"),
        ):
            self.assertEqual(
                android.analyze_supplied_android_components_bytes(
                    model_bytes=text.encode()
                ).to_json(),
                expected,
            )

    def test_embedded_and_separate_source_ownership_and_detachment(self):
        source = android.component_fixture()
        original = copy.deepcopy(source)
        report = android.analyze_supplied_android_components(source)
        text = report.to_json()
        source["components"][0]["exported"] = True
        exported = report.to_dict()
        exported["source_model"]["components"].clear()
        exported["component_observations"][0]["declared_exported"] = True
        self.assertEqual(report.to_json(), text)
        self.assertEqual(
            android.verify_supplied_android_component_analysis(report, model=original).to_json(),
            text,
        )
        with self.assertRaises(ERROR):
            android.verify_supplied_android_component_analysis(report, model=source)

    def test_original_array_order_and_source_premises_are_bound(self):
        original = android.component_fixture()
        report = android.analyze_supplied_android_components(original)
        for field, value in (
            ("source_id", "other-source"),
            ("target_sdk", 30),
            ("application_enabled", False),
            ("projection_complete", False),
        ):
            changed = copy.deepcopy(original)
            changed[field] = value
            with self.assertRaises(ERROR):
                android.verify_supplied_android_component_analysis(report, model=changed)
        changed = copy.deepcopy(original)
        changed["components"].reverse()
        other = android.analyze_supplied_android_components(changed)
        self.assertNotEqual(other.analysis_id, report.analysis_id)
        self.assertEqual(
            [r["component_id"] for r in other.to_dict()["component_observations"]],
            [c["component_id"] for c in changed["components"]],
        )
        with self.assertRaises(ERROR):
            android.verify_supplied_android_component_analysis(report, model=changed)

    def test_coherently_readdressed_false_facts_cannot_replay(self):
        report = android.analyze_supplied_android_components(android.component_fixture()).to_dict()
        for field, value in (
            ("declared_enabled", False),
            ("declared_exported", True),
            ("requires_explicit_exported", False),
            ("explicit_exported_requirement_satisfied", False),
            ("declared_enabled_and_exported", True),
            ("exported_resolution", "pre31_retained_filter_default_true"),
            ("outcome", "unassessed"),
            ("reasons", ["fabricated"]),
        ):
            document = copy.deepcopy(report)
            document["component_observations"][0][field] = value
            readdress(document)
            with self.assertRaises(ERROR):
                android.AndroidComponentAnalysis.from_dict(document)
            with self.assertRaises(ERROR):
                android.AndroidComponentAnalysis.from_json(canonical(document))

    def test_coherent_changed_source_is_unsigned_content_not_original_source(self):
        original = android.component_fixture()
        changed = copy.deepcopy(original)
        changed["components"][0]["exported"] = True
        report = android.analyze_supplied_android_components(changed)
        self.assertEqual(
            android.AndroidComponentAnalysis.from_json(report.to_json()).to_json(), report.to_json()
        )
        with self.assertRaises(ERROR):
            android.verify_supplied_android_component_analysis(report, model=original)

    def test_native_rehashed_metadata_aliases_and_promotions_are_rejected(self):
        baseline = android.analyze_supplied_android_components(
            android.component_fixture()
        ).to_dict()
        for path, value in (
            (("schema_version",), True),
            (("component_count",), 3.0),
            (("component_observations", 0, "declared_enabled"), 1),
            (("source_model_sha256",), "sha256:" + "a" * 64),
            (("flags", "installability_verified"), True),
            (("effects", "ipc"), "allowed"),
            (("parser_source_profile", "explicit_exported_target_sdk_threshold"), 30),
            (("bounds", "maximum_native_nodes"), 99999),
        ):
            document = copy.deepcopy(baseline)
            target = document
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            readdress(document)
            with self.assertRaises(ERROR):
                android.AndroidComponentAnalysis.from_dict(document)

    def test_incomplete_wrapper_and_wrong_family_fail_at_supported_public_use(self):
        incomplete = object.__new__(android.AndroidComponentAnalysis)
        for operation in (
            incomplete.to_dict,
            incomplete.to_json,
            lambda: android.verify_supplied_android_component_analysis(incomplete, model=model()),
        ):
            with self.assertRaises(ERROR):
                operation()
        for wrong in (None, {}, object()):
            with self.assertRaises(ERROR):
                android.verify_supplied_android_component_analysis(wrong, model=model())

        class Foreign(android.AndroidComponentAnalysis):
            pass

        valid = android.analyze_supplied_android_components(model())
        with self.assertRaises(ERROR):
            android.verify_supplied_android_component_analysis(
                Foreign(valid.to_dict()), model=model()
            )

    def test_exact_profile_no_effects_no_authority_or_runtime_promotion(self):
        result = android.analyze_supplied_android_components(android.component_fixture()).to_dict()
        for name, value in (
            ("component_id", "android_supplied_component_declarations"),
            ("profile_id", "AOE-GB-D08-S03"),
            ("capability_id", "army.gb.d08.s03"),
            ("vector_id", "AV-GB-D08-S03-01"),
            ("work_package_id", "IWP2-AOE-GB-D08-S03"),
            ("wave_id", "IW2-007"),
            ("commander_id", "AOE-GB-D08-CMD"),
            ("group_owner_id", "AOE-HQ-04"),
            ("independent_validator_id", "AOE-HQ-19"),
            (
                "blueprint_sha256",
                "sha256:85aad60ac63ea5f31466de3fcbc888d6ce67b9ec1358e231de7ee8a34709031b",
            ),
        ):
            self.assertEqual(result[name], value)
        self.assertTrue(
            all(type(flag) is bool and flag is False for flag in result["flags"].values())
        )
        self.assertEqual(set(result["effects"].values()), {"none"})


if __name__ == "__main__":
    unittest.main()
