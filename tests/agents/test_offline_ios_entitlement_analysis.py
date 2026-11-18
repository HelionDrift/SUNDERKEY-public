"""Genuine supplied allowlist arithmetic and exact native/source replay regressions."""

from __future__ import annotations

import copy
import hashlib
import itertools
import json
import unittest
from dataclasses import FrozenInstanceError
from unittest.mock import patch

from sunderkey import offline_ios_entitlement_analysis as s


def component_fixture():
    return s.component_fixture()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def readdress(document):
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = (
        "sha256:"
        + hashlib.sha256(
            b"sunderkey.offline-ios-entitlement-analysis.v1\n" + canonical(body).encode("ascii")
        ).hexdigest()
    )
    document["analysis_id"] = "IEA-" + digest[7:39].upper()
    document["analysis_sha256"] = digest
    return document


class IosEntitlementAnalysisTests(unittest.TestCase):
    def analyze(self, model=None):
        return s.analyze_supplied_ios_entitlements(component_fixture() if model is None else model)

    def row(self, document, key, value=None):
        rows = [
            row
            for row in document["entitlement_observations"]
            if row["entitlement_key"] == key and (value is None or row["claim_value"] == value)
        ]
        self.assertEqual(len(rows), 1)
        return rows[0]

    def denied_before_hash(self, call):
        with (
            patch.object(s, "_digest", side_effect=AssertionError("hash reached")) as digest,
            self.assertRaises(s.IosEntitlementAnalysisError),
        ):
            call()
        self.assertEqual(digest.call_count, 0)

    def test_actual_fixture_literal_addresses_and_allowlist_results(self):
        document = self.analyze().to_dict()
        self.assertEqual(document["analysis_id"], "IEA-6B521E7012850EFFCFE54D67DA106371")
        self.assertEqual(
            document["analysis_sha256"],
            "sha256:6b521e7012850effcfe54d67da106371a88c37b628c4f1de9ca2ad133c9532b6",
        )
        self.assertEqual(
            document["source_model_sha256"],
            "sha256:3ff969c2ee9ebd6628540ba8482e6324965e935e1a9834024ecd39afd0441fb0",
        )
        self.assertEqual(
            document["summary"],
            {
                "status": "consistent_supplied_subset",
                "application_claim_count": 4,
                "profile_grant_count": 5,
                "matched_claim_count": 4,
                "mismatched_claim_count": 0,
                "unavailable_claim_count": 0,
            },
        )
        for row in document["entitlement_observations"]:
            self.assertEqual(row["outcome"], "matched_profile_allowlist")
            self.assertTrue(row["matched_profile_grants"])

    def test_public_native_bytes_constructor_parser_and_exports_replay(self):
        model = component_fixture()
        report = self.analyze(model)
        text = report.to_json()
        document = report.to_dict()
        copies = (
            s.IosEntitlementAnalysis(text),
            s.IosEntitlementAnalysis.from_dict(document),
            s.IosEntitlementAnalysis.from_json(text),
            s.analyze_supplied_ios_entitlements_bytes(
                model_bytes=json.dumps(model, indent=2).encode("ascii")
            ),
            s.verify_supplied_ios_entitlement_analysis(report, model=model),
        )
        for copied in copies:
            self.assertIsNot(copied, report)
            self.assertEqual(copied.to_json(), text)
            self.assertEqual(copied.to_dict(), document)

    def test_app_id_prefix_and_team_id_are_independent_declarations(self):
        model = component_fixture()
        model["application_entitlements"][s.TEAM_IDENTIFIER] = "OTHERTEAM1"
        model["profile_entitlements"][s.TEAM_IDENTIFIER] = "OTHERTEAM1"
        document = self.analyze(model).to_dict()
        self.assertEqual(document["summary"]["status"], "consistent_supplied_subset")
        self.assertEqual(self.row(document, s.TEAM_IDENTIFIER)["claim_value"], "OTHERTEAM1")
        self.assertTrue(
            self.row(document, s.APPLICATION_IDENTIFIER)["claim_value"].startswith("APPID00001.")
        )

    def test_exact_com_apple_token_needs_its_own_allowlist_entry_not_an_app_prefix(self):
        model = component_fixture()
        document = self.analyze(model).to_dict()
        row = self.row(document, s.KEYCHAIN_GROUPS, "com.apple.token")
        self.assertEqual(row["matched_profile_grants"], ["com.apple.token"])
        model["profile_entitlements"][s.KEYCHAIN_GROUPS].remove("com.apple.token")
        document = self.analyze(model).to_dict()
        self.assertEqual(
            self.row(document, s.KEYCHAIN_GROUPS, "com.apple.token")["outcome"],
            "not_in_profile_allowlist",
        )
        self.assertEqual(document["summary"]["status"], "inconsistent_supplied_subset")

    def test_keychain_exact_grant_does_not_invent_common_app_prefix_requirement(self):
        model = component_fixture()
        model["application_entitlements"][s.KEYCHAIN_GROUPS].append("DIFFERENT1.shared")
        model["profile_entitlements"][s.KEYCHAIN_GROUPS].append("DIFFERENT1.shared")
        document = self.analyze(model).to_dict()
        self.assertEqual(document["summary"]["status"], "consistent_supplied_subset")
        self.assertEqual(
            self.row(document, s.KEYCHAIN_GROUPS, "DIFFERENT1.shared")["matched_profile_grants"],
            ["DIFFERENT1.shared"],
        )

    def test_unused_profile_grants_and_absent_app_keys_are_not_contradictions(self):
        model = component_fixture()
        model["profile_entitlements"][s.KEYCHAIN_GROUPS].extend(
            ["com.example.unused", "UNUSED0001.*"]
        )
        for key in (s.APPLICATION_IDENTIFIER, s.TEAM_IDENTIFIER, s.KEYCHAIN_GROUPS):
            smaller = copy.deepcopy(model)
            del smaller["application_entitlements"][key]
            document = self.analyze(smaller).to_dict()
            self.assertEqual(document["summary"]["status"], "consistent_supplied_subset")
            self.assertEqual(document["summary"]["mismatched_claim_count"], 0)
        model["application_entitlements"] = {}
        document = self.analyze(model).to_dict()
        self.assertEqual(document["summary"]["application_claim_count"], 0)
        self.assertEqual(document["summary"]["status"], "consistent_supplied_subset")
        self.assertFalse(document["flags"]["entitlement_authorization_proven"])

    def test_missing_profile_keys_deny_present_claims_only_with_complete_allowlist(self):
        for key, complete in itertools.product(
            (s.APPLICATION_IDENTIFIER, s.TEAM_IDENTIFIER, s.KEYCHAIN_GROUPS), (False, True)
        ):
            with self.subTest(key=key, complete=complete):
                model = component_fixture()
                del model["profile_entitlements"][key]
                model["coverage"]["profile_entitlements_complete"] = complete
                document = self.analyze(model).to_dict()
                rows = [
                    r for r in document["entitlement_observations"] if r["entitlement_key"] == key
                ]
                self.assertTrue(rows)
                self.assertEqual(
                    {r["outcome"] for r in rows},
                    {"not_in_profile_allowlist" if complete else "profile_allowlist_unavailable"},
                )
                self.assertEqual(
                    document["summary"]["status"],
                    "inconsistent_supplied_subset" if complete else "inconclusive",
                )

    def test_literal_and_prefix_wildcard_grants_do_not_mean_generic_globs(self):
        cases = (
            ("APPID00001.com.example.reader", "APPID00001.com.example.reader", True),
            ("APPID00001.com.example.*", "APPID00001.com.example.reader", True),
            ("APPID00001.*", "APPID00001.com.example.reader", True),
            ("APPID00001.com.example.*", "APPID00001.com.examples.reader", False),
            ("APPID00001.com.example.reader", "APPID00001.com.example.readers", False),
            ("APPID00001.com.example.*", "OTHER00001.com.example.reader", False),
        )
        for grant, claim, permitted in cases:
            with self.subTest(grant=grant, claim=claim):
                model = component_fixture()
                model["application_entitlements"][s.APPLICATION_IDENTIFIER] = claim
                model["profile_entitlements"][s.APPLICATION_IDENTIFIER] = grant
                row = self.row(self.analyze(model).to_dict(), s.APPLICATION_IDENTIFIER)
                self.assertEqual(
                    row["outcome"],
                    "matched_profile_allowlist" if permitted else "not_in_profile_allowlist",
                )

    def test_case_is_preserved_and_team_identifier_does_not_use_profile_wildcards(self):
        model = component_fixture()
        model["profile_entitlements"][s.TEAM_IDENTIFIER] = "teamid0001"
        document = self.analyze(model).to_dict()
        self.assertEqual(
            self.row(document, s.TEAM_IDENTIFIER)["outcome"], "not_in_profile_allowlist"
        )
        model["profile_entitlements"][s.TEAM_IDENTIFIER] = "TEAMID000*"
        self.denied_before_hash(lambda: self.analyze(model))

    def test_app_wildcards_are_closed_subset_errors_before_hash(self):
        for key in (s.APPLICATION_IDENTIFIER, s.KEYCHAIN_GROUPS):
            for value in ("APPID00001.*", "APPID00001.com.*.reader", "APPID00001.reader?"):
                model = component_fixture()
                model["application_entitlements"][key] = (
                    [value] if key == s.KEYCHAIN_GROUPS else value
                )
                self.denied_before_hash(lambda model=model: self.analyze(model))

    def test_unsupported_profile_pattern_spellings_fail_as_software_subset(self):
        for value in (
            "*",
            "APPID00001.reader*",
            "APPID00001.*.reader",
            "APPID00001.reader?",
            "APPID00001..*",
            "APPID00001.com example.*",
        ):
            model = component_fixture()
            model["profile_entitlements"][s.APPLICATION_IDENTIFIER] = value
            self.denied_before_hash(lambda model=model: self.analyze(model))

    def test_unknown_entitlement_keys_withhold_overall_consistency_but_keep_matches(self):
        for side in ("application", "profile"):
            model = component_fixture()
            model[f"unmodeled_{side}_entitlement_keys"] = ["get-task-allow", "aps-environment"]
            document = self.analyze(model).to_dict()
            self.assertEqual(document["summary"]["status"], "inconclusive")
            self.assertEqual(document["summary"]["matched_claim_count"], 4)
            self.assertEqual(
                document["unmodeled_entitlements"],
                [
                    {"side": side, "entitlement_key": "aps-environment"},
                    {"side": side, "entitlement_key": "get-task-allow"},
                ],
            )

    def test_known_mismatches_remain_labeled_even_with_unmodeled_or_incomplete_sources(self):
        for unknown in ("unmodeled", "application-incomplete", "profile-incomplete"):
            model = component_fixture()
            model["application_entitlements"][s.TEAM_IDENTIFIER] = "OTHERTEAM1"
            if unknown == "unmodeled":
                model["unmodeled_profile_entitlement_keys"] = ["get-task-allow"]
            else:
                side = unknown.split("-")[0]
                model["coverage"][f"{side}_entitlements_complete"] = False
            document = self.analyze(model).to_dict()
            self.assertEqual(document["summary"]["status"], "inconclusive")
            self.assertEqual(
                self.row(document, s.TEAM_IDENTIFIER)["outcome"],
                "profile_allowlist_unavailable"
                if unknown == "profile-incomplete"
                else "not_in_profile_allowlist",
            )

    def test_empty_declared_keychain_arrays_add_no_default_application_group(self):
        model = component_fixture()
        model["application_entitlements"][s.KEYCHAIN_GROUPS] = []
        model["profile_entitlements"][s.KEYCHAIN_GROUPS] = []
        document = self.analyze(model).to_dict()
        self.assertEqual(document["summary"]["application_claim_count"], 2)
        self.assertEqual(document["summary"]["status"], "consistent_supplied_subset")
        self.assertEqual(
            [
                row
                for row in document["entitlement_observations"]
                if row["entitlement_key"] == s.KEYCHAIN_GROUPS
            ],
            [],
        )

    def test_all_completeness_combinations_are_explicit_without_promoting_matches(self):
        for app, profile in itertools.product((False, True), repeat=2):
            model = component_fixture()
            model["coverage"] = {
                "application_entitlements_complete": app,
                "profile_entitlements_complete": profile,
            }
            document = self.analyze(model).to_dict()
            self.assertEqual(document["summary"]["matched_claim_count"], 4)
            self.assertEqual(
                document["summary"]["status"],
                "consistent_supplied_subset" if app and profile else "inconclusive",
            )

    def test_independent_small_prefix_allowlist_and_uncertainty_oracle(self):
        values = ("com.apple.token", "com.example.one", "com.example.ones", "com.other.one")
        grants = ("com.apple.token", "com.example.one", "com.example.*", "com.*")
        count = 0
        for value, grant, complete, unknown in itertools.product(
            values, grants, (False, True), (False, True)
        ):
            model = component_fixture()
            model["application_entitlements"][s.KEYCHAIN_GROUPS] = [value]
            model["profile_entitlements"][s.KEYCHAIN_GROUPS] = [grant]
            model["coverage"]["profile_entitlements_complete"] = complete
            if unknown:
                model["unmodeled_application_entitlement_keys"] = ["get-task-allow"]
            # Independent sequence comparison: a wildcard is the final component, not a regex.
            grant_parts = grant.split(".")
            value_parts = value.split(".")
            allowed = grant == value or (
                grant_parts[-1] == "*"
                and len(value_parts) > len(grant_parts) - 1
                and value_parts[: len(grant_parts) - 1] == grant_parts[:-1]
            )
            document = self.analyze(model).to_dict()
            self.assertEqual(
                self.row(document, s.KEYCHAIN_GROUPS)["outcome"],
                "matched_profile_allowlist"
                if allowed
                else ("not_in_profile_allowlist" if complete else "profile_allowlist_unavailable"),
            )
            self.assertEqual(
                document["summary"]["status"],
                "inconclusive"
                if unknown or not complete
                else ("consistent_supplied_subset" if allowed else "inconsistent_supplied_subset"),
            )
            count += 1
        self.assertEqual(count, 64)

    def test_permutations_preserve_math_and_retain_original_array_order_in_source_identity(self):
        model = component_fixture()
        first = self.analyze(model).to_dict()
        model["application_entitlements"][s.KEYCHAIN_GROUPS].reverse()
        model["profile_entitlements"][s.KEYCHAIN_GROUPS].reverse()
        second = self.analyze(model).to_dict()
        self.assertNotEqual(first["source_model_sha256"], second["source_model_sha256"])
        self.assertNotEqual(first["analysis_sha256"], second["analysis_sha256"])
        self.assertEqual(first["summary"], second["summary"])
        self.assertEqual(first["entitlement_observations"], second["entitlement_observations"])
        keys = list(model.keys())
        keys.reverse()
        self.assertEqual(self.analyze({key: model[key] for key in keys}).to_dict(), second)

    def test_separate_original_denies_valid_alternate_source_even_when_results_match(self):
        original = component_fixture()
        alternate = copy.deepcopy(original)
        alternate["profile_entitlements"][s.KEYCHAIN_GROUPS][-1] = "NEWUNUSED1.unused"
        report = self.analyze(alternate)
        self.assertEqual(report.to_dict()["summary"], self.analyze(original).to_dict()["summary"])
        self.assertEqual(
            s.IosEntitlementAnalysis.from_json(report.to_json()).to_json(), report.to_json()
        )
        with self.assertRaises(s.IosEntitlementAnalysisError):
            s.verify_supplied_ios_entitlement_analysis(report, model=original)

    def test_source_and_export_detachment_and_fixture_freshness(self):
        model = component_fixture()
        report = self.analyze(model)
        before = report.to_json()
        model["application_entitlements"][s.KEYCHAIN_GROUPS].clear()
        model["profile_entitlements"].clear()
        exported = report.to_dict()
        exported["source_model"]["application_entitlements"].clear()
        exported["entitlement_observations"].clear()
        self.assertEqual(report.to_json(), before)
        self.assertEqual(len(component_fixture()["application_entitlements"][s.KEYCHAIN_GROUPS]), 2)

    def test_cohashed_false_summary_observations_and_effect_claims_deny(self):
        valid = self.analyze().to_dict()
        mutations = (
            lambda d: d["summary"].update(status="inconsistent_supplied_subset"),
            lambda d: d["entitlement_observations"][0].update(outcome="not_in_profile_allowlist"),
            lambda d: d["entitlement_observations"][0].update(matched_profile_grants=[]),
            lambda d: d["effects"].update(code_signing="allowed"),
            lambda d: d["flags"].update(signature_verified=True),
            lambda d: d.update(source_model_sha256="sha256:" + "a" * 64),
            lambda d: d.update(profile_id="AOE-GB-D08-S06"),
        )
        for mutation in mutations:
            document = copy.deepcopy(valid)
            mutation(document)
            readdress(document)
            with self.assertRaises(s.IosEntitlementAnalysisError):
                s.IosEntitlementAnalysis.from_dict(document)
            with self.assertRaises(s.IosEntitlementAnalysisError):
                s.IosEntitlementAnalysis.from_json(canonical(document))

    def test_native_report_scalar_aliases_and_extra_fields_are_not_python_equal_replays(self):
        valid = self.analyze().to_dict()
        mutations = (
            lambda d: d.update(schema_version=True),
            lambda d: d.update(schema_version=1.0),
            lambda d: d["summary"].update(mismatched_claim_count=False),
            lambda d: d["summary"].update(mismatched_claim_count=0.0),
            lambda d: d["flags"].update(signature_verified=0),
            lambda d: d.update(additional=None),
        )
        for mutation in mutations:
            document = copy.deepcopy(valid)
            mutation(document)
            readdress(document)
            with self.assertRaises(s.IosEntitlementAnalysisError):
                s.IosEntitlementAnalysis.from_dict(document)

    def test_at_use_cohashed_false_wrapper_is_not_a_semantic_verification(self):
        model = component_fixture()
        report = self.analyze(model)
        document = report.to_dict()
        document["summary"]["matched_claim_count"] = 0
        document["entitlement_observations"][0]["outcome"] = "not_in_profile_allowlist"
        readdress(document)
        # Deliberate same-process mutation probes use-time replay, not a remote path.
        object.__setattr__(report, "document_json", canonical(document))
        for call in (
            report.to_dict,
            report.to_json,
            lambda: s.verify_supplied_ios_entitlement_analysis(report, model=model),
        ):
            with self.assertRaises(s.IosEntitlementAnalysisError):
                call()

    def test_frozen_wrapper_incomplete_subclass_and_late_mutation_fail_closed(self):
        report = self.analyze()
        with self.assertRaises(FrozenInstanceError):
            report.document_json = "{}"
        object.__setattr__(report, "document_json", "{}")
        missing = object.__new__(s.IosEntitlementAnalysis)
        for instance in (report, missing):
            for call in (
                instance.to_dict,
                instance.to_json,
                lambda instance=instance: s.verify_supplied_ios_entitlement_analysis(
                    instance, model=component_fixture()
                ),
            ):
                with self.assertRaises(s.IosEntitlementAnalysisError):
                    call()

        class Report(s.IosEntitlementAnalysis):
            pass

        with self.assertRaises(s.IosEntitlementAnalysisError):
            Report.from_dict(self.analyze().to_dict())
        with self.assertRaises(s.IosEntitlementAnalysisError):
            Report(self.analyze().to_json())

    def test_exact_native_model_primitives_collections_and_subclasses_before_hash(self):
        class Text(str):
            pass

        class Integer(int):
            pass

        class Mapping(dict):
            pass

        class Array(list):
            pass

        mutations = (
            lambda m: m.update(schema_version=True),
            lambda m: m.update(schema_version=1.0),
            lambda m: m.update(schema_version=Integer(1)),
            lambda m: m["coverage"].update(application_entitlements_complete=1),
            lambda m: m["application_entitlements"].update({s.TEAM_IDENTIFIER: None}),
            lambda m: m["application_entitlements"].update({s.TEAM_IDENTIFIER: Text("TEAMID0001")}),
            lambda m: m.update(application_entitlements=Mapping(m["application_entitlements"])),
            lambda m: m["application_entitlements"].update(
                {s.KEYCHAIN_GROUPS: ("com.apple.token",)}
            ),
            lambda m: m["application_entitlements"].update({s.KEYCHAIN_GROUPS: Array([])}),
            lambda m: m.update(unmodeled_profile_entitlement_keys=False),
            lambda m: m.update(coverage=True),
        )
        for mutation in mutations:
            model = component_fixture()
            mutation(model)
            self.denied_before_hash(lambda model=model: self.analyze(model))

    def test_unknown_missing_and_null_map_fields_do_not_silently_normalize(self):
        cases = (
            lambda m: m.update(extra=[]),
            lambda m: m.pop("coverage"),
            lambda m: m["coverage"].update(extra=True),
            lambda m: m["application_entitlements"].update({"get-task-allow": True}),
            lambda m: m.update(application_entitlements=None),
            lambda m: m["profile_entitlements"].update({s.KEYCHAIN_GROUPS: None}),
        )
        for mutate in cases:
            model = component_fixture()
            mutate(model)
            self.denied_before_hash(lambda model=model: self.analyze(model))

    def test_duplicate_group_or_unmodeled_key_and_known_key_shadow_deny_before_hash(self):
        cases = (
            lambda m: m["application_entitlements"][s.KEYCHAIN_GROUPS].append("com.apple.token"),
            lambda m: m["profile_entitlements"][s.KEYCHAIN_GROUPS].append("APPID00001.*"),
            lambda m: m.update(unmodeled_profile_entitlement_keys=["aps-environment"] * 2),
            lambda m: m.update(unmodeled_application_entitlement_keys=[s.APPLICATION_IDENTIFIER]),
        )
        for mutate in cases:
            model = component_fixture()
            mutate(model)
            self.denied_before_hash(lambda model=model: self.analyze(model))

    def test_actual_group_and_unmodeled_array_exact_boundaries(self):
        for side in ("application", "profile"):
            model = component_fixture()
            model[f"{side}_entitlements"][s.KEYCHAIN_GROUPS] = [
                f"com.example.group{index}" for index in range(s.MAX_KEYCHAIN_GROUPS)
            ]
            self.analyze(model)
            model[f"{side}_entitlements"][s.KEYCHAIN_GROUPS].append("com.example.one-more")
            self.denied_before_hash(lambda model=model: self.analyze(model))
            model = component_fixture()
            model[f"unmodeled_{side}_entitlement_keys"] = [
                f"unknown.entitlement{index}" for index in range(s.MAX_ENTITLEMENT_KEYS)
            ]
            self.assertEqual(self.analyze(model).to_dict()["summary"]["status"], "inconclusive")
            model[f"unmodeled_{side}_entitlement_keys"].append("unknown.additional")
            self.denied_before_hash(lambda model=model: self.analyze(model))

    def test_entitlement_string_and_dotted_grammar_supported_boundaries(self):
        model = component_fixture()
        claim = "a" * s.MAX_ENTITLEMENT_VALUE_BYTES
        model["application_entitlements"][s.KEYCHAIN_GROUPS] = [claim]
        model["profile_entitlements"][s.KEYCHAIN_GROUPS] = [claim]
        self.assertEqual(
            self.analyze(model).to_dict()["summary"]["status"], "consistent_supplied_subset"
        )
        model["application_entitlements"][s.KEYCHAIN_GROUPS] = [claim + "a"]
        self.denied_before_hash(lambda: self.analyze(model))
        for value in ("", "com..example", ".com", "com.", "com/ex", "com ex", "com_ex"):
            invalid = component_fixture()
            invalid["application_entitlements"][s.KEYCHAIN_GROUPS] = [value]
            self.denied_before_hash(lambda invalid=invalid: self.analyze(invalid))

    def test_raw_duplicate_member_including_escaped_spelling_before_hash(self):
        text = canonical(component_fixture())
        for addition in (
            '"schema_version":1,"schema_version":1',
            '"schema_version":1,"schema_\\u0076ersion":1',
        ):
            content = text.replace('"schema_version":1', addition).encode("ascii")
            self.denied_before_hash(
                lambda content=content: s.analyze_supplied_ios_entitlements_bytes(
                    model_bytes=content
                )
            )

    def test_raw_lexical_integer_string_nodes_and_scalar_depth_precede_decoder(self):
        cases = (
            b"[" * s.MAX_MODEL_DEPTH + b"0" + b"]" * s.MAX_MODEL_DEPTH,
            b"[" + b"0," * s.MAX_MODEL_NODES + b"0]",
            b'"' + b"a" * (s.MAX_STRING_BYTES + 1) + b'"',
            b'"' + b"\\u0061" * (s.MAX_STRING_BYTES + 1) + b'"',
            b"9223372036854775808",
            b"-9223372036854775809",
            b"--1",
            b"---1",
            b"--0",
            b"01",
            b"-01",
            b"1.0",
            b"NaN",
            b"Infinity",
            b'"\\ud800"',
            b'"\\u0000"',
        )
        for content in cases:
            with patch.object(s.json, "loads", side_effect=AssertionError("decoder")) as decoder:
                self.denied_before_hash(
                    lambda content=content: s.analyze_supplied_ios_entitlements_bytes(
                        model_bytes=content
                    )
                )
            self.assertEqual(decoder.call_count, 0)

    def test_raw_bytes_family_size_ascii_and_copy_work_precede_decoder(self):
        for content in (bytearray(b"{}"), b"", b"\xff", b" " * (s.MAX_MODEL_BYTES + 1)):
            with patch.object(s.json, "loads", side_effect=AssertionError("decoder")):
                self.denied_before_hash(
                    lambda content=content: s.analyze_supplied_ios_entitlements_bytes(
                        model_bytes=content
                    )
                )
        content = canonical(component_fixture()).encode("ascii")
        with (
            patch.object(s, "MAX_WORK", len(content) - 1),
            patch.object(s, "_decode", side_effect=AssertionError("decode before copy budget")),
        ):
            self.denied_before_hash(
                lambda: s.analyze_supplied_ios_entitlements_bytes(model_bytes=content)
            )

    def test_printable_escape_equivalence_does_not_change_canonical_model_address(self):
        model = component_fixture()
        text = canonical(model).replace("APPID00001", "APPID0000\\u0031")
        self.assertEqual(
            s.analyze_supplied_ios_entitlements_bytes(model_bytes=text.encode("ascii")).to_json(),
            self.analyze(model).to_json(),
        )
        with self.assertRaises(s.IosEntitlementAnalysisError):
            s.IosEntitlementAnalysis.from_json(json.dumps(self.analyze(model).to_dict(), indent=2))

    def test_native_cycles_depth_repeated_nodes_and_escaping_bytes_precede_hash(self):
        model = component_fixture()
        model["unmodeled_application_entitlement_keys"].append(model)
        self.denied_before_hash(lambda: self.analyze(model))
        nested = 0
        for _ in range(s.MAX_MODEL_DEPTH):
            nested = [nested]
        self.denied_before_hash(lambda: self.analyze(nested))
        shared = {"a": ["b"]}
        with patch.object(s, "MAX_MODEL_NODES", 8):
            self.denied_before_hash(lambda: self.analyze([shared, shared]))
        with (
            patch.object(s, "MAX_MODEL_BYTES", 10),
            patch.object(s, "_canonical", side_effect=AssertionError("serialization")),
        ):
            self.denied_before_hash(lambda: self.analyze("\\" * 5))
        self.denied_before_hash(lambda: self.analyze({"schema_version": 1 << 10000}))

    def test_exact_native_byte_node_and_report_limits_are_checked_before_hash(self):
        model = component_fixture()
        report = self.analyze(model)
        document = report.to_dict()
        _, source_bytes, source_nodes = s._capture(model, s._Budget())
        _, report_bytes, report_nodes = s._capture(document, s._Budget(), report=True)
        self.assertEqual(source_bytes, len(canonical(model)))
        self.assertEqual(report_bytes, len(report.to_json()))
        for name, needed in (
            ("MAX_MODEL_BYTES", source_bytes),
            ("MAX_MODEL_NODES", source_nodes),
            ("MAX_REPORT_BYTES", report_bytes),
            ("MAX_REPORT_NODES", report_nodes),
        ):
            with self.subTest(name=name):
                with patch.object(s, name, needed):
                    self.assertEqual(self.analyze(model).document_json, report.document_json)
                with patch.object(s, name, needed - 1):
                    self.denied_before_hash(lambda: self.analyze(model))

    def test_all_public_boundaries_fund_entire_operation_before_any_digest(self):
        model = component_fixture()
        report = self.analyze(model)
        text = report.to_json()
        document = report.to_dict()
        operations = {
            "produce": lambda: self.analyze(model),
            "bytes": lambda: s.analyze_supplied_ios_entitlements_bytes(
                model_bytes=canonical(model).encode("ascii")
            ),
            "constructor": lambda: s.IosEntitlementAnalysis(text),
            "from_dict": lambda: s.IosEntitlementAnalysis.from_dict(document),
            "from_json": lambda: s.IosEntitlementAnalysis.from_json(text),
            "to_dict": report.to_dict,
            "to_json": report.to_json,
            "separate_original": lambda: s.verify_supplied_ios_entitlement_analysis(
                report, model=model
            ),
        }
        real_charge = s._Budget.charge
        for name, operation in operations.items():
            with self.subTest(name=name):
                samples = []

                def observe(budget, amount, samples=samples):
                    real_charge(budget, amount)
                    samples.append(budget.used)

                with patch.object(s._Budget, "charge", observe):
                    value = operation()
                self.assertTrue(samples)
                required = samples[-1]
                with patch.object(s, "MAX_WORK", required - 1):
                    self.denied_before_hash(operation)
                with patch.object(s, "MAX_WORK", required):
                    exact = operation()
                self.assertEqual(
                    exact.document_json if type(exact) is s.IosEntitlementAnalysis else exact,
                    value.document_json if type(value) is s.IosEntitlementAnalysis else value,
                )

    def test_all_claims_effects_and_existing_exact_ownership_stay_nonauthorizing(self):
        document = self.analyze().to_dict()
        self.assertEqual(set(document["effects"].values()), {"none"})
        self.assertEqual(set(document["flags"].values()), {False})
        self.assertEqual(
            document["component_id"], "ios_supplied_entitlement_declaration_consistency"
        )
        self.assertEqual(document["profile_id"], "AOE-GB-D08-S07")
        self.assertEqual(document["capability_id"], "army.gb.d08.s07")
        self.assertEqual(document["vector_id"], "AV-GB-D08-S07-01")
        self.assertEqual(document["work_package_id"], "IWP2-AOE-GB-D08-S07")
        self.assertEqual(document["wave_id"], "IW2-011")
        self.assertEqual(document["commander_id"], "AOE-GB-D08-CMD")
        self.assertEqual(document["group_owner_id"], "AOE-HQ-04")
        self.assertEqual(document["independent_validator_id"], "AOE-HQ-19")
        self.assertEqual(
            document["blueprint_sha256"],
            "sha256:4c60c70e0dc5c482d661650a82790226acf8b54b540db5cdde766a8ea19a04e6",
        )


if __name__ == "__main__":
    unittest.main()
