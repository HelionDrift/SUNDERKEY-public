"""Supplied synthetic descriptors and SID assertions; no Windows or target calls."""

import hashlib
import itertools
import json
import unittest
from copy import deepcopy
from unittest.mock import patch

from sunderkey import offline_windows_dacl_analysis as module
from sunderkey.offline_windows_dacl_analysis import (
    DOMAIN,
    WindowsDaclAnalysis,
    WindowsDaclAnalysisError,
    analyze_supplied_windows_dacl,
    verify_supplied_windows_dacl_analysis,
)

USER = "S-1-5-21-100-200-300-1000"
GROUP = "S-1-5-32-545"
OTHER = "S-1-5-21-100-200-300-1001"


def ace(kind=0, mask=1, sid=USER, flags=0):
    return {"ace_type": kind, "sid": sid, "mask": mask, "flags": flags}


def component_fixture():
    """Fresh public synthetic projection only, not an acquired security descriptor."""
    return {
        "schema_version": 1,
        "security_descriptor": {
            "owner_sid": USER,
            "group_sid": GROUP,
            "dacl_state": "present",
            "aces": [ace(), ace(mask=2, sid=GROUP, flags=16)],
        },
        "token_sids": [
            {"sid": USER, "usage": "enabled"},
            {"sid": GROUP, "usage": "enabled"},
        ],
        "desired_access": 3,
    }


def model(aces, desired=3, *, usage="enabled", state="present"):
    value = component_fixture()
    value["security_descriptor"]["aces"] = aces
    value["security_descriptor"]["dacl_state"] = state
    value["token_sids"] = [{"sid": USER, "usage": usage}]
    value["desired_access"] = desired
    return value


def readdress(document):
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = (
        "sha256:"
        + hashlib.sha256(
            DOMAIN.encode("ascii")
            + b"\n"
            + json.dumps(body, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode(
                "ascii"
            )
        ).hexdigest()
    )
    return {"analysis_id": "WDA-" + digest[7:39].upper(), "analysis_sha256": digest, **body}


def evaluation(value):
    return analyze_supplied_windows_dacl(value).to_dict()["evaluation"]


class SuppliedWindowsDaclAnalysisTests(unittest.TestCase):
    def test_literal_baseline_and_original_source_roundtrip(self):
        supplied = component_fixture()
        report = analyze_supplied_windows_dacl(supplied)
        raw = report.to_dict()
        self.assertEqual(raw["analysis_id"], "WDA-1D401F7AA45DBBE849492E1189EDBE14")
        self.assertEqual(
            raw["analysis_sha256"],
            "sha256:1d401f7aa45dbbe849492e1189edbe14004602dd2cf35d2c7f90c806307a7a7b",
        )
        self.assertEqual(
            raw["source_model_sha256"],
            "sha256:d180a487ebb3f5937d8c53065f2ff16aad4e0d6facacbdaf0fda20e138839485",
        )
        self.assertEqual(raw["evaluation"]["outcome"], "supplied_dacl_allows_requested_bits")
        self.assertEqual(raw["evaluation"]["decisive_ace_index"], 1)
        self.assertEqual(raw["evaluation"]["trace"][1]["inherited"], True)
        self.assertEqual(WindowsDaclAnalysis.from_dict(raw).to_dict(), raw)
        self.assertEqual(WindowsDaclAnalysis.from_json(report.to_json()).to_dict(), raw)
        checked = verify_supplied_windows_dacl_analysis(report, model=supplied)
        self.assertIsNot(checked, report)
        self.assertEqual(checked.to_json(), report.to_json())

    def test_every_result_retains_unqualified_no_effects_and_exact_lane(self):
        for supplied in (component_fixture(), model([]), model([ace(kind=5)])):
            with self.subTest(supplied=supplied):
                raw = analyze_supplied_windows_dacl(supplied).to_dict()
                self.assertEqual(raw["profile_id"], "AOE-GC-D11-S05")
                self.assertEqual(raw["capability_id"], "army.gc.d11.s05")
                self.assertEqual(raw["vector_id"], "AV-GC-D11-S05-01")
                self.assertEqual(raw["wave_id"], "IW2-005")
                self.assertIs(raw["offline_only"], True)
                for field in (
                    "descriptor_authenticated",
                    "token_authenticated",
                    "effective_access_proven",
                    "live_use_approved",
                    "qualification_claimed",
                ):
                    self.assertIs(raw[field], False)
                self.assertTrue(all(effect == "none" for effect in raw["effects"].values()))

    def test_null_absent_and_present_empty_remain_distinct(self):
        for state in ("null", "absent"):
            with self.subTest(state=state):
                result = evaluation(model([], state=state))
                self.assertEqual(result["reason"], "no_dacl_restriction")
                self.assertEqual(result["allowed_mask"], 3)
                self.assertEqual(result["trace"], [])
        empty = evaluation(model([]))
        self.assertEqual(empty["outcome"], "supplied_dacl_denies_requested_bits")
        self.assertEqual(empty["reason"], "remaining_mask_not_allowed")
        self.assertEqual(empty["allowed_mask"], 0)
        for state in ("null", "absent"):
            with self.subTest(state=state), self.assertRaises(WindowsDaclAnalysisError):
                analyze_supplied_windows_dacl(model([ace()], state=state))

    def test_actual_order_is_preserved_not_preferred_deny_sorting(self):
        allow_first = model([ace(mask=3), ace(1, 3)])
        deny_first = model([ace(1, 3), ace(mask=3)])
        self.assertEqual(evaluation(allow_first)["outcome"], "supplied_dacl_allows_requested_bits")
        self.assertEqual(evaluation(deny_first)["outcome"], "supplied_dacl_denies_requested_bits")
        for supplied in (allow_first, deny_first):
            self.assertEqual(evaluation(supplied)["decisive_ace_index"], 0)
            self.assertEqual(len(evaluation(supplied)["trace"]), 1)

    def test_cumulative_allow_denies_only_remaining_requested_bits(self):
        supplied = model([ace(mask=1), ace(1, 1), ace(mask=2)])
        result = evaluation(supplied)
        self.assertEqual(result["allowed_mask"], 3)
        self.assertEqual(result["trace"][1]["disposition"], "deny_no_remaining_bits")
        self.assertEqual(result["trace"][1]["matched_mask"], 0)
        self.assertEqual(result["trace"][2]["matched_mask"], 2)
        partial = evaluation(model([ace(mask=1), ace(1, 2), ace(mask=3)]))
        self.assertEqual(partial["outcome"], "supplied_dacl_denies_requested_bits")
        self.assertEqual(partial["decisive_ace_index"], 1)
        self.assertEqual(partial["allowed_mask"], 0)
        self.assertEqual(partial["remaining_mask"], 2)

    def test_unrequested_denial_and_zero_mask_are_not_access_denials(self):
        for denied in (0, 4, 8, 32768):
            with self.subTest(mask=denied):
                self.assertEqual(
                    evaluation(model([ace(1, denied), ace(mask=3)]))["allowed_mask"], 3
                )
        self.assertEqual(evaluation(model([ace(mask=0), ace(mask=3)]))["allowed_mask"], 3)

    def test_enabled_deny_only_and_disabled_apply_to_every_explicit_sid(self):
        for sid in (USER, GROUP):
            for usage in ("enabled", "deny_only", "disabled"):
                with self.subTest(sid=sid, usage=usage):
                    supplied = model([ace(mask=3, sid=sid)])
                    supplied["token_sids"] = [{"sid": sid, "usage": usage}]
                    expected = 3 if usage == "enabled" else 0
                    self.assertEqual(evaluation(supplied)["allowed_mask"], expected)
                    supplied["security_descriptor"]["aces"] = [ace(1, 3, sid), ace(mask=3)]
                    supplied["token_sids"].append({"sid": OTHER, "usage": "enabled"})
                    result = evaluation(supplied)
                    self.assertEqual(
                        result["reason"],
                        "remaining_mask_not_allowed"
                        if usage == "disabled"
                        else "explicit_remaining_bit_denial",
                    )
        # The descriptor owner SID receives no invented owner or user allow.
        self.assertEqual(evaluation(model([], usage="enabled"))["allowed_mask"], 0)

    def test_no_implicit_everyone_group_or_name_resolution(self):
        for sid in (GROUP, "S-1-1-0", OTHER):
            with self.subTest(sid=sid):
                result = evaluation(model([ace(mask=3, sid=sid)]))
                self.assertEqual(result["trace"][0]["disposition"], "sid_not_supplied")
                self.assertEqual(result["allowed_mask"], 0)

    def test_inherited_entries_evaluate_but_inherit_only_entries_skip_current_object(self):
        self.assertEqual(evaluation(model([ace(mask=3, flags=16)]))["allowed_mask"], 3)
        for flags in (8, 9, 10, 12, 24, 31):
            with self.subTest(flags=flags):
                result = evaluation(model([ace(1, 3, flags=flags), ace(mask=3)]))
                self.assertEqual(result["allowed_mask"], 3)
                self.assertEqual(result["trace"][0]["disposition"], "inherit_only_skipped")
                self.assertIs(result["trace"][0]["inherited"], bool(flags & 16))
        for flags in (1, 2, 4, 7, 17, 23):
            with self.subTest(flags=flags):
                self.assertEqual(evaluation(model([ace(mask=3, flags=flags)]))["allowed_mask"], 3)

    def test_unsupported_later_ace_withholds_even_early_sufficient_allow(self):
        for kind in (2, 5, 6, 9, 10, 11, 12, 17, 255):
            for flags in (0, 8):
                with self.subTest(kind=kind, flags=flags):
                    supplied = model([ace(mask=3), ace(kind, 1, flags=flags)])
                    raw = analyze_supplied_windows_dacl(supplied).to_dict()
                    self.assertEqual(raw["evaluation"]["outcome"], "incomplete")
                    self.assertEqual(raw["evaluation"]["trace"], [])
                    self.assertIn(
                        {"code": "ace_type_unsupported", "ace_index": 1}, raw["incomplete_reasons"]
                    )

    def test_unsupported_masks_and_flags_do_not_use_optimistic_subset_projection(self):
        for field, values in (
            ("mask", (65536, 0x10000000, 0x01000000, 0xFFFFFFFF)),
            ("flags", (32, 64, 128, 255)),
        ):
            for value in values:
                with self.subTest(field=field, value=value):
                    entry = ace()
                    entry[field] = value
                    raw = analyze_supplied_windows_dacl(model([ace(mask=3), entry])).to_dict()
                    self.assertEqual(raw["evaluation"]["outcome"], "incomplete")
                    self.assertEqual(raw["evaluation"]["allowed_mask"], 0)
        for desired in (0, 65536, 0x20000, 0x40000, 0x80000, 0x02000000, 0xFFFFFFFF):
            with self.subTest(desired=desired):
                self.assertEqual(
                    evaluation(model([], desired, state="null"))["outcome"], "incomplete"
                )

    def test_substitution_sids_are_explicit_incomplete_not_literal_grants(self):
        for sid in ("S-1-3-0", "S-1-3-1", "S-1-3-2", "S-1-3-3", "S-1-3-4", "S-1-5-10"):
            for position in ("ace", "token", "owner", "group"):
                with self.subTest(sid=sid, position=position):
                    supplied = component_fixture()
                    if position == "ace":
                        supplied["security_descriptor"]["aces"].append(ace(mask=0, sid=sid))
                    elif position == "token":
                        supplied["token_sids"].append({"sid": sid, "usage": "disabled"})
                    else:
                        supplied["security_descriptor"][position + "_sid"] = sid
                    self.assertEqual(evaluation(supplied)["outcome"], "incomplete")

    def test_small_mask_oracle_keeps_order_not_union_precedence(self):
        # Independent per-requested-bit states, not the producer's remaining-mask code.
        choices = list(itertools.product((0, 1), range(4)))
        cases = 0
        for entries in itertools.product(choices, repeat=3):
            for requested in range(1, 4):
                state = {bit: "pending" for bit in (1, 2) if requested & bit}
                allowed = False
                for kind, mask in entries:
                    if kind == 1 and any(
                        mask & bit and value == "pending" for bit, value in state.items()
                    ):
                        break
                    if kind == 0:
                        for bit in state:
                            if mask & bit:
                                state[bit] = "satisfied"
                    if all(value == "satisfied" for value in state.values()):
                        allowed = True
                        break
                actual = evaluation(model([ace(kind, mask) for kind, mask in entries], requested))
                self.assertEqual(
                    actual["outcome"] == "supplied_dacl_allows_requested_bits",
                    allowed,
                    (entries, requested),
                )
                cases += 1
        self.assertEqual(cases, 1536)

    def test_maximum_standard_aces_and_token_sids_and_trace_are_supported(self):
        supplied = model(
            [ace(mask=0) for _ in range(module.MAX_ACES - 1)] + [ace(mask=65535)], 65535
        )
        supplied["token_sids"] += [
            {"sid": f"S-1-5-21-{index}", "usage": "disabled"}
            for index in range(module.MAX_TOKEN_SIDS - 1)
        ]
        raw = analyze_supplied_windows_dacl(supplied).to_dict()
        self.assertEqual(raw["evaluation"]["allowed_mask"], 65535)
        self.assertEqual(len(raw["evaluation"]["trace"]), module.MAX_ACES)
        verify_supplied_windows_dacl_analysis(WindowsDaclAnalysis.from_dict(raw), model=supplied)
        for extra in ("ace", "sid"):
            changed = deepcopy(supplied)
            if extra == "ace":
                changed["security_descriptor"]["aces"].append(ace(mask=0))
            else:
                changed["token_sids"].append({"sid": "S-1-5-21-9999", "usage": "disabled"})
            with self.subTest(extra=extra), self.assertRaises(WindowsDaclAnalysisError):
                analyze_supplied_windows_dacl(changed)

    def test_uint8_uint32_native_limits_and_sid_uint32_decimal_boundary(self):
        supported = "S-1-4294967295" + "-4294967295" * 15
        supplied = model([ace(mask=65535, sid=supported)], 65535)
        supplied["token_sids"] = [{"sid": supported, "usage": "enabled"}]
        self.assertEqual(evaluation(supplied)["allowed_mask"], 65535)
        for field, value in (("ace_type", 256), ("flags", 256), ("mask", 2**32), ("mask", -1)):
            with self.subTest(field=field, value=value):
                changed = component_fixture()
                changed["security_descriptor"]["aces"][0][field] = value
                with self.assertRaises(WindowsDaclAnalysisError):
                    analyze_supplied_windows_dacl(changed)
        for desired in (-1, 2**32):
            with self.subTest(desired=desired), self.assertRaises(WindowsDaclAnalysisError):
                analyze_supplied_windows_dacl(model([], desired))

    def test_sid_notation_is_canonical_finite_subset_not_sddl_or_account_names(self):
        for sid in (
            "BA",
            "BUILTIN\\Users",
            "S-01-5-21-1",
            "S-1-05-21-1",
            "S-1-5-021-1",
            "S-1-5-21-01",
            "s-1-5-21-1",
            "S-2-5-21-1",
            "S-1-5",
            "S-1-5--1",
            "S-1-4294967296-1",
            "S-1-5-4294967296",
            "S-1-5" + "-1" * 16,
            "S-1-0x000100000000-1",
            "S-1-5-21-1 ",
            "S-1-5-21-1\n",
        ):
            with self.subTest(sid=sid), self.assertRaises(WindowsDaclAnalysisError):
                analyze_supplied_windows_dacl(model([ace(sid=sid)]))

    def test_native_boolean_float_string_counter_aliases_fail_before_source_hash(self):
        mutations = [
            ("schema_version", True),
            ("schema_version", 1.0),
            ("desired_access", True),
            ("desired_access", 3.0),
            ("desired_access", "3"),
        ]
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                supplied = component_fixture()
                supplied[field] = value
                with (
                    patch.object(module, "_sha", side_effect=AssertionError("hash reached")),
                    self.assertRaises(WindowsDaclAnalysisError),
                ):
                    analyze_supplied_windows_dacl(supplied)
        for field, values in (
            ("ace_type", (False, 0.0, "0")),
            ("mask", (True, 1.0, "1")),
            ("flags", (False, 0.0, "0")),
        ):
            for value in values:
                with self.subTest(field=field, value=value):
                    supplied = component_fixture()
                    supplied["security_descriptor"]["aces"][0][field] = value
                    with (
                        patch.object(module, "_sha", side_effect=AssertionError("hash reached")),
                        self.assertRaises(WindowsDaclAnalysisError),
                    ):
                        analyze_supplied_windows_dacl(supplied)

    def test_native_collection_primitive_and_wrapper_subclasses_reject(self):
        class NativeDict(dict):
            pass

        class NativeList(list):
            pass

        class NativeInt(int):
            pass

        class NativeText(str):
            pass

        class OtherAnalysis(WindowsDaclAnalysis):
            pass

        values = [NativeDict(component_fixture())]
        for field, changed in ("schema_version", NativeInt(1)), ("token_sids", NativeList([])):
            supplied = component_fixture()
            supplied[field] = changed
            values.append(supplied)
        supplied = component_fixture()
        supplied["security_descriptor"]["owner_sid"] = NativeText(USER)
        values.append(supplied)
        for supplied in values:
            with self.subTest(supplied=supplied), self.assertRaises(WindowsDaclAnalysisError):
                analyze_supplied_windows_dacl(supplied)
        report = analyze_supplied_windows_dacl(component_fixture())
        with self.assertRaises(WindowsDaclAnalysisError):
            verify_supplied_windows_dacl_analysis(
                OtherAnalysis(report.to_json()), model=component_fixture()
            )

    def test_unknown_missing_fields_and_non_native_sources_reject(self):
        for location in ("model", "descriptor", "ace", "token"):
            for change in ("extra", "missing"):
                with self.subTest(location=location, change=change):
                    supplied = component_fixture()
                    selected = {
                        "model": supplied,
                        "descriptor": supplied["security_descriptor"],
                        "ace": supplied["security_descriptor"]["aces"][0],
                        "token": supplied["token_sids"][0],
                    }[location]
                    if change == "extra":
                        selected["unknown"] = "unsupported"
                    else:
                        selected.pop(next(iter(selected)))
                    with self.assertRaises(WindowsDaclAnalysisError):
                        analyze_supplied_windows_dacl(supplied)
        for supplied in (None, [], b"{}", "{}", (), set()):
            with self.subTest(supplied=supplied), self.assertRaises(WindowsDaclAnalysisError):
                analyze_supplied_windows_dacl(supplied)

    def test_no_empty_duplicate_or_conflicting_token_sid_assertions(self):
        for items in (
            [],
            [{"sid": USER, "usage": "enabled"}] * 2,
            [{"sid": USER, "usage": "enabled"}, {"sid": USER, "usage": "deny_only"}],
            [{"sid": USER, "usage": "unknown"}],
            [{"sid": USER, "usage": True}],
        ):
            with self.subTest(items=items):
                supplied = component_fixture()
                supplied["token_sids"] = items
                with self.assertRaises(WindowsDaclAnalysisError):
                    analyze_supplied_windows_dacl(supplied)

    def test_original_and_returned_source_are_detached(self):
        supplied = component_fixture()
        original = deepcopy(supplied)
        report = analyze_supplied_windows_dacl(supplied)
        document = report.to_dict()
        supplied["security_descriptor"]["aces"][0]["mask"] = 0
        document["source_model"]["token_sids"][0]["usage"] = "disabled"
        document["evaluation"]["trace"].clear()
        self.assertEqual(report.to_dict()["source_model"], original)
        self.assertEqual(len(report.to_dict()["evaluation"]["trace"]), 2)
        verify_supplied_windows_dacl_analysis(report, model=original)
        with self.assertRaises(WindowsDaclAnalysisError):
            verify_supplied_windows_dacl_analysis(report, model=supplied)
        first = component_fixture()
        first["security_descriptor"]["aces"].clear()
        self.assertEqual(len(component_fixture()["security_descriptor"]["aces"]), 2)

    def test_cohashed_false_outcome_trace_and_source_hash_reject(self):
        original = analyze_supplied_windows_dacl(component_fixture()).to_dict()
        for change in ("outcome", "allowed", "remaining", "trace", "matched", "index", "source"):
            with self.subTest(change=change):
                raw = deepcopy(original)
                selected = raw["evaluation"]
                if change == "outcome":
                    selected["outcome"] = "supplied_dacl_denies_requested_bits"
                elif change == "allowed":
                    selected["allowed_mask"] = 2
                elif change == "remaining":
                    selected["remaining_mask"] = 1
                elif change == "trace":
                    selected["trace"].reverse()
                elif change == "matched":
                    selected["trace"][0]["matched_mask"] = 0
                elif change == "index":
                    selected["decisive_ace_index"] = 0
                else:
                    raw["source_model_sha256"] = "sha256:" + "a" * 64
                with self.assertRaises(WindowsDaclAnalysisError):
                    WindowsDaclAnalysis.from_dict(readdress(raw))

    def test_cohashed_promotions_native_flag_aliases_and_bound_changes_reject(self):
        original = analyze_supplied_windows_dacl(component_fixture()).to_dict()
        for field in module._FLAGS:
            for value in (not module._FLAGS[field], int(module._FLAGS[field])):
                with self.subTest(field=field, value=value):
                    raw = deepcopy(original)
                    raw[field] = value
                    with self.assertRaises(WindowsDaclAnalysisError):
                        WindowsDaclAnalysis.from_dict(readdress(raw))
        for field in module._BOUNDS:
            raw = deepcopy(original)
            raw["bounds"][field] += 1
            with self.subTest(field=field), self.assertRaises(WindowsDaclAnalysisError):
                WindowsDaclAnalysis.from_dict(readdress(raw))
        raw = deepcopy(original)
        raw["effects"]["authority"] = "granted"
        with self.assertRaises(WindowsDaclAnalysisError):
            WindowsDaclAnalysis.from_dict(readdress(raw))
        for value in (True, 1.0):
            raw = deepcopy(original)
            raw["schema_version"] = value
            with self.subTest(value=value), self.assertRaises(WindowsDaclAnalysisError):
                WindowsDaclAnalysis.from_dict(readdress(raw))

    def test_coherently_changed_declared_model_still_cannot_replace_original_source(self):
        original = component_fixture()
        other = deepcopy(original)
        other["security_descriptor"]["owner_sid"] = OTHER
        changed = analyze_supplied_windows_dacl(other)
        self.assertEqual(changed.to_dict()["evaluation"], evaluation(original))
        self.assertNotEqual(
            changed.to_dict()["source_model_sha256"],
            analyze_supplied_windows_dacl(original).to_dict()["source_model_sha256"],
        )
        WindowsDaclAnalysis.from_json(changed.to_json())
        verify_supplied_windows_dacl_analysis(changed, model=other)
        with self.assertRaises(WindowsDaclAnalysisError):
            verify_supplied_windows_dacl_analysis(changed, model=original)

    def test_forged_wrapper_missing_or_changed_native_slot_rejects(self):
        forged = object.__new__(WindowsDaclAnalysis)
        with self.assertRaises(WindowsDaclAnalysisError):
            forged.to_dict()
        for value in (None, b"{}", 1, "{}"):
            with self.subTest(value=value):
                object.__setattr__(forged, "document_json", value)
                with self.assertRaises(WindowsDaclAnalysisError):
                    verify_supplied_windows_dacl_analysis(forged, model=component_fixture())

    def test_duplicate_json_fields_reject_without_hashing(self):
        raw = analyze_supplied_windows_dacl(component_fixture()).to_json()
        duplicate = raw.replace('"schema_version":1', '"schema_version":1,"schema_version":1', 1)
        with (
            patch.object(module, "_sha", side_effect=AssertionError("hash reached")),
            self.assertRaises(WindowsDaclAnalysisError),
        ):
            WindowsDaclAnalysis.from_json(duplicate)

    def test_json_depth_nodes_integers_strings_and_escapes_refuse_before_decoder(self):
        documents = [
            "[" * (module.MAX_NATIVE_DEPTH + 1) + "0" + "]" * (module.MAX_NATIVE_DEPTH + 1),
            "[" + ",".join("0" for _ in range(module.MAX_NATIVE_NODES + 1)) + "]",
            "{" + '"n":' + "9" * 1000 + "}",
            "[9223372036854775808]",
            "[1.0]",
            "[NaN]",
            '"' + "a" * (module.MAX_STRING_BYTES + 1) + '"',
            '"' + r"\u0061" * (module.MAX_STRING_BYTES + 1) + '"',
            r'"\u0080"',
            r'"\ud800"',
            r'"\n"',
        ]
        for raw in documents:
            with (
                self.subTest(size=len(raw)),
                patch.object(module.json, "loads", side_effect=AssertionError("decoder reached")),
                self.assertRaises(WindowsDaclAnalysisError),
            ):
                WindowsDaclAnalysis.from_json(raw)

    def test_malformed_integer_signs_fail_public_intake_before_conversion_or_decoder(self):
        original = analyze_supplied_windows_dacl(component_fixture()).to_json()
        for field, original_value in (("schema_version", 1), ("desired_access", 3)):
            for lexical in ("--1", "---1", "--0", "--9223372036854775807", "-+1", "+1", "-"):
                malformed = original.replace(
                    f'"{field}":{original_value}', f'"{field}":{lexical}', 1
                )
                with (
                    self.subTest(field=field, lexical=lexical),
                    patch.object(
                        module.json, "loads", side_effect=AssertionError("decoder reached")
                    ),
                    patch.object(module, "_sha", side_effect=AssertionError("hash reached")),
                    self.assertRaises(WindowsDaclAnalysisError),
                ):
                    WindowsDaclAnalysis.from_json(malformed)
        for lexical in ("01", "-01", "00", "-00"):
            with (
                self.subTest(lexical=lexical),
                patch.object(module.json, "loads", side_effect=AssertionError("decoder reached")),
                self.assertRaises(WindowsDaclAnalysisError),
            ):
                WindowsDaclAnalysis.from_json("[" + lexical + "]")
        self.assertEqual(
            module._json("[0,-0,-1,9223372036854775807,-9223372036854775807]"),
            [0, 0, -1, 9223372036854775807, -9223372036854775807],
        )
        for lexical in ("-1", "-0"):
            with self.subTest(lexical=lexical), self.assertRaises(WindowsDaclAnalysisError):
                WindowsDaclAnalysis.from_json(
                    original.replace('"schema_version":1', '"schema_version":' + lexical, 1)
                )

    def test_json_exact_cost_boundaries_and_valid_escaped_printable_text(self):
        with (
            patch.object(module, "MAX_NATIVE_NODES", 4),
            patch.object(module, "MAX_NATIVE_DEPTH", 2),
        ):
            self.assertEqual(module._json("[[1,2]]"), [[1, 2]])
            with self.assertRaises(WindowsDaclAnalysisError):
                module._json("[[1,2,3]]")
            with self.assertRaises(WindowsDaclAnalysisError):
                module._json("[[[1]]]")
        with patch.object(module, "MAX_STRING_BYTES", 3):
            self.assertEqual(module._json(r'"\u0041\/\""'), 'A/"')
            with self.assertRaises(WindowsDaclAnalysisError):
                module._json(r'"\u0041\/\"x"')
        with patch.object(module, "MAX_DOCUMENT_BYTES", 7):
            self.assertEqual(module._json("[1,2,3]"), [1, 2, 3])
            with self.assertRaises(WindowsDaclAnalysisError):
                module._json("[1,2,3] ")

    def test_native_repeated_graph_cycles_depth_and_huge_integer_refuse_before_serialization(self):
        graph = ["x"]
        for _ in range(10):
            graph = [graph] * 10
        cyclic = []
        cyclic.append(cyclic)
        deep = 0
        for _ in range(module.MAX_NATIVE_DEPTH + 1):
            deep = [deep]
        for supplied in (graph, cyclic, deep, {"n": 1 << 100000}, {"x": "a" * 513}):
            with (
                self.subTest(kind=type(supplied)),
                patch.object(
                    module.json, "dumps", side_effect=AssertionError("serialization reached")
                ),
                patch.object(module, "_sha", side_effect=AssertionError("hash reached")),
                self.assertRaises(WindowsDaclAnalysisError),
            ):
                analyze_supplied_windows_dacl(supplied)

    def test_native_byte_accounting_includes_escapes_and_structural_punctuation(self):
        value = {"quoted": ['"\\', '"\\']}
        exact = len(json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")))
        with patch.object(module, "MAX_DOCUMENT_BYTES", exact):
            self.assertEqual(module._capture(value), value)
        with (
            patch.object(module, "MAX_DOCUMENT_BYTES", exact - 1),
            patch.object(module.json, "dumps", side_effect=AssertionError("serialization reached")),
            self.assertRaises(WindowsDaclAnalysisError),
        ):
            module._capture(value)
        with patch.object(module, "MAX_NATIVE_NODES", 5):
            self.assertEqual(module._capture({"k": [1, 2]}), {"k": [1, 2]})
            with self.assertRaises(WindowsDaclAnalysisError):
                module._capture({"k": [1, 2, 3]})

    def test_native_aggregate_byte_limit_precedes_even_small_shared_graph_hashing(self):
        shared = '\\"' * 256
        value = [shared] * 1024
        with (
            patch.object(module.json, "dumps", side_effect=AssertionError("serialization reached")),
            self.assertRaises(WindowsDaclAnalysisError),
        ):
            analyze_supplied_windows_dacl(value)

    def test_report_unknown_fields_and_non_native_json_text_fail_closed(self):
        raw = analyze_supplied_windows_dacl(component_fixture()).to_dict()
        raw["undeclared"] = 1
        with self.assertRaises(WindowsDaclAnalysisError):
            WindowsDaclAnalysis.from_dict(readdress(raw))
        for text in (None, b"{}", [], 1, "", "{", "\u00a0", "[0]" * 400000):
            with self.subTest(kind=type(text)), self.assertRaises(WindowsDaclAnalysisError):
                WindowsDaclAnalysis.from_json(text)


if __name__ == "__main__":
    unittest.main()
