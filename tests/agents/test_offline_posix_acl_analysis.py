"""Supplied DAC fixtures and an independent finite set-based permission oracle."""

import hashlib
import itertools
import json
import unittest
from copy import deepcopy
from dataclasses import FrozenInstanceError
from unittest.mock import patch

from sunderkey import offline_posix_acl_analysis as module
from sunderkey.offline_posix_acl_analysis import (
    PosixAclAnalysis,
    PosixAclAnalysisError,
    analyze_supplied_posix_acl,
    analyze_supplied_posix_acl_bytes,
    verify_supplied_posix_acl_analysis,
)

ALLOW = "allowed_by_supplied_posix_dac"
DENY = "not_allowed_by_supplied_posix_dac"


def entry(tag, permission, qualifier=None):
    return {"tag": tag, "qualifier": qualifier, "permission_mask": permission}


def component_fixture():
    """Fresh logical declarations only, not a host inode or authenticated principal."""
    return {
        "schema_version": 1,
        "object": {
            "object_ref": "file:synthetic",
            "owner_uid": 1000,
            "owner_gid": 2000,
            "rwx_mode": 487,
            "access_acl": [
                {"tag": "user_obj", "qualifier": None, "permission_mask": 7},
                {"tag": "user", "qualifier": 1001, "permission_mask": 4},
                {"tag": "group_obj", "qualifier": None, "permission_mask": 5},
                {"tag": "mask", "qualifier": None, "permission_mask": 4},
                {"tag": "other", "qualifier": None, "permission_mask": 7},
            ],
        },
        "principal": {
            "principal_ref": "subject:synthetic",
            "fsuid": 1001,
            "fsgid": 2000,
            "supplementary_gids": [],
        },
        "requests": [
            {"request_id": "read", "requested_mask": 4},
            {"request_id": "write", "requested_mask": 2},
        ],
    }


def supplied(*, owner=7, owning_group=4, other=7, mask=6, user=None, group=2):
    model = component_fixture()
    acl = [entry("user_obj", owner)]
    if user is not None:
        acl.append(entry("user", user, 1001))
    acl.append(entry("group_obj", owning_group))
    if group is not None:
        acl.append(entry("group", group, 2001))
    if mask is not None:
        acl.append(entry("mask", mask))
    acl.append(entry("other", other))
    model["object"]["access_acl"] = acl
    model["object"]["rwx_mode"] = (
        (owner << 6) | ((owning_group if mask is None else mask) << 3) | other
    )
    model["principal"]["fsuid"] = 1002
    model["principal"]["supplementary_gids"] = [2001]
    model["requests"] = [{"request_id": "mask-" + str(n), "requested_mask": n} for n in range(1, 8)]
    return model


def permission_set(mask):
    return {name for name, bit in (("r", 4), ("w", 2), ("x", 1)) if mask & bit}


def oracle(model, requested):
    """Class selection over declared sets, not the implementation's bitwise matcher."""
    item, principal = model["object"], model["principal"]
    memberships = {principal["fsgid"], *principal["supplementary_gids"]}
    acl = item["access_acl"]
    wanted = permission_set(requested)
    if acl is None:
        mode = item["rwx_mode"]
        if principal["fsuid"] == item["owner_uid"]:
            permission = (mode // 64) % 8
        elif item["owner_gid"] in memberships:
            permission = (mode // 8) % 8
        else:
            permission = mode % 8
        return wanted <= permission_set(permission)
    buckets = {tag: [row for row in acl if row["tag"] == tag] for tag in module._TAGS}
    if principal["fsuid"] == item["owner_uid"]:
        return wanted <= permission_set(buckets["user_obj"][0]["permission_mask"])
    matched_user = [row for row in buckets["user"] if row["qualifier"] == principal["fsuid"]]
    ceiling = (
        permission_set(buckets["mask"][0]["permission_mask"])
        if buckets["mask"]
        else {"r", "w", "x"}
    )
    if matched_user:
        return wanted <= permission_set(matched_user[0]["permission_mask"]) & ceiling
    groups = list(buckets["group_obj"]) if item["owner_gid"] in memberships else []
    groups.extend(row for row in buckets["group"] if row["qualifier"] in memberships)
    if groups:
        return any(wanted <= permission_set(row["permission_mask"]) & ceiling for row in groups)
    return wanted <= permission_set(buckets["other"][0]["permission_mask"])


def readdress(document):
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    raw = json.dumps(body, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    digest = "sha256:" + hashlib.sha256(module.DOMAIN.encode("ascii") + b"\n" + raw).hexdigest()
    return {"analysis_id": "LPA-" + digest[7:39].upper(), "analysis_sha256": digest, **body}


class SuppliedPosixAclAnalysisTests(unittest.TestCase):
    def checked_rows(self, model):
        document = analyze_supplied_posix_acl(model).to_dict()
        self.assertEqual(len(document["request_results"]), len(model["requests"]))
        for row in document["request_results"]:
            self.assertEqual(
                row["decision"], ALLOW if oracle(model, row["requested_mask"]) else DENY
            )
        return document

    def test_public_fixture_roundtrips_and_deterministic_identity(self):
        model = component_fixture()
        report = analyze_supplied_posix_acl(model)
        document = report.to_dict()
        self.assertEqual(document["selection"]["selected_class"], "named_user")
        self.assertEqual([row["decision"] for row in document["request_results"]], [ALLOW, DENY])
        self.assertEqual(PosixAclAnalysis.from_dict(document).to_json(), report.to_json())
        self.assertEqual(PosixAclAnalysis.from_json(report.to_json()).to_json(), report.to_json())
        self.assertEqual(analyze_supplied_posix_acl(model).to_json(), report.to_json())
        self.assertEqual(
            verify_supplied_posix_acl_analysis(report, model=model).to_json(), report.to_json()
        )
        self.assertEqual(
            verify_supplied_posix_acl_analysis(document, model=model).to_json(), report.to_json()
        )

    def test_literal_fixture_model_digest_has_independent_canonical_projection(self):
        model = component_fixture()
        encoded = json.dumps(
            model, sort_keys=True, ensure_ascii=True, separators=(",", ":")
        ).encode("ascii")
        expected = (
            "sha256:"
            + hashlib.sha256(module.MODEL_DOMAIN.encode("ascii") + b"\n" + encoded).hexdigest()
        )
        document = analyze_supplied_posix_acl(model).to_dict()
        self.assertEqual(document["source_model_sha256"], expected)
        self.assertEqual(document["analysis_id"], "LPA-E2620599A2D7BE5CA8AB6EE62F48C845")
        self.assertEqual(
            document["analysis_sha256"],
            "sha256:e2620599a2d7be5ca8ab6ee62f48c845b06885a6501481ce3a7781e1866679fd",
        )
        self.assertEqual(
            document["source_model_sha256"],
            "sha256:fbe84a8e5dccfb589ad2f406c4206be8fd30782fedf385e9c5468d3bf40faa79",
        )

    def test_mode_only_class_oracle_covers_all_permission_masks(self):
        for selected, permission in itertools.product(("owner", "group", "other"), range(8)):
            model = supplied()
            model["object"]["access_acl"] = None
            model["object"]["rwx_mode"] = 511
            if selected == "owner":
                model["principal"]["fsuid"] = 1000
                model["object"]["rwx_mode"] = (permission << 6) | 63
            elif selected == "group":
                model["object"]["rwx_mode"] = 455 | (permission << 3)
            else:
                model["principal"]["fsgid"] = 999
                model["principal"]["supplementary_gids"] = []
                model["object"]["rwx_mode"] = 504 | permission
            with self.subTest(selected=selected, permission=permission):
                document = self.checked_rows(model)
                self.assertEqual(document["selection"]["selected_class"], selected)

    def test_two_group_entries_and_mask_exhaustive_nonunion_oracle(self):
        for owning, named, mask in itertools.product(range(8), repeat=3):
            with self.subTest(owning=owning, named=named, mask=mask):
                self.checked_rows(supplied(owning_group=owning, group=named, mask=mask))

    def test_read_and_write_from_different_groups_do_not_allow_combined_request(self):
        document = self.checked_rows(supplied(owning_group=4, group=2, mask=6))
        rows = {row["requested_mask"]: row for row in document["request_results"]}
        self.assertEqual(rows[4]["decision"], ALLOW)
        self.assertEqual(rows[2]["decision"], ALLOW)
        self.assertEqual(rows[6]["decision"], DENY)
        self.assertIsNone(rows[6]["witness_entry_index"])

    def test_owner_never_falls_back_or_uses_named_user_or_mask(self):
        for permission, mask in itertools.product(range(8), repeat=2):
            model = supplied(owner=permission, user=7, group=7, owning_group=7, mask=mask)
            model["object"]["access_acl"][1]["qualifier"] = 1000
            model["principal"]["fsuid"] = 1000
            with self.subTest(permission=permission, mask=mask):
                document = self.checked_rows(model)
                self.assertEqual(document["selection"]["selected_class"], "owner")
                self.assertIsNone(document["selection"]["mask_entry_index"])

    def test_named_user_mask_and_no_fallback_oracle(self):
        for permission, mask in itertools.product(range(8), repeat=2):
            model = supplied(user=permission, owning_group=7, group=7, mask=mask)
            model["principal"]["fsuid"] = 1001
            with self.subTest(permission=permission, mask=mask):
                document = self.checked_rows(model)
                self.assertEqual(document["selection"]["selected_class"], "named_user")

    def test_any_matching_group_prevents_other_fallback(self):
        model = supplied(owning_group=0, group=0, other=7, mask=7)
        document = self.checked_rows(model)
        self.assertEqual(document["selection"]["selected_class"], "group")
        self.assertTrue(all(row["decision"] == DENY for row in document["request_results"]))

    def test_no_group_membership_selects_other_without_mask(self):
        model = supplied(owning_group=7, group=7, other=5, mask=0)
        model["principal"]["fsgid"] = 999
        model["principal"]["supplementary_gids"] = []
        document = self.checked_rows(model)
        self.assertEqual(document["selection"]["selected_class"], "other")
        self.assertIsNone(document["selection"]["mask_permission_mask"])

    def test_fsgid_and_supplementary_membership_are_additive_identities_not_permissions(self):
        base = supplied(owning_group=4, group=2, mask=6)
        for fsgid, supplementary in (
            (2000, [2001]),
            (2001, [2000]),
            (999, [2000, 2001]),
            (2000, [2000, 2001]),
        ):
            model = deepcopy(base)
            model["principal"]["fsgid"] = fsgid
            model["principal"]["supplementary_gids"] = supplementary
            self.assertEqual(
                self.checked_rows(model)["request_results"],
                self.checked_rows(base)["request_results"],
            )

    def test_owning_and_named_group_with_same_gid_remain_separate_entries(self):
        model = supplied(owning_group=4, group=2, mask=6)
        model["object"]["access_acl"][2]["qualifier"] = 2000
        model["principal"]["supplementary_gids"] = []
        rows = self.checked_rows(model)["request_results"]
        self.assertEqual(next(row["decision"] for row in rows if row["requested_mask"] == 6), DENY)

    def test_acl_without_named_entries_may_omit_or_include_mask(self):
        for mask in (None, 0, 7):
            model = supplied(owning_group=5, group=None, mask=mask)
            self.checked_rows(model)

    def test_valid_uint32_boundaries_are_declarations_not_root_privilege(self):
        for identifier in (0, module.MAX_ID):
            model = component_fixture()
            model["object"]["owner_uid"] = identifier
            model["object"]["owner_gid"] = identifier
            model["principal"]["fsuid"] = identifier
            model["principal"]["fsgid"] = identifier
            document = self.checked_rows(model)
            self.assertEqual(document["selection"]["selected_class"], "owner")
            self.assertFalse(document["effective_access_proven"])

    def test_mode_acl_disagreement_is_rejected_before_hash(self):
        for bit in (1, 8, 64):
            model = component_fixture()
            model["object"]["rwx_mode"] ^= bit
            with patch.object(module, "_hash", side_effect=AssertionError("hash reached")):
                with self.assertRaisesRegex(PosixAclAnalysisError, "class bits disagree"):
                    analyze_supplied_posix_acl(model)

    def test_missing_duplicate_or_unknown_acl_tags_are_rejected(self):
        original = component_fixture()
        variants = []
        for tag in ("user_obj", "group_obj", "other", "mask"):
            model = deepcopy(original)
            model["object"]["access_acl"] = [
                row for row in model["object"]["access_acl"] if row["tag"] != tag
            ]
            variants.append(model)
        for replacement in (
            [],
            [entry("default", 7)],
            [entry("user_obj", 7), entry("user_obj", 7)],
        ):
            model = deepcopy(original)
            model["object"]["access_acl"] = replacement
            variants.append(model)
        for model in variants:
            with self.assertRaises(PosixAclAnalysisError):
                analyze_supplied_posix_acl(model)

    def test_canonical_tag_and_increasing_qualifier_order_are_required(self):
        original = supplied(user=4)
        variants = []
        for first, second in ((0, 1), (1, 2), (3, 4)):
            model = deepcopy(original)
            acl = model["object"]["access_acl"]
            acl[first], acl[second] = acl[second], acl[first]
            variants.append(model)
        for tag, qualifier, position in (
            ("user", 1001, 2),
            ("user", 1000, 2),
            ("group", 2001, 4),
            ("group", 1999, 4),
        ):
            model = deepcopy(original)
            model["object"]["access_acl"].insert(position, entry(tag, 7, qualifier))
            variants.append(model)
        for model in variants:
            with self.assertRaises(PosixAclAnalysisError):
                analyze_supplied_posix_acl(model)

    def test_qualifiers_and_all_permission_integer_fields_refuse_native_aliases(self):
        paths = [
            ("schema_version",),
            ("object", "owner_uid"),
            ("object", "owner_gid"),
            ("object", "rwx_mode"),
            ("object", "access_acl", 1, "qualifier"),
            ("object", "access_acl", 1, "permission_mask"),
            ("principal", "fsuid"),
            ("principal", "fsgid"),
            ("requests", 0, "requested_mask"),
        ]
        for path, value in itertools.product(paths, (True, False, 1.0, "1", None, -1, 2**1000)):
            model = component_fixture()
            target = model
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = value
            with self.subTest(path=path, value=type(value).__name__):
                with patch.object(module, "_hash", side_effect=AssertionError("hash reached")):
                    with self.assertRaises(PosixAclAnalysisError):
                        analyze_supplied_posix_acl(model)

    def test_uid_sentinel_invalid_masks_and_unqualified_values_are_rejected(self):
        for path, value in (
            (("object", "owner_uid"), 2**32 - 1),
            (("principal", "fsgid"), 2**32),
            (("object", "rwx_mode"), 512),
            (("object", "access_acl", 0, "qualifier"), 1000),
            (("object", "access_acl", 1, "qualifier"), None),
            (("object", "access_acl", 1, "permission_mask"), 8),
            (("requests", 0, "requested_mask"), 0),
            (("requests", 0, "requested_mask"), 8),
        ):
            model = component_fixture()
            target = model
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = value
            with self.assertRaises(PosixAclAnalysisError):
                analyze_supplied_posix_acl(model)

    def test_duplicate_groups_requests_and_closed_unknown_fields_are_rejected(self):
        variants = []
        model = component_fixture()
        model["principal"]["supplementary_gids"] = [2000, 2000]
        variants.append(model)
        model = component_fixture()
        model["requests"].append(deepcopy(model["requests"][0]))
        variants.append(model)
        for path in ((), ("object",), ("principal",), ("requests", 0), ("object", "access_acl", 0)):
            model = component_fixture()
            target = model
            for part in path:
                target = target[part]
            target["unmodeled"] = None
            variants.append(model)
        for model in variants:
            with self.assertRaises(PosixAclAnalysisError):
                analyze_supplied_posix_acl(model)

    def test_exact_native_families_not_subclasses_or_coercion(self):
        class Text(str):
            pass

        class Number(int):
            pass

        class Object(dict):
            pass

        class Array(list):
            pass

        for field, value in (
            ("fsuid", Number(1001)),
            ("principal_ref", Text("subject:synthetic")),
            ("supplementary_gids", Array()),
        ):
            model = component_fixture()
            model["principal"][field] = value
            with patch.object(module, "_hash", side_effect=AssertionError("hash reached")):
                with self.assertRaises(PosixAclAnalysisError):
                    analyze_supplied_posix_acl(model)
        for value in (Object(component_fixture()), [], (), None, "{}", b"{}"):
            with self.assertRaises(PosixAclAnalysisError):
                analyze_supplied_posix_acl(value)

    def test_maximum_collection_capacity_and_one_over_each_limit(self):
        model = supplied(user=None, group=None, mask=7)
        users = [entry("user", 7, n) for n in range(100, 226)]
        groups = [entry("group", 7, n) for n in range(200, 326)]
        model["object"]["access_acl"] = [
            entry("user_obj", 7),
            *users,
            entry("group_obj", 4),
            *groups,
            entry("mask", 7),
            entry("other", 7),
        ]
        model["object"]["rwx_mode"] = 511
        model["principal"]["supplementary_gids"] = list(range(200, 328))
        model["requests"] = [
            {"request_id": "query-" + str(n), "requested_mask": 7} for n in range(64)
        ]
        self.assertEqual(len(model["object"]["access_acl"]), 256)
        report = self.checked_rows(model)
        self.assertEqual(report["summary"]["request_count"], 64)
        self.assertEqual(report["summary"]["acl_entry_count"], 256)
        for field in ("groups", "acl", "requests"):
            extra = deepcopy(model)
            if field == "groups":
                extra["principal"]["supplementary_gids"].append(10000)
            elif field == "acl":
                extra["object"]["access_acl"].insert(127, entry("user", 7, 226))
            else:
                extra["requests"].append({"request_id": "query-extra", "requested_mask": 7})
            with self.assertRaises(PosixAclAnalysisError):
                analyze_supplied_posix_acl(extra)

    def test_shared_subtrees_are_charged_again_and_cycles_refused_before_hash(self):
        cycle = []
        cycle.append(cycle)
        shared = {"ref": "x" * 256}
        with patch.object(module, "_hash", side_effect=AssertionError("hash reached")):
            for graph in (cycle, [shared] * 300, [[None] * 4096] * 3):
                with self.assertRaises(PosixAclAnalysisError):
                    analyze_supplied_posix_acl(graph)

    def test_raw_node_depth_byte_and_string_budget_precedes_decoder(self):
        for scalar in ("0", '"x"', "null", "true"):
            raw = "[" * 12 + scalar + "]" * 12
            with patch.object(module.json, "loads", side_effect=AssertionError("decoder reached")):
                with self.assertRaises(PosixAclAnalysisError):
                    analyze_supplied_posix_acl_bytes(model_bytes=raw.encode("ascii"))
        for raw in (
            "[" + ",".join("0" for _ in range(module.MAX_NATIVE_NODES)) + "]",
            '"' + "x" * 257 + '"',
            " " * (module.MAX_DOCUMENT_BYTES + 1),
            '"\\uD800"',
        ):
            with patch.object(module.json, "loads", side_effect=AssertionError("decoder reached")):
                with self.assertRaises(PosixAclAnalysisError):
                    analyze_supplied_posix_acl_bytes(model_bytes=raw.encode("ascii"))
        with self.assertRaises(PosixAclAnalysisError):
            analyze_supplied_posix_acl_bytes(model_bytes=b"\xff")
        self.assertEqual(module._decode("[" * 11 + "0" + "]" * 11), self.nested(11, 0))

    @staticmethod
    def nested(count, value):
        for _ in range(count):
            value = [value]
        return value

    def test_raw_malformed_numeric_tokens_never_reach_decoder_or_hash(self):
        original = json.dumps(component_fixture(), separators=(",", ":"))
        for token in (
            "--1",
            "---1",
            "-",
            "+1",
            "01",
            "-01",
            "1.0",
            "1e0",
            "NaN",
            "Infinity",
            "9223372036854775808",
            "-9223372036854775808",
            "9" * 1000,
        ):
            raw = original.replace('"schema_version":1', '"schema_version":' + token, 1)
            with (
                patch.object(module.json, "loads", side_effect=AssertionError("decoder reached")),
                patch.object(module, "_hash", side_effect=AssertionError("hash reached")),
                self.assertRaises(PosixAclAnalysisError),
            ):
                analyze_supplied_posix_acl_bytes(model_bytes=raw.encode("ascii"))

    def test_duplicate_json_members_and_invalid_syntax_are_domain_errors(self):
        original = json.dumps(component_fixture(), separators=(",", ":"))
        for old, new in (
            ('"schema_version":1', '"schema_version":1,"schema_version":1'),
            ('"owner_uid":1000', '"owner_uid":1000,"owner_uid":1000'),
            ('"permission_mask":4', '"permission_mask":4,"permission_mask":4'),
        ):
            with self.assertRaisesRegex(PosixAclAnalysisError, "Duplicate"):
                analyze_supplied_posix_acl_bytes(
                    model_bytes=original.replace(old, new, 1).encode("ascii")
                )
        for text in ("", "{", "[}", '{"a" 1}', "[] trailing", '"unfinished'):
            with self.assertRaises(PosixAclAnalysisError):
                analyze_supplied_posix_acl_bytes(model_bytes=text.encode("ascii"))

    def test_whitespace_and_ascii_escapes_bind_parsed_not_raw_source_bytes(self):
        original = component_fixture()
        ordinary = json.dumps(original, separators=(",", ":"))
        pretty = json.dumps(original, indent=2)
        escaped = ordinary.replace("file:synthetic", "file:syntheti\\u0063")
        expected = analyze_supplied_posix_acl(original).to_json()
        for text in (ordinary, pretty, escaped):
            self.assertEqual(
                analyze_supplied_posix_acl_bytes(model_bytes=text.encode("ascii")).to_json(),
                expected,
            )

    def test_final_native_scalar_charge_is_checked_before_serialization(self):
        for value in (None, False, True, 0, -1):
            graph = {"k": value}
            exact_size = len(json.dumps(graph, sort_keys=True, separators=(",", ":")))
            with patch.object(module, "MAX_DOCUMENT_BYTES", exact_size):
                self.assertEqual(module._own(graph), graph)
            with patch.object(module, "MAX_DOCUMENT_BYTES", exact_size - 1):
                with patch.object(module.json, "dumps", side_effect=AssertionError("dump reached")):
                    with self.assertRaises(PosixAclAnalysisError):
                        module._own(graph)

    def test_matching_witness_and_full_output_budgets_precede_all_hashes(self):
        for name, limit in (
            ("MAX_MATCHING_STEPS", 1),
            ("MAX_WITNESSES", 0),
            ("MAX_REPORT_BYTES", 100),
            ("MAX_REPORT_NODES", 30),
        ):
            with (
                patch.object(module, name, limit),
                patch.object(module, "_hash", side_effect=AssertionError("hash reached")),
                self.assertRaises(PosixAclAnalysisError),
            ):
                analyze_supplied_posix_acl(component_fixture())

    def test_detached_owned_inputs_outputs_and_frozen_wrapper(self):
        model = component_fixture()
        original = deepcopy(model)
        report = analyze_supplied_posix_acl(model)
        raw = report.to_json()
        model["object"]["access_acl"][1]["permission_mask"] = 7
        document = report.to_dict()
        document["source_model"]["principal"]["fsuid"] = 1000
        document["selection"]["candidate_entries"][0]["permission_mask"] = 7
        self.assertEqual(report.to_json(), raw)
        verify_supplied_posix_acl_analysis(report, model=original)
        with self.assertRaises(FrozenInstanceError):
            report.document_json = "{}"

    def test_request_and_group_permutations_preserve_math_but_bind_source_order(self):
        original = supplied()
        original["principal"]["supplementary_gids"] = [2001, 3000]
        changed = deepcopy(original)
        changed["requests"].reverse()
        changed["principal"]["supplementary_gids"].reverse()
        first, second = analyze_supplied_posix_acl(original), analyze_supplied_posix_acl(changed)
        self.assertEqual(first.to_dict()["request_results"], second.to_dict()["request_results"])
        self.assertNotEqual(first.to_json(), second.to_json())
        with self.assertRaises(PosixAclAnalysisError):
            verify_supplied_posix_acl_analysis(second, model=original)

    def test_cohashed_false_results_selection_and_counters_do_not_replay(self):
        original = analyze_supplied_posix_acl(component_fixture()).to_dict()
        paths = [
            (("request_results", 1, "decision"), ALLOW),
            (("request_results", 1, "witness_entry_index"), 1),
            (("selection", "selected_class"), "other"),
            (("selection", "candidate_entries", 0, "effective_permission_mask"), 7),
            (("selection", "mask_permission_mask"), 7),
            (("summary", "matching_steps"), 0),
            (("summary", ALLOW), 2),
            (("source_model_sha256",), "sha256:" + "b" * 64),
            (("request_results", 0, "request_sha256"), "sha256:" + "b" * 64),
            (("semantics", "linux_version"), "6.18"),
        ]
        for path, value in paths:
            changed = deepcopy(original)
            target = changed
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = value
            with self.subTest(path=path):
                with self.assertRaises(PosixAclAnalysisError):
                    PosixAclAnalysis.from_dict(readdress(changed))

    def test_report_native_integer_and_boolean_aliases_are_not_equal_json(self):
        original = analyze_supplied_posix_acl(component_fixture()).to_dict()
        for path, value in (
            (("schema_version",), True),
            (("request_results", 0, "requested_mask"), 4.0),
            (("selection", "candidate_entries", 0, "entry_index"), True),
            (("summary", ALLOW), True),
            (("summary", "request_count"), 2.0),
            (("effective_access_proven",), 0),
            (("offline_only",), 1),
        ):
            document = deepcopy(original)
            target = document
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = value
            with self.assertRaises(PosixAclAnalysisError):
                PosixAclAnalysis.from_dict(readdress(document))

    def test_coherent_other_source_is_inspectable_but_not_original_source_replay(self):
        original = component_fixture()
        foreign = deepcopy(original)
        foreign["object"]["object_ref"] = "file:other"
        foreign["principal"]["principal_ref"] = "subject:other"
        report = analyze_supplied_posix_acl(foreign)
        self.assertEqual(PosixAclAnalysis.from_json(report.to_json()).to_json(), report.to_json())
        verify_supplied_posix_acl_analysis(report, model=foreign)
        with self.assertRaises(PosixAclAnalysisError):
            verify_supplied_posix_acl_analysis(report, model=original)

    def test_incomplete_late_mutated_or_foreign_wrapper_replays_or_rejects(self):
        incomplete = object.__new__(PosixAclAnalysis)
        with self.assertRaises(PosixAclAnalysisError):
            incomplete.to_dict()
        genuine = analyze_supplied_posix_acl(component_fixture())
        forged = object.__new__(PosixAclAnalysis)
        document = genuine.to_dict()
        document["request_results"][1]["decision"] = ALLOW
        object.__setattr__(
            forged, "document_json", json.dumps(readdress(document), separators=(",", ":"))
        )
        with self.assertRaises(PosixAclAnalysisError):
            verify_supplied_posix_acl_analysis(forged, model=component_fixture())

        class Derived(PosixAclAnalysis):
            pass

        with self.assertRaises(PosixAclAnalysisError):
            verify_supplied_posix_acl_analysis(
                Derived(genuine.to_json()), model=component_fixture()
            )

    def test_report_flags_effects_metadata_and_fields_are_closed(self):
        original = analyze_supplied_posix_acl(component_fixture()).to_dict()
        for path, value in (
            (("effective_access_proven",), True),
            (("qualification_claimed",), True),
            (("effects", "filesystem"), "write"),
            (("profile_id",), "AOE-GC-D12-S02"),
            (("blueprint_sha256",), "sha256:" + "b" * 64),
            (("bounds", "maximum_requests"), 65),
        ):
            document = deepcopy(original)
            target = document
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = value
            with self.assertRaises(PosixAclAnalysisError):
                PosixAclAnalysis.from_dict(readdress(document))
        for missing in original:
            document = deepcopy(original)
            del document[missing]
            with self.assertRaises(PosixAclAnalysisError):
                PosixAclAnalysis.from_dict(document)
        document = deepcopy(original)
        document["extension"] = None
        with self.assertRaises(PosixAclAnalysisError):
            PosixAclAnalysis.from_dict(document)

    def test_lane_partial_algorithm_and_no_effects_are_fixed_for_all_outcomes(self):
        document = analyze_supplied_posix_acl(component_fixture()).to_dict()
        self.assertEqual(document["component_id"], "linux_supplied_posix_acl_arithmetic")
        self.assertEqual(document["profile_id"], "AOE-GC-D12-S01")
        self.assertEqual(document["capability_id"], "host.linux.local-privilege-escalation")
        self.assertEqual(document["vector_id"], "AV-GC-D12-S01-01")
        self.assertEqual(document["wave_id"], "IW2-001")
        self.assertEqual(document["semantics"]["linux_version"], "6.17")
        self.assertTrue(all(value == "none" for value in document["effects"].values()))
        for flag in (
            "source_authenticated",
            "filesystem_observed",
            "effective_access_proven",
            "live_use_approved",
            "qualification_claimed",
        ):
            self.assertIs(document[flag], False)


if __name__ == "__main__":
    unittest.main()
