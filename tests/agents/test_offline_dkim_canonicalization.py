"""Inert supplied DKIM arithmetic vectors, not signed or delivered mail."""

from __future__ import annotations

import base64
import copy
import hashlib
import itertools
import json
import re
import unittest
from unittest import mock

from sunderkey import offline_dkim_canonicalization as m

SIMPLE_EMPTY_HASH = "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY="
RELAXED_EMPTY_HASH = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
_SENTINEL = object()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _body_oracle(body, mode):
    """A separate line-table oracle, unlike the production streaming accumulator."""
    lines = body.split(b"\r\n")
    if mode == "relaxed":
        lines = [re.sub(rb"[ \t]+", b" ", line.rstrip(b" \t")) for line in lines]
    while lines and lines[-1] == b"":
        lines.pop()
    if mode == "simple":
        return b"\r\n".join(lines) + b"\r\n"
    return b"\r\n".join(lines) + b"\r\n" if lines else b""


def _model(message, index=0, source_id="synthetic-dkim-test"):
    return {
        "schema_version": 1,
        "source_id": source_id,
        "message_base64": base64.b64encode(message).decode("ascii"),
        "dkim_header_index": index,
    }


def _message(
    body=b"",
    *,
    c=b"relaxed/relaxed",
    h=b"from:x-note:x-note:x-missing",
    length=None,
    bh=None,
    a=b"rsa-sha256",
    v=b"1",
    b=b"AQ==",
    extra_tags=b"",
    headers=None,
):
    mode = "relaxed" if c.split(b"/")[-1] == b"relaxed" and b"/" in c else "simple"
    canonical_body = _body_oracle(body, mode)
    covered = (
        canonical_body
        if length is None
        else canonical_body[: min(int(length), len(canonical_body))]
    )
    if bh is None:
        bh = base64.b64encode(hashlib.sha256(covered).digest())
    signature = (
        b"DKIM-Signature: v="
        + v
        + b"; a="
        + a
        + b"; c="
        + c
        + b"; d=example.test; s=offline; h="
        + h
        + b"; bh="
        + bh
        + b"; "
    )
    if length is not None:
        signature += b"l=" + str(length).encode("ascii") + b"; "
    signature += extra_tags + b"b=" + b + b";\r\n"
    fields = (
        headers
        if headers is not None
        else (b"From: sender@example.test\r\n", b"X-Note: older\r\n", b"X-Note: newer\r\n")
    )
    return signature + b"".join(fields) + b"\r\n" + body


def component_fixture():
    """Fresh hash-free synthetic public-only integration model."""
    return m.component_fixture()


def _readdress(document):
    owned = copy.deepcopy(document)
    body = {
        key: value for key, value in owned.items() if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = hashlib.sha256(
        m.DOMAIN.encode("ascii") + b"\n" + _canonical(body).encode("ascii")
    ).hexdigest()
    owned["analysis_sha256"] = "sha256:" + digest
    owned["analysis_id"] = "DCA-" + digest[:32].upper()
    return owned


class _Integer(int):
    pass


class _String(str):
    pass


class _Dictionary(dict):
    pass


class DkimCanonicalizationTests(unittest.TestCase):
    def analyze(self, message=_SENTINEL, *, model=_SENTINEL):
        if model is _SENTINEL:
            model = component_fixture() if message is _SENTINEL else _model(message)
        return m.analyze_supplied_dkim_canonicalization(model).to_dict()

    def test_fixture_literal_addresses_and_observations(self):
        source = component_fixture()
        body = self.analyze(model=source)
        self.assertEqual(body["analysis_id"], "DCA-F58B5A06975C4D52D03EF747BA432A59")
        self.assertEqual(
            body["analysis_sha256"],
            "sha256:f58b5a06975c4d52d03ef747ba432a592bdb38366c402a87e8aac89dbc034e9d",
        )
        self.assertEqual(
            body["source_model_sha256"],
            "sha256:444274ae769e57d41a7a0c92044636b5f60fe970031046e7300a3cb4761571da",
        )
        self.assertEqual(
            body["source_message_sha256"],
            "sha256:bea01854c5d658f9a90bfbd2d3f2bdbf1e5dde8c13a2dfeb6e8dc6c80d59833a",
        )
        self.assertEqual(body["source_model"], source)
        observation = body["body_observation"]
        self.assertEqual(observation["canonical_bytes"], 0)
        self.assertEqual(observation["covered_bytes"], 0)
        self.assertEqual(observation["coverage_state"], "full")
        self.assertTrue(observation["body_hash_matches_supplied_bh"])
        self.assertEqual(
            [row["physical_header_index"] for row in body["header_selection_observations"]],
            [1, 3, 2, None],
        )
        self.assertEqual(body["header_selection_observations"][-1]["contribution_bytes"], 0)

    def test_literal_empty_body_hashes_match_rfc_vectors(self):
        for mode, expected, canonical in (
            (b"simple/simple", SIMPLE_EMPTY_HASH, b"\r\n"),
            (b"relaxed/relaxed", RELAXED_EMPTY_HASH, b""),
        ):
            for raw in (b"", b"\r\n", b"\r\n\r\n"):
                with self.subTest(mode=mode, raw=raw):
                    body = self.analyze(_message(raw, c=mode))["body_observation"]
                    self.assertEqual(body["computed_body_hash_base64"], expected)
                    self.assertEqual(base64.b64decode(body["canonical_body_base64"]), canonical)
                    self.assertTrue(body["body_hash_matches_supplied_bh"])

    def test_independent_small_line_body_oracle(self):
        alphabet = (b"", b"A", b" ", b"\tA\t", b"A \tB", b"\v \f", b"\xff\tX")
        controls = 0
        for count in range(4):
            for lines in itertools.product(alphabet, repeat=count):
                for ending in (False, True):
                    raw = b"\r\n".join(lines) + (b"\r\n" if ending else b"")
                    for mode in ("simple", "relaxed"):
                        expected = _body_oracle(raw, mode)
                        observation = self.analyze(
                            _message(raw, c=(mode + "/" + mode).encode("ascii"))
                        )["body_observation"]
                        self.assertEqual(
                            base64.b64decode(observation["canonical_body_base64"]), expected
                        )
                        self.assertEqual(
                            observation["computed_body_hash_base64"],
                            base64.b64encode(hashlib.sha256(expected).digest()).decode("ascii"),
                        )
                        controls += 1
        self.assertEqual(controls, 1600)

    def test_body_simple_keeps_whitespace_only_lines(self):
        observation = self.analyze(_message(b"A\r\n \t\r\n\r\n", c=b"simple/simple"))[
            "body_observation"
        ]
        self.assertEqual(base64.b64decode(observation["canonical_body_base64"]), b"A\r\n \t\r\n")

    def test_body_relaxed_preserves_leading_and_internal_empty_lines(self):
        raw = b"\r\n\tA  B \t\r\n\r\nC\t\r\n \r\n"
        observation = self.analyze(_message(raw))["body_observation"]
        self.assertEqual(
            base64.b64decode(observation["canonical_body_base64"]), b"\r\n A B\r\n\r\nC\r\n"
        )

    def test_non_sp_htab_body_octets_are_not_unicode_whitespace(self):
        raw = b"\v\f\x00\xff\xc2\xa0 \tX\r\n"
        observation = self.analyze(_message(raw))["body_observation"]
        self.assertEqual(
            base64.b64decode(observation["canonical_body_base64"]), b"\v\f\x00\xff\xc2\xa0 X\r\n"
        )

    def test_nonempty_body_without_final_crlf_is_canonicalized(self):
        for mode in (b"simple/simple", b"relaxed/relaxed"):
            body = self.analyze(_message(b"ABC", c=mode))["body_observation"]
            self.assertEqual(base64.b64decode(body["canonical_body_base64"]), b"ABC\r\n")

    def test_missing_and_single_c_use_documented_defaults(self):
        raw = _message(b" A \t\r\n", c=b"simple/simple").replace(b"c=simple/simple; ", b"", 1)
        default = self.analyze(raw)
        self.assertEqual(
            (default["header_algorithm"], default["body_algorithm"]), ("simple", "simple")
        )
        single = self.analyze(_message(b" A \t\r\n", c=b"relaxed"))
        self.assertEqual(
            (single["header_algorithm"], single["body_algorithm"]), ("relaxed", "simple")
        )

    def test_header_simple_preserves_case_folds_and_before_colon_wsp(self):
        headers = (b"FrOm \t:  sender@example.test \t\r\n\tcontinued \r\n",)
        body = self.analyze(_message(c=b"simple/simple", h=b"from", headers=headers))
        preimage = base64.b64decode(body["header_preimage_base64"])
        self.assertTrue(preimage.startswith(headers[0]))
        self.assertEqual(body["before_colon_wsp_field_indices"], [1])

    def test_header_relaxed_unfolds_and_trims_only_prescribed_wsp(self):
        headers = (b"FrOm \t:  sender@example.test \t\r\n\tcontinued \r\n",)
        body = self.analyze(_message(h=b"FROM", headers=headers))
        self.assertTrue(
            base64.b64decode(body["header_preimage_base64"]).startswith(
                b"from:sender@example.test continued\r\n"
            )
        )
        self.assertEqual(body["before_colon_wsp_field_indices"], [1])

    def test_all_four_header_body_mode_combinations(self):
        for header, body in itertools.product(("simple", "relaxed"), repeat=2):
            result = self.analyze(
                _message(
                    b" A\t \r\n",
                    c=(header + "/" + body).encode("ascii"),
                    h=b"from",
                    headers=(b"FrOm: sender@example.test \r\n",),
                )
            )
            self.assertEqual((result["header_algorithm"], result["body_algorithm"]), (header, body))
            self.assertTrue(result["body_observation"]["body_hash_matches_supplied_bh"])

    def test_duplicate_h_names_select_bottom_up_unused_and_absent_zero_bytes(self):
        headers = (b"From: sender@example.test\r\n", b"X: A\r\n", b"x: B\r\n", b"X: C\r\n")
        result = self.analyze(_message(h=b"x:X:x:x:missing:from", headers=headers))
        rows = result["header_selection_observations"]
        self.assertEqual([row["physical_header_index"] for row in rows], [4, 3, 2, None, None, 1])
        self.assertEqual([row["contribution_bytes"] for row in rows[3:5]], [0, 0])
        self.assertTrue(
            base64.b64decode(result["header_preimage_base64"]).startswith(
                b"x:C\r\nx:B\r\nx:A\r\nfrom:sender@example.test\r\n"
            )
        )

    def test_independent_header_stack_selection_oracle(self):
        controls = 0
        for count in range(4):
            for names in itertools.product((b"X", b"Y"), repeat=count):
                headers = (b"From: sender@example.test\r\n",) + tuple(
                    name + b": " + str(index).encode("ascii") + b"\r\n"
                    for index, name in enumerate(names)
                )
                for requested in itertools.product(("x", "y", "z"), repeat=2):
                    expected = []
                    unused = list(range(1, count + 2))
                    labels = ["from"] + [name.decode("ascii").lower() for name in names]
                    for label in requested:
                        matches = [index for index in unused if labels[index - 1] == label]
                        chosen = max(matches) if matches else None
                        expected.append(chosen)
                        if chosen is not None:
                            unused.remove(chosen)
                    result = self.analyze(
                        _message(h=":".join(requested).encode("ascii"), headers=headers)
                    )
                    self.assertEqual(
                        [
                            row["physical_header_index"]
                            for row in result["header_selection_observations"]
                        ],
                        expected,
                    )
                    controls += 1
        self.assertEqual(controls, 135)

    def test_other_signature_b_is_retained_and_selected_signature_is_excluded(self):
        other = b"DKIM-Signature: original=opaque; b=KEEPTHIS==;\r\n"
        result = self.analyze(
            _message(
                h=b"dkim-signature:dkim-signature:from",
                headers=(other, b"From: sender@example.test\r\n"),
            )
        )
        self.assertEqual(
            [row["physical_header_index"] for row in result["header_selection_observations"]],
            [1, None, 2],
        )
        self.assertTrue(
            base64.b64decode(result["header_preimage_base64"]).startswith(
                b"dkim-signature:original=opaque; b=KEEPTHIS==;\r\n"
            )
        )

    def test_selected_signature_b_span_and_no_final_crlf_are_exact(self):
        for canonicalization in (b"simple/simple", b"relaxed/relaxed"):
            raw = _message(
                c=canonicalization,
                h=b"from",
                b=b" \tAQ\r\n\t== \t",
                extra_tags=b"unknown=Keep:This; B=NotLowercase; ",
            )
            result = self.analyze(raw)
            row = result["selected_signature_contribution"]
            self.assertEqual(
                raw[row["b_removed_start"] : row["b_removed_end"]], b" \tAQ\r\n\t== \t"
            )
            selected = raw[: row["source_end"]]
            deleted = selected[: row["b_removed_start"]] + selected[row["b_removed_end"] :]
            if canonicalization == b"simple/simple":
                expected = b"From: sender@example.test\r\n" + deleted[:-2]
            else:
                expected_signature = re.sub(
                    rb"[ \t]+", b" ", deleted[len(b"DKIM-Signature:") : -2].replace(b"\r\n", b"")
                ).strip(b" \t")
                expected = b"from:sender@example.test\r\n" + b"dkim-signature:" + expected_signature
            actual = base64.b64decode(result["header_preimage_base64"])
            self.assertEqual(actual, expected)
            self.assertFalse(actual.endswith(b"\r\n"))
            self.assertFalse(row["trailing_crlf_in_preimage"])
            self.assertIn(b"unknown=Keep:This; B=NotLowercase; b=;", actual)

    def test_b_first_middle_last_and_surrounding_fws_do_not_rebuild_tags(self):
        raw = _message(c=b"simple/simple", h=b"from", b=b"AQ==", extra_tags=b"unknown=case:VALUE; ")
        value = raw[: raw.find(b"\r\n")]
        bpart = b"b=AQ==;"
        without = value.replace(bpart, b"", 1)
        variants = (
            without.replace(b"DKIM-Signature: ", b"DKIM-Signature: " + bpart + b" ", 1),
            without.replace(b"s=offline;", b"s=offline; " + bpart, 1),
            value,
        )
        for first in variants:
            supplied = first + raw[len(value) :]
            result = self.analyze(supplied)
            row = result["selected_signature_contribution"]
            selected = supplied[: row["source_end"]]
            expected = (
                b"From: sender@example.test\r\n"
                + (selected[: row["b_removed_start"]] + selected[row["b_removed_end"] :])[:-2]
            )
            self.assertEqual(base64.b64decode(result["header_preimage_base64"]), expected)

    def test_unknown_empty_case_distinct_tags_are_preserved(self):
        result = self.analyze(_message(extra_tags=b"unrecognized=; A=Opaque; B=NotSignature; "))
        self.assertEqual(result["analysis_status"], "arithmetic_computed")
        self.assertIn(
            b"unrecognized=; A=Opaque; B=NotSignature; b=;",
            base64.b64decode(result["header_preimage_base64"]),
        )
        self.assertIn("B", [tag["name"] for tag in result["selected_tag_observations"]])

    def test_l_zero_exact_and_oversized_coverage_are_not_clamped(self):
        body = b"ABC\r\n"
        for declared, expected, covered, state in (
            (0, b"", 0, "prefix"),
            (2, b"AB", 2, "prefix"),
            (5, body, 5, "full"),
            (6, None, None, "declared_length_exceeds_canonical_body"),
        ):
            result = self.analyze(_message(body, length=declared))
            observation = result["body_observation"]
            self.assertEqual(observation["coverage_state"], state)
            self.assertEqual(observation["covered_bytes"], covered)
            if expected is None:
                self.assertIsNone(observation["computed_body_sha256"])
                self.assertIsNone(observation["computed_body_hash_base64"])
                self.assertIsNone(observation["body_hash_matches_supplied_bh"])
                self.assertIn(
                    "declared_body_length_exceeds_canonical_body",
                    result["declared_arithmetic_violations"],
                )
            else:
                self.assertEqual(
                    observation["computed_body_hash_base64"],
                    base64.b64encode(hashlib.sha256(expected).digest()).decode("ascii"),
                )
                self.assertTrue(observation["body_hash_matches_supplied_bh"])

    def test_l_leading_zero_and_76_digit_oversize_are_bounded_text(self):
        raw = _message(b"ABC\r\n", length=0).replace(b"l=0;", b"l=00002;", 1)
        result = self.analyze(raw)
        self.assertEqual(result["body_observation"]["declared_l_decimal"], "00002")
        self.assertEqual(result["body_observation"]["covered_bytes"], 2)
        huge = _message(length=0).replace(b"l=0;", b"l=" + b"9" * 76 + b";", 1)
        self.assertIsNone(self.analyze(huge)["body_observation"]["computed_body_sha256"])
        with self.assertRaises(m.DkimCanonicalizationError):
            self.analyze(huge.replace(b"9" * 76, b"9" * 77, 1))

    def test_wrong_body_hash_is_known_false_without_rewriting_bh(self):
        given = base64.b64encode(b"X" * 32)
        result = self.analyze(_message(b"ABC", bh=given))
        self.assertFalse(result["body_observation"]["body_hash_matches_supplied_bh"])
        self.assertEqual(result["analysis_status"], "arithmetic_computed")
        self.assertIn("declared_body_hash_mismatch", result["declared_arithmetic_violations"])
        self.assertIn(b"bh=" + given, base64.b64decode(result["header_preimage_base64"]))

    def test_bh_fws_is_decoded_without_changing_original_preimage(self):
        given = RELAXED_EMPTY_HASH.encode("ascii")
        folded = given[:12] + b" \t\r\n\t" + given[12:]
        result = self.analyze(_message(bh=folded))
        self.assertTrue(result["body_observation"]["body_hash_matches_supplied_bh"])
        self.assertEqual(
            result["body_observation"]["supplied_bh_base64_without_fws"], RELAXED_EMPTY_HASH
        )
        self.assertIn(
            b"bh=" + given[:12] + b" " + given[12:],
            base64.b64decode(result["header_preimage_base64"]),
        )

    def test_unsupported_choices_never_force_bh_to_sha256(self):
        for changes in (
            {"a": b"rsa-sha1", "bh": base64.b64encode(b"X" * 20)},
            {"v": b"2"},
            {"c": b"unknown/relaxed"},
            {"c": b"simple/unknown"},
            {"a": b"RSA-SHA256"},
        ):
            with self.subTest(changes=changes):
                result = self.analyze(_message(**changes))
                self.assertEqual(result["analysis_status"], "arithmetic_unassessed")
                self.assertIsNone(result["header_preimage_base64"])
                self.assertIsNone(result["header_preimage_sha256"])
                self.assertIsNone(result["body_observation"]["canonical_bytes"])
                self.assertIsNone(result["body_observation"]["body_hash_matches_supplied_bh"])
                self.assertIsNone(
                    result["selected_signature_contribution"]["trailing_crlf_in_preimage"]
                )
                self.assertTrue(result["unassessed_reasons"])

    def test_identity_time_query_and_from_conformance_are_not_inferred(self):
        result = self.analyze(
            _message(
                h=b"missing",
                extra_tags=b"i=unrelated@example.invalid; t=999999999999; x=0; q=unknown/method; ",
            )
        )
        self.assertEqual(result["analysis_status"], "arithmetic_computed")
        self.assertTrue(all(value is False for value in result["flags"].values()))
        self.assertTrue(all(value == "none" for value in result["effects"].values()))

    def test_missing_duplicate_and_malformed_required_tag_grammar_refuses(self):
        raw = _message()
        controls = (
            raw.replace(b"v=1; ", b"", 1),
            raw.replace(b"v=1; ", b"v=1; v=1; ", 1),
            raw.replace(b"b=AQ==", b"b=", 1),
            raw.replace(b"c=relaxed/relaxed", b"c=", 1),
            raw.replace(b"a=rsa-sha256", b"a=sha256", 1),
            raw.replace(b"h=from:x-note:x-note:x-missing", b"h=from::x", 1),
            raw.replace(b"bh=" + RELAXED_EMPTY_HASH.encode("ascii"), b"bh=AQ==", 1),
            raw.replace(b"v=1; ", b"bad-name=x; v=1; ", 1),
            raw.replace(b"b=AQ==;", b"b=AQ==;;", 1),
        )
        for supplied in controls:
            with (
                self.subTest(supplied=supplied),
                self.assertRaises(m.DkimCanonicalizationError),
                mock.patch.object(m.hashlib, "sha256") as digest,
            ):
                self.analyze(supplied)
            digest.assert_not_called()

    def test_bare_newline_orphan_fold_nonascii_header_and_missing_separator_refuse(self):
        raw = _message()
        for supplied in (
            raw.replace(b"\r\n", b"\n", 1),
            raw + b"\r",
            raw + b"\n",
            b"\t" + raw,
            raw.replace(b"From: ", b"From: \xff", 1),
            raw.replace(b"\r\n\r\n", b"\r\n", 1),
            raw.replace(b"From:", b"From", 1),
        ):
            with (
                self.subTest(supplied=supplied),
                self.assertRaises(m.DkimCanonicalizationError),
                mock.patch.object(m.hashlib, "sha256") as digest,
            ):
                self.analyze(supplied)
            digest.assert_not_called()

    def test_selected_index_must_resolve_the_physical_signature(self):
        raw = _message()
        for index in (1, 4, 511):
            with self.subTest(index=index), self.assertRaises(m.DkimCanonicalizationError):
                self.analyze(model=_model(raw, index))
        shifted = b"X-First: first\r\n" + raw
        result = self.analyze(model=_model(shifted, 1))
        self.assertEqual(result["selected_signature_index"], 1)

    def test_source_native_aliases_fail_before_clone_or_digest(self):
        source = component_fixture()
        cases = [None, [], _Dictionary(source)]
        for key, value in (
            ("schema_version", True),
            ("schema_version", 1.0),
            ("schema_version", _Integer(1)),
            ("dkim_header_index", False),
            ("dkim_header_index", 0.0),
            ("source_id", _String("synthetic")),
            ("message_base64", _String(source["message_base64"])),
            ("message_base64", source["message_base64"].encode("ascii")),
        ):
            changed = source.copy()
            changed[key] = value
            cases.append(changed)
        changed = source.copy()
        changed["unknown"] = 1
        cases.append(changed)
        for value in cases:
            with (
                self.subTest(value=value),
                mock.patch.object(m, "_clone") as clone,
                mock.patch.object(m.hashlib, "sha256") as digest,
                self.assertRaises(m.DkimCanonicalizationError),
            ):
                self.analyze(model=value)
            clone.assert_not_called()
            digest.assert_not_called()

    def test_message_base64_is_exact_complete_and_canonical(self):
        source = component_fixture()
        for value in ("", "!!!!", source["message_base64"] + "\n", "DQo", "AQ===", "AR=="):
            changed = source.copy()
            changed["message_base64"] = value
            with (
                self.subTest(value=value),
                self.assertRaises(m.DkimCanonicalizationError),
                mock.patch.object(m.hashlib, "sha256") as digest,
            ):
                self.analyze(model=changed)
            digest.assert_not_called()

    def test_raw_duplicate_float_malformed_integer_and_escape_fail_without_hashes(self):
        text = _canonical(component_fixture())
        for token in ("true", "1.0", "--1", "---1", "+1", "01", "9223372036854775808"):
            raw = text.replace('"schema_version":1', '"schema_version":' + token).encode("ascii")
            with (
                self.subTest(token=token),
                self.assertRaises(m.DkimCanonicalizationError),
                mock.patch.object(m.hashlib, "sha256") as digest,
            ):
                m.analyze_supplied_dkim_canonicalization_bytes(model_bytes=raw)
            digest.assert_not_called()
        for raw in (
            text[:-1] + ',"schema_version":1}',
            text.replace("synthetic-dkim", "synthetic\\u0009dkim"),
            text.replace("synthetic-dkim", "synthetic\\ud800dkim"),
        ):
            with self.assertRaises(m.DkimCanonicalizationError):
                m.analyze_supplied_dkim_canonicalization_bytes(model_bytes=raw.encode("ascii"))

    def test_raw_scalar_inclusive_depth_nodes_and_bytes_precede_decoder(self):
        cases = (
            ("[" * m.MAX_DEPTH + "0" + "]" * m.MAX_DEPTH).encode("ascii"),
            ("[" + ",".join("0" for _ in range(m.MAX_MODEL_NODES)) + "]").encode("ascii"),
            b" " * (m.MAX_MODEL_BYTES + 1),
        )
        for raw in cases:
            with (
                self.subTest(size=len(raw)),
                mock.patch.object(m.json, "loads") as decoder,
                mock.patch.object(m.hashlib, "sha256") as digest,
                self.assertRaises(m.DkimCanonicalizationError),
            ):
                m.analyze_supplied_dkim_canonicalization_bytes(model_bytes=raw)
            decoder.assert_not_called()
            digest.assert_not_called()
        with (
            mock.patch.object(m, "MAX_WORK", 1),
            mock.patch.object(m, "_decode") as decode,
            self.assertRaises(m.DkimCanonicalizationError),
        ):
            m.analyze_supplied_dkim_canonicalization_bytes(
                model_bytes=_canonical(component_fixture()).encode("ascii")
            )
        decode.assert_not_called()

    def test_native_cycle_queue_depth_integer_and_string_costs_precede_clone(self):
        report = self.analyze()
        cyclic = copy.deepcopy(report)
        cyclic["unknown"] = cyclic
        deep = 0
        for _ in range(m.MAX_DEPTH):
            deep = [deep]
        cases = (
            cyclic,
            {"unknown": deep},
            {"unknown": [0] * m.MAX_REPORT_NODES},
            {"unknown": 2**63},
            {"unknown": "X" * (m.MAX_BASE64_BYTES + 5)},
        )
        for document in cases:
            with (
                mock.patch.object(m, "_clone") as clone,
                mock.patch.object(m.hashlib, "sha256") as digest,
                self.assertRaises(m.DkimCanonicalizationError),
            ):
                m.DkimCanonicalizationAnalysis.from_dict(document)
            clone.assert_not_called()
            digest.assert_not_called()

    def test_actual_line_body_line_field_selection_and_tag_caps(self):
        self.analyze(_message(b"X" * m.MAX_LINE_BYTES, h=b"from"))
        with self.assertRaises(m.DkimCanonicalizationError):
            self.analyze(_message(b"X" * (m.MAX_LINE_BYTES + 1), h=b"from"))
        self.analyze(_message(b"\r\n" * m.MAX_BODY_LINES, h=b"from"))
        with self.assertRaises(m.DkimCanonicalizationError):
            self.analyze(_message(b"\r\n" * (m.MAX_BODY_LINES + 1), h=b"from"))
        headers = tuple(b"X: x\r\n" for _ in range(m.MAX_HEADER_FIELDS - 1))
        self.analyze(_message(h=b"missing", headers=headers))
        with self.assertRaises(m.DkimCanonicalizationError):
            self.analyze(_message(h=b"missing", headers=headers + (b"X: x\r\n",)))
        self.analyze(_message(h=b":".join([b"missing"] * m.MAX_HEADER_SELECTIONS)))
        with self.assertRaises(m.DkimCanonicalizationError):
            self.analyze(_message(h=b":".join([b"missing"] * (m.MAX_HEADER_SELECTIONS + 1))))
        extras = b"".join(
            b"t" + str(index).encode("ascii") + b"=x; " for index in range(m.MAX_TAGS - 8)
        )
        self.analyze(_message(extra_tags=extras))
        with self.assertRaises(m.DkimCanonicalizationError):
            self.analyze(_message(extra_tags=extras + b"extra=x; "))

    def test_actual_message_and_header_byte_caps(self):
        raw = _message(h=b"from")
        capacity = m.MAX_MESSAGE_BYTES - len(raw)
        body = (b"X" * 4094 + b"\r\n") * (capacity // 4096) + b"X" * (capacity % 4096)
        self.assertEqual(len(raw + body), m.MAX_MESSAGE_BYTES)
        m.analyze_supplied_dkim_canonicalization(_model(raw + body))
        with self.assertRaises(m.DkimCanonicalizationError):
            m.analyze_supplied_dkim_canonicalization(_model(raw + body + b"X"))
        base = _message(h=b"from", headers=(b"From: x\r\n",))
        capacity = m.MAX_HEADER_BYTES - len(base)
        rows = []
        while capacity >= 6:
            width = min(4096, capacity)
            if 0 < capacity - width < 6:
                width -= 6 - (capacity - width)
            rows.append(b"X: " + b"A" * (width - 5) + b"\r\n")
            capacity -= width
        self.assertEqual(capacity, 0)
        message = base[:-2] + b"".join(rows) + b"\r\n"
        self.assertEqual(len(message), m.MAX_HEADER_BYTES)
        self.analyze(message)
        with self.assertRaises(m.DkimCanonicalizationError):
            self.analyze(message[:-2] + b"X: x\r\n\r\n")

    def test_full_constructor_parser_bytes_export_and_original_roundtrips(self):
        source = component_fixture()
        wrapper = m.analyze_supplied_dkim_canonicalization(source)
        text = wrapper.to_json()
        document = wrapper.to_dict()
        values = (
            m.DkimCanonicalizationAnalysis(text),
            m.DkimCanonicalizationAnalysis.from_dict(document),
            m.DkimCanonicalizationAnalysis.from_json(text),
            m.analyze_supplied_dkim_canonicalization_bytes(
                model_bytes=_canonical(source).encode("ascii")
            ),
            m.verify_supplied_dkim_canonicalization_analysis(wrapper, model=source),
        )
        for value in values:
            self.assertEqual(value.to_json(), text)
            self.assertEqual(value.to_dict(), document)

    def test_noncanonical_report_json_and_unknown_fields_are_denied(self):
        document = self.analyze()
        with self.assertRaises(m.DkimCanonicalizationError):
            m.DkimCanonicalizationAnalysis.from_json(json.dumps(document, indent=2))
        document["unknown"] = "unselected"
        with (
            mock.patch.object(m.hashlib, "sha256") as digest,
            self.assertRaises(m.DkimCanonicalizationError),
        ):
            m.DkimCanonicalizationAnalysis.from_dict(document)
        digest.assert_not_called()

    def test_report_native_counter_bool_and_family_aliases_precede_clone_and_digest(self):
        original = self.analyze()
        for path, value in (
            (("schema_version",), True),
            (("physical_header_fields",), 4.0),
            (("source_message_bytes",), True),
            (("flags", "signature_verified"), 0),
            (("body_observation", "body_hash_matches_supplied_bh"), 1),
            (("header_selection_observations", 0, "physical_header_index"), True),
            (("selected_signature_contribution", "trailing_crlf_in_preimage"), 0),
            (("bounds", "message_bytes"), float(m.MAX_MESSAGE_BYTES)),
            (("effects", "network"), _String("none")),
        ):
            document = copy.deepcopy(original)
            node = document
            for key in path[:-1]:
                node = node[key]
            node[path[-1]] = value
            with (
                self.subTest(path=path),
                mock.patch.object(m, "_clone") as clone,
                mock.patch.object(m.hashlib, "sha256") as digest,
                self.assertRaises(m.DkimCanonicalizationError),
            ):
                m.DkimCanonicalizationAnalysis.from_dict(document)
            clone.assert_not_called()
            digest.assert_not_called()

    def test_cohashed_false_preimage_body_hash_and_promotion_require_original_replay(self):
        original = self.analyze()
        changes = (
            lambda value: value.__setitem__(
                "header_preimage_base64", base64.b64encode(b"forged").decode("ascii")
            ),
            lambda value: value["body_observation"].__setitem__("canonical_body_base64", "WA=="),
            lambda value: value["body_observation"].__setitem__(
                "body_hash_matches_supplied_bh", False
            ),
            lambda value: value["header_selection_observations"][0].__setitem__(
                "physical_header_index", 2
            ),
            lambda value: value["selected_signature_contribution"].__setitem__(
                "b_removed_start", 1
            ),
            lambda value: value["flags"].__setitem__("signature_verified", True),
            lambda value: value["effects"].__setitem__("network", "allowed"),
            lambda value: value.__setitem__("source_message_sha256", "sha256:" + "a" * 64),
            lambda value: value.__setitem__("unassessed_reasons", ["invented"]),
        )
        for change in changes:
            document = copy.deepcopy(original)
            change(document)
            document = _readdress(document)
            with self.assertRaises(m.DkimCanonicalizationError):
                m.DkimCanonicalizationAnalysis.from_dict(document)
            with self.assertRaises(m.DkimCanonicalizationError):
                m.DkimCanonicalizationAnalysis.from_json(_canonical(document))

    def test_separate_original_replay_rejects_source_spelling_and_index_substitution(self):
        source = component_fixture()
        wrapper = m.analyze_supplied_dkim_canonicalization(source)
        changed = source.copy()
        changed["source_id"] = "different-source-label"
        with self.assertRaises(m.DkimCanonicalizationError):
            m.verify_supplied_dkim_canonicalization_analysis(wrapper, model=changed)
        raw = base64.b64decode(source["message_base64"]).replace(
            b"X-Note: older", b"X-NOTE: older", 1
        )
        another = _model(raw, source_id=source["source_id"])
        other = m.analyze_supplied_dkim_canonicalization(another)
        self.assertEqual(
            other.to_dict()["header_preimage_base64"], wrapper.to_dict()["header_preimage_base64"]
        )
        self.assertNotEqual(other.analysis_sha256, wrapper.analysis_sha256)
        with self.assertRaises(m.DkimCanonicalizationError):
            m.verify_supplied_dkim_canonicalization_analysis(other, model=source)
        changed["dkim_header_index"] = 1
        with self.assertRaises(m.DkimCanonicalizationError):
            m.verify_supplied_dkim_canonicalization_analysis(wrapper, model=changed)

    def test_source_and_export_are_detached_and_fixture_is_fresh(self):
        source = component_fixture()
        wrapper = m.analyze_supplied_dkim_canonicalization(source)
        before = wrapper.to_json()
        source["source_id"] = "mutated-after-entry"
        exported = wrapper.to_dict()
        exported["source_model"]["source_id"] = "mutated-export"
        exported["header_selection_observations"].clear()
        self.assertEqual(wrapper.to_json(), before)
        self.assertNotEqual(source, component_fixture())

    def test_late_native_wrapper_mutation_cannot_export_or_verify_a_false_report(self):
        wrapper = m.analyze_supplied_dkim_canonicalization(component_fixture())
        document = wrapper.to_dict()
        document["body_observation"]["body_hash_matches_supplied_bh"] = False
        object.__setattr__(wrapper, "document_json", _canonical(_readdress(document)))
        for operation in (
            wrapper.to_dict,
            wrapper.to_json,
            lambda: m.verify_supplied_dkim_canonicalization_analysis(
                wrapper, model=component_fixture()
            ),
        ):
            with self.assertRaises(m.DkimCanonicalizationError):
                operation()

    def test_forged_incomplete_and_subclass_wrappers_fail_closed(self):
        class Foreign(m.DkimCanonicalizationAnalysis):
            pass

        wrapper = m.analyze_supplied_dkim_canonicalization(component_fixture())
        for invalid in (
            None,
            {},
            object.__new__(m.DkimCanonicalizationAnalysis),
            object.__new__(Foreign),
        ):
            with self.assertRaises(m.DkimCanonicalizationError):
                m.verify_supplied_dkim_canonicalization_analysis(invalid, model=component_fixture())
        with self.assertRaises(m.DkimCanonicalizationError):
            Foreign(wrapper.to_json())

    def test_report_cap_is_reserved_before_retained_rows_and_any_digest(self):
        source = component_fixture()
        with (
            mock.patch.object(m, "MAX_REPORT_BYTES", 1),
            mock.patch.object(m.hashlib, "sha256") as digest,
            self.assertRaises(m.DkimCanonicalizationError),
        ):
            m.analyze_supplied_dkim_canonicalization(source)
        digest.assert_not_called()
        original = m._Retained.reserve
        reservations = []

        def reserve(instance, size, nodes, budget):
            reservations.append((size, nodes))
            return original(instance, size, nodes, budget)

        with mock.patch.object(m._Retained, "reserve", new=reserve):
            m.analyze_supplied_dkim_canonicalization(source)
        self.assertIn((640, 32), reservations)
        self.assertIn((384, 16), reservations)

    def test_all_eight_public_paths_fund_content_hashes_before_any_digest(self):
        source = component_fixture()
        wrapper = m.analyze_supplied_dkim_canonicalization(source)
        document = wrapper.to_dict()
        text = wrapper.to_json()
        encoded = _canonical(source).encode("ascii")
        bounds = m._bounds()
        operations = (
            lambda: m.analyze_supplied_dkim_canonicalization(source),
            lambda: m.analyze_supplied_dkim_canonicalization_bytes(model_bytes=encoded),
            lambda: m.DkimCanonicalizationAnalysis(text),
            lambda: m.DkimCanonicalizationAnalysis.from_dict(document),
            lambda: m.DkimCanonicalizationAnalysis.from_json(text),
            wrapper.to_dict,
            wrapper.to_json,
            lambda: m.verify_supplied_dkim_canonicalization_analysis(wrapper, model=source),
        )
        original_charge = m._Budget.charge
        for index, operation in enumerate(operations):
            budgets = []

            def charge(instance, amount, retained_budgets=budgets):
                original_charge(instance, amount)
                if not any(instance is old for old in retained_budgets):
                    retained_budgets.append(instance)

            with mock.patch.object(m._Budget, "charge", new=charge):
                operation()
            self.assertEqual(len(budgets), 1)
            required = budgets[0].used
            with (
                self.subTest(operation=index, boundary="exact"),
                mock.patch.object(m, "MAX_WORK", required),
                mock.patch.object(m, "_bounds", return_value=bounds),
                mock.patch.object(m.hashlib, "sha256", wraps=hashlib.sha256) as digest,
            ):
                operation()
                self.assertGreaterEqual(digest.call_count, 5)
            with (
                self.subTest(operation=index, boundary="minus-one"),
                mock.patch.object(m, "MAX_WORK", required - 1),
                mock.patch.object(m, "_bounds", return_value=bounds),
                mock.patch.object(m.hashlib, "sha256", wraps=hashlib.sha256) as digest,
                self.assertRaises(m.DkimCanonicalizationError),
            ):
                operation()
            digest.assert_not_called()

    def test_both_separate_original_plans_are_funded_before_either_hashes(self):
        source = component_fixture()
        wrapper = m.analyze_supplied_dkim_canonicalization(source)
        original = m._plan
        calls = []

        def plan(model, budget):
            calls.append(model["source_id"])
            if len(calls) == 2:
                raise m.DkimCanonicalizationError("Synthetic original prehash cost denial")
            return original(model, budget)

        with (
            mock.patch.object(m, "_plan", side_effect=plan),
            mock.patch.object(m.hashlib, "sha256") as digest,
            self.assertRaises(m.DkimCanonicalizationError),
        ):
            m.verify_supplied_dkim_canonicalization_analysis(wrapper, model=source)
        self.assertEqual(len(calls), 2)
        digest.assert_not_called()

    def test_exact_ownership_and_all_effects_remain_nonauthoritative(self):
        result = self.analyze()
        expected = {
            "component_id": "dkim_supplied_canonicalization_and_body_hash",
            "profile_id": "AOE-GC-D13-S14",
            "capability_id": "army.gc.d13.s14",
            "vector_id": "AV-GC-D13-S14-01",
            "work_package_id": "IWP2-AOE-GC-D13-S14",
            "wave_id": "IW2-017",
            "commander_id": "AOE-GC-D13-CMD",
            "group_owner_id": "AOE-HQ-05",
            "independent_validator_id": "AOE-HQ-19",
            "blueprint_sha256": (
                "sha256:6ede9269d562acfd25fa6e2c0dc197ad9fc5b4b450d03fb2f5f3e1c768803e3a"
            ),
        }
        for key, value in expected.items():
            self.assertEqual(result[key], value)
        self.assertTrue(all(value is False for value in result["flags"].values()))
        self.assertTrue(all(value == "none" for value in result["effects"].values()))
        self.assertNotEqual(m.MODEL_DOMAIN, m.DOMAIN)


if __name__ == "__main__":
    unittest.main()
