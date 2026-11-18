from __future__ import annotations

import itertools
import json
import re
import unittest
from unittest.mock import patch

from sunderkey.offline_specialist_components import (
    MAX_REQUEST_BYTES,
    OfflineSpecialistComponentError,
    _json_preflight,
    _parse,
)


def reference_preflight(text: str) -> None:
    """Character-walk reference for the preexisting bounded scanner language."""
    index = nodes = depth = 0
    while index < len(text):
        character = text[index]
        if character in " \t\r\n,:":
            index += 1
            continue
        if character in "[{":
            if depth > 80:
                raise OfflineSpecialistComponentError("JSON depth exceeds offline limits")
            depth += 1
            nodes += 1
            index += 1
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise OfflineSpecialistComponentError("JSON nesting is invalid")
            index += 1
        elif character == '"':
            index += 1
            while index < len(text):
                if text[index] == "\\":
                    index += 2
                elif text[index] == '"':
                    index += 1
                    break
                else:
                    index += 1
            else:
                raise OfflineSpecialistComponentError("JSON string is incomplete")
            after = index
            while after < len(text) and text[after] in " \t\r\n":
                after += 1
            if after >= len(text) or text[after] != ":":
                nodes += 1
                if depth > 80:
                    raise OfflineSpecialistComponentError("JSON depth exceeds offline limits")
        else:
            end = index
            while end < len(text) and text[end] not in ' \t\r\n,:]}[{"':
                end += 1
            if end - index > 21:
                raise OfflineSpecialistComponentError("JSON scalar token exceeds the input range")
            token = text[index:end]
            if not token:
                raise OfflineSpecialistComponentError("JSON scalar token is invalid")
            if token not in {"null", "true", "false"}:
                digits = token[1:] if token.startswith("-") else token
                if len(digits) > 20 or re.fullmatch(r"[0-9]+", digits) is None:
                    raise OfflineSpecialistComponentError(
                        "JSON scalar type or magnitude is invalid"
                    )
                if int(token).bit_length() > 64:
                    raise OfflineSpecialistComponentError("JSON integer exceeds the input range")
            nodes += 1
            if depth > 80:
                raise OfflineSpecialistComponentError("JSON depth exceeds offline limits")
            index = end
        if nodes > 200_000:
            raise OfflineSpecialistComponentError("JSON node count exceeds offline limits")
    if depth:
        raise OfflineSpecialistComponentError("JSON nesting is incomplete")


def disposition(scanner, text: str) -> tuple[bool, str | None]:
    try:
        scanner(text)
    except OfflineSpecialistComponentError as error:
        return False, str(error)
    return True, None


class OfflineComponentJsonScanningTests(unittest.TestCase):
    def assert_reference_equal(self, text: str) -> None:
        self.assertEqual(
            disposition(_json_preflight, text),
            disposition(reference_preflight, text),
            repr(text[:100]),
        )

    def test_exhaustive_small_quote_and_escape_strings_preserve_language(self) -> None:
        for length in range(7):
            for characters in itertools.product(("a", '"', "\\", "\n"), repeat=length):
                self.assert_reference_equal('"' + "".join(characters) + '"')

    def test_every_prefix_of_escaped_nested_json_preserves_language(self) -> None:
        text = json.dumps(
            {'quoted\\"key': ["[{,}:]", '\\\\"', "\u03bb", "\U0001f642", None, 12]},
            indent=2,
        )
        for end in range(len(text) + 1):
            self.assert_reference_equal(text[:end])

    def test_delimiter_and_non_ascii_runs_inside_strings_do_not_become_nodes(self) -> None:
        for value in ("[{:]}," * 40_000, "\u03bb" * 32_768, '"' * 16_384, "\\" * 16_384):
            self.assert_reference_equal(json.dumps({"value": value}, ensure_ascii=False))

    def test_escaped_backslash_parity_and_incomplete_strings_match_reference(self) -> None:
        for count in range(33):
            for suffix in ('"', '""', "\\", "", '\\u0041"', '\\"'):
                self.assert_reference_equal('"text' + "\\" * count + suffix)

    def test_original_depth_boundaries_preserve_empty_and_scalar_distinction(self) -> None:
        for depth in (79, 80, 81, 82):
            for middle in ("", "null", '"[{"', "18446744073709551615"):
                self.assert_reference_equal("[" * depth + middle + "]" * depth)

    def test_original_node_boundary_is_not_replaced_by_character_count(self) -> None:
        for count in (199_998, 199_999, 200_000):
            self.assert_reference_equal("[" + ",".join(["null"] * count) + "]")

    def test_scalar_lexical_boundaries_and_invalid_native_tokens_are_unchanged(self) -> None:
        for token in (
            "0",
            "-0",
            "00",
            "true",
            "false",
            "null",
            "1.0",
            "1e0",
            "NaN",
            "Infinity",
            "18446744073709551615",
            "-18446744073709551615",
            "18446744073709551616",
            "-18446744073709551616",
            "9" * 100,
            "+1",
            "-",
            "\u0661",
        ):
            self.assert_reference_equal(token)

    def test_rejected_costs_still_precede_json_decoder_and_serialization(self) -> None:
        for content in (
            b'["unterminated',
            b'["trailing\\',
            b"[" * 81 + b"null" + b"]" * 81,
            b"[" + b"null," * 200_000 + b"null]",
            b"18446744073709551616",
            b"1.0",
        ):
            with (
                patch(
                    "sunderkey.offline_specialist_components.loads_json_without_duplicate_keys"
                ) as decoder,
                patch("sunderkey.offline_specialist_components._canonical_json") as canonical,
                self.assertRaises(OfflineSpecialistComponentError),
            ):
                _parse(content, MAX_REQUEST_BYTES)
            decoder.assert_not_called()
            canonical.assert_not_called()

    def test_json_decoder_still_rejects_invalid_escapes_controls_and_duplicate_keys(self) -> None:
        for content in (b'"\\q"', b'"\\u00"', b'"\x01"', b'{"a":1,"a":2}', b"00"):
            with self.assertRaises(OfflineSpecialistComponentError):
                _parse(content, MAX_REQUEST_BYTES)

    def test_valid_utf8_and_canonical_escaping_still_reconstruct_original_values(self) -> None:
        values = [
            {"key": '\\"[{]}\n\t\u03bb\U0001f642'},
            {"empty": [], "nested": [{"null": None, "truth": False}]},
            (1 << 64) - 1,
            -((1 << 64) - 1),
        ]
        for value in values:
            for ascii_only in (False, True):
                content = json.dumps(value, ensure_ascii=ascii_only).encode("utf-8")
                self.assertEqual(_parse(content, MAX_REQUEST_BYTES), value)
