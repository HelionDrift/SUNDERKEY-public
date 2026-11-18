"""Inert supplied-octet framing fixtures, never transport or attack generation."""

import ast
import base64
import hashlib
import json
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from sunderkey import offline_http_request_framing as module
from sunderkey.offline_http_request_framing import (
    HttpRequestFramingAnalysis,
    HttpRequestFramingError,
    analyze_supplied_http_request_framing,
    verify_supplied_http_request_framing,
)

ROOT = Path(__file__).resolve().parents[2]
GET = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"
CHUNKED = (
    b"POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n"
    b"3\r\nabc\r\n0\r\n\r\n"
)


def synthetic_request_model():
    """Return only a supplied benign request for offline catalog examples."""
    return _model(GET)


def _model(raw):
    return {"schema_version": 1, "request_base64": base64.b64encode(raw).decode("ascii")}


def _report(raw):
    return analyze_supplied_http_request_framing(_model(raw))


def _codes(report, field="violations"):
    return {item["code"] for item in report.to_dict()[field]}


def _readdress(document):
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    canonical = json.dumps(body, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    digest = (
        "sha256:"
        + hashlib.sha256(
            module.DOMAIN.encode("ascii") + b"\n" + canonical.encode("ascii")
        ).hexdigest()
    )
    return {"analysis_id": "HFA-" + digest[7:39].upper(), "analysis_sha256": digest, **body}


class OfflineHttpRequestFramingTests(unittest.TestCase):
    def test_benign_get_has_exact_zero_body_and_header_offsets(self):
        report = _report(GET)
        body = report.to_dict()
        framing = body["framing"]
        self.assertEqual(body["supported_checks_outcome"], "pass")
        self.assertEqual(framing["request_line_end"], GET.index(b"\r\n"))
        self.assertEqual(framing["header_start"], len(b"GET / HTTP/1.1\r\n"))
        self.assertEqual(framing["header_end"], len(GET))
        self.assertEqual(framing["body_start"], len(GET))
        self.assertEqual(framing["body_end"], len(GET))
        self.assertIs(framing["body_complete"], True)
        self.assertEqual(framing["body_payload_bytes"], 0)
        self.assertEqual(framing["unconsumed_bytes"], 0)
        self.assertEqual(
            framing["headers"],
            [
                {
                    "index": 0,
                    "category": "host",
                    "line_start": 16,
                    "line_end": 34,
                    "value_start": 22,
                    "value_end": 34,
                }
            ],
        )
        self.assertEqual(
            body["source"]["request_sha256"], "sha256:" + hashlib.sha256(GET).hexdigest()
        )
        self.assertEqual(HttpRequestFramingAnalysis.from_dict(body).to_json(), report.to_json())
        self.assertEqual(HttpRequestFramingAnalysis.from_json(report.to_json()).to_dict(), body)
        self.assertEqual(
            verify_supplied_http_request_framing(report, model=_model(GET)).to_json(),
            report.to_json(),
        )

    def test_literal_benign_source_and_analysis_goldens(self):
        body = _report(GET).to_dict()
        self.assertEqual(
            body["source"]["model_sha256"],
            "sha256:249c02f0c71c3420b60762c31edf910da3ead028b4e74463d3238146f0f0d708",
        )
        self.assertEqual(
            body["source"]["request_sha256"],
            "sha256:4c978059238d24f3ada3dee6091310f96414fd74bf78da8dbd7640b1ba62f3b1",
        )
        self.assertEqual(body["analysis_id"], "HFA-F9D88272BF18AE254590CB551B0A1E02")
        self.assertEqual(
            body["analysis_sha256"],
            "sha256:f9d88272bf18ae254590cb551b0a1e0256271faa043b3ceca6c772da5355a780",
        )

    def test_content_length_bodies_are_octets_not_decoded_text(self):
        for content in (b"abc", b"\x00\xff\r\n", b"", b"a\nb\rc"):
            with self.subTest(content=content):
                prefix = b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: "
                raw = prefix + str(len(content)).encode("ascii") + b"\r\n\r\n" + content
                report = _report(raw)
                framing = report.to_dict()["framing"]
                self.assertEqual(report.to_dict()["supported_checks_outcome"], "pass")
                self.assertEqual(framing["body_framing"], "content_length")
                self.assertEqual(framing["body_start"], len(raw) - len(content))
                self.assertEqual(framing["body_end"], len(raw))
                self.assertEqual(framing["body_payload_bytes"], len(content))

    def test_identical_content_length_repetitions_warn_without_false_conflict(self):
        for fields in (
            b"Content-Length: 3\r\nContent-Length: 03\r\n",
            b"Content-Length: 3, 3\r\n",
            b"cOnTeNt-LeNgTh: \t3,\t003 \t\r\n",
        ):
            with self.subTest(fields=fields):
                report = _report(b"POST / HTTP/1.1\r\nHost: example.test\r\n" + fields + b"\r\nabc")
                self.assertEqual(report.to_dict()["violations"], [])
                self.assertEqual(report.to_dict()["supported_checks_outcome"], "warnings")
                self.assertEqual(_codes(report, "warnings"), {"content_length_repetition"})
                self.assertEqual(report.to_dict()["framing"]["content_length_values"], [3, 3])
                self.assertTrue(report.to_dict()["framing"]["body_complete"])

    def test_conflicting_content_length_cannot_claim_a_complete_body(self):
        for fields in (b"Content-Length: 3, 4\r\n", b"Content-Length: 3\r\nContent-Length: 4\r\n"):
            with self.subTest(fields=fields):
                report = _report(b"POST / HTTP/1.1\r\nHost: example.test\r\n" + fields + b"\r\nabc")
                self.assertIn("content_length_conflicting", _codes(report))
                self.assertFalse(report.to_dict()["framing"]["body_complete"])
                self.assertIsNone(report.to_dict()["framing"]["body_end"])

    def test_invalid_decimal_content_length_is_not_python_integer_coercion(self):
        for value in (b"+3", b"-3", b"0x3", b"3.0", b"3 0", b"three", b"\xff"):
            with self.subTest(value=value):
                report = _report(
                    b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: "
                    + value
                    + b"\r\n\r\nabc"
                )
                self.assertIn("content_length_invalid", _codes(report))
                self.assertFalse(report.to_dict()["framing"]["body_complete"])

    def test_empty_content_length_list_is_outside_the_declared_subset(self):
        for value in (b"", b",3", b"3,,3", b"3,"):
            with self.subTest(value=value):
                report = _report(
                    b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: "
                    + value
                    + b"\r\n\r\nabc"
                )
                self.assertIn(
                    "content_length_list_outside_subset", _codes(report, "incomplete_reasons")
                )
                self.assertFalse(report.to_dict()["framing"]["body_complete"])

    def test_huge_declared_numbers_are_bounded_without_inventing_an_http_limit(self):
        for raw in (
            b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 9223372036854775808\r\n\r\n",
            CHUNKED[: CHUNKED.index(b"3\r\nabc")] + b"8000000000000000\r\n",
        ):
            with self.subTest(raw=raw):
                report = _report(raw)
                self.assertIn("numeric_size_outside_subset", _codes(report, "incomplete_reasons"))
                self.assertEqual(report.to_dict()["violations"], [])
                self.assertFalse(report.to_dict()["framing"]["body_complete"])
        raw = (
            b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: "
            + b"0" * 8000
            + b"3\r\n\r\nabc"
        )
        report = _report(raw)
        self.assertEqual(report.to_dict()["supported_checks_outcome"], "pass")
        self.assertEqual(report.to_dict()["framing"]["content_length_values"], [3])

    def test_content_length_truncation_and_unparsed_suffix_are_separate(self):
        prefix = b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 3\r\n\r\n"
        truncated = _report(prefix + b"ab")
        self.assertIn("content_length_body_incomplete", _codes(truncated, "incomplete_reasons"))
        self.assertFalse(truncated.to_dict()["framing"]["body_complete"])
        suffix = _report(prefix + b"abcXYZ")
        self.assertEqual(suffix.to_dict()["framing"]["body_end"], len(prefix) + 3)
        self.assertEqual(suffix.to_dict()["framing"]["unconsumed_bytes"], 3)
        self.assertEqual(_codes(suffix, "warnings"), {"unconsumed_suffix_not_parsed"})
        self.assertIs(suffix.to_dict()["server_vulnerability_proven"], False)

    def test_unframed_request_ends_at_headers_not_end_of_supplied_bytes(self):
        report = _report(GET + b"inert remaining octets")
        framing = report.to_dict()["framing"]
        self.assertEqual(framing["body_framing"], "none")
        self.assertEqual(framing["body_end"], len(GET))
        self.assertEqual(framing["body_payload_bytes"], 0)
        self.assertEqual(framing["unconsumed_bytes"], len(b"inert remaining octets"))

    def test_chunked_request_has_exact_data_and_terminal_offsets(self):
        report = _report(CHUNKED)
        framing = report.to_dict()["framing"]
        start = CHUNKED.index(b"3\r\nabc")
        self.assertEqual(report.to_dict()["supported_checks_outcome"], "pass")
        self.assertEqual(framing["body_payload_bytes"], 3)
        self.assertEqual(framing["body_start"], start)
        self.assertEqual(framing["body_end"], len(CHUNKED))
        self.assertEqual(
            framing["chunks"],
            [
                {
                    "index": 0,
                    "line_start": start,
                    "line_end": start + 1,
                    "data_start": start + 3,
                    "data_end": start + 6,
                    "ending_end": start + 8,
                    "size": 3,
                    "is_last": False,
                },
                {
                    "index": 1,
                    "line_start": start + 8,
                    "line_end": start + 9,
                    "data_start": start + 11,
                    "data_end": start + 11,
                    "ending_end": start + 11,
                    "size": 0,
                    "is_last": True,
                },
            ],
        )

    def test_chunk_sizes_count_binary_octets_and_leading_zero_is_supported(self):
        prefix = CHUNKED[: CHUNKED.index(b"3\r\nabc")]
        raw = prefix + b"04\r\n\x00\r\n\xff\r\n00\r\n\r\n"
        report = _report(raw)
        self.assertEqual(report.to_dict()["supported_checks_outcome"], "pass")
        self.assertEqual(report.to_dict()["framing"]["body_payload_bytes"], 4)
        self.assertEqual([item["size"] for item in report.to_dict()["framing"]["chunks"]], [4, 0])

    def test_chunked_transfer_encoding_takes_framing_precedence_but_conflict_warns(self):
        raw = CHUNKED.replace(
            b"Transfer-Encoding: chunked", b"Content-Length: 999\r\nTransfer-Encoding: cHuNkEd"
        )
        report = _report(raw)
        self.assertEqual(report.to_dict()["supported_checks_outcome"], "warnings")
        self.assertEqual(_codes(report, "warnings"), {"content_length_with_transfer_encoding"})
        self.assertEqual(report.to_dict()["framing"]["body_framing"], "chunked")
        self.assertEqual(report.to_dict()["framing"]["body_end"], len(raw))
        self.assertEqual(report.to_dict()["framing"]["body_payload_bytes"], 3)
        self.assertFalse(report.to_dict()["server_vulnerability_proven"])

    def test_repeated_nonfinal_parameterized_or_empty_chunked_is_not_accepted(self):
        for value, code in (
            (b"chunked, chunked", "chunked_repeated"),
            (b"chunked, gzip", "chunked_not_final"),
            (b"gzip", "chunked_not_final"),
            (b"chunked; q=1", "chunked_parameters"),
            (b"", "transfer_coding_empty"),
            (b"chunked,", "transfer_coding_empty"),
            (b"chun ked", "transfer_coding_invalid"),
        ):
            with self.subTest(value=value):
                report = _report(
                    CHUNKED.replace(b"Transfer-Encoding: chunked", b"Transfer-Encoding: " + value)
                )
                self.assertIn(code, _codes(report))
                self.assertFalse(report.to_dict()["framing"]["body_complete"])

    def test_other_codings_are_incomplete_even_with_a_known_chunk_boundary(self):
        raw = CHUNKED.replace(b"Transfer-Encoding: chunked", b"Transfer-Encoding: gzip, chunked")
        report = _report(raw)
        self.assertEqual(report.to_dict()["supported_checks_outcome"], "incomplete")
        self.assertIn("unsupported_transfer_coding", _codes(report, "incomplete_reasons"))
        self.assertEqual(report.to_dict()["framing"]["transfer_codings"], ["other", "chunked"])
        self.assertTrue(report.to_dict()["framing"]["body_complete"])
        self.assertEqual(report.to_dict()["framing"]["body_payload_bytes"], 3)

    def test_quoted_transfer_parameter_commas_and_escapes_are_not_coding_separators(self):
        for coding in (
            b'gzip; note="ab", chunked',
            b'gzip; note="a,b", chunked',
            b'gzip; note="a\\"b,c", chunked',
            b'gzip; note="a\\\\,b", chunked',
            b'gzip; note="a,b"; another="c,d", chunked',
        ):
            with self.subTest(coding=coding):
                raw = (
                    b"POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: "
                    + coding
                    + b"\r\n\r\n0\r\n\r\n"
                )
                report = _report(raw)
                body = report.to_dict()
                self.assertEqual(body["supported_checks_outcome"], "incomplete")
                self.assertEqual(body["violations"], [])
                self.assertEqual(
                    _codes(report, "incomplete_reasons"), {"unsupported_transfer_coding"}
                )
                self.assertEqual(body["framing"]["transfer_codings"], ["other", "chunked"])
                self.assertIs(body["framing"]["body_complete"], True)
                self.assertEqual(body["framing"]["body_end"], len(raw))
                self.assertEqual(body["framing"]["body_payload_bytes"], 0)
                self.assertEqual(
                    verify_supplied_http_request_framing(report, model=_model(raw)).to_json(),
                    report.to_json(),
                )

    def test_unterminated_transfer_parameter_quotes_remain_conservatively_incomplete(self):
        for coding in (
            b'gzip; note="a,b, chunked',
            b'gzip; note="a,b\\',
        ):
            with self.subTest(coding=coding):
                report = _report(
                    CHUNKED.replace(b"Transfer-Encoding: chunked", b"Transfer-Encoding: " + coding)
                )
                self.assertEqual(report.to_dict()["supported_checks_outcome"], "incomplete")
                self.assertEqual(report.to_dict()["violations"], [])
                self.assertIn(
                    "transfer_parameters_outside_subset", _codes(report, "incomplete_reasons")
                )
                self.assertFalse(report.to_dict()["framing"]["body_complete"])

    def test_quoted_transfer_parameters_preserve_entry_line_and_field_boundaries(self):
        for count in (module.MAX_CODINGS, module.MAX_CODINGS + 1):
            coding = b", ".join([b'gzip; note="a,b"'] * (count - 1) + [b"chunked"])
            raw = CHUNKED.replace(b"Transfer-Encoding: chunked", b"Transfer-Encoding: " + coding)
            report = _report(raw)
            if count == module.MAX_CODINGS:
                self.assertEqual(len(report.to_dict()["framing"]["transfer_codings"]), count)
                self.assertTrue(report.to_dict()["framing"]["body_complete"])
                self.assertEqual(report.to_dict()["violations"], [])
            else:
                self.assertIn(
                    "transfer_coding_count_outside_subset", _codes(report, "incomplete_reasons")
                )
                self.assertFalse(report.to_dict()["framing"]["body_complete"])
        prefix, suffix = b'Transfer-Encoding: gzip; note="', b'", chunked'
        coding_line = prefix + b"," * (module.MAX_LINE_BYTES - len(prefix) - len(suffix)) + suffix
        for extra, complete in ((b"", True), (b",", False)):
            raw = CHUNKED.replace(b"Transfer-Encoding: chunked", coding_line + extra)
            report = _report(raw)
            self.assertEqual(report.to_dict()["framing"]["body_complete"], complete)
            if not complete:
                self.assertIn("line_length_outside_subset", _codes(report, "incomplete_reasons"))
        raw = CHUNKED.replace(
            b"Transfer-Encoding: chunked",
            b'Transfer-Encoding: gzip; note="a,b"\r\nTransfer-Encoding: chunked',
        )
        report = _report(raw)
        self.assertEqual(report.to_dict()["framing"]["transfer_codings"], ["other", "chunked"])
        self.assertTrue(report.to_dict()["framing"]["body_complete"])
        self.assertEqual(report.to_dict()["violations"], [])

    def test_chunk_extensions_are_explicitly_unsupported_not_invented_invalid_syntax(self):
        raw = CHUNKED.replace(b"3\r\nabc", b'3; note="inert"\r\nabc')
        report = _report(raw)
        self.assertEqual(report.to_dict()["violations"], [])
        self.assertIn("chunk_extensions_outside_subset", _codes(report, "incomplete_reasons"))
        self.assertFalse(report.to_dict()["framing"]["body_complete"])

    def test_invalid_hex_chunk_size_and_wrong_data_crlf_are_adverse(self):
        for suffix, code in (
            (b"+3\r\nabc\r\n0\r\n\r\n", "chunk_size_invalid"),
            (b"0x3\r\nabc\r\n0\r\n\r\n", "chunk_size_invalid"),
            (b"3 \r\nabc\r\n0\r\n\r\n", "chunk_size_invalid"),
            (b"3\r\nabcXX0\r\n\r\n", "chunk_data_terminator_invalid"),
        ):
            with self.subTest(code=code, suffix=suffix):
                report = _report(CHUNKED[: CHUNKED.index(b"3\r\nabc")] + suffix)
                self.assertIn(code, _codes(report))
                self.assertFalse(report.to_dict()["framing"]["body_complete"])

    def test_every_chunked_truncation_cannot_claim_complete_body(self):
        for end in range(len(CHUNKED)):
            with self.subTest(end=end):
                if not end:
                    with self.assertRaises(HttpRequestFramingError):
                        _report(CHUNKED[:end])
                    continue
                report = _report(CHUNKED[:end])
                self.assertFalse(report.to_dict()["framing"]["body_complete"])
                self.assertIsNone(report.to_dict()["framing"]["body_end"])

    def test_trailer_offsets_are_separate_and_no_trailer_value_is_emitted(self):
        raw = CHUNKED[:-2] + b"X-Note: synthetic-private-value\r\n\r\n"
        report = _report(raw)
        framing = report.to_dict()["framing"]
        self.assertTrue(framing["body_complete"])
        self.assertEqual(framing["body_end"], len(raw))
        self.assertEqual(framing["body_payload_bytes"], 3)
        self.assertEqual(len(framing["headers"]), 2)
        self.assertEqual(len(framing["trailers"]), 1)
        self.assertEqual(framing["trailers"][0]["line_start"], len(CHUNKED) - 2)
        self.assertIn("trailer_field_semantics_unverified", _codes(report, "warnings"))
        self.assertNotIn("synthetic-private-value", report.to_json())

    def test_known_framing_routing_and_authentication_trailers_do_not_rewrite_headers(self):
        for name in (
            b"Content-Length",
            b"Transfer-Encoding",
            b"Host",
            b"Authorization",
            b"Cookie",
            b"Content-Type",
        ):
            with self.subTest(name=name):
                report = _report(CHUNKED[:-2] + name + b": inert\r\n\r\n")
                self.assertIn("forbidden_trailer_field", _codes(report))
                self.assertEqual(report.to_dict()["framing"]["content_length_values"], [])
                self.assertEqual(report.to_dict()["framing"]["transfer_codings"], ["chunked"])

    def test_strict_crlf_profile_does_not_scan_binary_body_as_protocol_lines(self):
        for raw in (
            GET.replace(b"\r\n", b"\n"),
            GET.replace(b"Host:", b"X: one\rHost:"),
        ):
            with self.subTest(raw=raw):
                report = _report(raw)
                entries = report.to_dict()["violations"]
                self.assertIn("line_ending_not_crlf", _codes(report))
                self.assertEqual(entries[0]["basis"], "strict_profile")
        raw = b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 3\r\n\r\n\n\r\x00"
        self.assertEqual(_report(raw).to_dict()["supported_checks_outcome"], "pass")

    def test_obs_fold_bad_colon_and_control_octets_have_structural_ranges(self):
        for field, code in (
            (b" folded: value", "obsolete_line_folding"),
            (b"\tfolded: value", "obsolete_line_folding"),
            (b"Host : value", "whitespace_before_colon"),
            (b"Host\t: value", "whitespace_before_colon"),
            (b"Bad/Name: value", "header_line_invalid"),
            (b"missing colon", "header_line_invalid"),
            (b"X: \x01value", "field_value_control_octet"),
        ):
            with self.subTest(code=code, field=field):
                raw = b"GET / HTTP/1.1\r\n" + field + b"\r\n\r\n"
                report = _report(raw)
                self.assertIn(code, _codes(report))
                self.assertEqual(report.to_dict()["violations"][0]["start"], 16)
        self.assertEqual(
            _report(GET[:-2] + b"X: \xff\t\r\n\r\n").to_dict()["supported_checks_outcome"], "pass"
        )

    def test_http11_host_count_and_empty_host_are_structural_checks_not_dns(self):
        for raw, code in (
            (b"GET / HTTP/1.1\r\n\r\n", "host_field_count_invalid"),
            (GET[:-2] + b"hOsT: other.test\r\n\r\n", "host_field_count_invalid"),
            (b"GET / HTTP/1.1\r\nHost: \t\r\n\r\n", "host_field_empty"),
        ):
            with self.subTest(raw=raw):
                self.assertIn(code, _codes(_report(raw)))

    def test_other_versions_targets_and_transitions_remain_explicitly_incomplete(self):
        for raw, code in (
            (GET.replace(b"HTTP/1.1", b"HTTP/1.0"), "http_version_outside_subset"),
            (
                GET.replace(b"GET / ", b"GET https://example.test/ "),
                "request_target_outside_subset",
            ),
            (GET.replace(b"GET / ", b"OPTIONS * "), "request_target_outside_subset"),
            (
                GET.replace(b"GET / ", b"CONNECT example.test:443 "),
                "protocol_transition_outside_subset",
            ),
            (GET[:-2] + b"Upgrade: synthetic\r\n\r\n", "protocol_transition_outside_subset"),
        ):
            with self.subTest(code=code):
                report = _report(raw)
                self.assertIn(code, _codes(report, "incomplete_reasons"))
                self.assertFalse(report.to_dict()["server_vulnerability_proven"])
        for raw in (GET.replace(b"GET / ", b"GET  / "), GET.replace(b"GET / ", b"GET\t/ ")):
            self.assertIn("request_line_invalid", _codes(_report(raw)))

    def test_line_header_field_coding_chunk_and_trailer_costs_are_explicit(self):
        cases = (
            (
                b"GET /" + b"x" * module.MAX_LINE_BYTES + b" HTTP/1.1\r\n\r\n",
                "line_length_outside_subset",
            ),
            (GET[:-2] + (b"X: a\r\n" * module.MAX_HEADERS) + b"\r\n", "field_count_outside_subset"),
            (
                GET[:-2] + ((b"X: " + b"a" * 8000 + b"\r\n") * 9) + b"\r\n",
                "header_bytes_outside_subset",
            ),
            (
                GET[:-2] + b"Content-Length: " + b"3," * module.MAX_LENGTH_VALUES + b"3\r\n\r\nabc",
                "content_length_count_outside_subset",
            ),
            (
                CHUNKED.replace(
                    b"Transfer-Encoding: chunked",
                    b"Transfer-Encoding: " + b"gzip," * module.MAX_CODINGS + b"chunked",
                ),
                "transfer_coding_count_outside_subset",
            ),
            (
                CHUNKED[: CHUNKED.index(b"3\r\nabc")]
                + b"1\r\na\r\n" * module.MAX_CHUNKS
                + b"0\r\n\r\n",
                "chunk_count_outside_subset",
            ),
            (
                CHUNKED[:-2] + b"X: a\r\n" * (module.MAX_TRAILERS + 1) + b"\r\n",
                "field_count_outside_subset",
            ),
        )
        for raw, code in cases:
            with self.subTest(code=code):
                self.assertIn(code, _codes(_report(raw), "incomplete_reasons"))

    def test_maximum_supported_chunk_metadata_fits_the_native_document_bounds(self):
        raw = (
            CHUNKED[: CHUNKED.index(b"3\r\nabc")]
            + b"1\r\na\r\n" * (module.MAX_CHUNKS - 1)
            + b"0\r\n\r\n"
        )
        report = _report(raw)
        self.assertEqual(report.to_dict()["supported_checks_outcome"], "pass")
        self.assertEqual(len(report.to_dict()["framing"]["chunks"]), module.MAX_CHUNKS)
        self.assertEqual(report.to_dict()["framing"]["body_payload_bytes"], module.MAX_CHUNKS - 1)
        self.assertLess(len(report.to_json()), module.MAX_DOCUMENT_BYTES)

    def test_content_length_boundary_matches_a_finite_independent_octet_oracle(self):
        for declared in range(17):
            prefix = (
                b"POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: "
                + str(declared).encode("ascii")
                + b"\r\n\r\n"
            )
            for supplied in range(20):
                with self.subTest(declared=declared, supplied=supplied):
                    framing = _report(prefix + b"x" * supplied).to_dict()["framing"]
                    self.assertIs(framing["body_complete"], supplied >= declared)
                    if supplied >= declared:
                        self.assertEqual(framing["body_end"], len(prefix) + declared)
                        self.assertEqual(framing["body_payload_bytes"], declared)
                        self.assertEqual(framing["unconsumed_bytes"], supplied - declared)
                    else:
                        self.assertIsNone(framing["body_end"])
                        self.assertIsNone(framing["body_payload_bytes"])
                        self.assertIsNone(framing["unconsumed_bytes"])

    def test_exact_line_and_source_byte_ceilings_keep_their_positive_boundaries(self):
        field = b"X: " + b"a" * (module.MAX_LINE_BYTES - 3)
        supported = GET[:-2] + field + b"\r\n\r\n"
        self.assertEqual(_report(supported).to_dict()["supported_checks_outcome"], "pass")
        unsupported = GET[:-2] + field + b"a\r\n\r\n"
        self.assertIn(
            "line_length_outside_subset", _codes(_report(unsupported), "incomplete_reasons")
        )
        maximum = GET + b"a" * (module.MAX_REQUEST_BYTES - len(GET))
        report = _report(maximum)
        self.assertEqual(report.to_dict()["source"]["byte_count"], module.MAX_REQUEST_BYTES)
        self.assertEqual(report.to_dict()["framing"]["body_end"], len(GET))
        self.assertEqual(report.to_dict()["framing"]["unconsumed_bytes"], len(maximum) - len(GET))

    def test_rehashed_metadata_cannot_change_native_bounds_or_field_framing_joins(self):
        original = _report(GET).to_dict()
        for field in original["bounds"]:
            for value in (True, float(original["bounds"][field])):
                with self.subTest(field=field, value=value):
                    changed = deepcopy(original)
                    changed["bounds"][field] = value
                    with self.assertRaises(HttpRequestFramingError):
                        HttpRequestFramingAnalysis.from_dict(_readdress(changed))
        changed = deepcopy(original)
        changed["framing"].update(body_framing="content_length", content_length_values=[0])
        with self.assertRaises(HttpRequestFramingError):
            HttpRequestFramingAnalysis.from_dict(_readdress(changed))
        changed = _report(CHUNKED).to_dict()
        changed["framing"]["headers"][1]["category"] = "other"
        with self.assertRaises(HttpRequestFramingError):
            HttpRequestFramingAnalysis.from_dict(_readdress(changed))
        changed = _report(CHUNKED).to_dict()
        changed["framing"]["transfer_codings"] = ["chunked", "chunked"]
        with self.assertRaises(HttpRequestFramingError):
            HttpRequestFramingAnalysis.from_dict(_readdress(changed))

    def test_source_base64_size_and_canonicality_fail_before_parser_or_hash(self):
        class Text(str):
            pass

        for value in (
            "",
            "!!!!",
            "AB==",
            base64.b64encode(GET).decode("ascii") + "\n",
            Text(base64.b64encode(GET).decode("ascii")),
            base64.b64encode(b"a" * (module.MAX_REQUEST_BYTES + 1)).decode("ascii"),
        ):
            with (
                self.subTest(size=len(value)),
                patch.object(module._Parser, "parse", side_effect=AssertionError("parser reached")),
                patch.object(module, "_sha", side_effect=AssertionError("hash reached")),
                self.assertRaises(HttpRequestFramingError),
            ):
                analyze_supplied_http_request_framing(
                    {"schema_version": 1, "request_base64": value}
                )

    def test_exact_native_model_and_aggregate_cost_guards_precede_serialization(self):
        class Integer(int):
            pass

        class Object(dict):
            pass

        model = _model(GET)
        graph = [0]
        for _ in range(7):
            graph = [graph] * 10
        deep = 0
        for _ in range(module.MAX_DEPTH + 2):
            deep = [deep]
        cycle = []
        cycle.append(cycle)
        cases = [{**model, "schema_version": value} for value in (True, 1.0, "1", Integer(1))] + [
            Object(model),
            {**model, "unknown": None},
            {**model, "request_base64": GET},
            {"bad": graph},
            {"bad": deep},
            {"bad": cycle},
            {"bad": 2**1_000_000},
            {"bad": ['\\"' * 100_000] * 4},
        ]
        for candidate in cases:
            with (
                self.subTest(kind=type(candidate).__name__),
                patch.object(
                    module, "_canonical", side_effect=AssertionError("serialization reached")
                ),
                patch.object(module, "_sha", side_effect=AssertionError("hash reached")),
                self.assertRaises(HttpRequestFramingError),
            ):
                analyze_supplied_http_request_framing(candidate)

    def test_input_and_output_are_detached_from_owned_wrapper(self):
        model = _model(GET)
        report = analyze_supplied_http_request_framing(model)
        golden = report.to_json()
        model["request_base64"] = "bad"
        returned = report.to_dict()
        returned["framing"]["headers"].clear()
        returned["effects"]["authority"] = "approved"
        self.assertEqual(report.to_json(), golden)
        self.assertEqual(
            verify_supplied_http_request_framing(report, model=_model(GET)).to_json(), golden
        )

    def test_source_replay_rejects_separately_valid_changed_sources(self):
        original = _report(GET)
        changed_bytes = GET.replace(b"example.test", b"another.test")
        changed = _report(changed_bytes)
        self.assertEqual(changed.to_dict()["supported_checks_outcome"], "pass")
        self.assertNotEqual(changed.to_json(), original.to_json())
        with self.assertRaises(HttpRequestFramingError):
            verify_supplied_http_request_framing(original, model=_model(changed_bytes))
        with self.assertRaises(HttpRequestFramingError):
            verify_supplied_http_request_framing(changed, model=_model(GET))

    def test_cohashed_metadata_is_not_original_byte_source_verification(self):
        document = _report(GET).to_dict()
        document["source"]["request_sha256"] = "sha256:" + "ab" * 32
        declared = HttpRequestFramingAnalysis.from_dict(_readdress(document))
        self.assertFalse(declared.to_dict()["server_vulnerability_proven"])
        with self.assertRaises(HttpRequestFramingError):
            verify_supplied_http_request_framing(declared, model=_model(GET))

    def test_cohashed_promotions_native_aliases_and_broken_ranges_fail_closed(self):
        original = _report(GET).to_dict()
        for field, value in (
            ("schema_version", True),
            ("schema_version", 1.0),
            ("offline_only", 1),
            ("server_vulnerability_proven", True),
            ("live_use_approved", True),
            ("qualification_claimed", True),
            ("effects", {**original["effects"], "target": "active"}),
        ):
            with self.subTest(field=field), self.assertRaises(HttpRequestFramingError):
                HttpRequestFramingAnalysis.from_dict(_readdress({**original, field: value}))
        for field, value in (
            ("body_complete", 1),
            ("body_start", True),
            ("body_end", 0),
            ("unconsumed_bytes", 1),
            ("body_payload_bytes", 1.0),
        ):
            with self.subTest(field=field):
                changed = deepcopy(original)
                changed["framing"][field] = value
                with self.assertRaises(HttpRequestFramingError):
                    HttpRequestFramingAnalysis.from_dict(_readdress(changed))
        for field, value in (
            ("index", False),
            ("line_start", 0),
            ("value_start", 0),
            ("category", {"other": True}),
        ):
            with self.subTest(field=field):
                changed = deepcopy(original)
                changed["framing"]["headers"][0][field] = value
                with self.assertRaises(HttpRequestFramingError):
                    HttpRequestFramingAnalysis.from_dict(_readdress(changed))
        for field, value in (("is_last", 0), ("ending_end", 0), ("size", 3.0), ("index", True)):
            with self.subTest(field=field):
                changed = _report(CHUNKED).to_dict()
                changed["framing"]["chunks"][0][field] = value
                with self.assertRaises(HttpRequestFramingError):
                    HttpRequestFramingAnalysis.from_dict(_readdress(changed))

    def test_report_parser_duplicate_unknown_float_depth_and_bounded_input_denials(self):
        report = _report(GET)
        for text in (
            report.to_json().replace('"schema_version":1', '"schema_version":1,"schema_version":1'),
            report.to_json().replace('"schema_version":1', '"schema_version":1.0'),
            "[" * 14 + "0" + "]" * 14,
            "x" * (module.MAX_DOCUMENT_BYTES + 1),
        ):
            with self.subTest(size=len(text)), self.assertRaises(HttpRequestFramingError):
                HttpRequestFramingAnalysis.from_json(text)
        document = report.to_dict()
        document["unknown"] = None
        with self.assertRaises(HttpRequestFramingError):
            HttpRequestFramingAnalysis.from_dict(_readdress(document))

    def test_forged_incomplete_and_subclass_wrappers_do_not_gain_source_verification(self):
        incomplete = object.__new__(HttpRequestFramingAnalysis)
        with self.assertRaises(HttpRequestFramingError):
            verify_supplied_http_request_framing(incomplete, model=_model(GET))
        report = _report(GET)
        object.__setattr__(report, "document_json", {"foreign": "value"})
        with self.assertRaises(HttpRequestFramingError):
            report.to_dict()

        class ForeignReport(HttpRequestFramingAnalysis):
            pass

        with self.assertRaises(HttpRequestFramingError):
            verify_supplied_http_request_framing(
                ForeignReport(_report(GET).to_json()), model=_model(GET)
            )

    def test_fixed_ownership_nonauthorizing_effects_and_no_external_imports(self):
        body = _report(GET).to_dict()
        self.assertEqual(
            (body["profile_id"], body["capability_id"], body["vector_id"], body["wave_id"]),
            ("AOE-GB-D05-S03", "army.gb.d05.s03", "AV-GB-D05-S03-01", "IW2-003"),
        )
        self.assertEqual(body["input_provenance"], "operator_supplied_unverified")
        self.assertIs(body["offline_only"], True)
        for field in ("server_vulnerability_proven", "live_use_approved", "qualification_claimed"):
            self.assertIs(body[field], False)
        self.assertTrue(all(value == "none" for value in body["effects"].values()))
        source = ast.parse(
            (ROOT / "src/sunderkey/offline_http_request_framing.py").read_text(encoding="utf-8")
        )
        imports = {
            node.module.split(".")[0]
            for node in ast.walk(source)
            if isinstance(node, ast.ImportFrom) and node.module
        }
        imports.update(
            alias.name.split(".")[0]
            for node in ast.walk(source)
            if isinstance(node, ast.Import)
            for alias in node.names
        )
        self.assertTrue(
            imports.isdisjoint(
                {
                    "socket",
                    "ssl",
                    "requests",
                    "httpx",
                    "urllib",
                    "http",
                    "subprocess",
                    "os",
                    "pathlib",
                    "keyring",
                }
            )
        )


if __name__ == "__main__":
    unittest.main()
