"""Independent synthetic encoders and offer-set controls, without TLS execution."""

from __future__ import annotations

import base64
import copy
import hashlib
import itertools
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_tls_hello_analysis as tls

ERROR = tls.TlsHelloAnalysisError
CONSISTENT = "consistent_with_supported_hello_selection"
VIOLATIONS = "violations_observed"
UNKNOWN = "unassessed"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def u16(value):
    return value.to_bytes(2, "big")


def vector(payload, width=2):
    return len(payload).to_bytes(width, "big") + payload


def extension(kind, payload):
    return u16(kind) + vector(payload)


def handshake(kind, body):
    return bytes((kind,)) + len(body).to_bytes(3, "big") + body


def versions(values):
    return vector(b"".join(u16(value) for value in values), 1)


def groups(values):
    return vector(b"".join(u16(value) for value in values))


def shares(values):
    return vector(b"".join(u16(group) + vector(data) for group, data in values))


def client_extensions(
    version_ids=(0x0304, 0x0303), group_ids=(29, 23), share_values=((29, b"c" * 32),)
):
    result = []
    if version_ids is not None:
        result.append((43, versions(version_ids)))
    if group_ids is not None:
        result.append((10, groups(group_ids)))
    if share_values is not None:
        result.append((51, shares(share_values)))
    return result


def server_extensions(version_id=0x0304, share_value=(29, b"s" * 32)):
    result = []
    if version_id is not None:
        result.append((43, u16(version_id)))
    if share_value is not None:
        result.append((51, u16(share_value[0]) + vector(share_value[1])))
    return result


def encode_client(
    *,
    legacy=0x0303,
    random=bytes(range(32)),
    session=b"ID",
    ciphers=(0x1301, 0x1302),
    compression=b"\0",
    extensions=None,
):
    exts = client_extensions() if extensions is None else extensions
    body = u16(legacy) + random + vector(session, 1)
    body += vector(b"".join(u16(value) for value in ciphers)) + vector(compression, 1)
    if exts is not False:
        body += vector(b"".join(extension(kind, payload) for kind, payload in exts))
    return handshake(1, body)


def encode_server(
    *,
    legacy=0x0303,
    random=bytes(range(32, 64)),
    session=b"ID",
    cipher=0x1301,
    compression=0,
    extensions=None,
):
    exts = server_extensions() if extensions is None else extensions
    body = u16(legacy) + random + vector(session, 1) + u16(cipher) + bytes((compression,))
    if exts is not False:
        body += vector(b"".join(extension(kind, payload) for kind, payload in exts))
    return handshake(2, body)


def pair(client=None, server=None):
    return {
        "schema_version": 1,
        "client_hello_base64": base64.b64encode(
            encode_client() if client is None else client
        ).decode("ascii"),
        "server_hello_base64": base64.b64encode(
            encode_server() if server is None else server
        ).decode("ascii"),
    }


def component_fixture():
    return {"model": pair()}


def document(model):
    return tls.analyze_supplied_tls_hello_pair(model).to_dict()


def codes(report):
    return {item["code"] for item in report["violations"]}


def readdress(report):
    report = copy.deepcopy(report)
    body = {
        key: value for key, value in report.items() if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = hashlib.sha256(
        canonical({"domain": tls.DOMAIN, "analysis": body}).encode("ascii")
    ).hexdigest()
    report["analysis_sha256"] = "sha256:" + digest
    report["analysis_id"] = "THA-" + digest[:32].upper()
    return report


class TlsHelloAnalysisTests(unittest.TestCase):
    def test_literal_fixture_and_full_roundtrips(self):
        model = component_fixture()["model"]
        report = tls.analyze_supplied_tls_hello_pair(model)
        value = report.to_dict()
        self.assertEqual(value["analysis_id"], "THA-5C4792683DD417BB8537391B63B72DCC")
        self.assertEqual(
            value["analysis_sha256"],
            "sha256:5c4792683dd417bb8537391b63b72dcc2f4ce5101f2b900c4bca59fd52d72f52",
        )
        self.assertEqual(
            value["source"]["model_sha256"],
            "sha256:5f0548f25f5b0066c4ec16179fd3e15c063e7c257174419095b2531b745d0bf0",
        )
        self.assertEqual(
            value["source"]["client_hello_sha256"],
            "sha256:9197b087946ec5608e641b806e5c5d37f9c025e45f2919d3f0adb8b93dc057dc",
        )
        self.assertEqual(
            value["source"]["server_hello_sha256"],
            "sha256:646adedd0af8ea8542f0e6130f28e35de11a043a21bdd79f6b1b7531ba0c20d6",
        )
        self.assertEqual(value["outcome"], CONSISTENT)
        self.assertTrue(value["ordinary_tls13_pair_evaluated"])
        self.assertTrue(value["supported_checks_complete"])
        self.assertEqual(set(value["selection_checks"].values()), {"passes"})
        self.assertEqual(value["violations"], [])
        self.assertEqual(value["unassessed_reasons"], [])
        self.assertEqual(tls.TlsHelloAnalysis.from_dict(value).to_json(), report.to_json())
        self.assertEqual(
            tls.TlsHelloAnalysis.from_json(report.to_json()).to_json(), report.to_json()
        )
        self.assertEqual(
            tls.verify_supplied_tls_hello_analysis(report, model=model).to_json(), report.to_json()
        )
        self.assertEqual(
            tls.analyze_supplied_tls_hello_pair_bytes(
                model_bytes=canonical(model).encode()
            ).to_json(),
            report.to_json(),
        )

    def test_independent_encoder_matches_fresh_public_fixture(self):
        self.assertEqual(tls.component_fixture(), component_fixture()["model"])
        value = document(pair())
        self.assertEqual(value["client_hello"]["cipher_suites"], [0x1301, 0x1302])
        self.assertEqual(value["client_hello"]["supported_versions"], [0x0304, 0x0303])
        self.assertEqual(value["client_hello"]["supported_groups"], [29, 23])
        self.assertEqual(
            value["client_hello"]["key_shares"],
            [{"group": 29, "key_exchange_bytes": 32, "offset": 76}],
        )
        self.assertEqual(value["server_hello"]["key_share"]["group"], 29)
        self.assertEqual(value["source"]["client_hello_bytes"], len(encode_client()))
        self.assertEqual(value["source"]["server_hello_bytes"], len(encode_server()))

    def test_selected_cipher_not_offered_is_a_concrete_pair_violation(self):
        value = document(pair(server=encode_server(cipher=0x1303)))
        self.assertEqual(value["outcome"], VIOLATIONS)
        self.assertIn("selected_cipher_not_offered", codes(value))
        self.assertEqual(value["selection_checks"]["cipher_suite_membership"], "violation")

    def test_independent_cipher_offer_set_oracle(self):
        for offered in ((0x1301,), (0x1302,), (0x1301, 0x1302), (0x1302, 0x1301), (0xAAAA, 0x1301)):
            for selected in (0x1301, 0x1302, 0x1303):
                with self.subTest(offered=offered, selected=selected):
                    value = document(
                        pair(encode_client(ciphers=offered), encode_server(cipher=selected))
                    )
                    self.assertEqual(
                        value["selection_checks"]["cipher_suite_membership"],
                        "passes" if selected in set(offered) else "violation",
                    )
                    self.assertEqual(
                        value["outcome"], CONSISTENT if selected in set(offered) else VIOLATIONS
                    )

    def test_version_selection_exact_membership_and_prior_version(self):
        for offered, selected in itertools.product(
            ((0x0304, 0x0303), (0x0303,), (0x0304,)), (0x0303, 0x0304)
        ):
            with self.subTest(offered=offered, selected=selected):
                value = document(
                    pair(
                        encode_client(extensions=client_extensions(version_ids=offered)),
                        encode_server(extensions=server_extensions(version_id=selected)),
                    )
                )
                self.assertEqual(
                    value["selection_checks"]["version_membership"],
                    "passes" if selected in offered else "violation",
                )
                if selected == 0x0303:
                    self.assertIn("server_supported_version_prior_to_tls13", codes(value))
                elif selected not in offered:
                    self.assertIn("selected_version_not_offered", codes(value))

    def test_session_echo_matches_exact_original_bytes(self):
        for client_session, server_session in (
            (b"", b""),
            (b"a", b"a"),
            (b"a", b"b"),
            (b"", b"b"),
            (b"a", b""),
        ):
            with self.subTest(client=client_session, server=server_session):
                value = document(
                    pair(
                        encode_client(session=client_session), encode_server(session=server_session)
                    )
                )
                self.assertEqual(
                    value["selection_checks"]["session_id_echo"],
                    "passes" if client_session == server_session else "violation",
                )

    def test_tls13_legacy_versions_are_not_version_negotiation(self):
        for side, legacy in itertools.product(("client", "server"), (0x0302, 0x0304)):
            with self.subTest(side=side, legacy=legacy):
                value = document(
                    pair(
                        encode_client(legacy=legacy) if side == "client" else None,
                        encode_server(legacy=legacy) if side == "server" else None,
                    )
                )
                self.assertIn(
                    {"code": "tls13_legacy_version_not_0303", "side": side}, value["violations"]
                )

    def test_tls13_compression_constraints_are_exact(self):
        for methods in (b"\x01", b"\x00\x00", b"\x00\x01"):
            with self.subTest(methods=methods):
                self.assertIn(
                    "tls13_client_compression_not_single_zero",
                    codes(document(pair(encode_client(compression=methods)))),
                )
        for method in (1, 255):
            self.assertIn(
                "tls13_server_compression_not_zero",
                codes(document(pair(server=encode_server(compression=method)))),
            )

    def test_unknown_offered_identifiers_do_not_invent_violations(self):
        exts = client_extensions(
            version_ids=(0xAAAA, 0x0304, 0x0303),
            group_ids=(0xBBBB, 29, 23),
            share_values=((0xBBBB, b"opaque"), (29, b"c")),
        )
        value = document(pair(encode_client(ciphers=(0xCCCC, 0x1301), extensions=exts)))
        self.assertEqual(value["outcome"], CONSISTENT)
        self.assertEqual(value["violations"], [])
        self.assertEqual(value["client_hello"]["supported_groups"], [0xBBBB, 29, 23])

    def test_future_selected_identifiers_preserve_known_witnesses_but_withhold_completeness(self):
        for future in ("cipher", "group"):
            with self.subTest(future=future):
                if future == "cipher":
                    model = pair(encode_client(ciphers=(0xCCCC,)), encode_server(cipher=0xCCCC))
                    code = "selected_cipher_identifier_unassessed"
                else:
                    model = pair(
                        encode_client(
                            extensions=client_extensions(
                                group_ids=(0xBBBB,), share_values=((0xBBBB, b"c"),)
                            )
                        ),
                        encode_server(extensions=server_extensions(share_value=(0xBBBB, b"s"))),
                    )
                    code = "selected_group_identifier_unassessed"
                value = document(model)
                self.assertEqual(value["outcome"], UNKNOWN)
                self.assertIn(code, value["unassessed_reasons"])
                self.assertEqual(value["violations"], [])

    def test_future_selected_version_is_not_automatically_a_violation(self):
        for offered in ((0x0304, 0x0305), (0x0304,)):
            with self.subTest(offered=offered):
                value = document(
                    pair(
                        encode_client(extensions=client_extensions(version_ids=offered)),
                        encode_server(extensions=server_extensions(version_id=0x0305)),
                    )
                )
                self.assertFalse(value["ordinary_tls13_pair_evaluated"])
                self.assertIn("selected_tls13_context_unestablished", value["unassessed_reasons"])
                self.assertEqual(value["outcome"], UNKNOWN if 0x0305 in offered else VIOLATIONS)

    def test_duplicate_cipher_and_version_offers_are_preserved_not_normalized(self):
        value = document(
            pair(
                encode_client(
                    ciphers=(0x1301, 0x1301, 0x1302),
                    extensions=client_extensions(version_ids=(0x0304, 0x0304, 0x0303)),
                )
            )
        )
        self.assertEqual(value["outcome"], CONSISTENT)
        self.assertEqual(value["client_hello"]["cipher_suites"], [0x1301, 0x1301, 0x1302])
        self.assertEqual(value["client_hello"]["supported_versions"], [0x0304, 0x0304, 0x0303])

    def test_independent_client_share_order_subset_oracle(self):
        group_ids = (29, 23, 24)
        for count in range(1, 4):
            for selected in itertools.permutations(group_ids, count):
                with self.subTest(shares=selected):
                    share_values = tuple((group, b"c") for group in selected)
                    value = document(
                        pair(
                            encode_client(
                                extensions=client_extensions(
                                    group_ids=group_ids, share_values=share_values
                                )
                            ),
                            encode_server(
                                extensions=server_extensions(share_value=(selected[0], b"s"))
                            ),
                        )
                    )
                    ordered_subsets = {
                        tuple(group_ids[index] for index in indices)
                        for indices in itertools.combinations(range(3), count)
                    }
                    self.assertEqual(
                        value["selection_checks"]["client_share_order_membership"],
                        "passes" if selected in ordered_subsets else "violation",
                    )

    def test_client_share_group_must_be_declared_supported(self):
        value = document(
            pair(
                encode_client(
                    extensions=client_extensions(group_ids=(23,), share_values=((29, b"c"),))
                )
            )
        )
        self.assertIn("client_key_share_group_not_supported", codes(value))
        self.assertIn("server_key_share_group_not_in_client_share_and_groups", codes(value))

    def test_duplicate_supported_group_order_is_explicitly_unassessed(self):
        value = document(pair(encode_client(extensions=client_extensions(group_ids=(29, 29, 23)))))
        self.assertEqual(value["outcome"], UNKNOWN)
        self.assertIn("duplicate_supported_groups_order_unassessed", value["unassessed_reasons"])
        self.assertEqual(value["selection_checks"]["client_share_order_membership"], "unassessed")

    def test_duplicate_client_key_share_group_is_a_structural_contradiction(self):
        value = document(
            pair(encode_client(extensions=client_extensions(share_values=((29, b"c"), (29, b"d")))))
        )
        self.assertIn("duplicate_client_key_share_group", codes(value))
        self.assertEqual(value["client_hello"]["parse_status"], "structural_contradiction")

    def test_missing_groups_do_not_fabricate_share_membership(self):
        value = document(pair(encode_client(extensions=client_extensions(group_ids=None))))
        self.assertIn("client_key_share_group_not_supported", codes(value))
        self.assertIn("server_key_share_group_not_in_client_share_and_groups", codes(value))

    def test_server_share_membership_uses_both_client_vectors(self):
        for offered, selected in itertools.product(((29,), (23,), (29, 23)), (29, 23, 24)):
            with self.subTest(offered=offered, selected=selected):
                value = document(
                    pair(
                        encode_client(
                            extensions=client_extensions(
                                group_ids=(29, 23, 24),
                                share_values=tuple((group, b"c") for group in offered),
                            )
                        ),
                        encode_server(extensions=server_extensions(share_value=(selected, b"s"))),
                    )
                )
                self.assertEqual(
                    value["selection_checks"]["server_share_membership"],
                    "passes" if selected in set(offered) else "violation",
                )

    def test_empty_client_share_vector_is_structural_but_needs_retry_for_selected_share(self):
        value = document(pair(encode_client(extensions=client_extensions(share_values=()))))
        self.assertEqual(value["client_hello"]["parse_status"], "complete")
        self.assertEqual(value["client_hello"]["key_shares"], [])
        self.assertIn("server_key_share_group_not_in_client_share_and_groups", codes(value))

    def test_non_psk_ordinary_server_requires_key_share(self):
        value = document(pair(server=encode_server(extensions=server_extensions(share_value=None))))
        self.assertIn("ordinary_non_psk_server_key_share_absent", codes(value))

    def test_checked_server_extension_response_must_have_client_request(self):
        value = document(pair(encode_client(extensions=client_extensions(share_values=None))))
        self.assertIn("server_checked_extension_not_offered", codes(value))
        self.assertIn("server_key_share_group_not_in_client_share_and_groups", codes(value))

    def test_supported_groups_not_permitted_in_ordinary_server_hello(self):
        value = document(
            pair(server=encode_server(extensions=server_extensions() + [(10, groups((29,)))]))
        )
        self.assertIn("supported_groups_not_permitted_in_server_hello", codes(value))

    def test_duplicate_extensions_are_not_collapsed(self):
        for side in ("client", "server"):
            with self.subTest(side=side):
                client = (
                    encode_client(extensions=client_extensions() + [(43, versions((0x0304,)))])
                    if side == "client"
                    else None
                )
                server = (
                    encode_server(extensions=server_extensions() + [(43, u16(0x0304))])
                    if side == "server"
                    else None
                )
                value = document(pair(client, server))
                self.assertIn(
                    {"code": "duplicate_extension_type", "side": side}, value["violations"]
                )

    def test_extension_permutations_preserve_math_not_original_byte_identity(self):
        original = document(pair())
        for exts in itertools.permutations(client_extensions()):
            value = document(pair(encode_client(extensions=exts)))
            self.assertEqual(value["outcome"], CONSISTENT)
            self.assertEqual(value["selection_checks"], original["selection_checks"])
            self.assertEqual(
                [x["type"] for x in value["client_hello"]["extensions"]], [x[0] for x in exts]
            )
            if tuple(exts) != tuple(client_extensions()):
                self.assertNotEqual(
                    value["source"]["client_hello_sha256"],
                    original["source"]["client_hello_sha256"],
                )

    def test_hello_retry_request_is_detected_before_ordinary_key_share_parse(self):
        for exts in ([(43, u16(0x0304)), (51, u16(23))], [(0xFFFF, b"opaque")], [(51, b"")]):
            with self.subTest(extensions=exts):
                value = document(
                    pair(
                        server=encode_server(random=tls.HELLO_RETRY_REQUEST_RANDOM, extensions=exts)
                    )
                )
                self.assertEqual(value["outcome"], UNKNOWN)
                self.assertTrue(value["server_hello"]["hello_retry_request"])
                self.assertEqual(value["server_hello"]["extensions"], [])
                self.assertEqual(value["server_hello"]["confirmed_prefix_end"], 38)
                self.assertIsNone(value["server_hello"]["key_share"])

    def test_psk_declarations_are_never_a_complete_conclusion(self):
        for side in ("client", "server", "both"):
            client = client_extensions() + (
                [(45, b"\x01\x01"), (41, b"opaque")] if side in ("client", "both") else []
            )
            server = server_extensions() + (
                [(41, b"\x00\x00")] if side in ("server", "both") else []
            )
            value = document(
                pair(encode_client(extensions=client), encode_server(extensions=server))
            )
            self.assertEqual(value["outcome"], UNKNOWN)
            self.assertFalse(value["supported_checks_complete"])
            self.assertTrue(
                any("psk_feature_unassessed" in code for code in value["unassessed_reasons"])
            )
        value = document(
            pair(
                server=encode_server(
                    extensions=server_extensions(share_value=None) + [(41, b"\x00\x00")]
                )
            )
        )
        self.assertEqual(value["outcome"], UNKNOWN)
        self.assertNotIn("ordinary_non_psk_server_key_share_absent", codes(value))

    def test_future_and_unhandled_extensions_withhold_complete_conclusions(self):
        for kind in (0, 13, 16, 42, 44, 49, 0xAAAA):
            with self.subTest(kind=kind):
                value = document(
                    pair(encode_client(extensions=client_extensions() + [(kind, b"opaque")]))
                )
                self.assertEqual(value["outcome"], UNKNOWN)
                self.assertIn("client_unhandled_extensions", value["unassessed_reasons"])

    def test_missing_supported_versions_has_no_legacy_version_inference(self):
        value = document(pair(encode_client(extensions=client_extensions(version_ids=None))))
        self.assertIn("selected_version_not_offered", codes(value))
        for raw in (
            encode_server(extensions=server_extensions(version_id=None)),
            encode_server(extensions=False),
        ):
            value = document(pair(server=raw))
            self.assertEqual(value["outcome"], UNKNOWN)
            self.assertFalse(value["ordinary_tls13_pair_evaluated"])

    def test_wrong_handshake_types_and_suffixes_are_concrete_contradictions(self):
        for side in ("client", "server"):
            original = encode_client() if side == "client" else encode_server()
            for raw in (b"\x14" + original[1:], original + b"suffix"):
                with self.subTest(side=side, suffix=len(raw) != len(original)):
                    value = document(
                        pair(raw if side == "client" else None, raw if side == "server" else None)
                    )
                    self.assertEqual(
                        value[side + "_hello"]["parse_status"], "structural_contradiction"
                    )
                    self.assertEqual(value["outcome"], VIOLATIONS)
                    self.assertTrue(
                        codes(value)
                        & {"unexpected_handshake_message_type", "bytes_follow_declared_handshake"}
                    )

    def test_declared_oversized_frame_is_unassessed_without_allocation(self):
        value = document(pair(client=b"\x01\xff\xff\xff"))
        self.assertEqual(value["outcome"], UNKNOWN)
        self.assertIn(
            "client_declared_message_exceeds_supported_ceiling", value["unassessed_reasons"]
        )
        self.assertEqual(value["client_hello"]["confirmed_prefix_end"], 4)

    def test_protocol_vector_lengths_and_enclosing_boundaries(self):
        # Well-framed outer messages with contradictory inner vector declarations.
        controls = [
            encode_client(ciphers=()),
            encode_client(compression=b""),
            encode_client(session=b"x" * 33),
            encode_server(session=b"x" * 33),
            encode_client(extensions=[(43, b"\x03\x03\x04\x00"), (10, groups((29,)))]),
            encode_client(extensions=[(43, versions((0x0304,))), (10, b"\x00\x03\x00\x1d\x00")]),
        ]
        for index, raw in enumerate(controls):
            side = "server" if index == 3 else "client"
            with self.subTest(index=index):
                value = document(
                    pair(raw if side == "client" else None, raw if side == "server" else None)
                )
                self.assertEqual(value[side + "_hello"]["parse_status"], "structural_contradiction")
                self.assertEqual(value["outcome"], VIOLATIONS)

    def test_checked_extension_payloads_consume_exact_declared_bytes(self):
        for side, kind in itertools.product(("client", "server"), (43, 51)):
            with self.subTest(side=side, kind=kind):
                exts = client_extensions() if side == "client" else server_extensions()
                exts = [(typ, data + (b"x" if typ == kind else b"")) for typ, data in exts]
                value = document(
                    pair(
                        encode_client(extensions=exts) if side == "client" else None,
                        encode_server(extensions=exts) if side == "server" else None,
                    )
                )
                self.assertIn("extension_payload_has_trailing_bytes", codes(value))

    def test_failed_nested_fields_do_not_claim_the_reserved_vector_end_as_confirmed(self):
        raw = encode_client(extensions=[(43, b"\x03\x03\x04\x00"), (10, groups((29,)))])
        value = document(pair(raw))
        self.assertEqual(value["client_hello"]["issue"], "uint16_vector_has_odd_length")
        self.assertEqual(value["client_hello"]["confirmed_prefix_end"], 56)
        self.assertLess(value["client_hello"]["confirmed_prefix_end"], len(raw))
        raw = encode_client(extensions=client_extensions() + [(43, versions((0x0304,)))])
        value = document(pair(raw))
        self.assertEqual(value["client_hello"]["confirmed_prefix_end"], len(encode_client()))
        self.assertLess(value["client_hello"]["confirmed_prefix_end"], len(raw))

    def test_key_exchange_vector_cannot_be_empty(self):
        for side in ("client", "server"):
            client = (
                encode_client(extensions=client_extensions(share_values=((29, b""),)))
                if side == "client"
                else None
            )
            server = (
                encode_server(extensions=server_extensions(share_value=(29, b"")))
                if side == "server"
                else None
            )
            with self.subTest(side=side):
                value = document(pair(client, server))
                self.assertEqual(value[side + "_hello"]["parse_status"], "structural_contradiction")

    def test_all_strict_prefixes_never_become_a_consistent_pair(self):
        for side, raw in (("client", encode_client()), ("server", encode_server())):
            for end in range(len(raw)):
                with self.subTest(side=side, end=end):
                    value = document(
                        pair(
                            raw[:end] if side == "client" else None,
                            raw[:end] if side == "server" else None,
                        )
                    )
                    self.assertNotEqual(value["outcome"], CONSISTENT)
                    self.assertLessEqual(value[side + "_hello"]["confirmed_prefix_end"], end)

    def test_exact_message_byte_ceiling_and_one_byte_over(self):
        current = encode_client(extensions=client_extensions() + [(0xAAAA, b"")])
        payload = b"p" * (tls.MAX_MESSAGE_BYTES - len(current))
        boundary = encode_client(extensions=client_extensions() + [(0xAAAA, payload)])
        self.assertEqual(len(boundary), tls.MAX_MESSAGE_BYTES)
        value = document(pair(boundary))
        self.assertEqual(value["outcome"], UNKNOWN)
        self.assertEqual(value["client_hello"]["parse_status"], "complete")
        over = pair(boundary + b"x")
        for intake in (
            lambda: tls.analyze_supplied_tls_hello_pair(over),
            lambda: tls.analyze_supplied_tls_hello_pair_bytes(model_bytes=canonical(over).encode()),
        ):
            with (
                patch.object(tls.base64, "b64decode", side_effect=AssertionError("decode reached")),
                patch.object(tls.hashlib, "sha256", side_effect=AssertionError("hash reached")),
                self.assertRaises(ERROR),
            ):
                intake()

    def test_cipher_group_share_and_extension_count_boundaries(self):
        def make_shares(count):
            ids = tuple(range(1000, 1000 + count))
            return pair(
                encode_client(
                    extensions=client_extensions(
                        group_ids=ids,
                        share_values=tuple((group, b"x") for group in ids),
                    )
                ),
                encode_server(extensions=server_extensions(share_value=(1000, b"s"))),
            )

        controls = (
            (
                lambda count: pair(encode_client(ciphers=tuple(0x1301 for _ in range(count)))),
                tls.MAX_CIPHER_SUITES,
            ),
            (
                lambda count: pair(
                    encode_client(
                        extensions=client_extensions(
                            group_ids=(29,) + tuple(range(1000, 999 + count))
                        )
                    )
                ),
                tls.MAX_SUPPORTED_GROUPS,
            ),
            (make_shares, tls.MAX_KEY_SHARES),
            (
                lambda count: pair(
                    encode_client(
                        extensions=client_extensions()
                        + [(5000 + index, b"") for index in range(count - 3)]
                    )
                ),
                tls.MAX_EXTENSIONS,
            ),
        )
        for make, limit in controls:
            with self.subTest(limit=limit):
                self.assertEqual(document(make(limit))["client_hello"]["parse_status"], "complete")
                with (
                    patch.object(tls.hashlib, "sha256", side_effect=AssertionError("hash reached")),
                    self.assertRaises(ERROR),
                ):
                    tls.analyze_supplied_tls_hello_pair(make(limit + 1))

    def test_version_vector_exact_unsigned_byte_boundary(self):
        value = document(
            pair(
                encode_client(
                    extensions=client_extensions(version_ids=(0x0304,) + tuple(range(1000, 1126)))
                )
            )
        )
        self.assertEqual(len(value["client_hello"]["supported_versions"]), 127)
        exts = client_extensions()
        exts[0] = (43, b"\xff" + b"x" * 255)
        value = document(pair(encode_client(extensions=exts)))
        self.assertEqual(value["client_hello"]["parse_status"], "structural_contradiction")

    def test_canonical_base64_and_native_text_are_not_normalized(self):
        for text in ("AB==", "AA=", "A===", "AA==\n", "_A==", " AA==", "a", 1, None):
            model = pair()
            model["client_hello_base64"] = text
            with (
                self.subTest(text=text),
                patch.object(tls.hashlib, "sha256", side_effect=AssertionError("hash reached")),
                self.assertRaises(ERROR),
            ):
                tls.analyze_supplied_tls_hello_pair(model)

    def test_exact_native_schema_alias_and_container_guards_before_hash(self):
        class Text(str):
            pass

        class Mapping(dict):
            pass

        for value in (True, 1.0, "1", None):
            model = pair()
            model["schema_version"] = value
            with (
                self.subTest(value=value),
                patch.object(tls.hashlib, "sha256", side_effect=AssertionError("hash reached")),
                self.assertRaises(ERROR),
            ):
                tls.analyze_supplied_tls_hello_pair(model)
        for model in (
            Mapping(pair()),
            {**pair(), "client_hello_base64": Text(pair()["client_hello_base64"])},
            {**pair(), "extra": 1},
        ):
            with (
                patch.object(tls.hashlib, "sha256", side_effect=AssertionError("hash reached")),
                self.assertRaises(ERROR),
            ):
                tls.analyze_supplied_tls_hello_pair(model)
        for missing in tuple(pair()):
            model = pair()
            model.pop(missing)
            with self.assertRaises(ERROR):
                tls.analyze_supplied_tls_hello_pair(model)

    def test_raw_duplicates_float_unicode_and_integer_lexical_denial(self):
        for raw in (
            b'{"schema_version":1,"schema_version":1}',
            b'{"schema_version":1.0}',
            b'{"schema_version":true}',
            b"NaN",
            b"Infinity",
            b"1e0",
            b"--1",
            b"01",
            b'"\\ud800"',
            b'"\\udc00"',
            b"\xff",
        ):
            with self.subTest(raw=raw), self.assertRaises(ERROR):
                tls.analyze_supplied_tls_hello_pair_bytes(model_bytes=raw)
        for raw in (b"9223372036854775808", b"-9223372036854775809", b"9" * 1000):
            with (
                self.subTest(length=len(raw)),
                patch.object(tls.json, "loads", side_effect=AssertionError("decoder reached")),
                patch.object(tls.hashlib, "sha256", side_effect=AssertionError("hash reached")),
                self.assertRaises(ERROR),
            ):
                tls.analyze_supplied_tls_hello_pair_bytes(model_bytes=raw)

    def test_raw_depth_nodes_strings_and_canonical_size_precede_decoder(self):
        controls = [
            b"[" * tls.MAX_DEPTH + b"0" + b"]" * tls.MAX_DEPTH,
            b"[0," + b"0," * tls.MAX_NODES + b"0]",
            b'"' + b"x" * (tls.MAX_BASE64_CHARS + 1) + b'"',
            b" " * (tls.MAX_MODEL_BYTES + 1),
            ('"' + "\u00e9" * 80_000 + '"').encode("utf-8"),
        ]
        for raw in controls:
            with (
                self.subTest(size=len(raw)),
                patch.object(tls.json, "loads", side_effect=AssertionError("decoder reached")),
                patch.object(tls.hashlib, "sha256", side_effect=AssertionError("hash reached")),
                self.assertRaises(ERROR),
            ):
                tls.analyze_supplied_tls_hello_pair_bytes(model_bytes=raw)
        for scalar in (b'"x"', b"true", b"false", b"null"):
            raw = b"[" * tls.MAX_DEPTH + scalar + b"]" * tls.MAX_DEPTH
            with (
                patch.object(tls.json, "loads", side_effect=AssertionError("decoder reached")),
                self.assertRaises(ERROR),
            ):
                tls.analyze_supplied_tls_hello_pair_bytes(model_bytes=raw)

    def test_native_repeated_subtrees_cycles_and_large_integer_precede_dump(self):
        cycle = []
        cycle.append(cycle)
        shared = ["\\" * 4096] * 64
        for value in (cycle, [shared] * 64, {"value": 2**10000}, [0] * (tls.MAX_NODES + 1)):
            with (
                patch.object(tls.json, "dumps", side_effect=AssertionError("dump reached")),
                patch.object(tls.hashlib, "sha256", side_effect=AssertionError("hash reached")),
                self.assertRaises(ERROR),
            ):
                tls.analyze_supplied_tls_hello_pair(value)

    def test_exact_raw_model_ceiling_allows_whitespace_but_binds_canonical_snapshot(self):
        original = pair()
        raw = canonical(original).encode()
        raw = b" " * (tls.MAX_MODEL_BYTES - len(raw)) + raw
        self.assertEqual(len(raw), tls.MAX_MODEL_BYTES)
        self.assertEqual(
            tls.analyze_supplied_tls_hello_pair_bytes(model_bytes=raw).to_json(),
            tls.analyze_supplied_tls_hello_pair(original).to_json(),
        )

    def test_full_output_reservation_and_work_deny_before_any_hash(self):
        # Reduced bounds prove guard placement only, not a production-ceiling bypass.
        model = pair()
        valid = tls.analyze_supplied_tls_hello_pair(model).to_json()
        for attribute, reduced in (
            ("MAX_REPORT_BYTES", len(valid.encode()) - 1),
            ("MAX_NODES", 128),
            ("MAX_WORK", 1),
        ):
            with (
                self.subTest(attribute=attribute),
                patch.object(tls, attribute, reduced),
                patch.object(tls.hashlib, "sha256", side_effect=AssertionError("hash reached")),
                self.assertRaises(ERROR),
            ):
                tls.analyze_supplied_tls_hello_pair(model)

    def test_coherently_readdressed_false_derived_outputs_cannot_replay(self):
        original = document(pair())
        for field, value in (
            ("outcome", VIOLATIONS),
            ("ordinary_tls13_pair_evaluated", 1),
            ("supported_checks_complete", False),
            ("violations", [{"code": "selected_cipher_not_offered", "side": "pair"}]),
            ("source", {}),
            ("full_tls_validity_verified", True),
            ("qualification_claimed", True),
            ("effects", {"target": "allowed"}),
        ):
            changed = copy.deepcopy(original)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ERROR):
                tls.TlsHelloAnalysis.from_json(canonical(readdress(changed)))
        changed = copy.deepcopy(original)
        changed["server_hello"]["cipher_suite"] = 0x1302
        with self.assertRaises(ERROR):
            tls.TlsHelloAnalysis.from_dict(readdress(changed))

    def test_valid_bounded_report_replay_binds_separately_supplied_original_bytes(self):
        original = pair()
        candidate = pair(encode_client(random=b"c" * 32))
        report = tls.analyze_supplied_tls_hello_pair(candidate)
        self.assertEqual(report.to_dict()["outcome"], CONSISTENT)
        self.assertEqual(
            tls.TlsHelloAnalysis.from_json(report.to_json()).to_json(), report.to_json()
        )
        with self.assertRaises(ERROR):
            tls.verify_supplied_tls_hello_analysis(report, model=original)
        with self.assertRaises(ERROR):
            tls.verify_supplied_tls_hello_analysis(
                tls.analyze_supplied_tls_hello_pair(original), model=candidate
            )

    def test_missing_slots_native_report_family_and_raw_type_errors_are_bounded(self):
        missing = object.__new__(tls.TlsHelloAnalysis)
        with self.assertRaises(ERROR):
            missing.to_dict()

        class Foreign(tls.TlsHelloAnalysis):
            pass

        report = tls.analyze_supplied_tls_hello_pair(pair())
        with self.assertRaises(ERROR):
            tls.verify_supplied_tls_hello_analysis(Foreign(report.to_json()), model=pair())
        for raw in (bytearray(b"{}"), memoryview(b"{}"), "{}", None):
            with self.assertRaises(ERROR):
                tls.analyze_supplied_tls_hello_pair_bytes(model_bytes=raw)
        for raw in (b"{}", None, 1):
            with self.assertRaises(ERROR):
                tls.TlsHelloAnalysis.from_json(raw)

    def test_detached_source_and_effects_remain_nonqualifying(self):
        model = pair()
        original = copy.deepcopy(model)
        report = tls.analyze_supplied_tls_hello_pair(model)
        before = report.to_json()
        model["server_hello_base64"] = ""
        mutable = report.to_dict()
        mutable["model"]["client_hello_base64"] = ""
        mutable["client_hello"]["cipher_suites"].clear()
        mutable["effects"]["target"] = "allowed"
        self.assertEqual(report.to_json(), before)
        self.assertEqual(
            tls.verify_supplied_tls_hello_analysis(report, model=original).to_json(), before
        )
        value = report.to_dict()
        for field in (
            "full_tls_validity_verified",
            "message_authenticity_verified",
            "cryptographic_validation_performed",
            "vulnerability_proven",
            "live_use_approved",
            "qualification_claimed",
        ):
            self.assertIs(value[field], False)
        self.assertTrue(value["offline_only"])
        self.assertEqual(set(value["effects"].values()), {"none"})

    def test_opaque_share_bytes_are_not_crypto_or_key_validity_checks(self):
        value = document(
            pair(
                encode_client(extensions=client_extensions(share_values=((29, b"x"),))),
                encode_server(extensions=server_extensions(share_value=(29, b"y"))),
            )
        )
        self.assertEqual(value["outcome"], CONSISTENT)
        self.assertEqual(value["client_hello"]["key_shares"][0]["key_exchange_bytes"], 1)
        self.assertFalse(value["cryptographic_validation_performed"])
        self.assertFalse(value["full_tls_validity_verified"])


if __name__ == "__main__":
    unittest.main()
