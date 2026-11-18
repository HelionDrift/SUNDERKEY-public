"""Independent binary/list oracles for supplied SSH KEXINIT declarations."""

from __future__ import annotations

import base64
import copy
import hashlib
import itertools
import json
import struct
import unittest
from unittest.mock import patch

from sunderkey import offline_ssh_kexinit_analysis as ssh

_FIELDS = (
    "kex_algorithms",
    "server_host_key_algorithms",
    "encryption_algorithms_client_to_server",
    "encryption_algorithms_server_to_client",
    "mac_algorithms_client_to_server",
    "mac_algorithms_server_to_client",
    "compression_algorithms_client_to_server",
    "compression_algorithms_server_to_client",
    "languages_client_to_server",
    "languages_server_to_client",
)
_DEFAULT = (
    ("diffie-hellman-group14-sha256",),
    ("rsa-sha2-256",),
    ("aes128-ctr",),
    ("aes128-ctr",),
    ("hmac-sha2-256",),
    ("hmac-sha2-256",),
    ("none",),
    ("none",),
    (),
    (),
)
_GOLDEN_ID = "SKA-3CB2321BD41F99BB674FD0CA767537D4"
_GOLDEN_REPORT_SHA = "sha256:3cb2321bd41f99bb674fd0ca767537d4dda4e8ba1f375d41c7f22924115ddb01"
_GOLDEN_MODEL_SHA = "sha256:d7b10a549bed4bf54e114ca43a59a0bf93c5cffd907a02e7e5734693adc22f9b"
_GOLDEN_CLIENT_SHA = "sha256:5fb0eb08d150191c2da4b44625fd33e084a014ec0f63e09e41f431910fd9fa70"
_GOLDEN_SERVER_SHA = "sha256:78348431272213ab75410e8bff89d643b9a8a0e3e6e3474e19c580b941dd5758"


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _encode(rows=_DEFAULT, *, truth=0, reserved=0, cookie=None, message=20):
    """Independent fixed-width encoder, not the production fixture/parser."""
    cookie = bytes(range(16)) if cookie is None else cookie
    fields = []
    for row in rows:
        raw = b",".join(name.encode("ascii") for name in row)
        fields.append(struct.pack("!I", len(raw)) + raw)
    return (
        bytes([message]) + cookie + b"".join(fields) + bytes([truth]) + struct.pack("!I", reserved)
    )


def _rows(**changes):
    result = list(_DEFAULT)
    for field, names in changes.items():
        result[_FIELDS.index(field)] = tuple(names)
    return result


def _model(client=None, server=None, *, source_id="synthetic-kexinit"):
    return {
        "schema_version": 1,
        "source_id": source_id,
        "client_payload_base64": base64.b64encode(_encode() if client is None else client).decode(
            "ascii"
        ),
        "server_payload_base64": base64.b64encode(
            _encode(cookie=bytes(range(16, 32))) if server is None else server
        ).decode("ascii"),
    }


def _report(client=None, server=None):
    return ssh.analyze_supplied_ssh_kexinit_pair(_model(client, server)).to_dict()


def _first_common(client, server):
    """Independent positional equality oracle, without production/set helpers."""
    for proposed in client:
        for offered in server:
            if proposed == offered:
                return proposed
    return None


def _readdress(document):
    body = {
        key: value
        for key, value in document.items()
        if key not in ("analysis_id", "analysis_sha256")
    }
    digest = hashlib.sha256(
        ssh.DOMAIN.encode("ascii") + b"\n" + _canonical(body).encode("ascii")
    ).hexdigest()
    document["analysis_sha256"] = "sha256:" + digest
    document["analysis_id"] = "SKA-" + digest[:32].upper()
    return document


def _wrapper(text):
    result = object.__new__(ssh.SshKexinitAnalysis)
    object.__setattr__(result, "document_json", text)
    return result


def _names_with_encoded_size(size):
    if not size:
        return ()
    count = (size + 65) // 65
    remaining = size - count + 1
    names = []
    for index in range(count):
        width = min(64, remaining - (count - index - 1))
        names.append("x" * width)
        remaining -= width
    assert remaining == 0
    assert len(",".join(names)) == size
    return tuple(names)


class SshKexinitAnalysisTests(unittest.TestCase):
    def test_public_fixture_matches_independent_encoder_and_literal_goldens(self):
        model = ssh.component_fixture()
        self.assertEqual(model, _model())
        document = ssh.analyze_supplied_ssh_kexinit_pair(model).to_dict()
        self.assertEqual(document["analysis_id"], _GOLDEN_ID)
        self.assertEqual(document["analysis_sha256"], _GOLDEN_REPORT_SHA)
        self.assertEqual(document["source_model_sha256"], _GOLDEN_MODEL_SHA)
        self.assertEqual(document["client_payload_sha256"], _GOLDEN_CLIENT_SHA)
        self.assertEqual(document["server_payload_sha256"], _GOLDEN_SERVER_SHA)
        self.assertEqual(document["outcome"], "consistent_supported_selection_declarations")
        self.assertEqual(
            document["semantic_candidates"]["kex_algorithms"]["supported_candidate_name"],
            "diffie-hellman-group14-sha256",
        )

    def test_all_public_round_trips_are_exact_and_identity_preserving(self):
        model = _model()
        result = ssh.analyze_supplied_ssh_kexinit_pair(model)
        text, document = result.to_json(), result.to_dict()
        variants = (
            ssh.analyze_supplied_ssh_kexinit_pair_bytes(
                model_bytes=_canonical(model).encode("ascii")
            ),
            ssh.SshKexinitAnalysis(text),
            ssh.SshKexinitAnalysis.from_dict(document),
            ssh.SshKexinitAnalysis.from_json(text),
            ssh.verify_supplied_ssh_kexinit_analysis(result, model=model),
        )
        for variant in variants:
            self.assertEqual(variant.to_json(), text)

    def test_public_fixture_and_exports_are_fresh_and_detached(self):
        first, second = ssh.component_fixture(), ssh.component_fixture()
        first["source_id"] = "changed"
        self.assertEqual(second, _model())
        result = ssh.analyze_supplied_ssh_kexinit_pair(second)
        document = result.to_dict()
        document["client"]["name_lists"][0]["names"].append("changed")
        second["client_payload_base64"] = ""
        self.assertEqual(result.to_dict()["client"]["name_lists"][0]["names"], list(_DEFAULT[0]))
        with self.assertRaises((AttributeError, TypeError)):
            result.document_json = "changed"

    def test_received_nonzero_booleans_are_true_and_raw_octets_survive(self):
        for value in (0, 1, 2, 127, 255):
            with self.subTest(value=value):
                document = _report(_encode(truth=value))
                self.assertEqual(document["client"]["first_kex_packet_follows_octet"], value)
                self.assertIs(document["client"]["first_kex_packet_follows"], value != 0)
                self.assertIs(
                    document["client"]["sender_boolean_encoding_is_canonical"], value in (0, 1)
                )
                self.assertEqual(document["declaration_violations"], [])

    def test_nonzero_reserved_is_retained_ignored_and_addressed_not_rejected(self):
        ordinary = _report()
        for value in (1, 255, 65_536, 2**32 - 1):
            with self.subTest(value=value):
                document = _report(_encode(reserved=value))
                self.assertEqual(document["client"]["reserved_uint32"], value)
                self.assertTrue(document["client"]["reserved_ignored_for_base_selection"])
                self.assertEqual(document["semantic_candidates"], ordinary["semantic_candidates"])
                self.assertNotEqual(
                    document["client_payload_sha256"], ordinary["client_payload_sha256"]
                )
                self.assertNotEqual(document["analysis_sha256"], ordinary["analysis_sha256"])

    def test_cookie_octets_are_opaque_not_a_randomness_claim(self):
        raw = _encode(cookie=b"\0" * 16)
        document = _report(raw)
        self.assertEqual(
            document["client"]["cookie_base64"], base64.b64encode(b"\0" * 16).decode("ascii")
        )
        self.assertFalse(document["client"]["cookie_randomness_assessed"])
        self.assertEqual(document["declaration_violations"], [])

    def test_exact_wire_offsets_and_names_come_from_original_octets(self):
        document = _report()
        position = 17
        for field, names, row in zip(
            _FIELDS, _DEFAULT, document["client"]["name_lists"], strict=True
        ):
            width = len(",".join(names))
            self.assertEqual(
                row,
                {
                    "field": field,
                    "length_offset": position,
                    "data_offset": position + 4,
                    "end_offset": position + 4 + width,
                    "declared_bytes": width,
                    "names": list(names),
                },
            )
            position += 4 + width
        self.assertEqual(document["client"]["first_kex_packet_follows_offset"], position)
        self.assertEqual(document["client"]["payload_bytes"], position + 5)

    def test_every_truncated_prefix_is_typed_rejection_before_hashing(self):
        raw = _encode()
        for role in ("client_payload_base64", "server_payload_base64"):
            for length in range(len(raw)):
                with self.subTest(role=role, length=length):
                    model = _model()
                    model[role] = base64.b64encode(raw[:length]).decode("ascii")
                    with patch.object(ssh.hashlib, "sha256") as digest:
                        with self.assertRaises(ssh.SshKexinitAnalysisError):
                            ssh.analyze_supplied_ssh_kexinit_pair(model)
                        digest.assert_not_called()

    def test_message_kind_trailing_bytes_and_false_lengths_reject(self):
        original = _encode()
        cases = (_encode(message=19), original + b"\0", original[:17] + b"\xff" * 4 + original[21:])
        for raw in cases:
            with self.subTest(raw=raw[:24]), self.assertRaises(ssh.SshKexinitAnalysisError):
                _report(raw)

    def test_empty_required_lists_are_contextual_observations_not_wire_errors(self):
        for field in _FIELDS[:8]:
            with self.subTest(field=field):
                document = _report(_encode(_rows(**{field: ()})))
                self.assertIn(
                    "client:" + field + ":empty_required_declaration",
                    document["declaration_violations"],
                )
                self.assertEqual(document["outcome"], "known_declaration_contradictions")

    def test_empty_and_nonempty_languages_are_ignored_without_tag_validation(self):
        rows = _rows(
            languages_client_to_server=("en-US", "x:opaque"),
            languages_server_to_client=("EN-us", "en-US"),
        )
        document = _report(_encode(rows))
        self.assertEqual(document["client"]["name_lists"][8]["names"], ["en-US", "x:opaque"])
        self.assertEqual(document["outcome"], "consistent_supported_selection_declarations")
        self.assertNotIn("languages_client_to_server", document["literal_first_common_names"])

    def test_empty_entries_controls_nonascii_and_name_size_are_closed_rejections(self):
        original = _encode()
        for encoded in (
            b",",
            b"a,,b",
            b"a,",
            b",a",
            b"a b",
            b"a\0b",
            b"a\x7fb",
            b"\xff",
            b"x" * 65,
        ):
            with self.subTest(encoded=encoded):
                raw = (
                    original[:17]
                    + struct.pack("!I", len(encoded))
                    + encoded
                    + original[21 + len(_DEFAULT[0][0]) :]
                )
                with self.assertRaises(ssh.SshKexinitAnalysisError):
                    _report(raw)

    def test_name_duplicates_case_and_order_are_retained(self):
        names = ("future@owner", "Future@owner", "future@owner", "aes128-ctr")
        raw = _encode(_rows(encryption_algorithms_client_to_server=names))
        document = _report(
            raw,
            _encode(_rows(encryption_algorithms_client_to_server=("aes128-ctr", "future@owner"))),
        )
        self.assertEqual(document["client"]["name_lists"][2]["names"], list(names))
        self.assertEqual(document["literal_first_common_names"][_FIELDS[2]], "future@owner")
        self.assertIsNone(document["semantic_candidates"][_FIELDS[2]]["supported_candidate_name"])
        self.assertEqual(
            document["semantic_candidates"][_FIELDS[2]]["known_fallback_witness"], "aes128-ctr"
        )

    def test_independent_finite_client_preference_oracle_in_both_directions(self):
        sequences = (
            ("aes128-ctr",),
            ("aes256-cbc",),
            ("aes128-ctr", "aes256-cbc"),
            ("aes256-cbc", "aes128-ctr"),
            ("aes128-ctr", "aes128-ctr", "aes256-cbc"),
            ("aes256-cbc", "aes256-cbc", "aes128-ctr"),
        )
        cases = 0
        for client, server in itertools.product(sequences, repeat=2):
            for field in _FIELDS[2:4]:
                document = _report(
                    _encode(_rows(**{field: client})), _encode(_rows(**{field: server}))
                )
                expected = _first_common(client, server)
                self.assertEqual(document["literal_first_common_names"][field], expected)
                self.assertEqual(
                    document["semantic_candidates"][field]["supported_candidate_name"], expected
                )
                cases += 1
        self.assertEqual(cases, 72)

    def test_unknown_common_kex_before_known_does_not_promote_later_winner(self):
        names = ("unknown-kex", "diffie-hellman-group14-sha256")
        document = _report(
            _encode(_rows(kex_algorithms=names)), _encode(_rows(kex_algorithms=names))
        )
        row = document["semantic_candidates"]["kex_algorithms"]
        self.assertEqual(document["literal_first_common_names"]["kex_algorithms"], "unknown-kex")
        self.assertIsNone(row["supported_candidate_name"])
        self.assertEqual(row["known_eligible_fallback_witness"], "diffie-hellman-group14-sha256")
        self.assertEqual(document["declaration_violations"], [])
        self.assertEqual(document["outcome"], "unassessed_selection_semantics")

    def test_noncommon_unknown_predecessor_does_not_hide_known_candidate(self):
        names = ("unknown-client-only", "diffie-hellman-group14-sha256")
        document = _report(_encode(_rows(kex_algorithms=names)))
        self.assertEqual(
            document["semantic_candidates"]["kex_algorithms"]["supported_candidate_name"],
            "diffie-hellman-group14-sha256",
        )

    def test_known_signature_witness_proves_kex_eligibility_not_first_unknown_hostkey(self):
        hosts = ("unknown-hostkey", "rsa-sha2-256")
        document = _report(
            _encode(_rows(server_host_key_algorithms=hosts)),
            _encode(_rows(server_host_key_algorithms=hosts)),
        )
        candidates = document["semantic_candidates"]
        self.assertEqual(
            candidates["kex_algorithms"]["supported_candidate_name"],
            "diffie-hellman-group14-sha256",
        )
        self.assertEqual(
            candidates["kex_algorithms"]["signature_capable_hostkey_witness"], "rsa-sha2-256"
        )
        self.assertIsNone(candidates["server_host_key_algorithms"]["supported_candidate_name"])
        self.assertFalse(candidates["server_host_key_algorithms"]["encryption_capability_inferred"])
        self.assertEqual(document["outcome"], "unassessed_selection_semantics")

    def test_only_unknown_common_hostkey_withholds_known_kex_eligibility(self):
        hosts = ("unknown-hostkey",)
        document = _report(
            _encode(_rows(server_host_key_algorithms=hosts)),
            _encode(_rows(server_host_key_algorithms=hosts)),
        )
        self.assertEqual(document["declaration_violations"], [])
        self.assertEqual(
            document["semantic_candidates"]["kex_algorithms"]["status"],
            "hostkey_capability_unassessed",
        )
        self.assertIsNone(
            document["semantic_candidates"]["kex_algorithms"]["supported_candidate_name"]
        )

    def test_known_kex_without_common_hostkey_is_a_declaration_contradiction(self):
        document = _report(
            _encode(_rows(server_host_key_algorithms=("ssh-rsa",))),
            _encode(_rows(server_host_key_algorithms=("rsa-sha2-256",))),
        )
        self.assertIn(
            "kex_algorithms:no_common_signature_capable_hostkey", document["declaration_violations"]
        )
        self.assertEqual(document["outcome"], "known_declaration_contradictions")

    def test_unknown_kex_with_no_common_hostkey_is_not_invented_capability_failure(self):
        document = _report(
            _encode(_rows(kex_algorithms=("future-kex",), server_host_key_algorithms=("ssh-rsa",))),
            _encode(
                _rows(kex_algorithms=("future-kex",), server_host_key_algorithms=("rsa-sha2-256",))
            ),
        )
        self.assertEqual(document["declaration_violations"], [])
        self.assertEqual(document["outcome"], "unassessed_selection_semantics")

    def test_every_named_kex_and_signing_hostkey_pair_uses_exact_labels(self):
        exchanges = (
            "diffie-hellman-group1-sha1",
            "diffie-hellman-group14-sha1",
            "diffie-hellman-group14-sha256",
            "diffie-hellman-group15-sha512",
            "diffie-hellman-group16-sha512",
            "diffie-hellman-group17-sha512",
            "diffie-hellman-group18-sha512",
        )
        hosts = (
            "ssh-dss",
            "ssh-rsa",
            "pgp-sign-rsa",
            "pgp-sign-dss",
            "rsa-sha2-256",
            "rsa-sha2-512",
        )
        cases = 0
        for exchange, host in itertools.product(exchanges, hosts):
            rows = _rows(kex_algorithms=(exchange,), server_host_key_algorithms=(host,))
            document = _report(_encode(rows), _encode(rows))
            self.assertEqual(
                document["semantic_candidates"]["kex_algorithms"]["supported_candidate_name"],
                exchange,
            )
            self.assertEqual(
                document["semantic_candidates"]["server_host_key_algorithms"][
                    "supported_candidate_name"
                ],
                host,
            )
            self.assertEqual(document["declaration_violations"], [])
            cases += 1
        self.assertEqual(cases, 42)

    def test_correct_role_ext_info_indicators_do_not_change_kex_candidate(self):
        client = _rows(kex_algorithms=("ext-info-c", "diffie-hellman-group14-sha256"))
        server = _rows(kex_algorithms=("diffie-hellman-group14-sha256", "ext-info-s"))
        document = _report(_encode(client, truth=1), _encode(server, truth=1))
        self.assertEqual(document["declaration_violations"], [])
        self.assertEqual(
            document["semantic_candidates"]["kex_algorithms"]["supported_candidate_name"],
            "diffie-hellman-group14-sha256",
        )
        self.assertTrue(
            document["conditional_optimistic_guesses"][0]["preferred_nonindicator_kex_names_equal"]
        )

    def test_wrong_role_indicators_are_declaration_violations_never_kex_candidates(self):
        client = _rows(kex_algorithms=("ext-info-s", "diffie-hellman-group14-sha256"))
        server = _rows(kex_algorithms=("ext-info-s", "diffie-hellman-group14-sha256"))
        document = _report(_encode(client), _encode(server))
        self.assertEqual(document["literal_first_common_names"]["kex_algorithms"], "ext-info-s")
        self.assertIn("client:incorrect_ext_info_role", document["declaration_violations"])
        self.assertEqual(
            document["semantic_candidates"]["kex_algorithms"]["supported_candidate_name"],
            "diffie-hellman-group14-sha256",
        )
        self.assertFalse(document["claims"]["actual_negotiation_proven"])

    def test_marker_only_lists_and_no_common_kex_are_not_clean(self):
        for client, server in (("ext-info-c", "ext-info-s"), ("future-one", "future-two")):
            document = _report(
                _encode(_rows(kex_algorithms=(client,))), _encode(_rows(kex_algorithms=(server,)))
            )
            self.assertIn(
                "kex_algorithms:no_common_nonindicator_name", document["declaration_violations"]
            )

    def test_other_modern_marker_names_are_not_prefix_stripped(self):
        names = ("kex-strict-c-v00@openssh.com", "diffie-hellman-group14-sha256")
        document = _report(
            _encode(_rows(kex_algorithms=names)), _encode(_rows(kex_algorithms=names))
        )
        self.assertIsNone(
            document["semantic_candidates"]["kex_algorithms"]["supported_candidate_name"]
        )
        self.assertEqual(document["outcome"], "unassessed_selection_semantics")

    def test_unknown_or_aead_cipher_withholds_mac_even_without_literal_match(self):
        for cipher in ("AEAD_AES_128_GCM", "aes128-gcm@openssh.com", "future-cipher"):
            rows = _rows(
                encryption_algorithms_client_to_server=(cipher,),
                mac_algorithms_client_to_server=("hmac-sha1",),
            )
            server = _rows(
                encryption_algorithms_client_to_server=(cipher,),
                mac_algorithms_client_to_server=("hmac-sha2-256",),
            )
            document = _report(_encode(rows), _encode(server))
            self.assertIsNone(
                document["literal_first_common_names"]["mac_algorithms_client_to_server"]
            )
            self.assertIsNone(
                document["semantic_candidates"]["mac_algorithms_client_to_server"][
                    "supported_candidate_name"
                ]
            )
            self.assertNotIn(
                "mac_algorithms_client_to_server:no_common_name", document["declaration_violations"]
            )
            self.assertEqual(document["outcome"], "unassessed_selection_semantics")

    def test_supported_cipher_makes_independent_no_common_mac_adverse(self):
        document = _report(
            _encode(_rows(mac_algorithms_server_to_client=("hmac-sha1",))),
            _encode(_rows(mac_algorithms_server_to_client=("hmac-sha2-256",))),
        )
        self.assertIn(
            "mac_algorithms_server_to_client:no_common_name", document["declaration_violations"]
        )
        self.assertEqual(document["outcome"], "known_declaration_contradictions")

    def test_unknown_mac_and_compression_predecessors_do_not_promote_known_fallbacks(self):
        for field, known in (
            ("mac_algorithms_client_to_server", "hmac-sha2-256"),
            ("compression_algorithms_server_to_client", "none"),
        ):
            names = ("unknown-method", known)
            document = _report(_encode(_rows(**{field: names})), _encode(_rows(**{field: names})))
            self.assertIsNone(document["semantic_candidates"][field]["supported_candidate_name"])
            self.assertEqual(
                document["semantic_candidates"][field]["known_fallback_witness"], known
            )
            self.assertEqual(document["outcome"], "unassessed_selection_semantics")

    def test_finite_cipher_mac_compression_names_and_explicit_none(self):
        tables = (
            (
                _FIELDS[2],
                (
                    "aes128-cbc",
                    "aes192-cbc",
                    "aes256-cbc",
                    "aes128-ctr",
                    "aes192-ctr",
                    "aes256-ctr",
                    "none",
                ),
            ),
            (
                _FIELDS[4],
                (
                    "hmac-sha1",
                    "hmac-sha1-96",
                    "hmac-md5",
                    "hmac-md5-96",
                    "none",
                    "hmac-sha2-256",
                    "hmac-sha2-512",
                ),
            ),
            (_FIELDS[6], ("none", "zlib")),
        )
        for field, names in tables:
            for name in names:
                rows = _rows(**{field: (name,)})
                document = _report(_encode(rows), _encode(rows))
                self.assertEqual(
                    document["semantic_candidates"][field]["supported_candidate_name"], name
                )
                self.assertEqual(document["declaration_violations"], [])

    def test_known_contradictions_dominate_unknowns_and_are_sorted(self):
        client = _rows(
            kex_algorithms=("unknown-kex",),
            encryption_algorithms_client_to_server=("aes128-ctr",),
            compression_algorithms_server_to_client=("none",),
        )
        server = _rows(
            kex_algorithms=("unknown-kex",),
            encryption_algorithms_client_to_server=("aes256-ctr",),
            compression_algorithms_server_to_client=("zlib",),
        )
        document = _report(_encode(client), _encode(server))
        self.assertEqual(document["outcome"], "known_declaration_contradictions")
        self.assertEqual(
            document["declaration_violations"], sorted(set(document["declaration_violations"]))
        )
        self.assertTrue(document["unassessed_selection_semantics"])

    def test_optimistic_declared_true_and_preference_mismatch_are_conditional_only(self):
        client = _rows(
            kex_algorithms=("diffie-hellman-group14-sha256", "diffie-hellman-group16-sha512")
        )
        server = _rows(
            kex_algorithms=("diffie-hellman-group16-sha512", "diffie-hellman-group14-sha256")
        )
        document = _report(_encode(client, truth=255), _encode(server, truth=1))
        for row in document["conditional_optimistic_guesses"]:
            self.assertEqual(
                row["conditional_rule"], "if_a_guessed_packet_follows_the_preference_guess_is_wrong"
            )
            self.assertFalse(row["following_packet_observed"])
            self.assertFalse(row["packet_discard_performed"])
        self.assertFalse(document["claims"]["guessed_packet_existence_proven"])

    def test_optimistic_supported_unknown_and_no_guess_conditions(self):
        ordinary = _report(_encode(truth=1))
        self.assertEqual(
            ordinary["conditional_optimistic_guesses"][0]["conditional_rule"],
            "if_a_guessed_packet_follows_the_supported_base_guess_is_consistent",
        )
        self.assertEqual(
            ordinary["conditional_optimistic_guesses"][1]["conditional_rule"],
            "no_following_guess_declared",
        )
        names = ("future-kex", "diffie-hellman-group14-sha256")
        unknown = _report(
            _encode(_rows(kex_algorithms=names), truth=1), _encode(_rows(kex_algorithms=names))
        )
        self.assertEqual(
            unknown["conditional_optimistic_guesses"][0]["conditional_rule"],
            "conditional_guess_assessment_unassessed",
        )

    def test_schema_native_aliases_and_subclasses_reject_before_hash(self):
        class Text(str):
            pass

        class Mapping(dict):
            pass

        variants = (True, 1.0, "1", None)
        for version in variants:
            model = _model()
            model["schema_version"] = version
            with patch.object(ssh.hashlib, "sha256") as digest:
                with self.assertRaises(ssh.SshKexinitAnalysisError):
                    ssh.analyze_supplied_ssh_kexinit_pair(model)
                digest.assert_not_called()
        for model in (
            Mapping(_model()),
            {**_model(), "source_id": Text("native")},
            {**_model(), "unknown": 1},
            None,
        ):
            with self.assertRaises(ssh.SshKexinitAnalysisError):
                ssh.analyze_supplied_ssh_kexinit_pair(model)

    def test_base64_native_alias_wrong_utf8_and_noncanonical_padding_reject(self):
        model = _model()
        encoded = model["client_payload_base64"]
        for value in (None, True, 1, b"bytes", encoded + "=", encoded + "\n", "AA=A", "AAAA-"):
            with self.subTest(value=value), self.assertRaises(ssh.SshKexinitAnalysisError):
                ssh.analyze_supplied_ssh_kexinit_pair({**model, "client_payload_base64": value})
        for value in (b"\xff", bytearray(b"{}"), "{}", b""):
            with self.assertRaises(ssh.SshKexinitAnalysisError):
                ssh.analyze_supplied_ssh_kexinit_pair_bytes(model_bytes=value)
        with self.assertRaises(ssh.SshKexinitAnalysisError):
            ssh.analyze_supplied_ssh_kexinit_pair({**model, "client_payload_base64": "AB=="})

    def test_raw_duplicate_float_integer_and_malformed_lexemes_are_domain_rejections(self):
        for raw in (
            b'{"schema_version":1,"schema_version":1}',
            b'{"x":1.0}',
            b'{"x":NaN}',
            b'{"x":9223372036854775808}',
            b'{"x":-9223372036854775809}',
            b'{"x":--1}',
            b'{"x":01}',
            b'{"x":}',
            b'{"x":"\\ud800"}',
        ):
            with self.subTest(raw=raw), self.assertRaises(ssh.SshKexinitAnalysisError):
                ssh.analyze_supplied_ssh_kexinit_pair_bytes(model_bytes=raw)

    def test_raw_depth_node_string_and_integer_caps_precede_decoder(self):
        raw_cases = (
            (b"[" * 16 + b"0" + b"]" * 16),
            (b"[" + b"0," * 4096 + b"0]"),
            (b'{"x":"' + b"a" * (ssh.MAX_STRING_BYTES + 1) + b'"}'),
            (b'{"x":9223372036854775808}'),
        )
        for raw in raw_cases:
            with (
                patch.object(ssh.json, "loads") as decoder,
                patch.object(ssh.hashlib, "sha256") as digest,
            ):
                with self.assertRaises(ssh.SshKexinitAnalysisError):
                    ssh.analyze_supplied_ssh_kexinit_pair_bytes(model_bytes=raw)
                decoder.assert_not_called()
                digest.assert_not_called()

    def test_cyclic_shared_container_and_native_queued_nodes_are_bounded(self):
        cycle = []
        cycle.append(cycle)
        for extra in (cycle, [0] * 4096, 2**64, "a" * (ssh.MAX_STRING_BYTES + 1)):
            with patch.object(ssh.hashlib, "sha256") as digest:
                with self.assertRaises(ssh.SshKexinitAnalysisError):
                    ssh.analyze_supplied_ssh_kexinit_pair({**_model(), "extra": extra})
                digest.assert_not_called()
        shared = [0] * 128
        with self.assertRaises(ssh.SshKexinitAnalysisError):
            ssh.analyze_supplied_ssh_kexinit_pair({**_model(), "extra": [shared] * 33})

    def test_actual_name_and_entry_count_boundaries(self):
        for names in (("x" * 64,), ("x",) * 128):
            document = _report(_encode(_rows(kex_algorithms=names)))
            self.assertEqual(document["client"]["name_lists"][0]["names"], list(names))
        for names in (("x" * 65,), ("x",) * 129):
            with patch.object(ssh.hashlib, "sha256") as digest:
                with self.assertRaises(ssh.SshKexinitAnalysisError):
                    _report(_encode(_rows(kex_algorithms=names)))
                digest.assert_not_called()

    def test_actual_list_and_payload_byte_boundaries(self):
        for size in (8192, 8193):
            raw = _encode(_rows(languages_client_to_server=_names_with_encoded_size(size)))
            if size == 8192:
                self.assertEqual(_report(raw)["client"]["name_lists"][8]["declared_bytes"], size)
            else:
                with self.assertRaises(ssh.SshKexinitAnalysisError):
                    _report(raw)
        rows = [_names_with_encoded_size(size) for size in (8192, 8192, 8192, 8130)] + [()] * 6
        raw = _encode(rows)
        self.assertEqual(len(raw), 32768)
        self.assertEqual(_report(raw)["client"]["payload_bytes"], 32768)
        rows[3] = _names_with_encoded_size(8131)
        with patch.object(ssh.hashlib, "sha256") as digest:
            with self.assertRaises(ssh.SshKexinitAnalysisError):
                _report(_encode(rows))
            digest.assert_not_called()

    def test_actual_raw_model_byte_ceiling_precedes_decode(self):
        for raw in (b" " * (ssh.MAX_MODEL_BYTES + 1), b'{"x":"' + b"\\u007f" * 22_000 + b'"}'):
            with (
                patch.object(ssh.json, "loads") as decoder,
                patch.object(ssh.hashlib, "sha256") as digest,
            ):
                with self.assertRaises(ssh.SshKexinitAnalysisError):
                    ssh.analyze_supplied_ssh_kexinit_pair_bytes(model_bytes=raw)
                decoder.assert_not_called()
                digest.assert_not_called()

    def test_reduced_retained_output_and_node_limits_deny_before_any_hash(self):
        model = _model()
        document = ssh.analyze_supplied_ssh_kexinit_pair(model).to_dict()
        fixed_limits = document["software_limits"]
        budget = ssh._Budget()
        size, nodes = ssh._measure(document, budget, report=True)
        for setting, ceiling in (("MAX_REPORT_BYTES", size - 1), ("MAX_REPORT_NODES", nodes - 1)):
            with (
                patch.object(ssh, "_limits", return_value=fixed_limits),
                patch.object(ssh, setting, ceiling),
                patch.object(ssh.hashlib, "sha256") as digest,
            ):
                with self.assertRaises(ssh.SshKexinitAnalysisError):
                    ssh.analyze_supplied_ssh_kexinit_pair(model)
                digest.assert_not_called()

    def test_all_eight_public_forms_prefund_exact_work_before_first_sha(self):
        model = _model()
        result = ssh.analyze_supplied_ssh_kexinit_pair(model)
        text, document = result.to_json(), result.to_dict()
        fixed_limits = document["software_limits"]
        operations = (
            lambda: ssh.analyze_supplied_ssh_kexinit_pair(model),
            lambda: ssh.analyze_supplied_ssh_kexinit_pair_bytes(
                model_bytes=_canonical(model).encode("ascii")
            ),
            lambda: ssh.SshKexinitAnalysis(text),
            lambda: ssh.SshKexinitAnalysis.from_dict(document),
            lambda: ssh.SshKexinitAnalysis.from_json(text),
            lambda: result.to_dict(),
            lambda: result.to_json(),
            lambda: ssh.verify_supplied_ssh_kexinit_analysis(result, model=model),
        )
        real_charge, real_sha = ssh._Budget.charge, hashlib.sha256
        for index, operation in enumerate(operations):
            with self.subTest(operation=index):
                budgets = {}
                hashed = [False]

                def charge(budget, amount, *, owned_hashed=hashed, owned_budgets=budgets):
                    self.assertFalse(
                        owned_hashed[0], "No public work may be charged after first SHA"
                    )
                    real_charge(budget, amount)
                    owned_budgets[id(budget)] = budget.used

                def digest(*args, owned_hashed=hashed, **kwargs):
                    owned_hashed[0] = True
                    return real_sha(*args, **kwargs)

                with (
                    patch.object(ssh._Budget, "charge", charge),
                    patch.object(ssh.hashlib, "sha256", digest),
                ):
                    operation()
                self.assertTrue(hashed[0])
                self.assertEqual(len(budgets), 1)
                threshold = next(iter(budgets.values()))
                with (
                    patch.object(ssh, "_limits", return_value=fixed_limits),
                    patch.object(ssh, "MAX_WORK", threshold),
                ):
                    operation()
                with (
                    patch.object(ssh, "_limits", return_value=fixed_limits),
                    patch.object(ssh, "MAX_WORK", threshold - 1),
                    patch.object(ssh.hashlib, "sha256") as no_hash,
                ):
                    with self.assertRaises(ssh.SshKexinitAnalysisError):
                        operation()
                    no_hash.assert_not_called()

    def test_cohashed_false_outcomes_and_candidates_fail_full_source_replay(self):
        document = _report()
        mutations = (
            lambda value: value.__setitem__("outcome", "unassessed_selection_semantics"),
            lambda value: value["semantic_candidates"]["kex_algorithms"].__setitem__(
                "supported_candidate_name", "diffie-hellman-group1-sha1"
            ),
            lambda value: value["client"].__setitem__("first_kex_packet_follows", True),
            lambda value: value["declaration_violations"].append("invented"),
            lambda value: value["claims"].__setitem__("actual_negotiation_proven", True),
            lambda value: value["effects"].__setitem__("packet_discard", "performed"),
        )
        for mutation in mutations:
            changed = copy.deepcopy(document)
            mutation(changed)
            _readdress(changed)
            for operation in (
                lambda value=changed: ssh.SshKexinitAnalysis.from_dict(value),
                lambda value=changed: ssh.SshKexinitAnalysis.from_json(_canonical(value)),
                lambda value=changed: _wrapper(_canonical(value)).to_dict(),
            ):
                with self.assertRaises(ssh.SshKexinitAnalysisError):
                    operation()

    def test_report_boolean_integer_float_aliases_do_not_survive_cohash(self):
        for value in (0, 0.0, None):
            document = _report()
            document["client"]["first_kex_packet_follows"] = value
            _readdress(document)
            with self.assertRaises(ssh.SshKexinitAnalysisError):
                ssh.SshKexinitAnalysis.from_dict(document)
        document = _report()
        document["schema_version"] = True
        _readdress(document)
        with self.assertRaises(ssh.SshKexinitAnalysisError):
            ssh.SshKexinitAnalysis.from_json(_canonical(document))

    def test_valid_alternate_embedded_source_never_verifies_separate_original(self):
        original = _model()
        alternate = {**original, "source_id": "alternate"}
        result = ssh.analyze_supplied_ssh_kexinit_pair(alternate)
        self.assertEqual(
            ssh.SshKexinitAnalysis.from_json(result.to_json()).to_json(), result.to_json()
        )
        with self.assertRaises(ssh.SshKexinitAnalysisError):
            ssh.verify_supplied_ssh_kexinit_analysis(result, model=original)
        for change in ("client_payload_base64", "server_payload_base64"):
            other = {**original, change: base64.b64encode(_encode(reserved=1)).decode("ascii")}
            result = ssh.analyze_supplied_ssh_kexinit_pair(other)
            with self.assertRaises(ssh.SshKexinitAnalysisError):
                ssh.verify_supplied_ssh_kexinit_analysis(result, model=original)

    def test_noncanonical_report_text_rejects_but_raw_model_spelling_is_not_provenance(self):
        model = _model()
        result = ssh.analyze_supplied_ssh_kexinit_pair(model)
        raw = json.dumps(model, indent=2).encode("ascii")
        self.assertEqual(
            ssh.analyze_supplied_ssh_kexinit_pair_bytes(model_bytes=raw).to_json(), result.to_json()
        )
        for text in (" " + result.to_json(), json.dumps(result.to_dict(), indent=2)):
            with self.assertRaises(ssh.SshKexinitAnalysisError):
                ssh.SshKexinitAnalysis.from_json(text)

    def test_complete_native_wrapper_subclass_missing_slot_and_late_mutation_reject(self):
        class Derived(ssh.SshKexinitAnalysis):
            pass

        text = ssh.analyze_supplied_ssh_kexinit_pair(_model()).to_json()
        with self.assertRaises(ssh.SshKexinitAnalysisError):
            Derived(text)
        incomplete = object.__new__(ssh.SshKexinitAnalysis)
        with self.assertRaises(ssh.SshKexinitAnalysisError):
            incomplete.to_dict()
        changed = _wrapper(text)
        object.__setattr__(changed, "document_json", "{}")
        for operation in (
            changed.to_dict,
            changed.to_json,
            lambda: ssh.verify_supplied_ssh_kexinit_analysis(changed, model=_model()),
        ):
            with self.assertRaises(ssh.SshKexinitAnalysisError):
                operation()

    def test_report_has_only_false_claims_none_effects_and_exact_existing_ownership(self):
        document = _report()
        self.assertTrue(all(value is False for value in document["claims"].values()))
        self.assertEqual(set(document["effects"].values()), {"none"})
        self.assertEqual(
            (
                document["profile_id"],
                document["capability_id"],
                document["vector_id"],
                document["wave_id"],
                document["commander_id"],
                document["command_group_id"],
                document["validator_id"],
                document["evidence_package_ids"],
            ),
            (
                "AOE-GC-D12-S06",
                "army.gc.d12.s06",
                "AV-GC-D12-S06-01",
                "IW2-006",
                "AOE-GC-D12-CMD",
                "AOE-HQ-05",
                "AOE-HQ-19",
                ["A7.4"],
            ),
        )


if __name__ == "__main__":
    unittest.main()
