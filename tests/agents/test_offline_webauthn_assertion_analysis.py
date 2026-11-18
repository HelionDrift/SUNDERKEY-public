"""Independent supplied-byte/context controls, not authentication fixtures."""

import base64
import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_webauthn_assertion_analysis as w


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def readdress(document):
    result = copy.deepcopy(document)
    body = {
        key: value for key, value in result.items() if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = hashlib.sha256(
        b"sunderkey.offline-webauthn-assertion-analysis.v1\n" + canonical(body).encode("ascii")
    ).hexdigest()
    result["analysis_sha256"] = "sha256:" + digest
    result["analysis_id"] = "WAA-" + digest[:32].upper()
    return result


def model(*, flags=5, count=1, client=None, context=None, tail=b""):
    # Separate octet arithmetic, not a leaf-private encoder.
    result = w.component_fixture()
    if context:
        result["context"].update(context)
    prefix = hashlib.sha256(result["context"]["rp_id"].encode("ascii")).digest()
    data = prefix + bytes([flags]) + bytes((count >> shift) & 255 for shift in (24, 16, 8, 0))
    result["authenticator_data_base64"] = base64.b64encode(data + tail).decode("ascii")
    if client is not None:
        raw = (
            client
            if type(client) is bytes
            else json.dumps(client, ensure_ascii=False).encode("utf-8")
        )
        result["client_data_json_base64"] = base64.b64encode(raw).decode("ascii")
    return result


def client_data():
    return json.loads(base64.b64decode(w.component_fixture()["client_data_json_base64"]))


class WebAuthnAssertionAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.model = w.component_fixture()
        self.report = w.analyze_supplied_webauthn_assertion(self.model)
        self.document = self.report.to_dict()

    def test_literal_fixture_identities_and_preimage(self):
        self.assertEqual(self.document["analysis_id"], "WAA-BE65FA2B0545BFC348421C8EB4E4ACA8")
        self.assertEqual(
            self.document["analysis_sha256"],
            "sha256:be65fa2b0545bfc348421c8eb4e4aca8f5ef18a89b86ac71bad48e7b13c42f7a",
        )
        self.assertEqual(
            self.document["source_model_sha256"],
            "sha256:dbbca9327380669976d8ace7ace7f583e8b4b9b11abf43ae733b1bd171b76cc9",
        )
        self.assertEqual(
            self.document["authenticator_data_sha256"],
            "sha256:8c4880fbae44870cb9f7e664ec7ce8c5049d3a6b2875921f2f8c8dc8ba406859",
        )
        self.assertEqual(
            self.document["client_data_json_sha256"],
            "sha256:6986406c42c310130d9fd30dee5dbf9542cbbb66afa4af4c1a77372c4ce80bb2",
        )
        self.assertEqual(
            self.document["signature_input_sha256"],
            "sha256:49c97136c9313a6fd5f4083af786bedd11148feabcaae7d5432ba92db8b6e4a4",
        )
        auth = base64.b64decode(self.model["authenticator_data_base64"])
        raw = base64.b64decode(self.model["client_data_json_base64"])
        self.assertEqual(
            self.document["signature_input_sha256"],
            "sha256:" + hashlib.sha256(auth + hashlib.sha256(raw).digest()).hexdigest(),
        )
        self.assertEqual(self.document["signature_input_bytes"], 69)
        self.assertTrue(all(self.document["checks"].values()))
        self.assertEqual(self.document["counter_relation"], "increased")

    def test_all_eight_public_paths_and_fresh_fixture(self):
        text = canonical(self.document)
        results = [
            w.analyze_supplied_webauthn_assertion(self.model),
            w.analyze_supplied_webauthn_assertion_bytes(model_bytes=canonical(self.model).encode()),
            w.WebAuthnAssertionAnalysis(text),
            w.WebAuthnAssertionAnalysis.from_dict(self.document),
            w.WebAuthnAssertionAnalysis.from_json(text),
            w.verify_supplied_webauthn_assertion_analysis(self.report, model=self.model),
        ]
        for result in results:
            self.assertEqual(result.to_dict(), self.document)
            self.assertEqual(result.to_json(), text)
        self.assertIsNot(w.component_fixture(), w.component_fixture())
        self.assertIsNot(w.component_fixture()["context"], w.component_fixture()["context"])

    def test_complete_256_flag_table(self):
        for flags in range(256):
            with self.subTest(flags=flags):
                result = w.analyze_supplied_webauthn_assertion(model(flags=flags)).to_dict()
                checks = result["checks"]
                unsupported = bool(flags & (2 + 32 + 64 + 128))
                contradiction = (
                    not bool(flags & 1)
                    or not bool(flags & 4)
                    or bool(flags & 16)
                    and not bool(flags & 8)
                )
                expected = (
                    "contradictory_supplied_checks"
                    if contradiction
                    else (
                        "unassessed_supported_profile"
                        if unsupported
                        else "consistent_with_supplied_checks"
                    )
                )
                self.assertEqual(result["analysis_status"], expected)
                self.assertEqual(checks["user_present_bit_set"], bool(flags & 1))
                self.assertEqual(
                    checks["backup_flags_consistent"], not flags & 16 or bool(flags & 8)
                )
                self.assertEqual(
                    checks["fixed_layout_length_matches"], None if unsupported else True
                )
                self.assertEqual(result["authenticator_prefix"]["flags_byte"], flags)

    def test_uv_not_required_preserves_up_requirement(self):
        for flags in (0, 1, 4, 5):
            result = w.analyze_supplied_webauthn_assertion(
                model(flags=flags, context={"user_verification_required": False})
            ).to_dict()
            self.assertTrue(result["checks"]["user_verification_requirement_satisfied"])
            self.assertEqual(result["checks"]["user_present_bit_set"], flags in (1, 5))

    def test_unknown_suffix_is_not_parsed_and_known_contradictions_survive(self):
        for flags in (0x45, 0x85, 0x27, 0xC5):
            result = w.analyze_supplied_webauthn_assertion(
                model(flags=flags, tail=b"\xff\x00not-CBOR")
            ).to_dict()
            self.assertEqual(result["analysis_status"], "unassessed_supported_profile")
            self.assertEqual(result["authenticator_prefix"]["unparsed_suffix_bytes"], 10)
            self.assertIsNone(result["checks"]["fixed_layout_length_matches"])
        value = client_data()
        value["origin"] = "https://foreign.invalid"
        result = w.analyze_supplied_webauthn_assertion(model(flags=0xD5, client=value)).to_dict()
        self.assertEqual(result["analysis_status"], "contradictory_supplied_checks")
        self.assertFalse(result["checks"]["backup_flags_consistent"])
        self.assertFalse(result["checks"]["origin_matches"])
        self.assertEqual(len(result["unsupported_reasons"]), 2)

    def test_unextended_extra_tail_contradicts_and_truncated_prefix_denies(self):
        result = w.analyze_supplied_webauthn_assertion(model(tail=b"\x00")).to_dict()
        self.assertFalse(result["checks"]["fixed_layout_length_matches"])
        self.assertEqual(result["analysis_status"], "contradictory_supplied_checks")
        raw = base64.b64decode(self.model["authenticator_data_base64"])
        for length in range(37):
            value = copy.deepcopy(self.model)
            value["authenticator_data_base64"] = base64.b64encode(raw[:length]).decode()
            with self.subTest(length=length), self.assertRaises(w.WebAuthnAssertionAnalysisError):
                w.analyze_supplied_webauthn_assertion(value)

    def test_bom_semantics_and_unchanged_raw_hash(self):
        raw = base64.b64decode(self.model["client_data_json_base64"])
        result = w.analyze_supplied_webauthn_assertion(
            model(client=b"\xef\xbb\xbf" + raw)
        ).to_dict()
        self.assertTrue(all(result["checks"].values()))
        self.assertTrue(result["client_data"]["leading_bom_present"])
        self.assertEqual(
            result["client_data_json_sha256"],
            "sha256:" + hashlib.sha256(b"\xef\xbb\xbf" + raw).hexdigest(),
        )
        self.assertNotEqual(
            result["client_data_json_sha256"], self.document["client_data_json_sha256"]
        )

    def test_client_member_spelling_order_and_unknown_values(self):
        original = client_data()
        original["unknown"] = {"nested": [None, True, 1.25, "non-ASCII-" + chr(9731)]}
        forms = [
            json.dumps(original).encode(),
            json.dumps(original, ensure_ascii=False, indent=2).encode(),
            json.dumps(dict(reversed(list(original.items())))).encode(),
        ]
        identities = set()
        for raw in forms:
            result = w.analyze_supplied_webauthn_assertion(model(client=raw)).to_dict()
            self.assertTrue(all(result["checks"].values()))
            self.assertEqual(result["client_data"]["unknown_member_count"], 1)
            identities.add(result["client_data_json_sha256"])
        self.assertEqual(len(identities), 3)
        raw = base64.b64decode(self.model["client_data_json_base64"]).replace(
            b'"type"', b'"t\\u0079pe"'
        )
        result = w.analyze_supplied_webauthn_assertion(model(client=raw)).to_dict()
        self.assertTrue(result["checks"]["client_type_matches"])
        self.assertNotEqual(
            result["client_data_json_sha256"], self.document["client_data_json_sha256"]
        )

    def test_unknown_number_lexicals_not_native_numeric_conversion(self):
        raw = base64.b64decode(self.model["client_data_json_base64"])
        for lexical in (b"1e99999999999999999999", b"-0.125", b"9" * 128):
            result = w.analyze_supplied_webauthn_assertion(
                model(client=raw[:-1] + b',"unknown":' + lexical + b"}")
            ).to_dict()
            self.assertTrue(all(result["checks"].values()))
        value = raw[:-1] + b',"unknown":' + b"9" * 129 + b"}"
        changed = model(client=value)
        with (
            patch.object(w.json, "loads", side_effect=AssertionError("decoder reached")),
            patch.object(w.hashlib, "sha256", side_effect=AssertionError("hash reached")),
            self.assertRaises(w.WebAuthnAssertionAnalysisError),
        ):
            w.analyze_supplied_webauthn_assertion(changed)

    def test_known_fields_do_not_accept_number_placeholders(self):
        for key in ("type", "origin", "challenge", "topOrigin", "crossOrigin"):
            value = client_data()
            value[key] = 0
            with self.subTest(key=key), self.assertRaises(w.WebAuthnAssertionAnalysisError):
                w.analyze_supplied_webauthn_assertion(model(client=value))

    def test_challenge_uses_separate_bytes_and_canonical_unpadded_url_encoding(self):
        for challenge in (b"", b"\xff", b"\xfb\xff", bytes(range(256)) * 4):
            value = client_data()
            value["challenge"] = base64.urlsafe_b64encode(challenge).decode().rstrip("=")
            result = w.analyze_supplied_webauthn_assertion(
                model(
                    client=value, context={"challenge_base64": base64.b64encode(challenge).decode()}
                )
            ).to_dict()
            self.assertTrue(result["checks"]["challenge_matches"])
            if challenge:
                value["challenge"] += "="
                self.assertFalse(
                    w.analyze_supplied_webauthn_assertion(
                        model(
                            client=value,
                            context={"challenge_base64": base64.b64encode(challenge).decode()},
                        )
                    ).to_dict()["checks"]["challenge_matches"]
                )

    def test_wrong_type_challenge_origin_and_rp_are_observations(self):
        for key, changed in (
            ("type", "webauthn.create"),
            ("challenge", "wrong"),
            ("origin", "https://other.invalid"),
        ):
            value = client_data()
            value[key] = changed
            result = w.analyze_supplied_webauthn_assertion(model(client=value)).to_dict()
            self.assertFalse(
                result["checks"][
                    {
                        "type": "client_type_matches",
                        "challenge": "challenge_matches",
                        "origin": "origin_matches",
                    }[key]
                ]
            )
            self.assertEqual(result["analysis_status"], "contradictory_supplied_checks")
        value = copy.deepcopy(self.model)
        value["context"]["rp_id"] = "different.invalid"
        result = w.analyze_supplied_webauthn_assertion(value).to_dict()
        self.assertFalse(result["checks"]["rp_id_hash_matches"])

    def test_absent_cross_origin_defaults_false(self):
        value = client_data()
        del value["crossOrigin"]
        result = w.analyze_supplied_webauthn_assertion(model(client=value)).to_dict()
        self.assertFalse(result["client_data"]["cross_origin_present"])
        self.assertFalse(result["client_data"]["cross_origin"])
        self.assertTrue(result["checks"]["cross_origin_matches"])
        self.assertFalse(
            w.analyze_supplied_webauthn_assertion(
                model(client=value, context={"cross_origin": True})
            ).to_dict()["checks"]["cross_origin_matches"]
        )

    def test_cross_top_origin_exact_presence_and_value_table(self):
        for observed_cross in (False, True):
            for expected_cross in (False, True):
                for observed_top in (None, "https://top.invalid", "https://foreign.invalid"):
                    for expected_top in (None, "https://top.invalid"):
                        if expected_top and not expected_cross:
                            continue
                        value = client_data()
                        value["crossOrigin"] = observed_cross
                        if observed_top is not None:
                            value["topOrigin"] = observed_top
                        result = w.analyze_supplied_webauthn_assertion(
                            model(
                                client=value,
                                context={
                                    "cross_origin": expected_cross,
                                    "top_origin": expected_top,
                                },
                            )
                        ).to_dict()
                        checks = result["checks"]
                        self.assertEqual(
                            checks["cross_origin_matches"], observed_cross == expected_cross
                        )
                        self.assertEqual(
                            checks["top_origin_presence_matches"],
                            (observed_top is None) == (expected_top is None),
                        )
                        self.assertEqual(
                            checks["top_origin_value_matches"], observed_top == expected_top
                        )
                        self.assertEqual(
                            checks["top_origin_cross_origin_consistent"],
                            observed_top is None or observed_cross,
                        )

    def test_optional_top_origin_and_null_field_are_distinct(self):
        value = client_data()
        value["crossOrigin"] = True
        result = w.analyze_supplied_webauthn_assertion(
            model(client=value, context={"cross_origin": True})
        ).to_dict()
        self.assertTrue(all(result["checks"].values()))
        value["topOrigin"] = None
        with self.assertRaises(w.WebAuthnAssertionAnalysisError):
            w.analyze_supplied_webauthn_assertion(
                model(client=value, context={"cross_origin": True})
            )

    def test_counter_relations_all_boundary_pairs(self):
        for previous in (None, 0, 1, 2, 0xFFFFFFFF):
            for count in (0, 1, 2, 0xFFFFFFFF):
                expected = (
                    "prior_unavailable"
                    if previous is None
                    else (
                        "both_zero"
                        if previous == count == 0
                        else "increased"
                        if count > previous
                        else "nonincreasing_signal"
                    )
                )
                result = w.analyze_supplied_webauthn_assertion(
                    model(count=count, context={"previous_sign_count": previous})
                ).to_dict()
                self.assertEqual(result["counter_relation"], expected)
                self.assertEqual(result["analysis_status"], "consistent_with_supplied_checks")
                self.assertEqual(result["authenticator_prefix"]["sign_count"], count)

    def test_fixed_claims_effects_and_exact_registry_bindings(self):
        self.assertTrue(all(value is False for value in self.document["claims"].values()))
        self.assertTrue(all(value == "none" for value in self.document["effects"].values()))
        self.assertEqual(self.document["profile_id"], "AOE-GA-D03-S08")
        self.assertEqual(self.document["commander_id"], "AOE-GA-D03-CMD")
        self.assertEqual(self.document["independent_validator_id"], "AOE-HQ-19")
        self.assertIn("unsanitized", " ".join(self.document["limitations"]))

    def test_model_context_closed_keys_and_schema_aliases(self):
        values = []
        for schema in (True, False, 1.0, "1", None):
            value = copy.deepcopy(self.model)
            value["schema_version"] = schema
            values.append(value)
        value = copy.deepcopy(self.model)
        value["unknown"] = True
        values.append(value)
        for key in self.model:
            value = copy.deepcopy(self.model)
            del value[key]
            values.append(value)
        value = copy.deepcopy(self.model)
        value["context"]["unknown"] = True
        values.append(value)
        for value in values:
            with self.subTest(value=value), self.assertRaises(w.WebAuthnAssertionAnalysisError):
                w.analyze_supplied_webauthn_assertion(value)

    def test_malformed_context_families_and_uint32_bounds(self):
        for key, values in {
            "cross_origin": (0, 1, [], {}, None),
            "user_verification_required": (0, 1, [], {}, None),
            "previous_sign_count": (True, 0.0, -1, 2**32, "0", [], {}),
            "rp_id": (None, [], {}, "", chr(127), "a" * 254),
            "origin": (None, [], {}, "", "a" * 2049),
            "top_origin": (True, [], {}, "", "a" * 2049),
        }.items():
            for changed in values:
                value = copy.deepcopy(self.model)
                value["context"][key] = changed
                with (
                    self.subTest(key=key, changed=changed),
                    self.assertRaises(w.WebAuthnAssertionAnalysisError),
                ):
                    w.analyze_supplied_webauthn_assertion(value)
        value = copy.deepcopy(self.model)
        value["context"]["top_origin"] = "https://top.invalid"
        with self.assertRaises(w.WebAuthnAssertionAnalysisError):
            w.analyze_supplied_webauthn_assertion(value)

    def test_native_subclasses_cycles_and_unsupported_families_before_hash(self):
        class Text(str):
            pass

        class Integer(int):
            pass

        class Document(dict):
            pass

        values = [Document(self.model), [], (), None]
        for parent, key, changed in (
            (None, "schema_version", Integer(1)),
            (None, "source_id", Text("fixture-assertion-01")),
            ("context", "rp_id", Text("example.invalid")),
            ("context", "previous_sign_count", Integer(0)),
        ):
            value = copy.deepcopy(self.model)
            (value if parent is None else value[parent])[key] = changed
            values.append(value)
        cycle = copy.deepcopy(self.model)
        cycle["loop"] = cycle
        values.append(cycle)
        with patch.object(w.hashlib, "sha256", side_effect=AssertionError("hash reached")):
            for value in values:
                with self.assertRaises(w.WebAuthnAssertionAnalysisError):
                    w.analyze_supplied_webauthn_assertion(value)

    def test_byte_intake_exact_native_and_bounded(self):
        content = canonical(self.model).encode()

        class Bytes(bytes):
            pass

        for value in (
            bytearray(content),
            memoryview(content),
            Bytes(content),
            content.decode(),
            b"",
            b"x" * (w.MAX_MODEL_BYTES + 1),
            b"\xff",
        ):
            with self.assertRaises(w.WebAuthnAssertionAnalysisError):
                w.analyze_supplied_webauthn_assertion_bytes(model_bytes=value)

    def test_noncanonical_base64_and_declared_bounds_before_decoder(self):
        for key, value in (
            ("authenticator_data_base64", "A" * 5500),
            ("client_data_json_base64", "A" * 21848),
            ("authenticator_data_base64", "AA=A"),
            ("authenticator_data_base64", "x"),
            ("client_data_json_base64", "e31="),
        ):
            changed = copy.deepcopy(self.model)
            changed[key] = value
            with (
                self.subTest(key=key, value=value[:10]),
                self.assertRaises(w.WebAuthnAssertionAnalysisError),
            ):
                w.analyze_supplied_webauthn_assertion(changed)
        changed = copy.deepcopy(self.model)
        changed["context"]["challenge_base64"] = base64.b64encode(bytes(1025)).decode()
        with (
            patch.object(w.base64, "b64decode", side_effect=AssertionError("decoder reached")),
            self.assertRaises(w.WebAuthnAssertionAnalysisError),
        ):
            w.analyze_supplied_webauthn_assertion(changed)

    def test_client_duplicate_keys_malformed_utf8_and_json(self):
        raw = base64.b64decode(self.model["client_data_json_base64"])
        for value in (
            b"\xff" + raw,
            b"\xef\xbb\xbf\xef\xbb\xbf" + raw,
            b"[]",
            b"null",
            b"{",
            b'{"type":"webauthn.get","type":"webauthn.get"}',
            raw[:-1] + b',"unknown":{"x":1,"x":2}}',
        ):
            changed = model(client=value)
            with (
                self.subTest(value=value[:10]),
                self.assertRaises(w.WebAuthnAssertionAnalysisError),
            ):
                w.analyze_supplied_webauthn_assertion(changed)

    def test_inner_unicode_del_controls_and_unpaired_escape_are_bounded(self):
        value = client_data()
        value["unknown"] = [chr(127), chr(0), chr(128512), "\ud800"]
        raw = json.dumps(value, ensure_ascii=True).encode()
        result = w.analyze_supplied_webauthn_assertion(model(client=raw)).to_dict()
        self.assertTrue(all(result["checks"].values()))
        value["origin"] = "\ud800"
        result = w.analyze_supplied_webauthn_assertion(
            model(client=json.dumps(value).encode())
        ).to_dict()
        self.assertFalse(result["checks"]["origin_matches"])
        self.assertEqual(result["client_data"]["origin"], "\ud800")

    def test_raw_outer_integer_depth_and_node_guards_before_decoder(self):
        base = canonical(self.model).encode()
        invalid = [
            base.replace(b'"schema_version":1', b'"schema_version":' + text)
            for text in (b"--1", b"01", b"1.0", b"9223372036854775808", b"9" * 100)
        ]
        invalid.extend((b"[" * 16 + b"0" + b"]" * 16, b"[" + b"0," * 4096 + b"0]"))
        with (
            patch.object(w.json, "loads", side_effect=AssertionError("decoder reached")),
            patch.object(w.hashlib, "sha256", side_effect=AssertionError("hash reached")),
        ):
            for content in invalid:
                with self.assertRaises(w.WebAuthnAssertionAnalysisError):
                    w.analyze_supplied_webauthn_assertion_bytes(model_bytes=content)

    def test_client_depth_and_nodes_are_predecoder_bounded(self):
        prefix = base64.b64decode(self.model["client_data_json_base64"])[:-1] + b',"unknown":'
        for suffix in (b"[" * 15 + b"0" + b"]" * 15, b"[" + b"0," * 4096 + b"0]"):
            changed = model(client=prefix + suffix + b"}")
            with (
                patch.object(w.json, "loads", side_effect=AssertionError("decoder reached")),
                patch.object(w.hashlib, "sha256", side_effect=AssertionError("hash reached")),
                self.assertRaises(w.WebAuthnAssertionAnalysisError),
            ):
                w.analyze_supplied_webauthn_assertion(changed)

    def test_default_client_auth_challenge_and_text_byte_boundaries(self):
        raw = base64.b64decode(self.model["client_data_json_base64"])
        exact = raw + b" " * (w.MAX_CLIENT_BYTES - len(raw))
        self.assertTrue(
            all(
                w.analyze_supplied_webauthn_assertion(model(client=exact))
                .to_dict()["checks"]
                .values()
            )
        )
        with self.assertRaises(w.WebAuthnAssertionAnalysisError):
            w.analyze_supplied_webauthn_assertion(model(client=exact + b" "))
        result = w.analyze_supplied_webauthn_assertion(
            model(flags=0x85, tail=bytes(4096 - 37))
        ).to_dict()
        self.assertEqual(result["authenticator_data_bytes"], 4096)
        with self.assertRaises(w.WebAuthnAssertionAnalysisError):
            w.analyze_supplied_webauthn_assertion(model(flags=0x85, tail=bytes(4097 - 37)))
        value = client_data()
        value["origin"] = "a" * 2048
        self.assertTrue(
            w.analyze_supplied_webauthn_assertion(
                model(client=value, context={"origin": value["origin"], "rp_id": "a" * 253})
            ).to_dict()["checks"]["origin_matches"]
        )

    def test_real_client_node_default_ceiling(self):
        # Root + four key/value pairs + one unknown key and array = eleven nodes.
        raw = base64.b64decode(self.model["client_data_json_base64"])
        value = raw[:-1] + b',"unknown":[' + b",".join([b"0"] * 4085) + b"]}"
        self.assertTrue(
            w.analyze_supplied_webauthn_assertion(model(client=value)).to_dict()["checks"][
                "client_type_matches"
            ]
        )
        value = raw[:-1] + b',"unknown":[' + b",".join([b"0"] * 4086) + b"]}"
        with (
            patch.object(w.json, "loads", side_effect=AssertionError("decoder reached")),
            self.assertRaises(w.WebAuthnAssertionAnalysisError),
        ):
            w.analyze_supplied_webauthn_assertion(model(client=value))

    def test_cohashed_false_checks_status_hash_preimage_and_promotions_reject(self):
        changes = []
        for key in ("origin_matches", "rp_id_hash_matches", "backup_flags_consistent"):
            value = copy.deepcopy(self.document)
            value["checks"][key] = False
            changes.append(value)
        for key, changed in (
            ("analysis_status", "unassessed_supported_profile"),
            ("signature_input_sha256", "sha256:" + "a" * 64),
            ("source_model_sha256", "sha256:" + "a" * 64),
            ("counter_relation", "nonincreasing_signal"),
            ("component_id", "other"),
        ):
            value = copy.deepcopy(self.document)
            value[key] = changed
            changes.append(value)
        value = copy.deepcopy(self.document)
        value["claims"]["signature_verified"] = True
        changes.append(value)
        value = copy.deepcopy(self.document)
        value["effects"]["network"] = "performed"
        changes.append(value)
        for value in changes:
            changed = readdress(value)
            with self.assertRaises(w.WebAuthnAssertionAnalysisError):
                w.WebAuthnAssertionAnalysis.from_dict(changed)
            with self.assertRaises(w.WebAuthnAssertionAnalysisError):
                w.WebAuthnAssertionAnalysis.from_json(canonical(changed))

    def test_original_source_substitution_and_equivalent_client_spelling_are_bound(self):
        for changed in (
            dict(self.model, source_id="other"),
            model(client=json.dumps(client_data(), indent=2).encode()),
            model(count=2),
        ):
            with self.assertRaises(w.WebAuthnAssertionAnalysisError):
                w.verify_supplied_webauthn_assertion_analysis(self.report, model=changed)
        changed = dict(reversed(list(self.model.items())))
        self.assertEqual(
            w.verify_supplied_webauthn_assertion_analysis(self.report, model=changed).to_json(),
            self.report.to_json(),
        )

    def test_complete_source_and_canonical_report_are_required(self):
        value = copy.deepcopy(self.document)
        del value["source_model"]["context"]["previous_sign_count"]
        with self.assertRaises(w.WebAuthnAssertionAnalysisError):
            w.WebAuthnAssertionAnalysis.from_dict(readdress(value))
        with self.assertRaises(w.WebAuthnAssertionAnalysisError):
            w.WebAuthnAssertionAnalysis.from_json(json.dumps(self.document, indent=2))
        value = copy.deepcopy(self.document)
        value["schema_version"] = True
        with self.assertRaises(w.WebAuthnAssertionAnalysisError):
            w.WebAuthnAssertionAnalysis.from_dict(readdress(value))

    def test_input_export_and_replay_are_detached(self):
        original = copy.deepcopy(self.model)
        report = w.analyze_supplied_webauthn_assertion(original)
        original["context"]["rp_id"] = "foreign.invalid"
        detached = report.to_dict()
        detached["source_model"]["context"]["rp_id"] = "foreign.invalid"
        detached["checks"]["rp_id_hash_matches"] = False
        self.assertEqual(report.to_dict(), self.document)
        parsed = w.WebAuthnAssertionAnalysis.from_dict(self.document)
        self.document["claims"]["positive_use_approved"] = True
        self.assertFalse(parsed.to_dict()["claims"]["positive_use_approved"])

    def test_forged_subclass_and_incomplete_wrappers_fail_supported_entrypoints(self):
        class Foreign(w.WebAuthnAssertionAnalysis):
            pass

        with self.assertRaises(w.WebAuthnAssertionAnalysisError):
            Foreign(self.report.document_json)
        incomplete = object.__new__(w.WebAuthnAssertionAnalysis)
        for operation in (
            incomplete.to_dict,
            incomplete.to_json,
            lambda: w.verify_supplied_webauthn_assertion_analysis(incomplete, model=self.model),
        ):
            with self.assertRaises(w.WebAuthnAssertionAnalysisError):
                operation()
        forged = object.__new__(w.WebAuthnAssertionAnalysis)
        document = copy.deepcopy(self.document)
        document["checks"]["origin_matches"] = False
        object.__setattr__(forged, "document_json", canonical(readdress(document)))
        for operation in (
            forged.to_dict,
            forged.to_json,
            lambda: w.verify_supplied_webauthn_assertion_analysis(forged, model=self.model),
        ):
            with self.assertRaises(w.WebAuthnAssertionAnalysisError):
                operation()

    def test_reduced_report_node_byte_and_observation_caps_precede_hash(self):
        for name, limit in (
            ("MAX_REPORT_BYTES", 4000),
            ("MAX_REPORT_NODES", 100),
            ("MAX_OBSERVATIONS", 12),
        ):
            with (
                patch.object(w, name, limit),
                patch.object(w.hashlib, "sha256", side_effect=AssertionError("hash reached")),
                self.assertRaises(w.WebAuthnAssertionAnalysisError),
            ):
                w.analyze_supplied_webauthn_assertion(self.model)

    def test_actual_retained_unicode_expansion_budget_before_hash(self):
        value = client_data()
        value["origin"] = chr(127) * 4000
        source = model(client=json.dumps(value, ensure_ascii=False).encode())
        document = w.analyze_supplied_webauthn_assertion(source).to_dict()
        self.assertGreater(len(canonical(document)), 30000)
        for cap in (30000, 32000):
            with (
                patch.object(w, "MAX_REPORT_BYTES", cap),
                patch.object(w.hashlib, "sha256", side_effect=AssertionError("hash reached")),
                self.assertRaises(w.WebAuthnAssertionAnalysisError),
            ):
                w.analyze_supplied_webauthn_assertion(source)

    def test_all_eight_actual_fixed_point_work_thresholds_precede_every_digest(self):
        original_charge = w._Budget.charge
        original_hash = hashlib.sha256
        last = []
        hashes = []

        def charge(budget, amount):
            self.assertFalse(hashes, "Cost discovered after hashing")
            original_charge(budget, amount)
            last[:] = [budget.used]

        def digest(*args, **kwargs):
            hashes.append(last[0])
            return original_hash(*args, **kwargs)

        def prepare(cap):
            document = copy.deepcopy(self.document)
            document["bounds"]["cumulative_work_per_public_operation"] = cap
            return readdress(document)

        for kind in range(8):
            cap = w.MAX_WORK
            for _ in range(5):
                with patch.object(w, "MAX_WORK", cap):
                    document = prepare(cap)
                    text = canonical(document)
                    wrapper = w.WebAuthnAssertionAnalysis(text) if kind >= 5 else None
                    operations = (
                        lambda: w.analyze_supplied_webauthn_assertion(self.model),
                        lambda: w.analyze_supplied_webauthn_assertion_bytes(
                            model_bytes=canonical(self.model).encode()
                        ),
                        lambda text=text: w.WebAuthnAssertionAnalysis(text),
                        lambda document=document: w.WebAuthnAssertionAnalysis.from_dict(document),
                        lambda text=text: w.WebAuthnAssertionAnalysis.from_json(text),
                        lambda wrapper=wrapper: wrapper.to_dict(),
                        lambda wrapper=wrapper: wrapper.to_json(),
                        lambda wrapper=wrapper: w.verify_supplied_webauthn_assertion_analysis(
                            wrapper, model=self.model
                        ),
                    )
                    last.clear()
                    hashes.clear()
                    with (
                        patch.object(w._Budget, "charge", charge),
                        patch.object(w.hashlib, "sha256", digest),
                    ):
                        operations[kind]()
                    measured = last[0]
                    self.assertEqual(len(hashes), 12 if kind == 7 else 6)
                    self.assertTrue(all(value == measured for value in hashes))
                if cap == measured:
                    break
                cap = measured
            else:
                self.fail("Work fixed point did not converge")
            with (
                patch.object(w, "MAX_WORK", cap - 1),
                patch.object(w.hashlib, "sha256", side_effect=AssertionError("hash reached")),
                self.assertRaises(w.WebAuthnAssertionAnalysisError),
            ):
                operations[kind]()


if __name__ == "__main__":
    unittest.main()
