"""Independent finite controls for supplied retained-cookie candidate predicates."""

from __future__ import annotations

import copy
import hashlib
import itertools
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_cookie_selection as cookies

ERROR = cookies.CookieSelectionError
MATCH = "matches_supplied_predicates"
NO_MATCH = "does_not_match_supplied_predicates"


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def readdress(value):
    body = copy.deepcopy(value)
    body.pop("analysis_id", None)
    body.pop("analysis_sha256", None)
    digest = hashlib.sha256(
        b"sunderkey.offline-cookie-selection.v1\n" + canonical(body).encode("ascii")
    ).hexdigest()
    return {
        **body,
        "analysis_id": "CKS-" + digest[:32].upper(),
        "analysis_sha256": "sha256:" + digest,
    }


def cookie(
    identifier="cookie",
    *,
    name="SID",
    domain="example.invalid",
    path="/",
    host_only=False,
    secure=False,
    http_only=False,
):
    return {
        "cookie_id": identifier,
        "name": name,
        "domain": domain,
        "path": path,
        "host_only": host_only,
        "secure": secure,
        "http_only": http_only,
    }


def request(
    identifier="request",
    *,
    host="example.invalid",
    path="/",
    secure_transport=True,
    http_api=True,
):
    return {
        "request_id": identifier,
        "host": host,
        "path": path,
        "secure_transport": secure_transport,
        "http_api": http_api,
    }


def model(retained=None, requests=None):
    return {
        "schema_version": 1,
        "cookies": [cookie()] if retained is None else retained,
        "requests": [request()] if requests is None else requests,
    }


def observations(value):
    return cookies.analyze_supplied_cookie_selection(value).to_dict()["pair_observations"]


class CookieSelectionTests(unittest.TestCase):
    def denied_before_hash(self, value):
        with (
            patch.object(cookies, "_hash") as derive_hash,
            patch.object(cookies.hashlib, "sha256") as digest,
        ):
            with self.assertRaises(ERROR):
                cookies.analyze_supplied_cookie_selection(value)
            derive_hash.assert_not_called()
            digest.assert_not_called()

    def raw_denied_before_decoder(self, text):
        with (
            patch.object(cookies.json, "loads") as decoder,
            patch.object(cookies.hashlib, "sha256") as digest,
        ):
            with self.assertRaises(ERROR):
                cookies.CookieSelectionAnalysis.from_json(text)
            decoder.assert_not_called()
            digest.assert_not_called()

    def test_fixture_literal_identity_and_predicates(self):
        original = cookies.component_fixture()
        report = cookies.analyze_supplied_cookie_selection(original)
        document = report.to_dict()
        self.assertEqual(document["analysis_id"], "CKS-0C48DD34662DCE4EC3766D5134C7227D")
        self.assertEqual(
            document["analysis_sha256"],
            "sha256:0c48dd34662dce4ec3766d5134c7227d51b2be12e2b7f2832b1d8cdcdf5416f7",
        )
        self.assertEqual(
            document["source_model_sha256"],
            "sha256:3b275b7cb82d9127fb7528a605c4e6a744a97841391daf33b4f9de03cfb7db90",
        )
        self.assertEqual(document["pair_count"], 4)
        self.assertEqual(
            [row["outcome"] for row in document["pair_observations"]],
            [MATCH, MATCH, NO_MATCH, MATCH],
        )
        first, _, adverse, _ = document["pair_observations"]
        self.assertEqual(first["domain_basis"], "label_boundary_suffix")
        self.assertEqual(first["path_basis"], "prefix_next_slash")
        self.assertTrue(first["secure_matches"])
        self.assertTrue(first["http_only_matches"])
        self.assertTrue(adverse["domain_matches"])
        self.assertFalse(adverse["path_matches"])
        self.assertFalse(adverse["secure_matches"])
        self.assertFalse(adverse["http_only_matches"])
        self.assertEqual(
            cookies.CookieSelectionAnalysis.from_dict(document).to_json(), report.to_json()
        )
        self.assertEqual(
            cookies.CookieSelectionAnalysis.from_json(report.to_json()).to_json(), report.to_json()
        )
        self.assertEqual(
            cookies.analyze_supplied_cookie_selection_bytes(
                model_bytes=canonical(original).encode("ascii")
            ).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            cookies.verify_supplied_cookie_selection(report, model=original).to_json(),
            report.to_json(),
        )

    def test_domain_label_list_oracle(self):
        names = [
            ".".join(labels)
            for count in range(1, 4)
            for labels in itertools.product("ab", repeat=count)
        ]
        retained = [
            cookie(
                f"cookie-{index}-{int(only)}",
                name=f"N{index}-{int(only)}",
                domain=domain,
                host_only=only,
            )
            for index, domain in enumerate(names)
            for only in (False, True)
        ]
        requests = [request(f"request-{index}", host=host) for index, host in enumerate(names)]
        rows = observations(model(retained, requests))
        self.assertEqual(len(rows), 392)
        for row, (query, item) in zip(rows, itertools.product(requests, retained), strict=True):
            wanted = item["domain"].split(".")
            actual = query["host"].split(".")
            expected = actual == wanted or (
                not item["host_only"]
                and len(actual) > len(wanted)
                and actual[-len(wanted) :] == wanted
            )
            with self.subTest(cookie=row["cookie_id"], request=row["request_id"]):
                self.assertEqual(row["domain_matches"], expected)
                self.assertEqual(row["outcome"], MATCH if expected else NO_MATCH)

    def test_domain_literal_boundary_and_case_premises(self):
        for host, expected in (
            ("example.invalid", True),
            ("api.example.invalid", True),
            ("deep.api.example.invalid", True),
            ("notexample.invalid", False),
            ("example.invalid.attacker.invalid", False),
            ("exampleinvalid", False),
        ):
            with self.subTest(host=host):
                row = observations(model(requests=[request(host=host)]))[0]
                self.assertEqual(row["domain_matches"], expected)
        # Public suffix enforcement is explicitly outside the supplied predicate.
        self.assertTrue(
            observations(model([cookie(domain="invalid")], [request(host="x.invalid")]))[0][
                "domain_matches"
            ]
        )
        self.assertTrue(
            observations(
                model(
                    [cookie(domain="xn--synthetic-abc.invalid")],
                    [request(host="xn--synthetic-abc.invalid")],
                )
            )[0]["domain_matches"]
        )

    def test_host_only_requires_exact_host(self):
        for host, expected in (("example.invalid", True), ("api.example.invalid", False)):
            row = observations(model([cookie(host_only=True)], [request(host=host)]))[0]
            self.assertEqual(row["domain_matches"], expected)
            self.assertEqual(
                row["domain_basis"], "host_only_equal" if expected else "host_only_different"
            )

    def test_canonical_ip_equality_and_suffix_exclusion(self):
        for address in ("192.0.2.1", "2001:db8::1", "::1"):
            for only in (False, True):
                with self.subTest(address=address, host_only=only):
                    row = observations(
                        model([cookie(domain=address, host_only=only)], [request(host=address)])
                    )[0]
                    self.assertTrue(row["domain_matches"])
        for domain in ("2.1", "0.2.1"):
            row = observations(model([cookie(domain=domain)], [request(host="192.0.2.1")]))[0]
            self.assertFalse(row["domain_matches"])
            self.assertEqual(row["domain_basis"], "request_ip_suffix_excluded")

    def test_literal_path_boundary_table(self):
        table = {
            "/": {
                "/",
                "/app",
                "/app/",
                "/app/item",
                "/application",
                "//app",
                "/a%2Fb",
                "/a/b",
                "/A",
                "/a/../b",
            },
            "/app": {"/app", "/app/", "/app/item"},
            "/app/": {"/app/", "/app/item"},
            "/a%2Fb": {"/a%2Fb", "/a%2Fb/item"},
            "/a/b": {"/a/b", "/a/b/item"},
            "/A": {"/A", "/A/item"},
            "//": {"//", "//app"},
            "/a/../b": {"/a/../b", "/a/../b/item"},
        }
        paths = sorted(
            set().union(*table.values()) | {"/APP", "/app2", "/a%2fb", "/b", "/app;parameters"}
        )
        table["/"] = set(paths)
        retained = [
            cookie(f"cookie-{index}", name=f"N{index}", path=path)
            for index, path in enumerate(table)
        ]
        requests = [request(f"request-{index}", path=path) for index, path in enumerate(paths)]
        for row, (query, item) in zip(
            observations(model(retained, requests)),
            itertools.product(requests, retained),
            strict=True,
        ):
            self.assertEqual(
                row["path_matches"],
                query["path"] in table[item["path"]],
                (item["path"], query["path"]),
            )

    def test_path_equality_precedes_prefix_and_preserves_literal_spelling(self):
        for path in ("/", "/app/", "/a%2Fb", "/a%2fb", "/a/../b", "//a", "/a;b:c@d"):
            row = observations(model([cookie(path=path)], [request(path=path)]))[0]
            self.assertEqual(row["path_basis"], "exact_path")
        row = observations(model([cookie(path="/a%2Fb")], [request(path="/a/b")]))[0]
        self.assertFalse(row["path_matches"])
        row = observations(model([cookie(path="/a/../b")], [request(path="/b")]))[0]
        self.assertFalse(row["path_matches"])

    def test_secure_and_http_only_independent_truth_table(self):
        for secure, http_only, transport, api in itertools.product((False, True), repeat=4):
            row = observations(
                model(
                    [cookie(secure=secure, http_only=http_only)],
                    [request(secure_transport=transport, http_api=api)],
                )
            )[0]
            expected_secure = (secure, transport) != (True, False)
            expected_http = (http_only, api) != (True, False)
            self.assertEqual(row["secure_matches"], expected_secure)
            self.assertEqual(row["http_only_matches"], expected_http)
            self.assertEqual(
                row["outcome"], MATCH if expected_secure and expected_http else NO_MATCH
            )

    def test_false_domain_and_path_do_not_suppress_other_predicates(self):
        row = observations(
            model(
                [cookie(path="/restricted", secure=True, http_only=True)],
                [
                    request(
                        host="foreign.invalid",
                        path="/elsewhere",
                        secure_transport=False,
                        http_api=False,
                    )
                ],
            )
        )[0]
        self.assertEqual(
            [
                row[name]
                for name in (
                    "domain_matches",
                    "path_matches",
                    "secure_matches",
                    "http_only_matches",
                )
            ],
            [False] * 4,
        )

    def test_zero_cookies_and_maximum_single_axis_counts(self):
        empty = cookies.analyze_supplied_cookie_selection(model([], [request()])).to_dict()
        self.assertEqual(empty["pair_observations"], [])
        self.assertEqual(empty["pair_count"], 0)
        retained = [cookie(f"c-{index}", name=f"N{index}") for index in range(128)]
        self.assertEqual(len(observations(model(retained))), 128)
        requests = [request(f"r-{index}") for index in range(64)]
        self.assertEqual(len(observations(model(requests=requests))), 64)

    def test_collection_and_pair_cost_caps_are_not_cookie_authority(self):
        self.denied_before_hash(
            model([cookie(f"c-{index}", name=f"N{index}") for index in range(129)])
        )
        self.denied_before_hash(model(requests=[request(f"r-{index}") for index in range(65)]))
        self.denied_before_hash(model(requests=[]))
        self.denied_before_hash(model(retained=(), requests=[request()]))

    def test_duplicate_source_identities_and_closed_retained_tuple(self):
        self.denied_before_hash(model([cookie(), cookie(name="OTHER")]))
        self.denied_before_hash(model(requests=[request(), request(path="/other")]))
        self.denied_before_hash(
            model([cookie("first"), cookie("second", host_only=True, secure=True, http_only=True)])
        )
        valid = [
            cookie("a"),
            cookie("b", path="/app"),
            cookie("c", domain="api.example.invalid"),
            cookie("d", name="sid"),
        ]
        self.assertEqual(len(observations(model(valid))), 4)

    def test_exact_native_boolean_flags_before_digest(self):
        for side, flags in (
            ("cookies", ("host_only", "secure", "http_only")),
            ("requests", ("secure_transport", "http_api")),
        ):
            for name, value in itertools.product(flags, (0, 1, None, "false", [], {})):
                supplied = model()
                supplied[side][0][name] = value
                with self.subTest(side=side, name=name, value=value):
                    self.denied_before_hash(supplied)

    def test_native_schema_aliases_and_numeric_limits(self):
        for value in (
            True,
            False,
            1.0,
            None,
            "1",
            0,
            2,
            -(2**63),
            2**63 - 1,
            -(2**63) - 1,
            2**63,
            2**5000,
        ):
            supplied = model()
            supplied["schema_version"] = value
            with self.subTest(
                kind=type(value), bit_length=value.bit_length() if type(value) is int else None
            ):
                self.denied_before_hash(supplied)

    def test_native_subclasses_and_hooks_do_not_normalize_into_supported_input(self):
        class Text(str):
            def __str__(self):
                raise AssertionError("Foreign string hook reached")

        class Number(int):
            def __str__(self):
                raise AssertionError("Foreign integer hook reached")

        class Sequence(list):
            def __iter__(self):
                raise AssertionError("Foreign list hook reached")

        class Mapping(dict):
            def items(self):
                raise AssertionError("Foreign mapping hook reached")

        supplied = model()
        cases = [Mapping(supplied)]
        for side, field, value in (
            ("cookies", "domain", Text("example.invalid")),
            ("requests", "request_id", Text("request")),
        ):
            current = model()
            current[side][0][field] = value
            cases.append(current)
        current = model()
        current["schema_version"] = Number(1)
        cases.append(current)
        current = model()
        current["cookies"] = Sequence(current["cookies"])
        cases.append(current)
        for current in cases:
            with patch.object(cookies.json, "dumps") as serializer:
                self.denied_before_hash(current)
                serializer.assert_not_called()

    def test_unknown_fields_are_not_silently_ignored(self):
        for side, name in (
            (None, "tenant_id"),
            ("cookies", "value"),
            ("cookies", "expires_at"),
            ("cookies", "same_site"),
            ("requests", "url"),
            ("requests", "credential"),
        ):
            current = model()
            target = current if side is None else current[side][0]
            target[name] = "excluded"
            self.denied_before_hash(current)
        for side, name in ((None, "requests"), ("cookies", "name"), ("requests", "http_api")):
            current = model()
            target = current if side is None else current[side][0]
            target.pop(name)
            self.denied_before_hash(current)

    def test_canonical_ascii_host_premise_boundaries(self):
        maximum = ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 61))
        self.assertEqual(len(maximum), 253)
        self.assertTrue(
            observations(model([cookie(domain=maximum)], [request(host=maximum)]))[0][
                "domain_matches"
            ]
        )
        invalid = (
            "",
            "EXAMPLE.invalid",
            ".example.invalid",
            "example.invalid.",
            "a..invalid",
            "a_underscore.invalid",
            "-a.invalid",
            "a-.invalid",
            "a" * 64 + ".invalid",
            maximum + "d",
            "ex\u00e4mple.invalid",
            "192.000.2.1",
            "999.0.2.1",
            "[2001:db8::1]",
            "2001:DB8::1",
            "2001:db8:0:0:0:0:0:1",
            "fe80::1%eth0",
        )
        for value, side in itertools.product(invalid, ("cookies", "requests")):
            current = model()
            current[side][0]["domain" if side == "cookies" else "host"] = value
            with self.subTest(value=value, side=side):
                self.denied_before_hash(current)

    def test_name_path_and_source_id_exact_boundaries(self):
        path = "/" + "a" * 1023
        valid = model(
            [cookie("c" * 128, name="N" * 128, path=path)], [request("r" * 128, path=path)]
        )
        self.assertEqual(observations(valid)[0]["outcome"], MATCH)
        for side, field, value in (
            ("cookies", "name", "N" * 129),
            ("cookies", "cookie_id", "c" * 129),
            ("requests", "request_id", "r" * 129),
            ("cookies", "path", path + "a"),
            ("requests", "path", path + "a"),
        ):
            current = model()
            current[side][0][field] = value
            self.denied_before_hash(current)
        for path, side in itertools.product(
            (
                "",
                "relative",
                "/a?query",
                "/a#fragment",
                "/a b",
                "/a\\b",
                "/a%",
                "/a%2",
                "/a%2G",
                "/\u00e4",
                "/a\n",
            ),
            ("cookies", "requests"),
        ):
            current = model()
            current[side][0]["path"] = path
            self.denied_before_hash(current)
        for name in ("", "space name", "a=b", "a;b", "name\n", "n\u00e4me"):
            self.denied_before_hash(model([cookie(name=name)]))

    def test_native_cycles_shared_subtrees_and_escaped_costs_precede_serializer(self):
        cycle = []
        cycle.append(cycle)
        shared = ["a" * 1024] * 100
        for value in (cycle, [shared] * 12, ["\\" * 1024] * 600, ['"' * 1024] * 600):
            with (
                self.subTest(cyclic=value is cycle),
                patch.object(cookies.json, "dumps") as serializer,
            ):
                self.denied_before_hash(value)
                serializer.assert_not_called()

    def test_complete_report_cost_is_reserved_before_first_hash(self):
        retained = [cookie(f"cookie-{index}", name=f"N{index}") for index in range(128)]
        requests = [request(f"request-{index}") for index in range(64)]
        with (
            patch.object(cookies, "_hash") as addressed,
            patch.object(cookies.hashlib, "sha256") as digest,
        ):
            with self.assertRaisesRegex(ERROR, "report.*bound"):
                cookies.analyze_supplied_cookie_selection(model(retained, requests))
            addressed.assert_not_called()
            digest.assert_not_called()

    def test_work_budget_is_checked_before_copy_and_hash(self):
        with (
            patch.object(cookies, "MAX_WORK", 1),
            patch.object(cookies.json, "dumps") as serializer,
        ):
            self.denied_before_hash(model())
            serializer.assert_not_called()

    def test_final_serialization_and_digest_work_precede_first_hash(self):
        # These limits cover source processing but not the final complete work.
        for limit in (11000, 18500):
            with (
                self.subTest(limit=limit),
                patch.object(cookies, "MAX_WORK", limit),
                patch.object(cookies, "_hash", wraps=cookies._hash) as addressed,
                patch.object(cookies.hashlib, "sha256", wraps=hashlib.sha256) as digest,
            ):
                with self.assertRaisesRegex(ERROR, "work bound"):
                    cookies.analyze_supplied_cookie_selection(cookies.component_fixture())
                addressed.assert_not_called()
                digest.assert_not_called()

    def test_final_public_output_work_is_reserved_before_replay_hash(self):
        original = cookies.analyze_supplied_cookie_selection(cookies.component_fixture())
        for limit in (11000, 18500):
            with (
                self.subTest(limit=limit),
                patch.object(cookies, "MAX_WORK", limit),
                patch.object(cookies, "_hash", wraps=cookies._hash) as addressed,
                patch.object(cookies.hashlib, "sha256", wraps=hashlib.sha256) as digest,
            ):
                with self.assertRaisesRegex(ERROR, "work bound"):
                    original.to_json()
                addressed.assert_not_called()
                digest.assert_not_called()

    def test_genuine_high_character_cost_input_is_denied_before_hash(self):
        host = ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 61))
        path = "/" + "x" * 1023
        retained = [
            cookie(f"cookie-{index}", name=f"N{index:03d}" + "a" * 124, domain=host, path=path)
            for index in range(80)
        ]
        requests = [request(f"request-{index}", host=host, path=path) for index in range(8)]
        supplied = model(retained, requests)
        self.assertLess(len(canonical(supplied)), 1048576)
        self.assertEqual(len(retained) * len(requests), 640)
        with (
            patch.object(cookies, "_hash", wraps=cookies._hash) as addressed,
            patch.object(cookies.hashlib, "sha256", wraps=hashlib.sha256) as digest,
        ):
            with self.assertRaisesRegex(ERROR, "work bound"):
                cookies.analyze_supplied_cookie_selection(supplied)
            addressed.assert_not_called()
            digest.assert_not_called()

    def test_raw_depth_nodes_strings_and_bytes_before_decoder(self):
        for scalar in ('"a"', "0", "true", "null"):
            self.raw_denied_before_decoder("[" * 16 + scalar + "]" * 16)
        self.raw_denied_before_decoder("[" + ",".join("0" for _ in range(32768)) + "]")
        self.raw_denied_before_decoder('"' + "a" * 1025 + '"')
        self.raw_denied_before_decoder('"' + "\\u0061" * 1025 + '"')
        self.raw_denied_before_decoder(" " * 1048577)
        self.raw_denied_before_decoder("9" * 20000)
        self.raw_denied_before_decoder('"\\u00e4"')
        self.raw_denied_before_decoder('"\\u000a"')

    def test_raw_integer_grammar_before_decoder(self):
        for scalar in (
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
            "-Infinity",
            "9223372036854775808",
            "-9223372036854775809",
        ):
            self.raw_denied_before_decoder(
                '{"schema_version":' + scalar + ',"cookies":[],"requests":[]}'
            )

    def test_raw_duplicate_members_and_missing_semantic_fields(self):
        native = canonical(model())
        duplicate_root = native.replace(
            '"schema_version":1', '"schema_version":1,"schema_version":1'
        )
        duplicate_nested = native.replace(
            '"host_only":false', '"host_only":false,"host_only":false'
        )
        for text in (
            duplicate_root,
            duplicate_nested,
            "{}",
            "[]",
            "null",
            '{"schema_version":true}',
            '{"schema_version":1.0}',
        ):
            with patch.object(cookies, "_hash") as addressed, self.assertRaises(ERROR):
                cookies.analyze_supplied_cookie_selection_bytes(model_bytes=text.encode("ascii"))
            addressed.assert_not_called()

    def test_model_byte_intake_exact_native_and_size(self):
        class Bytes(bytes):
            pass

        for value in (
            b"",
            b" " * 1048577,
            "{}",
            bytearray(b"{}"),
            memoryview(b"{}"),
            Bytes(b"{}"),
            b"\xff",
        ):
            with (
                patch.object(cookies.json, "loads") as decoder,
                patch.object(cookies.hashlib, "sha256") as digest,
            ):
                with self.assertRaises(ERROR):
                    cookies.analyze_supplied_cookie_selection_bytes(model_bytes=value)
                decoder.assert_not_called()
                digest.assert_not_called()

    def test_raw_signed64_intake_and_whitespace_normalization(self):
        for value in ("-9223372036854775808", "9223372036854775807", "-0"):
            with self.assertRaises(ERROR):
                cookies.analyze_supplied_cookie_selection_bytes(
                    model_bytes=(
                        '{"schema_version":' + value + ',"cookies":[],"requests":[]} '
                    ).encode("ascii")
                )
        original = cookies.component_fixture()
        spaced = json.dumps(original, indent=2).encode("ascii")
        self.assertEqual(
            cookies.analyze_supplied_cookie_selection_bytes(model_bytes=spaced).to_json(),
            cookies.analyze_supplied_cookie_selection(original).to_json(),
        )

    def test_detached_input_outputs_and_fresh_fixture(self):
        original = cookies.component_fixture()
        frozen = copy.deepcopy(original)
        report = cookies.analyze_supplied_cookie_selection(original)
        expected = report.to_json()
        original["cookies"][0]["domain"] = "changed.invalid"
        exported = report.to_dict()
        exported["source_model"]["cookies"][0]["domain"] = "foreign.invalid"
        exported["pair_observations"][0]["outcome"] = NO_MATCH
        exported["flags"]["qualification_claimed"] = True
        self.assertEqual(report.to_json(), expected)
        self.assertEqual(cookies.component_fixture(), frozen)
        self.assertEqual(
            cookies.verify_supplied_cookie_selection(report, model=frozen).to_json(), expected
        )
        with self.assertRaises(ERROR):
            cookies.verify_supplied_cookie_selection(report, model=original)

    def test_coherently_rehashed_false_predicates_fail_embedded_replay(self):
        original = cookies.analyze_supplied_cookie_selection(cookies.component_fixture()).to_dict()
        modifications = {
            "domain_matches": False,
            "domain_basis": "exact_domain",
            "path_matches": False,
            "path_basis": "exact_path",
            "secure_matches": False,
            "http_only_matches": False,
            "outcome": NO_MATCH,
            "cookie_id": "valid-foreign-id",
            "request_id": "valid-foreign-id",
        }
        for field, value in modifications.items():
            changed = copy.deepcopy(original)
            changed["pair_observations"][0][field] = value
            forged = readdress(changed)
            with self.subTest(field=field):
                for intake in (
                    cookies.CookieSelectionAnalysis.from_dict,
                    lambda item: cookies.CookieSelectionAnalysis.from_json(canonical(item)),
                ):
                    with self.assertRaises(ERROR):
                        intake(forged)

    def test_coherently_rehashed_bindings_counts_limits_and_promotions_fail(self):
        original = cookies.analyze_supplied_cookie_selection(cookies.component_fixture()).to_dict()
        for field, value in (
            ("schema_version", True),
            ("pair_count", 4.0),
            ("cookie_count", 1),
            ("request_count", True),
            ("profile_id", "AOE-GB-D05-S10"),
            ("capability_id", "army.gb.d05.s11"),
            ("standard", "foreign-standard"),
            ("source_model_sha256", "sha256:" + "a" * 64),
            ("limitations", []),
        ):
            changed = copy.deepcopy(original)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ERROR):
                cookies.CookieSelectionAnalysis.from_dict(readdress(changed))
        for section, field, value in (
            ("flags", "positive_use_approved", True),
            ("flags", "source_authenticated", 0),
            ("effects", "browser", "invoked"),
            ("bounds", "work_steps", 4000001),
        ):
            changed = copy.deepcopy(original)
            changed[section][field] = value
            with self.assertRaises(ERROR):
                cookies.CookieSelectionAnalysis.from_json(canonical(readdress(changed)))

    def test_source_swap_and_permutation_need_separately_supplied_original(self):
        original = cookies.component_fixture()
        for change in (
            "cookie_id",
            "request_id",
            "domain",
            "flags",
            "cookie_order",
            "request_order",
        ):
            supplied = copy.deepcopy(original)
            if change == "cookie_id":
                supplied["cookies"][0]["cookie_id"] = "other-cookie"
            elif change == "request_id":
                supplied["requests"][0]["request_id"] = "other-request"
            elif change == "domain":
                supplied["cookies"][0]["domain"] = "other.invalid"
            elif change == "flags":
                supplied["cookies"][0]["http_only"] = False
            elif change == "cookie_order":
                supplied["cookies"].reverse()
            else:
                supplied["requests"].reverse()
            report = cookies.analyze_supplied_cookie_selection(supplied)
            self.assertEqual(
                cookies.CookieSelectionAnalysis.from_json(report.to_json()).to_json(),
                report.to_json(),
            )
            with self.subTest(change=change), self.assertRaises(ERROR):
                cookies.verify_supplied_cookie_selection(report, model=original)

    def test_public_wrapper_forgery_and_incomplete_objects_fail_at_use(self):
        missing = object.__new__(cookies.CookieSelectionAnalysis)
        with self.assertRaises(ERROR):
            missing.to_dict()
        with self.assertRaises(ERROR):
            cookies.verify_supplied_cookie_selection(missing, model=cookies.component_fixture())
        original = cookies.analyze_supplied_cookie_selection(cookies.component_fixture())
        forged = original.to_dict()
        forged["pair_observations"][0]["domain_matches"] = False
        object.__setattr__(original, "_document_json", canonical(readdress(forged)))
        with self.assertRaises(ERROR):
            original.to_json()
        with self.assertRaises(ERROR):
            cookies.verify_supplied_cookie_selection(original, model=cookies.component_fixture())
        for foreign in (None, {}, "{}", object()):
            with self.assertRaises(ERROR):
                cookies.verify_supplied_cookie_selection(foreign, model=cookies.component_fixture())

    def test_exact_none_effects_false_flags_and_existing_catalog_binding(self):
        document = cookies.analyze_supplied_cookie_selection(cookies.component_fixture()).to_dict()
        self.assertEqual(document["profile_id"], "AOE-GB-D05-S11")
        self.assertEqual(document["capability_id"], "web.browser-auth-session")
        self.assertEqual(document["vector_id"], "AV-GB-D05-S11-01")
        self.assertEqual(document["work_package_id"], "IWP2-AOE-GB-D05-S11")
        self.assertEqual(document["wave_id"], "IW2-011")
        self.assertEqual(document["commander_id"], "AOE-GB-D05-CMD")
        self.assertEqual(document["group_owner_id"], "AOE-HQ-04")
        self.assertEqual(document["independent_validator_id"], "AOE-HQ-34")
        self.assertEqual(
            document["blueprint_sha256"],
            "sha256:b83a03607604ae4f7f4edf728b5a6baed306bddbf63bd5a372c7c2b15e0c79f8",
        )
        self.assertTrue(
            all(type(value) is bool and value is False for value in document["flags"].values())
        )
        self.assertTrue(all(value == "none" for value in document["effects"].values()))
        self.assertNotIn("value", document["source_model"]["cookies"][0])
        self.assertEqual(document["bounds"]["pairs"], 8192)


if __name__ == "__main__":
    unittest.main()
