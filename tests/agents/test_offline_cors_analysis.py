"""Literal and independently structured controls for supplied CORS metadata."""

from __future__ import annotations

import copy
import hashlib
import itertools
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_cors_analysis as cors

ERROR = cors.CorsAnalysisError
PASS = "passes_supplied_check"
FAIL = "fails_supplied_check"
UNKNOWN = "unassessed"
ORIGIN = "https://client.invalid"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def readdress(value):
    document = copy.deepcopy(value)
    body = {
        key: item for key, item in document.items() if key not in {"report_id", "report_sha256"}
    }
    digest = hashlib.sha256(
        canonical({"domain": cors.DOMAIN, "analysis": body}).encode("ascii")
    ).hexdigest()
    return {**body, "report_id": "CRA-" + digest[:32].upper(), "report_sha256": "sha256:" + digest}


def field(name, value):
    return {"name": name, "value": value}


def response(source_id, fields, *, actual=False, status=204, names=()):
    result = {
        "source_id": source_id,
        "status": status,
        "cors_fields": fields,
        "headers_complete": True,
    }
    if actual:
        inventory = list(dict.fromkeys([item["name"].lower() for item in fields] + list(names)))
        result["response_header_names"] = inventory
    return result


def model(
    *,
    credentials="omit",
    origin=ORIGIN,
    method="PUT",
    unsafe=("x-review",),
    required=True,
    forced=False,
    preflight=None,
    actual=None,
):
    return {
        "schema_version": 1,
        "cases": [
            {
                "case_id": "control",
                "request": {
                    "source_id": "request",
                    "serialized_origin": origin,
                    "credentials_mode": credentials,
                    "method": method,
                    "unsafe_header_names": list(unsafe),
                    "preflight_required": required,
                    "use_cors_preflight": forced,
                    "projection_complete": True,
                },
                "preflight_response": preflight,
                "actual_response": actual,
            }
        ],
    }


def actual(fields, *, names=(), status=200):
    return response("actual", fields, actual=True, status=status, names=names)


def preflight(fields, *, status=204):
    return response("preflight", fields, status=status)


def result(value):
    return cors.analyze_supplied_cors(value).to_dict()["cases"][0]


def acoa(value=ORIGIN):
    return field("Access-Control-Allow-Origin", value)


def token_boundary_model(field_name, length):
    token = "a" * length
    before = preflight(
        [
            acoa("*"),
            field("Access-Control-Allow-Methods", "PUT"),
            field("Access-Control-Allow-Headers", "x-review"),
        ]
    )
    after = actual(
        [acoa("*"), field("Access-Control-Expose-Headers", "x-review")],
        names=("content-type", "x-review"),
        status=403,
    )
    if field_name == "Access-Control-Expose-Headers":
        after["cors_fields"][1]["value"] += "," + token
    else:
        for item in before["cors_fields"]:
            if item["name"] == field_name:
                item["value"] += "," + token
    return model(preflight=before, actual=after)


class CorsAnalysisTests(unittest.TestCase):
    def test_literal_fixture_and_detached_roundtrip(self):
        original = cors.component_fixture()
        report = cors.analyze_supplied_cors(original)
        document = report.to_dict()
        self.assertEqual(document["report_id"], "CRA-6E647D978BAB1CB48A14B3ADD93EDF35")
        self.assertEqual(
            document["report_sha256"],
            "sha256:6e647d978bab1cb48a14b3add93edf356167ee64a9098ad623b96579af3055b4",
        )
        self.assertEqual(
            document["source"]["model_sha256"],
            "sha256:fa541eda5ee988c9b5a9eabd1a31f461895bc1cc4b5a7a2e4e1e4c451663378d",
        )
        self.assertEqual(document["cases"][0]["preflight_check"]["outcome"], PASS)
        self.assertEqual(document["cases"][0]["actual_response_check"]["outcome"], PASS)
        self.assertEqual(
            document["cases"][0]["exposed_header_names"], ["content-type", "x-synthetic-result"]
        )
        self.assertEqual(
            document["cases"][0]["comprehensive_share_result"], "passes_supplied_checks"
        )
        self.assertEqual(cors.CorsAnalysis.from_json(report.to_json()).to_json(), report.to_json())
        self.assertEqual(cors.CorsAnalysis.from_dict(document).to_json(), report.to_json())
        self.assertEqual(
            cors.verify_supplied_cors_analysis(report, model=original).to_json(), report.to_json()
        )
        self.assertEqual(
            cors.analyze_supplied_cors_bytes(model_json=canonical(original).encode()).to_json(),
            report.to_json(),
        )
        self.assertEqual(document["component_id"], "cors_supplied_negotiation_and_exposure")
        self.assertEqual(document["capability_id"], "army.gb.d05.s14")

    def test_origin_credentials_literal_truth_table(self):
        # Expected values are a finite literal table, not a copy of the leaf predicate.
        outcomes = {
            "omit": {
                "absent": FAIL,
                "*": PASS,
                ORIGIN: PASS,
                "https://other.invalid": FAIL,
                "null": FAIL,
            },
            "same-origin": {
                "absent": FAIL,
                "*": PASS,
                ORIGIN: PASS,
                "https://other.invalid": FAIL,
                "null": FAIL,
            },
            "include": {
                "absent": FAIL,
                "*": FAIL,
                ORIGIN: PASS,
                "https://other.invalid": FAIL,
                "null": FAIL,
            },
        }
        for credentials, expectations in outcomes.items():
            for origin, expected in expectations.items():
                with self.subTest(credentials=credentials, origin=origin):
                    fields = [] if origin == "absent" else [acoa(origin)]
                    fields += [field("Access-Control-Allow-Credentials", "true")]
                    row = result(
                        model(credentials=credentials, required=False, actual=actual(fields))
                    )
                    self.assertEqual(row["actual_response_check"]["outcome"], expected)

    def test_opaque_null_origin_is_distinct_from_absence(self):
        for credentials in ("omit", "include"):
            fields = [acoa("null"), field("Access-Control-Allow-Credentials", "true")]
            self.assertEqual(
                result(
                    model(
                        origin="null",
                        credentials=credentials,
                        required=False,
                        actual=actual(fields),
                    )
                )["actual_response_check"]["outcome"],
                PASS,
            )
        self.assertEqual(
            result(model(origin="null", required=False, actual=actual([])))[
                "actual_response_check"
            ]["outcome"],
            FAIL,
        )

    def test_allow_credentials_exact_case_and_duplicates(self):
        for values, expected in [
            ([], FAIL),
            (["true"], PASS),
            (["True"], FAIL),
            ([" true "], FAIL),
            (["false"], FAIL),
            (["true", "true"], FAIL),
            (["true", "false"], FAIL),
        ]:
            with self.subTest(values=values):
                fields = [acoa()] + [
                    field("Access-Control-Allow-Credentials", value) for value in values
                ]
                self.assertEqual(
                    result(model(credentials="include", required=False, actual=actual(fields)))[
                        "actual_response_check"
                    ]["outcome"],
                    expected,
                )

    def test_allow_origin_singletons_are_not_deduplicated(self):
        for values in [["*", "*"], [ORIGIN, ORIGIN], [ORIGIN, "*"], [ORIGIN + ", " + ORIGIN]]:
            with self.subTest(values=values):
                fields = [acoa(value) for value in values]
                self.assertEqual(
                    result(model(required=False, actual=actual(fields)))["actual_response_check"][
                        "outcome"
                    ],
                    FAIL,
                )

    def test_preflight_uses_original_credentials_mode(self):
        fields = [
            acoa("*"),
            field("Access-Control-Allow-Methods", "*"),
            field("Access-Control-Allow-Headers", "*"),
        ]
        self.assertEqual(
            result(model(preflight=preflight(fields)))["preflight_check"]["outcome"], PASS
        )
        self.assertEqual(
            result(model(credentials="include", preflight=preflight(fields)))["preflight_check"][
                "outcome"
            ],
            FAIL,
        )

    def test_required_and_forced_preflight_are_distinct(self):
        fields = [acoa(), field("Access-Control-Allow-Headers", "x-review")]
        self.assertEqual(
            result(model(preflight=preflight(fields)))["preflight_check"]["outcome"], FAIL
        )
        self.assertEqual(
            result(model(forced=True, preflight=preflight(fields)))["preflight_check"]["outcome"],
            PASS,
        )
        empty = fields + [field("Access-Control-Allow-Methods", "")]
        self.assertEqual(
            result(model(forced=True, preflight=preflight(empty)))["preflight_check"]["outcome"],
            FAIL,
        )
        with self.assertRaises(ERROR):
            cors.analyze_supplied_cors(model(required=False, forced=True))

    def test_safelisted_method_exception(self):
        for method in ("GET", "HEAD", "POST"):
            for credentials in ("omit", "include"):
                with self.subTest(method=method, credentials=credentials):
                    fields = [acoa(), field("Access-Control-Allow-Credentials", "true")]
                    self.assertEqual(
                        result(
                            model(
                                method=method,
                                credentials=credentials,
                                unsafe=(),
                                preflight=preflight(fields),
                            )
                        )["preflight_check"]["outcome"],
                        PASS,
                    )

    def test_method_case_and_known_normalization(self):
        for request_method, allowed_method, expected in [
            ("PATCH", "PATCH", PASS),
            ("patch", "patch", PASS),
            ("PATCH", "patch", FAIL),
            ("patch", "PATCH", FAIL),
        ]:
            with self.subTest(request=request_method, allowed=allowed_method):
                fields = [acoa(), field("Access-Control-Allow-Methods", allowed_method)]
                self.assertEqual(
                    result(model(method=request_method, unsafe=(), preflight=preflight(fields)))[
                        "preflight_check"
                    ]["outcome"],
                    expected,
                )
        for method in ("get", "gEt", "put", "Head", "options", "post", "delete"):
            with self.subTest(method=method), self.assertRaises(ERROR):
                cors.analyze_supplied_cors(model(method=method))

    def test_allow_lists_combine_instances_and_ascii_ows(self):
        fields = [
            acoa(),
            field("Access-Control-Allow-Methods", "GET, ,"),
            field("access-control-allow-methods", " \tPUT\t ,"),
            field("Access-Control-Allow-Headers", ",X-Other,"),
            field("ACCESS-CONTROL-ALLOW-HEADERS", "\tx-REVIEW\t, ,"),
        ]
        self.assertEqual(
            result(model(preflight=preflight(fields)))["preflight_check"]["outcome"], PASS
        )
        for malformed in ('"PUT"', "PUT; q=1", "P UT", "\u00a0PUT\u00a0", "\u2003PUT"):
            with self.subTest(value=malformed):
                changed = [
                    acoa(),
                    field("Access-Control-Allow-Methods", malformed),
                    field("Access-Control-Allow-Headers", "x-review"),
                ]
                if malformed.isascii():
                    self.assertEqual(
                        result(model(preflight=preflight(changed)))["preflight_check"]["outcome"],
                        FAIL,
                    )
                else:
                    with self.assertRaises(ERROR):
                        cors.analyze_supplied_cors(model(preflight=preflight(changed)))

    def test_authorization_never_comes_from_allow_headers_wildcard(self):
        for credentials, explicit in itertools.product(("omit", "include"), (False, True)):
            with self.subTest(credentials=credentials, explicit=explicit):
                fields = [
                    acoa(),
                    field("Access-Control-Allow-Credentials", "true"),
                    field("Access-Control-Allow-Methods", "PUT"),
                    field(
                        "Access-Control-Allow-Headers", "*" + (",AUTHORIZATION" if explicit else "")
                    ),
                ]
                expected = PASS if explicit else FAIL
                self.assertEqual(
                    result(
                        model(
                            credentials=credentials,
                            unsafe=("Authorization",),
                            preflight=preflight(fields),
                        )
                    )["preflight_check"]["outcome"],
                    expected,
                )

    def test_independent_set_oracle_for_preflight_methods_and_headers(self):
        # Enumerate finite permissions and use a set-universe oracle, not leaf helpers.
        origins = [acoa(), field("Access-Control-Allow-Credentials", "true")]
        for credentials, method, names, allow_method, allow_headers in itertools.product(
            ("omit", "include"),
            ("GET", "PUT", "PATCH"),
            ((), ("x-review",), ("authorization",)),
            ((), ("PUT",), ("PATCH",), ("*",)),
            ((), ("x-review",), ("authorization",), ("*",), ("*", "authorization")),
        ):
            with self.subTest(
                credentials=credentials,
                method=method,
                names=names,
                methods=allow_method,
                headers=allow_headers,
            ):
                method_universe = {"GET", "HEAD", "POST"} | set(allow_method)
                header_universe = set(allow_headers)
                if credentials != "include":
                    if "*" in method_universe:
                        method_universe.update({"GET", "PUT", "PATCH"})
                    if "*" in header_universe:
                        header_universe.add("x-review")
                expected = (
                    PASS if method in method_universe and set(names) <= header_universe else FAIL
                )
                fields = origins + [
                    field("Access-Control-Allow-Methods", ",".join(allow_method)),
                    field("Access-Control-Allow-Headers", ",".join(allow_headers)),
                ]
                self.assertEqual(
                    result(
                        model(
                            credentials=credentials,
                            method=method,
                            unsafe=names,
                            preflight=preflight(fields),
                        )
                    )["preflight_check"]["outcome"],
                    expected,
                )

    def test_preflight_and_actual_statuses_and_conclusions_are_separate(self):
        base = [
            acoa(),
            field("Access-Control-Allow-Methods", "PUT"),
            field("Access-Control-Allow-Headers", "x-review"),
        ]
        for preflight_status, actual_status in itertools.product(
            (200, 204, 299, 300, 403, 599), (200, 403, 599)
        ):
            with self.subTest(before=preflight_status, actual=actual_status):
                row = result(
                    model(
                        preflight=preflight(base, status=preflight_status),
                        actual=actual([acoa()], status=actual_status),
                    )
                )
                self.assertEqual(
                    row["preflight_check"]["outcome"], PASS if preflight_status < 300 else FAIL
                )
                self.assertEqual(row["actual_response_check"]["outcome"], PASS)
                self.assertEqual(
                    row["comprehensive_share_result"],
                    "passes_supplied_checks" if preflight_status < 300 else "fails_supplied_checks",
                )

    def test_complete_safelisted_response_name_projection(self):
        safe = [
            "cache-control",
            "content-language",
            "content-length",
            "content-type",
            "expires",
            "last-modified",
            "pragma",
        ]
        row = result(
            model(required=False, actual=actual([acoa()], names=safe + ["x-review", "set-cookie"]))
        )
        self.assertEqual(row["exposed_header_names"], sorted(safe))

    def test_exposure_wildcard_credentials_and_forbidden_headers(self):
        for credentials in ("omit", "same-origin", "include"):
            with self.subTest(credentials=credentials):
                fields = [
                    acoa(),
                    field("Access-Control-Allow-Credentials", "true"),
                    field("Access-Control-Expose-Headers", "*"),
                ]
                row = result(
                    model(
                        credentials=credentials,
                        required=False,
                        actual=actual(
                            fields,
                            names=("*", "x-review", "content-type", "set-cookie", "set-cookie2"),
                        ),
                    )
                )
                self.assertNotIn("set-cookie", row["exposed_header_names"])
                self.assertNotIn("set-cookie2", row["exposed_header_names"])
                self.assertIn("*", row["exposed_header_names"])
                self.assertEqual(
                    "x-review" in row["exposed_header_names"], credentials != "include"
                )
        fields = [acoa(), field("Access-Control-Expose-Headers", "Set-Cookie,Set-Cookie2,X-Review")]
        self.assertEqual(
            result(
                model(
                    required=False,
                    actual=actual(fields, names=("set-cookie", "set-cookie2", "x-review")),
                )
            )["exposed_header_names"],
            ["x-review"],
        )

    def test_invalid_optional_exposure_list_preserves_cors_check(self):
        for value in (
            '"x-review"',
            "x-review;parameter",
            "x-review, not a token",
        ):
            with self.subTest(value=value):
                fields = [acoa(), field("Access-Control-Expose-Headers", value)]
                row = result(
                    model(required=False, actual=actual(fields, names=("content-type", "x-review")))
                )
                self.assertEqual(row["actual_response_check"]["outcome"], PASS)
                self.assertEqual(row["exposed_header_names"], ["content-type"])
                self.assertEqual(
                    row["actual_response_check"]["issues"],
                    ["optional_expose_list_invalid_safelist_only"],
                )

    def _check_token_byte_boundary(self, field_name):
        accepted = token_boundary_model(field_name, 128)
        row = result(accepted)
        self.assertEqual(row["preflight_check"], {"outcome": PASS, "issues": []})
        self.assertEqual(row["actual_response_check"], {"outcome": PASS, "issues": []})
        self.assertEqual(row["exposed_header_names"], ["content-type", "x-review"])
        denied = token_boundary_model(field_name, 129)
        with self.assertRaises(ERROR):
            cors.analyze_supplied_cors(denied)
        for intake in (
            lambda: cors.analyze_supplied_cors(denied),
            lambda: cors.analyze_supplied_cors_bytes(model_json=canonical(denied).encode()),
        ):
            with (
                self.subTest(intake=intake),
                patch.object(cors, "_hash", side_effect=AssertionError("hash input reached")),
                patch.object(cors.hashlib, "sha256", side_effect=AssertionError("hash reached")),
                self.assertRaises(ERROR),
            ):
                intake()

    def test_allow_methods_token_byte_limit_is_software_rejection(self):
        self._check_token_byte_boundary("Access-Control-Allow-Methods")

    def test_allow_headers_token_byte_limit_is_software_rejection(self):
        self._check_token_byte_boundary("Access-Control-Allow-Headers")

    def test_expose_headers_token_byte_limit_is_software_rejection(self):
        self._check_token_byte_boundary("Access-Control-Expose-Headers")

    def test_complete_report_node_overflow_precedes_all_digests(self):
        # Every response has exactly 32 fields; empty duplicate list fields are valid.
        # The 29,381-node model is bounded, but 64 derived exposed-name lists are not.
        value = model(
            unsafe=tuple(f"h{i}" for i in range(32)),
            preflight=preflight(
                [
                    acoa("*"),
                    field("Access-Control-Allow-Methods", "PUT"),
                    field("Access-Control-Allow-Headers", "*"),
                ]
                + [field("Access-Control-Allow-Headers", "") for _ in range(29)]
            ),
            actual=actual(
                [
                    acoa("*"),
                    field("Access-Control-Expose-Headers", ",".join(f"h{i}" for i in range(32))),
                ]
                + [field("Access-Control-Expose-Headers", "") for _ in range(30)],
                names=tuple(f"h{i}" for i in range(62)),
            ),
        )
        value["cases"] = [copy.deepcopy(value["cases"][0]) for _ in range(64)]
        for index, case in enumerate(value["cases"]):
            case["case_id"] = f"case-{index}"
        pending = [value]
        source_nodes = 0
        while pending:
            item = pending.pop()
            source_nodes += 1
            if type(item) is dict:
                pending.extend(item)
                pending.extend(item.values())
            elif type(item) is list:
                pending.extend(item)
        self.assertEqual(source_nodes, 29_381)
        self.assertLess(len(canonical(value).encode()), cors.MAX_DOCUMENT_BYTES)
        with patch.object(cors, "_hash", wraps=cors._hash) as hashes:
            with self.assertRaisesRegex(ERROR, "node"):
                cors.analyze_supplied_cors(value)
            self.assertEqual(hashes.call_count, 0)
        with (
            patch.object(cors.hashlib, "sha256", side_effect=AssertionError("hash reached")),
            self.assertRaisesRegex(ERROR, "node"),
        ):
            cors.analyze_supplied_cors(value)

    def test_no_preflight_required_is_only_a_caller_premise(self):
        row = result(model(required=False, actual=actual([acoa()])))
        self.assertEqual(row["preflight_check"]["outcome"], "not_required_by_supplied_premise")
        self.assertEqual(row["comprehensive_share_result"], "passes_supplied_checks")
        report = cors.analyze_supplied_cors(
            model(required=False, actual=actual([acoa()]))
        ).to_dict()
        self.assertFalse(report["browser_fetch_eligibility_verified"])

    def test_incomplete_premises_and_snapshots_withhold_results(self):
        base = cors.component_fixture()
        for path in ("request", "preflight_response", "actual_response"):
            with self.subTest(path=path):
                value = copy.deepcopy(base)
                key = "projection_complete" if path == "request" else "headers_complete"
                value["cases"][0][path][key] = False
                row = result(value)
                self.assertEqual(row["comprehensive_share_result"], UNKNOWN)
                if path == "request":
                    self.assertEqual(row["preflight_check"]["outcome"], UNKNOWN)
                    self.assertEqual(row["actual_response_check"]["outcome"], UNKNOWN)
                if path == "actual_response":
                    self.assertEqual(row["exposed_header_names"], [])
        for missing in ("preflight_response", "actual_response"):
            value = copy.deepcopy(base)
            value["cases"][0][missing] = None
            self.assertEqual(result(value)["comprehensive_share_result"], UNKNOWN)

    def test_actual_cors_failure_does_not_overwrite_preflight_success(self):
        value = cors.component_fixture()
        value["cases"][0]["actual_response"]["cors_fields"][0]["value"] = "https://other.invalid"
        row = result(value)
        self.assertEqual(row["preflight_check"]["outcome"], PASS)
        self.assertEqual(row["actual_response_check"]["outcome"], FAIL)
        self.assertEqual(row["exposed_header_names"], [])

    def test_names_and_values_are_not_reinterpreted_as_wire_or_origin_normalization(self):
        for origin in (ORIGIN + "/", ORIGIN.upper(), ORIGIN + ":443"):
            row = result(model(required=False, actual=actual([acoa(origin)])))
            self.assertEqual(row["actual_response_check"]["outcome"], FAIL)
        with self.assertRaises(ERROR):
            cors.analyze_supplied_cors(model(origin="*"))
        for value in ("a\r\nb", "a\x00b", "\x7f", "\u00a0"):
            with self.subTest(value=value), self.assertRaises(ERROR):
                cors.analyze_supplied_cors(model(required=False, actual=actual([acoa(value)])))

    def test_header_name_inventory_and_complete_metadata_are_joined(self):
        for change in (
            "extra_policy",
            "missing_inventory",
            "duplicate_inventory",
            "duplicate_unsafe",
        ):
            value = cors.component_fixture()
            selected = value["cases"][0]
            if change == "extra_policy":
                selected["actual_response"]["response_header_names"].append(
                    "Access-Control-Allow-Credentials"
                )
            elif change == "missing_inventory":
                selected["actual_response"]["response_header_names"].remove(
                    "Access-Control-Allow-Origin"
                )
            elif change == "duplicate_inventory":
                selected["actual_response"]["response_header_names"].append("CONTENT-TYPE")
            else:
                selected["request"]["unsafe_header_names"].append("x-synthetic")
            with self.subTest(change=change), self.assertRaises(ERROR):
                cors.analyze_supplied_cors(value)

    def test_credentials_mode_malformed_shapes_use_domain_error(self):
        for value in ([], {}, None, True, 1, 1.0, "unrecognized"):
            supplied = cors.component_fixture()
            supplied["cases"][0]["request"]["credentials_mode"] = value
            with (
                self.subTest(value=value),
                patch.object(cors.hashlib, "sha256", side_effect=AssertionError("hash reached")),
                self.assertRaises(ERROR),
            ):
                cors.analyze_supplied_cors(supplied)

    def test_exact_native_aliases_are_denied_before_hash(self):
        class Text(str):
            pass

        class Integer(int):
            pass

        class Mapping(dict):
            pass

        class Sequence(list):
            pass

        controls = []
        for version in (True, 1.0, Integer(1)):
            value = cors.component_fixture()
            value["schema_version"] = version
            controls.append(value)
        for status in (True, 204.0, Integer(204)):
            value = cors.component_fixture()
            value["cases"][0]["preflight_response"]["status"] = status
            controls.append(value)
        for replacement in (Text("omit"), [], {}):
            value = cors.component_fixture()
            value["cases"][0]["request"]["credentials_mode"] = replacement
            controls.append(value)
        for replacement in (0, 1, None, "true"):
            value = cors.component_fixture()
            value["cases"][0]["request"]["projection_complete"] = replacement
            controls.append(value)
        controls.extend(
            (Mapping(cors.component_fixture()), {"schema_version": 1, "cases": Sequence([])})
        )
        for value in controls:
            with (
                self.subTest(value=repr(value)[:100]),
                patch.object(cors.hashlib, "sha256", side_effect=AssertionError("hash reached")),
                self.assertRaises(ERROR),
            ):
                cors.analyze_supplied_cors(value)

    def test_closed_fields_missing_and_unsupported_input_are_denied(self):
        for path in ("root", "case", "request", "preflight", "actual"):
            value = cors.component_fixture()
            targets = {
                "root": value,
                "case": value["cases"][0],
                "request": value["cases"][0]["request"],
                "preflight": value["cases"][0]["preflight_response"],
                "actual": value["cases"][0]["actual_response"],
            }
            for mutation in ("extra", "missing"):
                supplied = copy.deepcopy(value)
                selected = {
                    "root": supplied,
                    "case": supplied["cases"][0],
                    "request": supplied["cases"][0]["request"],
                    "preflight": supplied["cases"][0]["preflight_response"],
                    "actual": supplied["cases"][0]["actual_response"],
                }[path]
                if mutation == "extra":
                    selected["unsupported"] = []
                else:
                    selected.pop(next(iter(targets[path])))
                with self.subTest(path=path, mutation=mutation), self.assertRaises(ERROR):
                    cors.analyze_supplied_cors(supplied)
        value = cors.component_fixture()
        value["cases"][0]["actual_response"]["cors_fields"].append(
            field("Set-Cookie", "not-consumed")
        )
        with self.assertRaises(ERROR):
            cors.analyze_supplied_cors(value)

    def test_duplicate_case_ids_and_bounded_statuses(self):
        value = cors.component_fixture()
        value["cases"].append(copy.deepcopy(value["cases"][0]))
        with self.assertRaises(ERROR):
            cors.analyze_supplied_cors(value)
        for status in (0, 199, 600, -(2**63), 2**63 - 1):
            value = cors.component_fixture()
            value["cases"][0]["actual_response"]["status"] = status
            with self.subTest(status=status), self.assertRaises(ERROR):
                cors.analyze_supplied_cors(value)

    def test_raw_duplicate_float_nonfinite_integer_and_unicode_guards(self):
        for raw in (
            b'{"schema_version":1,"schema_version":1,"cases":[]}',
            b'{"schema_version":true,"cases":[]}',
            b'{"schema_version":1.0,"cases":[]}',
            b"NaN",
            b"Infinity",
            b"1e0",
            b"--1",
            b"01",
            b"9223372036854775808",
            b"-9223372036854775809",
            b'"\\ud800"',
            b'"\\udc00"',
            b"\xff",
        ):
            with self.subTest(raw=raw), self.assertRaises(ERROR):
                cors.analyze_supplied_cors_bytes(model_json=raw)
        for raw in (b'{"schema_version":true,"cases":[]}', b'{"schema_version":1.0,"cases":[]}'):
            with self.assertRaises(ERROR):
                cors.CorsAnalysis.from_json(raw.decode())

    def test_raw_budgets_reject_before_decoder_or_hash(self):
        cases = [
            b'"' + b"x" * (cors.MAX_STRING_BYTES + 1) + b'"',
            b"[" * cors.MAX_DEPTH + b"0" + b"]" * cors.MAX_DEPTH,
            b"[" + b"0," * cors.MAX_NODES + b"0]",
            b"9" * 10_000,
            b" " * (cors.MAX_DOCUMENT_BYTES + 1),
            b'"' + b"\\u0061" * (cors.MAX_STRING_BYTES + 1) + b'"',
        ]
        for raw in cases:
            with (
                self.subTest(length=len(raw)),
                patch.object(cors.json, "loads", side_effect=AssertionError("decoder reached")),
                patch.object(cors.hashlib, "sha256", side_effect=AssertionError("hash reached")),
                self.assertRaises(ERROR),
            ):
                cors.analyze_supplied_cors_bytes(model_json=raw)
        for scalar in (b'"x"', b"true", b"false", b"null"):
            with (
                self.subTest(scalar=scalar),
                patch.object(cors.json, "loads", side_effect=AssertionError("decoder reached")),
                self.assertRaises(ERROR),
            ):
                cors.CorsAnalysis.from_json(
                    (b"[" * cors.MAX_DEPTH + scalar + b"]" * cors.MAX_DEPTH).decode()
                )

    def test_native_repeated_graph_and_escaped_cost_before_serialization(self):
        shared = ["\\" * cors.MAX_STRING_BYTES] * 64
        controls = [[shared] * 64, [0] * (cors.MAX_NODES + 1), {"value": 2**10000}]
        nested = 0
        for _ in range(cors.MAX_DEPTH):
            nested = [nested]
        controls.append(nested)
        for value in controls:
            with (
                self.subTest(kind=type(value).__name__),
                patch.object(
                    cors.json, "dumps", side_effect=AssertionError("serialization reached")
                ),
                self.assertRaises(ERROR),
            ):
                cors.analyze_supplied_cors(value)

    def test_semantic_case_field_token_and_work_ceiling_denials(self):
        value = cors.component_fixture()
        value["cases"] = [copy.deepcopy(value["cases"][0]) for _ in range(cors.MAX_CASES + 1)]
        for index, case in enumerate(value["cases"]):
            case["case_id"] = f"case-{index}"
        with self.assertRaises(ERROR):
            cors.analyze_supplied_cors(value)
        value = cors.component_fixture()
        value["cases"][0]["preflight_response"]["cors_fields"] = [acoa()] * 33
        with self.assertRaises(ERROR):
            cors.analyze_supplied_cors(value)
        value = model(
            method="GET",
            unsafe=(),
            preflight=preflight(
                [
                    acoa(),
                    field("Access-Control-Allow-Methods", ",".join(["a"] * 2048)),
                    field("Access-Control-Allow-Headers", ",".join(["b"] * 2048)),
                ]
            ),
        )
        value["cases"].append(copy.deepcopy(value["cases"][0]))
        value["cases"][1]["case_id"] = "second"
        with self.assertRaises(ERROR):
            cors.analyze_supplied_cors(value)
        with (
            patch.object(cors, "MAX_WORK", 1),
            patch.object(cors.json, "dumps", side_effect=AssertionError("serialization reached")),
            self.assertRaises(ERROR),
        ):
            cors.analyze_supplied_cors(cors.component_fixture())

    def test_native_bytes_and_text_wrapper_boundaries(self):
        class Bytes(bytes):
            pass

        class Text(str):
            pass

        for raw in (bytearray(b"{}"), memoryview(b"{}"), Bytes(b"{}"), "{}", None):
            with self.subTest(type=type(raw)), self.assertRaises(ERROR):
                cors.analyze_supplied_cors_bytes(model_json=raw)
        for text in (Text("{}"), b"{}", None):
            with self.subTest(type=type(text)), self.assertRaises(ERROR):
                cors.CorsAnalysis.from_json(text)

    def test_coherently_rehashed_false_outputs_are_rejected(self):
        original = cors.analyze_supplied_cors(cors.component_fixture()).to_dict()
        controls = []
        for changes in (
            {"exposed_header_names": ["set-cookie"]},
            {"comprehensive_share_result": UNKNOWN},
            {"preflight_check": {"outcome": FAIL, "issues": []}},
            {"actual_source_id": "foreign"},
        ):
            document = copy.deepcopy(original)
            document["cases"][0].update(changes)
            controls.append(readdress(document))
        for key, replacement in (
            ("case_count", True),
            ("schema_version", True),
            ("positive_use_approved", True),
            ("standard_commit", "0" * 40),
            ("limits", {}),
            ("effects", {}),
        ):
            document = copy.deepcopy(original)
            document[key] = replacement
            controls.append(readdress(document))
        for document in controls:
            with self.subTest(keys=document["cases"][0]), self.assertRaises(ERROR):
                cors.CorsAnalysis.from_json(canonical(document))

    def test_public_report_forgery_and_original_model_substitution(self):
        original = cors.component_fixture()
        report = cors.analyze_supplied_cors(original)
        malformed = object.__new__(cors.CorsAnalysis)
        with self.assertRaises(ERROR):
            malformed.to_dict()
        document = report.to_dict()
        document["cases"][0]["exposed_header_names"] = ["set-cookie"]
        object.__setattr__(malformed, "document_json", canonical(readdress(document)))
        with self.assertRaises(ERROR):
            cors.verify_supplied_cors_analysis(malformed, model=original)

        class Foreign(cors.CorsAnalysis):
            pass

        with self.assertRaises(ERROR):
            cors.verify_supplied_cors_analysis(Foreign(report.to_json()), model=original)
        for path in ("source", "origin", "credentials", "status", "case_order"):
            changed = copy.deepcopy(original)
            selected = changed["cases"][0]
            if path == "source":
                selected["request"]["source_id"] = "foreign"
            elif path == "origin":
                selected["request"]["serialized_origin"] = "https://other.invalid"
            elif path == "credentials":
                selected["request"]["credentials_mode"] = "same-origin"
            elif path == "status":
                selected["actual_response"]["status"] = 200
            else:
                changed["cases"].append(copy.deepcopy(selected))
                changed["cases"][1]["case_id"] = "second"
                changed["cases"].reverse()
            candidate = cors.analyze_supplied_cors(changed)
            self.assertEqual(
                cors.CorsAnalysis.from_json(candidate.to_json()).to_json(), candidate.to_json()
            )
            with self.subTest(path=path), self.assertRaises(ERROR):
                cors.verify_supplied_cors_analysis(candidate, model=original)

    def test_output_and_input_detachment_and_no_effects(self):
        original = cors.component_fixture()
        second = cors.component_fixture()
        report = cors.analyze_supplied_cors(original)
        before = report.to_json()
        original["cases"][0]["request"]["unsafe_header_names"].append("authorization")
        document = report.to_dict()
        document["model"]["cases"][0]["request"]["serialized_origin"] = "null"
        document["cases"][0]["exposed_header_names"].clear()
        self.assertEqual(report.to_json(), before)
        self.assertEqual(cors.verify_supplied_cors_analysis(report, model=second).to_json(), before)
        self.assertEqual(second, cors.component_fixture())
        value = report.to_dict()
        self.assertTrue(value["offline_only"])
        self.assertTrue(value["supplied_metadata_only"])
        for flag in (
            "positive_use_approved",
            "browser_fetch_eligibility_verified",
            "server_authorization_verified",
            "source_authentication_verified",
            "vulnerability_claimed",
            "qualification_claimed",
        ):
            self.assertIs(value[flag], False)
        self.assertTrue(all(effect == "none" for effect in value["effects"].values()))
        self.assertIn(
            "metadata_completeness_and_preflight_requirement_are_supplied_premises",
            value["limitations"],
        )


if __name__ == "__main__":
    unittest.main()
