"""Finite native-source and symbolic-oracle tests for declaration evolution."""

from __future__ import annotations

import copy
import hashlib
import itertools
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_openapi_security_evolution as analysis

_ABSENT = object()
_DOMAIN = "sunderkey.offline-openapi-security-evolution.v1"
_ERROR = analysis.OpenAPISecurityEvolutionError
_REPORT = analysis.OpenAPISecurityEvolutionReport


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def address(document):
    value = copy.deepcopy(document)
    body = {key: child for key, child in value.items() if key not in {"report_id", "report_sha256"}}
    digest = hashlib.sha256(
        canonical({"domain": _DOMAIN, "analysis": body}).encode("ascii")
    ).hexdigest()
    value["report_id"] = "OAE-" + digest[:32].upper()
    value["report_sha256"] = "sha256:" + digest
    return value


def document(security=_ABSENT, *, definitions=None, paths=None):
    result = {
        "openapi": "3.0.4",
        "info": {"title": "Synthetic comparison", "version": "1"},
        "components": {
            "securitySchemes": definitions
            if definitions is not None
            else {
                "a": {"type": "http", "scheme": "bearer"},
                "b": {"type": "apiKey", "in": "header", "name": "X-Synthetic"},
            }
        },
        "paths": paths
        if paths is not None
        else {
            "/synthetic": {"get": {"responses": {"200": {"description": "synthetic"}}}},
        },
    }
    if security is not _ABSENT:
        result["security"] = security
    return result


def model(previous, current):
    return {"schema_version": 1, "previous_document": previous, "current_document": current}


def oauth(scopes):
    return {
        "type": "oauth2",
        "flows": {
            "clientCredentials": {
                "tokenUrl": "https://issuer.invalid/synthetic",
                "scopes": {scope: "synthetic" for scope in scopes},
            }
        },
    }


def row(previous, current, *, definitions=None):
    report = analysis.analyze_openapi_security_evolution(
        model(
            document(previous, definitions=definitions),
            document(current, definitions=definitions),
        )
    )
    return report.to_dict()["operations"][0]


def formula_value(security, assignment):
    terms = security or [{}]
    return any(all(name in assignment for name in term) for term in terms)


def witness_value(witness, assignment):
    return all(group["scheme"] in assignment for group in witness)


class OpenAPISecurityEvolutionTests(unittest.TestCase):
    def test_literal_fixture_identity_and_exact_source_replay(self):
        original = analysis.component_fixture()
        report = analysis.analyze_openapi_security_evolution(original)
        value = report.to_dict()
        self.assertEqual(value["report_id"], "OAE-D38F72F34C8201A36AF20ED153E8C2ED")
        self.assertEqual(
            value["report_sha256"],
            "sha256:d38f72f34c8201a36af20ed153e8c2ed8ac792b05c41c4c2cedf3a68e2e3644e",
        )
        self.assertEqual(
            value["source"],
            {
                "model_sha256": (
                    "sha256:ffba13fa579f346945206fd9b549b39dd9a105f255c16ae3a3937bb22c65edb4"
                ),
                "previous_document_sha256": (
                    "sha256:f18676fb792da21330fdd9da537f531d3649dd64fde6eb91d354a516794d2fb4"
                ),
                "current_document_sha256": (
                    "sha256:92c53b70b7ea7b8c2ada38c8abdbdace9ea6f0ce529a6950da0f6698b462e652"
                ),
            },
        )
        self.assertEqual(value["capability_id"], "army.gb.d06.s01")
        self.assertEqual(value["operations"][0]["relationship"], "weakened")
        self.assertEqual(
            value["operations"][0]["current_not_previous_witness"],
            [{"scheme": "bearer", "scopes": []}],
        )
        verified = analysis.verify_openapi_security_evolution(report, model=original)
        self.assertIsNot(verified, report)
        self.assertEqual(verified.to_json(), report.to_json())
        self.assertEqual(len(report.to_json().encode("ascii")), 2163)

    def test_report_roundtrips_and_whitespace_is_not_source_identity(self):
        report = analysis.analyze_openapi_security_evolution(analysis.component_fixture())
        value = report.to_dict()
        self.assertEqual(_REPORT.from_dict(value).to_json(), report.to_json())
        self.assertEqual(_REPORT.from_json(json.dumps(value, indent=2)).to_json(), report.to_json())
        self.assertEqual(_REPORT(report.to_json()).to_json(), report.to_json())
        with self.assertRaises(_ERROR):
            _REPORT(json.dumps(value, indent=2))

    def test_fixture_and_report_are_independently_detached(self):
        original = analysis.component_fixture()
        preserved = copy.deepcopy(original)
        report = analysis.analyze_openapi_security_evolution(original)
        original["current_document"]["security"].append({})
        self.assertEqual(analysis.component_fixture(), preserved)
        value = report.to_dict()
        value["operations"][0]["current"]["formula"].clear()
        self.assertEqual(
            report.to_dict()["operations"][0]["current"]["formula"],
            [[{"scheme": "bearer", "scopes": []}]],
        )
        analysis.verify_openapi_security_evolution(report, model=preserved)
        with self.assertRaises(_ERROR):
            analysis.verify_openapi_security_evolution(report, model=original)

    def test_all_versions_and_exact_method_path_matching(self):
        for version in ("3.0.0", "3.0.1", "3.0.2", "3.0.3", "3.0.4"):
            with self.subTest(version=version):
                previous = document([{"a": []}])
                previous["openapi"] = version
                current = copy.deepcopy(previous)
                current["paths"] = {"/Synthetic": {"post": {}}}
                result = analysis.analyze_openapi_security_evolution(
                    model(previous, current)
                ).to_dict()
                self.assertEqual(
                    [
                        (entry["path"], entry["method"], entry["relationship"])
                        for entry in result["operations"]
                    ],
                    [("/Synthetic", "POST", "added"), ("/synthetic", "GET", "removed")],
                )
                for entry in result["operations"]:
                    self.assertIsNone(entry["previous_implies_current"])
                    self.assertIsNone(entry["current_implies_previous"])

    def test_inclusive_relations_and_compact_witnesses(self):
        vectors = [
            ([{"a": []}], [{"a": []}], "equivalent", True, True),
            ([{"a": [], "b": []}], [{"a": []}], "weakened", True, False),
            ([{"a": []}], [{"a": [], "b": []}], "strengthened", False, True),
            ([{"a": []}], [{"b": []}], "incomparable", False, False),
            ([{"a": []}, {"b": []}], [{"a": []}], "strengthened", False, True),
        ]
        for before, after, relation, forward, backward in vectors:
            with self.subTest(relation=relation, before=before, after=after):
                value = row(before, after)
                self.assertEqual(value["relationship"], relation)
                self.assertIs(value["previous_implies_current"], forward)
                self.assertIs(value["current_implies_previous"], backward)
                self.assertEqual(value["previous_not_current_witness"] is None, forward)
                self.assertEqual(value["current_not_previous_witness"] is None, backward)

    def test_exhaustive_two_scheme_oracle_through_public_analyzer(self):
        possible = [{}, {"a": []}, {"b": []}, {"a": [], "b": []}]
        formulas = [
            [copy.deepcopy(term) for index, term in enumerate(possible) if mask & (1 << index)]
            for mask in range(16)
        ]
        assignments = [
            set(name for index, name in enumerate(("a", "b")) if mask & (1 << index))
            for mask in range(4)
        ]
        for before, after in itertools.product(formulas, repeat=2):
            with self.subTest(before=before, after=after):
                value = row(before, after)
                forward = all(
                    not formula_value(before, assignment) or formula_value(after, assignment)
                    for assignment in assignments
                )
                backward = all(
                    not formula_value(after, assignment) or formula_value(before, assignment)
                    for assignment in assignments
                )
                self.assertIs(value["previous_implies_current"], forward)
                self.assertIs(value["current_implies_previous"], backward)
                for witness, left, right in (
                    (value["previous_not_current_witness"], before, after),
                    (value["current_not_previous_witness"], after, before),
                ):
                    if witness is not None:
                        assignment = {group["scheme"] for group in witness}
                        self.assertTrue(witness_value(witness, assignment))
                        self.assertTrue(formula_value(left, assignment))
                        self.assertFalse(formula_value(right, assignment))

    def test_oauth_scope_and_scheme_presence_obligations(self):
        definitions = {
            "auth": oauth(["read", "write"]),
            "key": {"type": "apiKey", "in": "cookie", "name": "synthetic"},
        }
        vectors = [
            ([{"auth": ["read"]}], [{"auth": []}], "weakened"),
            ([{"auth": ["read"]}], [{"auth": ["read", "write"]}], "strengthened"),
            ([{"auth": ["read"]}], [{"auth": ["write"]}], "incomparable"),
            ([{"auth": ["read"]}, {"key": []}], [{"auth": ["read"], "key": []}], "strengthened"),
        ]
        for before, after, relation in vectors:
            with self.subTest(before=before, after=after):
                value = row(before, after, definitions=definitions)
                self.assertEqual(value["relationship"], relation)
                self.assertTrue(value["previous"]["resolved"])
                self.assertTrue(value["current"]["resolved"])

    def test_oauth_flows_are_locally_resolved_without_discovery(self):
        flows = {
            "implicit": {"authorizationUrl": "https://issuer.invalid/authorize"},
            "password": {"tokenUrl": "https://issuer.invalid/token"},
            "clientCredentials": {"tokenUrl": "https://issuer.invalid/token"},
            "authorizationCode": {
                "authorizationUrl": "https://issuer.invalid/authorize",
                "tokenUrl": "https://issuer.invalid/token",
            },
        }
        for name, urls in flows.items():
            with self.subTest(flow=name):
                definition = {
                    "type": "oauth2",
                    "flows": {
                        name: {
                            **urls,
                            "refreshUrl": "https://issuer.invalid/refresh",
                            "scopes": {"read": "synthetic"},
                        }
                    },
                }
                value = row(
                    [{"auth": ["read"]}], [{"auth": ["read"]}], definitions={"auth": definition}
                )
                self.assertEqual(value["relationship"], "equivalent")

    def test_empty_absent_and_anonymous_remain_distinct(self):
        explicit = row([], [{}])
        self.assertEqual(explicit["relationship"], "equivalent")
        self.assertEqual(explicit["previous"]["declaration_form"], "explicit_empty")
        self.assertEqual(explicit["previous"]["declared_alternative_count"], 0)
        self.assertEqual(explicit["current"]["declaration_form"], "anonymous_alternative")
        self.assertEqual(explicit["current"]["declared_alternative_count"], 1)
        self.assertEqual(explicit["previous"]["formula"], [[]])
        value = row(_ABSENT, [])
        self.assertEqual(value["relationship"], "unassessed")
        self.assertEqual(value["previous"]["declaration_origin"], "absent")
        self.assertEqual(value["previous"]["formula"], [])
        self.assertIn(
            {"code": "no_security_declaration", "subject": ""}, value["previous"]["issues"]
        )

    def test_operation_override_inherits_only_when_missing(self):
        previous = document([{"a": [], "b": []}])
        current = copy.deepcopy(previous)
        previous["paths"]["/synthetic"]["get"]["security"] = [{"a": []}]
        current["paths"]["/synthetic"]["get"]["security"] = []
        value = analysis.analyze_openapi_security_evolution(model(previous, current)).to_dict()[
            "operations"
        ][0]
        self.assertEqual(value["relationship"], "weakened")
        self.assertEqual(value["previous"]["declaration_origin"], "operation")
        self.assertEqual(value["current"]["declaration_origin"], "operation")
        current["paths"]["/synthetic"]["get"].pop("security")
        value = analysis.analyze_openapi_security_evolution(model(previous, current)).to_dict()[
            "operations"
        ][0]
        self.assertEqual(value["relationship"], "strengthened")
        self.assertEqual(value["current"]["declaration_origin"], "root")

    def test_absorption_deduplication_and_permutation_keep_semantics(self):
        before = [{"b": [], "a": []}, {"a": []}, {"a": []}]
        after = [{"a": []}]
        value = row(before, after)
        self.assertEqual(value["relationship"], "equivalent")
        self.assertEqual(value["previous"]["formula"], [[{"scheme": "a", "scopes": []}]])
        original = model(document(before), document(after))
        report = analysis.analyze_openapi_security_evolution(original)
        reordered = copy.deepcopy(original)
        reordered["previous_document"]["security"].reverse()
        changed = analysis.analyze_openapi_security_evolution(reordered)
        self.assertEqual(changed.to_dict()["operations"], report.to_dict()["operations"])
        self.assertNotEqual(changed.to_dict()["source"], report.to_dict()["source"])
        with self.assertRaises(_ERROR):
            analysis.verify_openapi_security_evolution(report, model=reordered)

    def test_native_mapping_order_is_canonical_source_identity(self):
        original = analysis.component_fixture()
        reordered = {key: copy.deepcopy(original[key]) for key in reversed(list(original))}
        reordered["previous_document"] = dict(
            reversed(list(reordered["previous_document"].items()))
        )
        self.assertEqual(
            analysis.analyze_openapi_security_evolution(original).to_json(),
            analysis.analyze_openapi_security_evolution(reordered).to_json(),
        )

    def test_one_unresolved_or_absorbed_alternative_withholds_whole_row(self):
        for alternatives in ([{}, {"missing": []}], [{"a": []}, {"a": [], "missing": []}]):
            with self.subTest(alternatives=alternatives):
                value = row(alternatives, [{}])
                self.assertEqual(value["relationship"], "unassessed")
                self.assertFalse(value["previous"]["resolved"])
                self.assertIn(
                    {"code": "undefined_scheme", "subject": "missing"}, value["previous"]["issues"]
                )
                self.assertIsNone(value["previous_implies_current"])
                self.assertIsNone(value["current_not_previous_witness"])

    def test_changed_or_missing_referenced_definitions_are_unassessed(self):
        modifications = [
            {"type": "http", "scheme": "basic"},
            {"type": "http", "scheme": "bearer", "description": "changed"},
            None,
        ]
        for replacement in modifications:
            with self.subTest(replacement=replacement):
                previous = document([{"a": []}])
                current = copy.deepcopy(previous)
                if replacement is None:
                    current["components"]["securitySchemes"].pop("a")
                else:
                    current["components"]["securitySchemes"]["a"] = replacement
                value = analysis.analyze_openapi_security_evolution(
                    model(previous, current)
                ).to_dict()["operations"][0]
                self.assertEqual(value["relationship"], "unassessed")
                for side in ("previous", "current"):
                    self.assertIn(
                        {"code": "definition_not_shared", "subject": "a"}, value[side]["issues"]
                    )

    def test_unreferenced_definition_change_does_not_change_relation(self):
        previous = document([{"a": []}])
        current = copy.deepcopy(previous)
        current["components"]["securitySchemes"]["b"] = {"type": "unimplemented"}
        value = analysis.analyze_openapi_security_evolution(model(previous, current)).to_dict()
        self.assertEqual(value["operations"][0]["relationship"], "equivalent")
        self.assertNotEqual(
            value["source"]["previous_document_sha256"], value["source"]["current_document_sha256"]
        )

    def test_unsupported_local_scheme_semantics_withhold_certainty(self):
        definitions = [
            {"type": "openIdConnect", "openIdConnectUrl": "https://issuer.invalid/discovery"},
            {"$ref": "https://schema.invalid/security"},
            {"type": "http", "scheme": "digest"},
            {"type": "mutualTLS"},
            {"type": "http", "scheme": "bearer", "x-runtime-rule": True},
            {"type": "apiKey", "name": "synthetic", "in": []},
            {"type": "apiKey", "name": "synthetic", "in": {}},
            {"type": "oauth2", "flows": {}},
            {
                "type": "oauth2",
                "flows": {
                    "password": {
                        "tokenUrl": "relative/token",
                        "scopes": {},
                    }
                },
            },
            {
                "type": "oauth2",
                "flows": {
                    "password": {
                        "tokenUrl": "https://issuer.invalid/token",
                        "scopes": {},
                        "x-runtime-rule": True,
                    }
                },
            },
        ]
        for definition in definitions:
            with self.subTest(definition=definition):
                value = row([{"auth": []}], [{"auth": []}], definitions={"auth": definition})
                self.assertEqual(value["relationship"], "unassessed")
                self.assertFalse(value["previous"]["resolved"])
                self.assertIsNone(value["previous_implies_current"])

    def test_non_oauth_scopes_and_undefined_oauth_scope_are_unassessed(self):
        self.assertEqual(row([{"a": ["read"]}], [{"a": []}])["relationship"], "unassessed")
        value = row([{"auth": ["unknown"]}], [{"auth": []}], definitions={"auth": oauth(["read"])})
        self.assertEqual(value["relationship"], "unassessed")
        self.assertIn({"code": "undefined_scope", "subject": "auth"}, value["previous"]["issues"])

    def test_opaque_paths_do_not_invent_added_removed_operations(self):
        reference = document(
            [{"a": []}],
            paths={
                "/synthetic": {"$ref": "https://schema.invalid/opaque"},
            },
        )
        inline = document([{"a": []}])
        for previous, current in ((reference, inline), (inline, reference)):
            with self.subTest(previous=previous):
                value = analysis.analyze_openapi_security_evolution(
                    model(previous, current)
                ).to_dict()
                self.assertEqual(value["operations"][0]["relationship"], "unassessed")
                self.assertEqual(value["summary"]["added"], 0)
                self.assertEqual(value["summary"]["removed"], 0)
                self.assertEqual(len(value["opaque_paths"]), 1)
        value = analysis.analyze_openapi_security_evolution(
            model(reference, copy.deepcopy(reference))
        ).to_dict()
        self.assertEqual(value["operations"], [])
        self.assertEqual(value["analysis_status"], "partially_assessed")

    def test_inline_reference_and_extensions_are_unassessed(self):
        for location in ("root", "components", "path", "operation"):
            with self.subTest(location=location):
                previous = document([{"a": []}])
                target = {
                    "root": previous,
                    "components": previous["components"],
                    "path": previous["paths"]["/synthetic"],
                    "operation": previous["paths"]["/synthetic"]["get"],
                }[location]
                target["x-auth-rule"] = True
                value = analysis.analyze_openapi_security_evolution(
                    model(previous, copy.deepcopy(previous))
                ).to_dict()
                self.assertEqual(value["operations"][0]["relationship"], "unassessed")
        previous = document(
            [{"a": []}],
            paths={
                "/synthetic": {"get": {"$ref": "#/opaque"}},
            },
        )
        current = document([{"a": []}], paths={})
        value = analysis.analyze_openapi_security_evolution(model(previous, current)).to_dict()[
            "operations"
        ][0]
        self.assertEqual(value["relationship"], "unassessed")

    def test_source_metadata_only_no_effects_or_positive_authority(self):
        value = analysis.analyze_openapi_security_evolution(analysis.component_fixture()).to_dict()
        self.assertTrue(value["offline_only"])
        self.assertTrue(value["declaration_only"])
        self.assertEqual(set(value["effects"].values()), {"none"})
        for key in (
            "positive_use_approved",
            "target_authorization_verified",
            "credential_rights_verified",
            "server_behavior_verified",
            "full_openapi_validation_claimed",
            "qualification_claimed",
        ):
            self.assertIs(value[key], False)
        self.assertNotIn("previous_document", value)
        self.assertNotIn("current_document", value)
        self.assertNotIn("issuer.invalid", canonical(value))

    def test_coherently_rehashed_false_formula_fails_original_source_replay(self):
        original = analysis.component_fixture()
        report = analysis.analyze_openapi_security_evolution(original)
        substituted = copy.deepcopy(original)
        substituted["current_document"]["security"] = [{"key": []}]
        false_value = analysis.analyze_openapi_security_evolution(substituted).to_dict()
        false_value["source"] = report.to_dict()["source"]
        forged = _REPORT.from_dict(address(false_value))
        self.assertEqual(
            forged.to_dict()["operations"][0]["current"]["formula"],
            [[{"scheme": "key", "scopes": []}]],
        )
        with self.assertRaisesRegex(_ERROR, "original model"):
            analysis.verify_openapi_security_evolution(forged, model=original)

    def test_false_direction_witness_counts_and_flags_reject_after_readdress(self):
        original = analysis.analyze_openapi_security_evolution(
            analysis.component_fixture()
        ).to_dict()
        mutations = [
            (
                "direction",
                lambda value: value["operations"][0].update(current_implies_previous=True),
            ),
            (
                "relationship",
                lambda value: value["operations"][0].update(relationship="equivalent"),
            ),
            (
                "witness",
                lambda value: value["operations"][0].update(current_not_previous_witness=[]),
            ),
            ("count", lambda value: value.update(operation_count=False)),
            ("summary", lambda value: value["summary"].update(weakened=True)),
            ("resolved", lambda value: value["operations"][0]["current"].update(resolved=1)),
            ("authority", lambda value: value.update(positive_use_approved=True)),
            ("effect", lambda value: value["effects"].update(network="observed")),
        ]
        for name, mutate in mutations:
            with self.subTest(mutation=name):
                value = copy.deepcopy(original)
                mutate(value)
                with self.assertRaises(_ERROR):
                    _REPORT.from_dict(address(value))

    def test_self_consistent_source_work_substitution_requires_original_model(self):
        original = analysis.component_fixture()
        base = analysis.analyze_openapi_security_evolution(original).to_dict()
        for key in ("work_units", "source"):
            with self.subTest(key=key):
                value = copy.deepcopy(base)
                if key == "work_units":
                    value[key] += 1
                else:
                    value[key]["model_sha256"] = "sha256:" + "a" * 64
                forged = _REPORT.from_dict(address(value))
                with self.assertRaises(_ERROR):
                    analysis.verify_openapi_security_evolution(forged, model=original)

    def test_model_substitutions_and_source_permutations_reject_original_report(self):
        original = analysis.component_fixture()
        report = analysis.analyze_openapi_security_evolution(original)
        changes = [
            lambda value: value["current_document"]["info"].update(version="2"),
            lambda value: value["current_document"]["paths"].update(
                {"/other": {"get": {"security": []}}}
            ),
            lambda value: value["previous_document"].update(security=[]),
        ]
        for change in changes:
            with self.subTest(change=change):
                changed = copy.deepcopy(original)
                change(changed)
                with self.assertRaises(_ERROR):
                    analysis.verify_openapi_security_evolution(report, model=changed)

    def test_model_fields_and_schema_require_exact_native_types(self):
        for bad in (None, [], True, 1.0, "1", 2):
            with self.subTest(schema=bad):
                value = analysis.component_fixture()
                value["schema_version"] = bad
                with self.assertRaises(_ERROR):
                    analysis.analyze_openapi_security_evolution(value)
        for field, bad in (
            ("openapi", []),
            ("openapi", {}),
            ("openapi", "3.1.0"),
            ("paths", []),
            ("components", []),
        ):
            with self.subTest(field=field, bad=bad):
                value = analysis.component_fixture()
                value["current_document"][field] = bad
                with self.assertRaises(_ERROR):
                    analysis.analyze_openapi_security_evolution(value)
        value = analysis.component_fixture()
        value["unexpected"] = None
        with self.assertRaises(_ERROR):
            analysis.analyze_openapi_security_evolution(value)

    def test_native_aliases_and_subclasses_reject_before_hash_hooks(self):
        class Text(str):
            def __eq__(self, other):
                raise AssertionError("custom equality must not run")

            __hash__ = str.__hash__

        class Integer(int):
            pass

        class Array(list):
            pass

        class Mapping(dict):
            pass

        values = (Text("3.0.4"), Integer(1), Array(), Mapping(), 1.0, float("nan"))
        for bad in values:
            with self.subTest(kind=type(bad)):
                value = analysis.component_fixture()
                value["current_document"]["info"]["uninterpreted"] = bad
                with patch.object(analysis, "_digest", side_effect=AssertionError("hash reached")):
                    with self.assertRaises(_ERROR):
                        analysis.analyze_openapi_security_evolution(value)
        value = analysis.component_fixture()
        value[Text("unexpected")] = None
        with self.assertRaises(_ERROR):
            analysis.analyze_openapi_security_evolution(value)

    def test_malformed_security_shapes_fail_closed(self):
        for bad in (
            None,
            {},
            "a",
            [None],
            [{"a": None}],
            [{"a": "read"}],
            [{"a": [""]}],
            [{"a": ["\x00"]}],
            [{"$ref": []}],
        ):
            with self.subTest(security=bad):
                with self.assertRaises(_ERROR):
                    row(bad, [])

    def test_report_dataclass_forgery_and_incomplete_wrapper_fail_closed(self):
        valid = analysis.analyze_openapi_security_evolution(analysis.component_fixture())
        for encoded in (
            "{}",
            canonical(
                address(
                    {
                        **valid.to_dict(),
                        "schema_version": True,
                    }
                )
            ),
            None,
        ):
            with self.subTest(encoded=encoded):
                with self.assertRaises(_ERROR):
                    _REPORT(encoded)
                forged = object.__new__(_REPORT)
                object.__setattr__(forged, "document_json", encoded)
                with self.assertRaises(_ERROR):
                    analysis.verify_openapi_security_evolution(
                        forged, model=analysis.component_fixture()
                    )
        incomplete = object.__new__(_REPORT)
        with self.assertRaises(_ERROR):
            incomplete.to_dict()
        with self.assertRaises(_ERROR):
            analysis.verify_openapi_security_evolution(
                incomplete, model=analysis.component_fixture()
            )

        class ForeignReport(_REPORT):
            pass

        foreign = ForeignReport(valid.to_json())
        with self.assertRaises(_ERROR):
            analysis.verify_openapi_security_evolution(foreign, model=analysis.component_fixture())

    def test_duplicate_raw_json_keys_and_nonnative_numbers_reject(self):
        report = analysis.analyze_openapi_security_evolution(analysis.component_fixture()).to_json()
        for changed in (
            report.replace('"schema_version":1', '"schema_version":1,"schema_version":1'),
            report.replace('"schema_version":1', '"schema_version":true'),
            report.replace('"schema_version":1', '"schema_version":1.0'),
            report.replace('"schema_version":1', '"schema_version":NaN'),
            report.replace('"schema_version":1', '"schema_version":Infinity'),
        ):
            with self.subTest(changed=changed[:64]):
                with self.assertRaises(_ERROR):
                    _REPORT.from_json(changed)

    def test_raw_predecode_depth_nodes_integer_and_string_bounds(self):
        cases = [
            "[" * 33 + "0" + "]" * 33,
            "[" + ",".join("0" for _ in range(50_001)) + "]",
            '{"n":9223372036854775808}',
            '{"n":-9223372036854775809}',
            '{"n":' + "9" * 4096 + "}",
            '{"n":1.0}',
            '{"n":"' + "a" * 8193 + '"}',
            '{"n":"' + "\\u0061" * 8193 + '"}',
            '{"n":"\\ud800"}',
            "[" + ",".join('"' + "\u0800" * 500 + '"' for _ in range(400)) + "]",
            " " * (analysis.MAX_DOCUMENT_BYTES + 1),
        ]
        for index, raw in enumerate(cases):
            with self.subTest(case=index):
                with patch.object(
                    analysis.json, "loads", side_effect=AssertionError("decoder reached")
                ):
                    with self.assertRaises(_ERROR):
                        _REPORT.from_json(raw)

    def test_raw_native_unicode_escape_and_integer_boundaries(self):
        value = analysis.analyze_openapi_security_evolution(analysis.component_fixture()).to_dict()
        value["source"]["model_sha256"] = "sha256:" + "a" * 64
        self.assertEqual(
            _REPORT.from_json(json.dumps(address(value))).to_dict()["source"], value["source"]
        )
        for scalar in (analysis.MIN_INTEGER, analysis.MAX_INTEGER, "\u0800", "\U0001f600"):
            with self.subTest(scalar=scalar):
                # Metadata outside the analyzed security subset is still fully source bound.
                original = analysis.component_fixture()
                original["current_document"]["info"]["description"] = scalar
                report = analysis.analyze_openapi_security_evolution(original)
                analysis.verify_openapi_security_evolution(report, model=original)
        for escaped in ('"\\ud83d\\ude00"', '"\\u0800"', '"\\t\\n\\r\\b\\f\\/\\\\\\""'):
            self.assertEqual(analysis._decode('{"n":' + escaped + "}")["n"], json.loads(escaped))

    def test_native_aggregate_bounds_charge_shared_graph_before_dumps_hash(self):
        cases = []
        oversized = analysis.component_fixture()
        oversized["current_document"]["info"]["description"] = ["\u0800" * 2000] * 128
        cases.append(oversized)
        queued = analysis.component_fixture()
        queued["current_document"]["info"]["description"] = [0] * 50_001
        cases.append(queued)
        deep = analysis.component_fixture()
        value = 0
        for _ in range(33):
            value = [value]
        deep["current_document"]["info"]["description"] = value
        cases.append(deep)
        cyclic = analysis.component_fixture()
        shared = []
        shared.append(shared)
        cyclic["current_document"]["info"]["description"] = shared
        cases.append(cyclic)
        for index, value in enumerate(cases):
            with self.subTest(case=index):
                with patch.object(
                    analysis.json, "dumps", side_effect=AssertionError("dumps reached")
                ):
                    with self.assertRaises(_ERROR):
                        analysis.analyze_openapi_security_evolution(value)

    def test_operation_union_count_boundary(self):
        previous = document([], paths={f"/p{index:03}": {"get": {}} for index in range(256)})
        current = document([], paths={f"/p{index:03}": {"get": {}} for index in range(256, 512)})
        report = analysis.analyze_openapi_security_evolution(model(previous, current))
        self.assertEqual(report.to_dict()["operation_count"], 512)
        current["paths"]["/p512"] = {"get": {}}
        with patch.object(analysis, "_digest", side_effect=AssertionError("hash reached")):
            with self.assertRaisesRegex(_ERROR, "Union operation"):
                analysis.analyze_openapi_security_evolution(model(previous, current))

    def test_alternative_scheme_atom_and_scope_limits(self):
        with self.assertRaises(_ERROR):
            row([{}] * 65, [])
        with self.assertRaises(_ERROR):
            row([{f"s{index}": [] for index in range(129)}], [])
        with self.assertRaises(_ERROR):
            row([{"auth": [f"s{index}" for index in range(128)]}], [])
        with self.assertRaises(_ERROR):
            row([{"auth": ["s" * 257]}], [])
        previous = document([], definitions={f"s{index}": {} for index in range(257)})
        with self.assertRaises(_ERROR):
            analysis.analyze_openapi_security_evolution(model(previous, copy.deepcopy(previous)))
        definitions = {f"s{index}": {"type": "http", "scheme": "bearer"} for index in range(64)}
        self.assertEqual(
            row(
                [{name: []} for name in definitions],
                [{name: []} for name in definitions],
                definitions=definitions,
            )["relationship"],
            "equivalent",
        )

    def test_total_raw_atoms_boundary_before_hash(self):
        scopes = [f"s{index:03}" for index in range(127)]
        definitions = {"auth": oauth(scopes)}
        previous = document(
            [{"auth": scopes}],
            definitions=definitions,
            paths={f"/p{index:03}": {"get": {}} for index in range(64)},
        )
        original = model(previous, copy.deepcopy(previous))
        self.assertEqual(
            analysis.analyze_openapi_security_evolution(original).to_dict()["operation_count"], 64
        )
        for source in ("previous_document", "current_document"):
            original[source]["paths"]["/p064"] = {"get": {}}
        with patch.object(analysis, "_digest", side_effect=AssertionError("hash reached")):
            with self.assertRaisesRegex(_ERROR, "Raw atom occurrence"):
                analysis.analyze_openapi_security_evolution(original)

    def test_genuine_symbolic_work_bound_before_hash(self):
        scopes = [f"s{term:02}{index:03}" for term in range(64) for index in range(127)]
        requirements = [
            {"auth": scopes[start : start + 127]} for start in range(0, len(scopes), 127)
        ]
        previous = document(requirements, definitions={"auth": oauth(scopes)})
        original = model(previous, copy.deepcopy(previous))
        with patch.object(analysis, "_digest", side_effect=AssertionError("hash reached")):
            with self.assertRaisesRegex(_ERROR, "work limit"):
                analysis.analyze_openapi_security_evolution(original)

    def test_large_definition_is_validated_and_serialized_once_per_source(self):
        scopes = [f"s{index:04}" for index in range(4000)]
        previous = document(
            [{"auth": ["s0000"]}],
            definitions={"auth": oauth(scopes)},
            paths={f"/p{index:03}": {"get": {}} for index in range(80)},
        )
        original = model(previous, copy.deepcopy(previous))
        serializations = []
        canonical_function = analysis._canonical

        def measured(value):
            if type(value) is dict and value.get("type") == "oauth2" and "flows" in value:
                serializations.append(value)
            return canonical_function(value)

        with patch.object(
            analysis, "_scheme_structure", wraps=analysis._scheme_structure
        ) as structural:
            with patch.object(analysis, "_canonical", side_effect=measured):
                report = analysis.analyze_openapi_security_evolution(original)
        self.assertEqual(structural.call_count, 2)
        self.assertEqual(len(serializations), 2)
        self.assertEqual(report.to_dict()["summary"]["equivalent"], 80)
        self.assertEqual(report.to_dict()["operation_count"], 80)

    def test_genuine_output_reservation_bound_before_hash(self):
        scopes = [f"s{index:02}" for index in range(16)]
        previous = document(
            [{"auth": [scope]} for scope in scopes],
            definitions={"auth": oauth(scopes)},
            paths={f"/p{index:03}": {"get": {}} for index in range(200)},
        )
        original = model(previous, copy.deepcopy(previous))
        with patch.object(analysis, "_digest", side_effect=AssertionError("hash reached")):
            with self.assertRaisesRegex(_ERROR, "output reservation"):
                analysis.analyze_openapi_security_evolution(original)

    def test_report_closed_shape_limits_and_ordering(self):
        original = analysis.analyze_openapi_security_evolution(
            analysis.component_fixture()
        ).to_dict()
        variants = []
        value = copy.deepcopy(original)
        value["extra"] = None
        variants.append(value)
        value = copy.deepcopy(original)
        value["limits"]["max_depth"] += 1
        variants.append(value)
        value = copy.deepcopy(original)
        value["operations"][0]["current"]["formula"][0][0]["scopes"] = ["z", "a"]
        variants.append(value)
        value = copy.deepcopy(original)
        value["operations"].append(copy.deepcopy(value["operations"][0]))
        value["operation_count"] += 1
        value["summary"]["weakened"] += 1
        variants.append(value)
        value = copy.deepcopy(original)
        value["operations"][0]["previous"]["formula"].append([{"scheme": "bearer", "scopes": []}])
        variants.append(value)
        for index, value in enumerate(variants):
            with self.subTest(case=index):
                with self.assertRaises(_ERROR):
                    _REPORT.from_dict(address(value))


if __name__ == "__main__":
    unittest.main()
