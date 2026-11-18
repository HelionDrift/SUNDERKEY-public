"""Synthetic supplied policy documents and independent finite semantic oracles."""

import hashlib
import itertools
import json
import unittest
from copy import deepcopy
from functools import lru_cache
from unittest.mock import patch

from sunderkey import offline_aws_identity_policy_analysis as module
from sunderkey.offline_aws_identity_policy_analysis import (
    AwsIdentityPolicyAnalysis,
    AwsIdentityPolicyAnalysisError,
    analyze_aws_identity_policy_set,
    analyze_aws_identity_policy_set_bytes,
    verify_aws_identity_policy_analysis,
)

RESOURCE = "arn:aws:s3:::synthetic-bucket/public/one"
ALLOW = "allowed_by_supplied_identity_policies"
DENY = "explicit_denial_by_supplied_identity_policies"
IMPLICIT = "implicit_denial_by_supplied_identity_policies"


def statement(effect="Allow", action="s3:Get*", resource="*", **extra):
    return {"Effect": effect, "Action": action, "Resource": resource, **extra}


def policy(identifier="reads", statements=None, **extra):
    return {
        "policy_id": identifier,
        "document": {
            "Version": "2012-10-17",
            "Statement": [statement()] if statements is None else statements,
            **extra,
        },
    }


def query(
    identifier="read-one",
    action="s3:GetObject",
    resource=RESOURCE,
    *,
    applicable=True,
    values=None,
    absent=None,
):
    return {
        "query_id": identifier,
        "action": action,
        "resource": resource,
        "action_resource_applicability": applicable,
        "context": {
            "values": {} if values is None else values,
            "absent_keys": [] if absent is None else absent,
        },
    }


def component_fixture():
    """Fresh inert public model, not acquired IAM attachments or AWS request context."""
    return {
        "schema_version": 1,
        "principal_ref": "principal:synthetic",
        "attachments_complete": True,
        "policies": [
            policy(statements=[statement(resource="arn:aws:s3:::synthetic-bucket/public/*")])
        ],
        "queries": [query()],
    }


def supplied(policies=None, queries=None, *, complete=True):
    model = component_fixture()
    model["policies"] = [policy()] if policies is None else policies
    model["queries"] = [query()] if queries is None else queries
    model["attachments_complete"] = complete
    return model


def result(model):
    return analyze_aws_identity_policy_set(model).to_dict()["results"][0]


def readdress(document):
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = (
        "sha256:"
        + hashlib.sha256(
            module.DOMAIN.encode("ascii")
            + b"\n"
            + json.dumps(body, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode(
                "ascii"
            )
        ).hexdigest()
    )
    return {"analysis_id": "AIP-" + digest[7:39].upper(), "analysis_sha256": digest, **body}


def oracle_glob(pattern, value):
    @lru_cache(None)
    def match(left, right):
        if left == len(pattern):
            return right == len(value)
        if pattern[left] == "*":
            return match(left + 1, right) or (right < len(value) and match(left, right + 1))
        return (
            right < len(value)
            and (pattern[left] == "?" or pattern[left] == value[right])
            and match(left + 1, right + 1)
        )

    return match(0, 0)


class SuppliedAwsIdentityPolicyAnalysisTests(unittest.TestCase):
    def test_public_fixture_exact_roundtrip_and_original_source_replay(self):
        model = component_fixture()
        report = analyze_aws_identity_policy_set(model)
        document = report.to_dict()
        self.assertEqual(document["analysis_id"], "AIP-C2F92383D435FB6B46450672B61B9D69")
        self.assertEqual(
            document["analysis_sha256"],
            "sha256:c2f92383d435fb6b46450672b61b9d6995a55fef8630e28ec83df26d08a6740c",
        )
        self.assertEqual(
            document["source_model_sha256"],
            "sha256:70d7d7ddc7f86430f320b92b6a4a3e99fa6d4ce171edd3ef852dc4e5b43336ab",
        )
        self.assertEqual(document["summary"]["matching_steps"], 145)
        self.assertEqual(document["results"][0]["decision"], ALLOW)
        self.assertEqual(document["summary"][ALLOW], 1)
        self.assertEqual(AwsIdentityPolicyAnalysis.from_dict(document).to_dict(), document)
        self.assertEqual(AwsIdentityPolicyAnalysis.from_json(report.to_json()).to_dict(), document)
        self.assertEqual(
            analyze_aws_identity_policy_set_bytes(
                model_bytes=json.dumps(model).encode("ascii")
            ).to_dict(),
            document,
        )
        checked = verify_aws_identity_policy_analysis(report, model=model)
        self.assertIsNot(checked, report)
        self.assertEqual(checked.to_dict(), document)

    def test_identity_policy_allows_union_not_scp_intersection(self):
        model = supplied(
            [
                policy("objects", [statement(action="s3:GetObject")]),
                policy("buckets", [statement(action="s3:ListBucket")]),
            ],
            [query("object"), query("bucket", "s3:ListBucket")],
        )
        report = analyze_aws_identity_policy_set(model).to_dict()
        self.assertEqual([item["decision"] for item in report["results"]], [ALLOW, ALLOW])
        self.assertEqual(
            {item["allow_witnesses"][0]["policy_id"] for item in report["results"]},
            {"objects", "buckets"},
        )

    def test_known_explicit_deny_overrides_union_and_retains_other_uncertainty(self):
        allow = policy("allow", [statement()])
        deny = policy("deny", [statement("Deny")])
        unknown = policy("unknown", [statement(Principal="*")])
        for items in itertools.permutations([allow, deny, unknown]):
            observed = result(supplied(list(items), complete=False))
            self.assertEqual(observed["decision"], DENY)
            self.assertEqual(len(observed["deny_witnesses"]), 1)
            self.assertEqual(len(observed["unresolved_witnesses"]), 1)
            self.assertIn("incomplete_policy_attachments", observed["reasons"])
            self.assertIn("unsupported_statement_fields", observed["reasons"])

    def test_complete_empty_and_missing_sets_are_distinct(self):
        self.assertEqual(result(supplied([]))["decision"], IMPLICIT)
        self.assertEqual(result(supplied([], complete=False))["decision"], "inconclusive")
        self.assertEqual(
            result(supplied([policy(statements=[statement(action="ec2:StartInstances")])]))[
                "decision"
            ],
            IMPLICIT,
        )

    def test_action_is_case_insensitive_resource_is_case_sensitive(self):
        good = supplied(
            [policy(statements=[statement(action="S3:gEtObJeCt", resource=RESOURCE)])],
            [query(action="s3:GetObject")],
        )
        self.assertEqual(result(good)["decision"], ALLOW)
        good["queries"][0]["resource"] = RESOURCE.replace("synthetic", "Synthetic")
        self.assertEqual(result(good)["decision"], IMPLICIT)

    def test_both_selector_complements_use_nor_and_exclusions_never_grant(self):
        for action_key, resource_key in itertools.product(
            ("Action", "NotAction"), ("Resource", "NotResource")
        ):
            for action_match, resource_match in itertools.product((False, True), repeat=2):
                rule = {
                    "Effect": "Allow",
                    action_key: [
                        "s3:GetObject" if action_match else "s3:DeleteObject",
                        "ec2:StartInstances",
                    ],
                    resource_key: [
                        RESOURCE if resource_match else RESOURCE + "-different",
                        "arn:aws:s3:::another/value",
                    ],
                }
                expected = (action_match if action_key == "Action" else not action_match) and (
                    resource_match if resource_key == "Resource" else not resource_match
                )
                with self.subTest(
                    action_key=action_key,
                    resource_key=resource_key,
                    action_match=action_match,
                    resource_match=resource_match,
                ):
                    self.assertEqual(
                        result(supplied([policy(statements=[rule])]))["decision"],
                        ALLOW if expected else IMPLICIT,
                    )
        self.assertEqual(
            result(
                supplied(
                    [
                        policy(
                            statements=[
                                {
                                    "Effect": "Deny",
                                    "NotAction": "s3:GetObject",
                                    "NotResource": "arn:aws:s3:::exception/*",
                                }
                            ]
                        )
                    ]
                )
            )["decision"],
            IMPLICIT,
        )

    def test_notaction_applicability_is_explicit_never_inferred_from_resource_service(self):
        rule = {"Effect": "Allow", "NotAction": "s3:DeleteBucket", "Resource": "arn:aws:s3:::*"}
        for applicable, decision in (
            (True, ALLOW),
            (False, "not_applicable"),
            (None, "inconclusive"),
        ):
            with self.subTest(applicable=applicable):
                self.assertEqual(
                    result(
                        supplied(
                            [policy(statements=[rule])],
                            [query(action="ec2:StartInstances", applicable=applicable)],
                        )
                    )["decision"],
                    decision,
                )
        self.assertFalse(
            result(supplied([policy(statements=[rule])], [query(applicable=False)]))[
                "allow_witnesses"
            ]
        )

    def test_notresource_exclusion_and_separate_regrant_keep_explicit_deny(self):
        rules = [
            policy(
                "boundary",
                [
                    {
                        "Effect": "Deny",
                        "Action": "s3:*",
                        "NotResource": "arn:aws:s3:::synthetic-bucket/public/*",
                    }
                ],
            ),
            policy("allow", [statement()]),
        ]
        self.assertEqual(result(supplied(rules))["decision"], ALLOW)
        self.assertEqual(
            result(supplied(rules, [query(resource="arn:aws:s3:::synthetic-bucket/private/one")]))[
                "decision"
            ],
            DENY,
        )

    def test_tail_globs_span_slashes_and_colon_subset_stays_uncertain(self):
        supported = supplied(
            [policy(statements=[statement(resource="arn:aws:s3:::synthetic-bucket/*/one")])],
            [query(resource="arn:aws:s3:::synthetic-bucket/a/b/one")],
        )
        self.assertEqual(result(supported)["decision"], ALLOW)
        for key in ("Resource", "NotResource"):
            rule = {
                "Effect": "Allow",
                "Action": "lambda:InvokeFunction",
                key: "arn:aws:lambda:us-west-2:123456789012:f?n*",
            }
            observed = result(
                supplied(
                    [policy(statements=[rule])],
                    [
                        query(
                            action="lambda:InvokeFunction",
                            resource="arn:aws:lambda:us-west-2:123456789012:function:one",
                        )
                    ],
                )
            )
            self.assertEqual(observed["decision"], "inconclusive")
            self.assertIn("unsupported_query_resource_tail_boundary", observed["reasons"])
        rule[key] = "arn:aws:lambda:us-west-2:123456789012:*"
        rule.pop("NotResource")
        rule["Resource"] = "arn:aws:lambda:us-west-2:123456789012:*"
        self.assertEqual(
            result(
                supplied(
                    [policy(statements=[rule])],
                    [
                        query(
                            action="lambda:InvokeFunction",
                            resource="arn:aws:lambda:us-west-2:123456789012:function:one",
                        )
                    ],
                )
            )["decision"],
            ALLOW,
        )

    def test_unsupported_resource_shapes_do_not_turn_negation_into_known_match(self):
        for pattern in (
            "arn:*:s3:::bucket/*",
            "arn:aws:*:::bucket/*",
            "arn:aws:lambda:*:123456789012:*",
            "arn:aws:lambda:us-west-2:123456789012:function:*",
            "arn:aws:s3:::${aws:username}/*",
        ):
            for key in ("Resource", "NotResource"):
                with self.subTest(pattern=pattern, key=key):
                    observed = result(
                        supplied(
                            [policy(statements=[{"Effect": "Allow", "Action": "*", key: pattern}])]
                        )
                    )
                    self.assertEqual(observed["decision"], "inconclusive")
                    self.assertFalse(observed["allow_witnesses"])

    def test_stringequals_is_literal_even_when_context_or_candidates_contain_wildcards(self):
        for value, candidate, expected in (
            ("*", "*", ALLOW),
            ("?", "?", ALLOW),
            ("one", "*", IMPLICIT),
            ("*", "one", IMPLICIT),
        ):
            rule = statement(Condition={"StringEquals": {"aws:tag": candidate}})
            with self.subTest(value=value, candidate=candidate):
                self.assertEqual(
                    result(
                        supplied([policy(statements=[rule])], [query(values={"aws:tag": value})])
                    )["decision"],
                    expected,
                )
        for value in ("*", "?", "one"):
            rule = statement(Condition={"StringLike": {"aws:tag": "*"}})
            self.assertEqual(
                result(supplied([policy(statements=[rule])], [query(values={"aws:tag": value})]))[
                    "decision"
                ],
                ALLOW,
            )

    def test_negated_condition_candidates_are_nor_not_individual_or(self):
        for operator in ("StringNotEquals", "StringNotLike"):
            rule = statement(Condition={operator: {"aws:tag": ["allowed", "another"]}})
            for value, expected in (
                ("allowed", IMPLICIT),
                ("another", IMPLICIT),
                ("outside", ALLOW),
            ):
                with self.subTest(operator=operator, value=value):
                    self.assertEqual(
                        result(
                            supplied(
                                [policy(statements=[rule])], [query(values={"aws:tag": value})]
                            )
                        )["decision"],
                        expected,
                    )

    def test_known_absence_is_not_unknown_for_positive_negated_and_null_conditions(self):
        for operator, expected in (
            ("StringEquals", IMPLICIT),
            ("StringLike", IMPLICIT),
            ("Bool", IMPLICIT),
            ("StringNotEquals", ALLOW),
            ("StringNotLike", ALLOW),
        ):
            candidate = "true" if operator == "Bool" else "one"
            rule = statement(Condition={operator: {"aws:key": candidate}})
            self.assertEqual(
                result(supplied([policy(statements=[rule])], [query(absent=["AWS:KEY"])]))[
                    "decision"
                ],
                expected,
            )
            self.assertEqual(
                result(supplied([policy(statements=[rule])]))["decision"], "inconclusive"
            )
        for candidate, values, absent, expected in (
            ("true", {}, ["aws:key"], ALLOW),
            ("false", {"aws:key": "value"}, [], ALLOW),
            ("true", {"aws:key": "value"}, [], IMPLICIT),
        ):
            rule = statement(Condition={"Null": {"aws:key": candidate}})
            self.assertEqual(
                result(
                    supplied([policy(statements=[rule])], [query(values=values, absent=absent)])
                )["decision"],
                expected,
            )

    def test_known_false_condition_conjunct_dominates_unavailable_context(self):
        rule = statement(Condition={"StringEquals": {"aws:known": "yes", "aws:missing": "one"}})
        observed = result(
            supplied([policy(statements=[rule])], [query(values={"aws:known": "no"})])
        )
        self.assertEqual(observed["decision"], IMPLICIT)
        self.assertFalse(observed["unresolved_witnesses"])
        self.assertEqual(
            result(supplied([policy(statements=[rule])], [query(values={"aws:known": "yes"})]))[
                "decision"
            ],
            "inconclusive",
        )

    def test_key_case_and_equalsignorecase_do_not_change_stringequals_semantics(self):
        for operator, expected in (
            ("StringEquals", IMPLICIT),
            ("StringEqualsIgnoreCase", ALLOW),
            ("StringLike", IMPLICIT),
        ):
            rule = statement(Condition={operator: {"AWS:Tag": "YES"}})
            self.assertEqual(
                result(supplied([policy(statements=[rule])], [query(values={"aws:tag": "yes"})]))[
                    "decision"
                ],
                expected,
            )

    def test_different_condition_operators_and_keys_are_and_not_or(self):
        rule = statement(
            Condition={
                "StringEquals": {"aws:known": "yes"},
                "Bool": {"aws:transport": "true"},
                "Null": {"aws:absent": "true"},
            }
        )
        for transport, expected in (
            ("true", ALLOW),
            ("false", IMPLICIT),
            ("unknown", "inconclusive"),
        ):
            self.assertEqual(
                result(
                    supplied(
                        [policy(statements=[rule])],
                        [
                            query(
                                values={"aws:known": "yes", "aws:transport": transport},
                                absent=["aws:absent"],
                            )
                        ],
                    )
                )["decision"],
                expected,
            )
        # A false supported key wins even when another operator lacks context.
        self.assertEqual(
            result(
                supplied(
                    [policy(statements=[rule])],
                    [query(values={"aws:known": "no"}, absent=["aws:absent"])],
                )
            )["decision"],
            IMPLICIT,
        )

    def test_bool_nonboolean_context_remains_unknown_not_silent_false(self):
        rule = statement(Condition={"Bool": {"aws:SecureTransport": "true"}})
        for value, expected in (
            ("true", ALLOW),
            ("false", IMPLICIT),
            ("True", "inconclusive"),
            ("unavailable", "inconclusive"),
        ):
            self.assertEqual(
                result(
                    supplied(
                        [policy(statements=[rule])], [query(values={"aws:securetransport": value})]
                    )
                )["decision"],
                expected,
            )

    def test_missing_versions_unsupported_documents_and_features_are_retained_not_normalized(self):
        changes = ("missing", "null", "older", "extra", "principal", "variables", "operator")
        for change in changes:
            model = component_fixture()
            doc = model["policies"][0]["document"]
            if change == "missing":
                doc.pop("Version")
            elif change == "null":
                doc["Version"] = None
            elif change == "older":
                doc["Version"] = "2008-10-17"
            elif change == "extra":
                doc["ProviderUnknown"] = {"present": True}
            elif change == "principal":
                doc["Statement"][0]["Principal"] = "*"
            elif change == "variables":
                doc["Statement"][0]["Resource"] = "arn:aws:s3:::${aws:username}/*"
            else:
                doc["Statement"][0]["Condition"] = {"StringEqualsIfExists": {"aws:key": "one"}}
            with self.subTest(change=change):
                report = analyze_aws_identity_policy_set(model).to_dict()
                self.assertEqual(report["results"][0]["decision"], "inconclusive")
                self.assertEqual(report["source_model"], model)
                self.assertTrue(report["source_issues"])
                self.assertFalse(report["results"][0]["allow_witnesses"])

    def test_unsupported_operator_families_and_action_service_globs_stay_uncertain(self):
        for operator in (
            "ForAnyValue:StringEquals",
            "BoolIfExists",
            "ArnLike",
            "NumericGreaterThan",
            "DateLessThan",
            "IpAddress",
        ):
            rule = statement(Condition={operator: {"aws:key": "one"}})
            observed = result(
                supplied([policy(statements=[rule])], [query(values={"aws:key": "one"})])
            )
            self.assertEqual(observed["decision"], "inconclusive")
            self.assertFalse(observed["allow_witnesses"])
            self.assertIn("unsupported_condition_operator", observed["reasons"])
        for selector in ("Action", "NotAction"):
            observed = result(
                supplied(
                    [
                        policy(
                            statements=[
                                {"Effect": "Allow", selector: "s*:GetObject", "Resource": "*"}
                            ]
                        )
                    ]
                )
            )
            self.assertEqual(observed["decision"], "inconclusive")
            self.assertIn("unsupported_action_pattern", observed["reasons"])

    def test_optional_policy_id_and_sid_names_are_source_bound_not_global_identities(self):
        model = supplied(
            [
                policy("one", [statement(Sid="same")], Id="declared-one"),
                policy("two", [statement(Sid="same")], Id="declared-two"),
            ]
        )
        observed = result(model)
        self.assertEqual(observed["decision"], ALLOW)
        self.assertEqual(len(observed["allow_witnesses"]), 2)
        duplicate = result(supplied([policy(statements=[statement(), statement()])]))
        self.assertEqual(len(duplicate["allow_witnesses"]), 2)
        self.assertEqual({item["statement_index"] for item in duplicate["allow_witnesses"]}, {0, 1})

    def test_query_never_expands_wildcards_variables_or_a_service_action_set(self):
        for field, values in (
            (
                "action",
                [
                    "*",
                    "s3:*",
                    "s*:GetObject",
                    "s3:Get?Object",
                    "s3:${name}",
                    "s3:GetObject,s3:PutObject",
                ],
            ),
            (
                "resource",
                ["*", RESOURCE + "*", RESOURCE + "?", "arn:aws:s3:::${bucket}/one", "not-an-arn"],
            ),
        ):
            for value in values:
                model = component_fixture()
                model["queries"][0][field] = value
                with (
                    self.subTest(field=field, value=value),
                    patch.object(module, "_sha", side_effect=AssertionError("hash reached")),
                    self.assertRaises(AwsIdentityPolicyAnalysisError),
                ):
                    analyze_aws_identity_policy_set(model)

    def test_native_schema_completeness_and_applicability_aliases_fail_before_hash(self):
        for field, values in (
            ("schema_version", [True, 1.0, "1", 2]),
            ("attachments_complete", [1, 0, "true"]),
            ("action_resource_applicability", [1, 0, "true"]),
        ):
            for value in values:
                model = component_fixture()
                target = model["queries"][0] if field == "action_resource_applicability" else model
                target[field] = value
                with (
                    self.subTest(field=field, value=value),
                    patch.object(module, "_sha", side_effect=AssertionError("hash reached")),
                    self.assertRaises(AwsIdentityPolicyAnalysisError),
                ):
                    analyze_aws_identity_policy_set(model)

    def test_malformed_required_fields_selectors_and_closed_outer_shapes_reject(self):
        for change in (
            "missing_root",
            "unknown_query",
            "empty_statement",
            "both_action",
            "both_resource",
            "effect_alias",
            "empty_selector",
            "selector_alias",
            "single_statement",
            "version_alias",
        ):
            model = component_fixture()
            doc = model["policies"][0]["document"]
            rule = doc["Statement"][0]
            if change == "missing_root":
                model.pop("principal_ref")
            elif change == "unknown_query":
                model["queries"][0]["unknown"] = 1
            elif change == "empty_statement":
                doc["Statement"] = []
            elif change == "both_action":
                rule["NotAction"] = "s3:DeleteObject"
            elif change == "both_resource":
                rule["NotResource"] = "*"
            elif change == "effect_alias":
                rule["Effect"] = True
            elif change == "empty_selector":
                rule["Action"] = []
            elif change == "selector_alias":
                rule["Resource"] = 1
            elif change == "single_statement":
                doc["Statement"] = rule
            else:
                doc["Version"] = 1
            with self.subTest(change=change), self.assertRaises(AwsIdentityPolicyAnalysisError):
                analyze_aws_identity_policy_set(model)

    def test_unique_policy_query_sid_and_context_case_conflicts_reject(self):
        for change in ("policy", "query", "sid", "context", "absent", "presence", "condition"):
            model = component_fixture()
            if change == "policy":
                model["policies"].append(deepcopy(model["policies"][0]))
            elif change == "query":
                model["queries"].append(deepcopy(model["queries"][0]))
            elif change == "sid":
                model["policies"][0]["document"]["Statement"] = [
                    statement(Sid="same"),
                    statement(Sid="same"),
                ]
            elif change == "context":
                model["queries"][0]["context"]["values"] = {"AWS:key": "one", "aws:KEY": "two"}
            elif change == "absent":
                model["queries"][0]["context"]["absent_keys"] = ["aws:key", "AWS:KEY"]
            elif change == "presence":
                model["queries"][0]["context"] = {
                    "values": {"aws:key": "one"},
                    "absent_keys": ["AWS:KEY"],
                }
            else:
                model["policies"][0]["document"]["Statement"][0]["Condition"] = {
                    "StringEquals": {"aws:key": "one", "AWS:KEY": "two"}
                }
            with self.subTest(change=change), self.assertRaises(AwsIdentityPolicyAnalysisError):
                analyze_aws_identity_policy_set(model)

    def test_native_primitive_collection_and_wrapper_subclasses_reject(self):
        class ForeignDict(dict):
            pass

        class ForeignList(list):
            pass

        class ForeignString(str):
            pass

        class ForeignInt(int):
            pass

        for value in (ForeignDict(component_fixture()), [], None, b"{}", (), 1):
            with self.subTest(value=type(value)), self.assertRaises(AwsIdentityPolicyAnalysisError):
                analyze_aws_identity_policy_set(value)
        for field, value in (
            ("queries", ForeignList([query()])),
            ("principal_ref", ForeignString("principal:one")),
            ("schema_version", ForeignInt(1)),
        ):
            model = component_fixture()
            model[field] = value
            with self.subTest(field=field), self.assertRaises(AwsIdentityPolicyAnalysisError):
                analyze_aws_identity_policy_set(model)

        class ForeignReport(AwsIdentityPolicyAnalysis):
            pass

        with self.assertRaises(AwsIdentityPolicyAnalysisError):
            verify_aws_identity_policy_analysis(
                ForeignReport(analyze_aws_identity_policy_set(component_fixture()).to_json()),
                model=component_fixture(),
            )

    def test_repeated_graph_cycles_depth_huge_integer_and_bytes_precede_hash_or_serializer(self):
        repeated = ["x" * 512] * 32
        graphs = [[repeated] * 1000, 2**1_000_000, [None]]
        graphs[-1][0] = graphs[-1]
        nested = 0
        for _ in range(module.MAX_NATIVE_DEPTH + 1):
            nested = [nested]
        graphs.append(nested)
        for graph in graphs:
            with (
                self.subTest(graph=type(graph)),
                patch.object(
                    module.json, "dumps", side_effect=AssertionError("serializer reached")
                ),
                self.assertRaises(AwsIdentityPolicyAnalysisError),
            ):
                analyze_aws_identity_policy_set(graph)
        for value in (b"{}" * module.MAX_DOCUMENT_BYTES, bytearray(b"{}"), b"\xff", b""):
            with self.subTest(kind=type(value)), self.assertRaises(AwsIdentityPolicyAnalysisError):
                analyze_aws_identity_policy_set_bytes(model_bytes=value)

    def test_raw_costs_and_malformed_integer_grammar_refuse_before_decoder(self):
        raw_documents = [
            "[" * (module.MAX_NATIVE_DEPTH + 1) + "0" + "]" * (module.MAX_NATIVE_DEPTH + 1),
            "[" + ",".join("0" for _ in range(module.MAX_NATIVE_NODES + 1)) + "]",
            '"' + "x" * 513 + '"',
            '"' + r"\u0061" * 513 + '"',
            r'"\u0080"',
            "[--1]",
            "[---1]",
            "[-01]",
            "[01]",
            "[1.0]",
            "[NaN]",
            "[9223372036854775808]",
        ]
        for text in raw_documents:
            with (
                self.subTest(size=len(text)),
                patch.object(module.json, "loads", side_effect=AssertionError("decoder reached")),
                self.assertRaises(AwsIdentityPolicyAnalysisError),
            ):
                analyze_aws_identity_policy_set_bytes(model_bytes=text.encode("ascii"))

    def test_duplicate_members_anywhere_reject_before_semantic_hash(self):
        text = json.dumps(component_fixture(), separators=(",", ":"))
        for old, new in (
            ('"schema_version":1', '"schema_version":1,"schema_version":1'),
            ('"Effect":"Allow"', '"Effect":"Allow","Effect":"Allow"'),
        ):
            with (
                self.subTest(old=old),
                patch.object(module, "_sha", side_effect=AssertionError("hash reached")),
                self.assertRaises(AwsIdentityPolicyAnalysisError),
            ):
                analyze_aws_identity_policy_set_bytes(
                    model_bytes=text.replace(old, new, 1).encode("ascii")
                )

    def test_exact_native_cost_and_escaped_string_bounds_are_not_unbounded_json_claims(self):
        self.assertEqual(
            module._json("[0,-0,-1,9223372036854775807]"), [0, 0, -1, 9223372036854775807]
        )
        with (
            patch.object(module, "MAX_NATIVE_NODES", 4),
            patch.object(module, "MAX_NATIVE_DEPTH", 3),
        ):
            self.assertEqual(module._json("[[1,2]]"), [[1, 2]])
            with self.assertRaises(AwsIdentityPolicyAnalysisError):
                module._json("[[1,2,3]]")
        with patch.object(module, "MAX_DOCUMENT_BYTES", 7):
            self.assertEqual(module._capture(['"']), ['"'])
            with self.assertRaises(AwsIdentityPolicyAnalysisError):
                module._capture(['"', '"'])
        with patch.object(module, "MAX_STRING_BYTES", 3):
            self.assertEqual(module._json(r'"\u0041\/\""'), 'A/"')
            with self.assertRaises(AwsIdentityPolicyAnalysisError):
                module._json(r'"\u0041\/\"X"')

    def test_final_native_scalar_cost_is_checked_before_semantic_hashing(self):
        model = component_fixture()
        model["queries"][0]["context"]["values"] = {"aws:key": '"' * 32 + "\\" * 32}
        actual_size = len(
            json.dumps(model, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        )
        with (
            patch.object(module, "MAX_DOCUMENT_BYTES", actual_size - 1),
            patch.object(module.json, "dumps", side_effect=AssertionError("serializer reached")),
            self.assertRaisesRegex(AwsIdentityPolicyAnalysisError, "byte budget"),
        ):
            analyze_aws_identity_policy_set(model)
        with (
            patch.object(module, "MAX_NATIVE_NODES", 4),
            patch.object(module.json, "dumps", side_effect=AssertionError("serializer reached")),
            self.assertRaisesRegex(AwsIdentityPolicyAnalysisError, "node or depth"),
        ):
            module._capture({"a": [1, "last"]})

    def test_complete_output_cost_is_checked_before_its_address_hash(self):
        model = component_fixture()
        original_sha = module._sha
        source_size = len(
            json.dumps(model, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
        )

        def source_hashes_only(domain, value):
            if domain == module.DOMAIN:
                raise AssertionError("report address hash reached")
            return original_sha(domain, value)

        with (
            patch.object(module, "MAX_DOCUMENT_BYTES", source_size + 512),
            patch.object(module, "_sha", side_effect=source_hashes_only),
            self.assertRaisesRegex(AwsIdentityPolicyAnalysisError, "byte budget"),
        ):
            analyze_aws_identity_policy_set(model)

    def test_native_count_ceilings_work_and_witness_budgets_deny_not_truncate(self):
        for change in ("policies", "statements", "queries", "selectors", "context", "operators"):
            model = component_fixture()
            if change == "policies":
                model["policies"] = [policy(str(i)) for i in range(65)]
            elif change == "statements":
                model["policies"][0]["document"]["Statement"] = [statement()] * 513
            elif change == "queries":
                model["queries"] = [query(str(i)) for i in range(65)]
            elif change == "selectors":
                model["policies"][0]["document"]["Statement"][0]["Action"] = ["s3:GetObject"] * 33
            elif change == "context":
                model["queries"][0]["context"]["values"] = {str(i): "one" for i in range(33)}
            else:
                model["policies"][0]["document"]["Statement"][0]["Condition"] = {
                    str(i): {"aws:key": "one"} for i in range(9)
                }
            with self.subTest(change=change), self.assertRaises(AwsIdentityPolicyAnalysisError):
                analyze_aws_identity_policy_set(model)
        with (
            patch.object(module, "MAX_MATCHING_STEPS", 1),
            self.assertRaises(AwsIdentityPolicyAnalysisError),
        ):
            analyze_aws_identity_policy_set(component_fixture())
        with (
            patch.object(module, "MAX_WITNESSES", 1),
            self.assertRaises(AwsIdentityPolicyAnalysisError),
        ):
            analyze_aws_identity_policy_set(supplied([policy("one"), policy("two")]))

    def test_public_finite_policy_query_and_statement_maxima_remain_supported(self):
        model = supplied(
            [policy(str(i), [statement(action="ec2:StartInstances")]) for i in range(64)],
            [query(str(i)) for i in range(64)],
        )
        self.assertEqual(analyze_aws_identity_policy_set(model).to_dict()["summary"][IMPLICIT], 64)
        model = supplied([policy(statements=[statement(action="ec2:StartInstances")] * 512)])
        self.assertEqual(
            analyze_aws_identity_policy_set(model).to_dict()["summary"]["statement_count"], 512
        )

    def test_small_identity_decision_oracle_covers_union_denial_and_unknown_sets(self):
        choices = ("allow", "deny", "miss", "unknown")
        for first, second, complete in itertools.product(choices, choices, (False, True)):
            rules = []
            for i, kind in enumerate((first, second)):
                rule = statement(
                    "Deny" if kind == "deny" else "Allow",
                    action="ec2:StartInstances" if kind == "miss" else "s3:GetObject",
                )
                if kind == "unknown":
                    rule["Condition"] = {"StringEquals": {"aws:missing": "yes"}}
                rules.append(policy(str(i), [rule]))
            expected = (
                DENY
                if "deny" in (first, second)
                else (
                    "inconclusive"
                    if "unknown" in (first, second) or not complete
                    else (ALLOW if "allow" in (first, second) else IMPLICIT)
                )
            )
            with self.subTest(first=first, second=second, complete=complete):
                self.assertEqual(result(supplied(rules, complete=complete))["decision"], expected)

    def test_independent_dynamic_programming_glob_oracle_includes_literal_wildcard_values(self):
        patterns = [
            "".join(chars) for size in range(4) for chars in itertools.product("ab*?", repeat=size)
        ]
        values = [
            "".join(chars) for size in range(4) for chars in itertools.product("ab*?", repeat=size)
        ]
        for pattern in patterns:
            for value in values:
                with self.subTest(pattern=pattern, value=value):
                    self.assertEqual(
                        module._glob(pattern, value, module._Work()), oracle_glob(pattern, value)
                    )

    def test_public_stringlike_and_negated_stringlike_match_independent_oracle(self):
        for operator, pattern, value in itertools.product(
            ("StringLike", "StringNotLike"),
            ("*", "?", "a*", "*a", "a?", "*?", "a*b", "*a*"),
            ("a", "b", "ab", "*", "?"),
        ):
            matched = oracle_glob(pattern, value)
            if operator == "StringNotLike":
                matched = not matched
            rule = statement(Condition={operator: {"aws:key": pattern}})
            with self.subTest(operator=operator, pattern=pattern, value=value):
                self.assertEqual(
                    result(
                        supplied([policy(statements=[rule])], [query(values={"aws:key": value})])
                    )["decision"],
                    ALLOW if matched else IMPLICIT,
                )

    def test_original_and_exported_sources_are_detached(self):
        model = component_fixture()
        original = deepcopy(model)
        report = analyze_aws_identity_policy_set(model)
        model["policies"][0]["document"]["Statement"][0]["Effect"] = "Deny"
        exported = report.to_dict()
        exported["source_model"]["queries"][0]["action"] = "s3:DeleteObject"
        exported["results"][0]["allow_witnesses"].clear()
        self.assertEqual(report.to_dict()["source_model"], original)
        self.assertTrue(report.to_dict()["results"][0]["allow_witnesses"])
        verify_aws_identity_policy_analysis(report, model=original)
        with self.assertRaises(AwsIdentityPolicyAnalysisError):
            verify_aws_identity_policy_analysis(report, model=model)

    def test_cohashed_fabricated_outcomes_witnesses_and_digests_do_not_replay(self):
        document = analyze_aws_identity_policy_set(component_fixture()).to_dict()
        for change in ("decision", "policy", "statement", "index", "summary", "source"):
            other = deepcopy(document)
            witness = other["results"][0]["allow_witnesses"][0]
            if change == "decision":
                other["results"][0]["decision"] = DENY
            elif change == "policy":
                witness["policy_id"] = "unselected"
            elif change == "statement":
                witness["statement_sha256"] = "sha256:" + "a" * 64
            elif change == "index":
                witness["statement_index"] = 1
            elif change == "summary":
                other["summary"]["statement_count"] = 2
            else:
                other["source_model_sha256"] = "sha256:" + "a" * 64
            with self.subTest(change=change), self.assertRaises(AwsIdentityPolicyAnalysisError):
                AwsIdentityPolicyAnalysis.from_dict(readdress(other))

    def test_native_report_aliases_and_promotions_fail_before_rederivation_hash(self):
        document = analyze_aws_identity_policy_set(component_fixture()).to_dict()
        variants = []
        for field in module._FLAGS:
            raw = deepcopy(document)
            raw[field] = int(raw[field])
            variants.append(raw)
            raw = deepcopy(document)
            raw[field] = not raw[field]
            variants.append(raw)
        for value in (True, 1.0):
            raw = deepcopy(document)
            raw["schema_version"] = value
            variants.append(raw)
            raw = deepcopy(document)
            raw["summary"]["query_count"] = value
            variants.append(raw)
        raw = deepcopy(document)
        raw["results"][0]["allow_witnesses"][0]["statement_index"] = False
        variants.append(raw)
        raw = deepcopy(document)
        raw["effects"]["authority"] = "granted"
        variants.append(raw)
        for raw in variants:
            raw = readdress(raw)
            with (
                self.subTest(),
                patch.object(module, "_sha", side_effect=AssertionError("hash reached")),
                self.assertRaises(AwsIdentityPolicyAnalysisError),
            ):
                AwsIdentityPolicyAnalysis.from_dict(raw)

    def test_truthfully_readdressed_source_does_not_replace_original_model(self):
        original = component_fixture()
        other = deepcopy(original)
        other["principal_ref"] = "principal:unrelated"
        replacement = analyze_aws_identity_policy_set(other)
        AwsIdentityPolicyAnalysis.from_json(replacement.to_json())
        verify_aws_identity_policy_analysis(replacement, model=other)
        with self.assertRaises(AwsIdentityPolicyAnalysisError):
            verify_aws_identity_policy_analysis(replacement, model=original)

    def test_forged_wrapper_and_missing_unknown_report_fields_fail_closed(self):
        forged = object.__new__(AwsIdentityPolicyAnalysis)
        with self.assertRaises(AwsIdentityPolicyAnalysisError):
            forged.to_dict()
        for value in (None, b"{}", 1, "{}"):
            object.__setattr__(forged, "document_json", value)
            with self.subTest(value=value), self.assertRaises(AwsIdentityPolicyAnalysisError):
                forged.to_dict()
        for change in ("missing", "unknown"):
            document = analyze_aws_identity_policy_set(component_fixture()).to_dict()
            if change == "missing":
                document.pop("effects")
            else:
                document["unknown"] = True
            with self.assertRaises(AwsIdentityPolicyAnalysisError):
                AwsIdentityPolicyAnalysis.from_dict(document)

    def test_every_declared_outcome_keeps_exact_existing_lane_and_no_effects(self):
        models = [
            component_fixture(),
            supplied([policy(statements=[statement("Deny")])]),
            supplied([]),
            supplied([], complete=False),
            supplied(queries=[query(applicable=False)]),
        ]
        for model in models:
            document = analyze_aws_identity_policy_set(model).to_dict()
            self.assertEqual(document["component_id"], "aws-identity-policy-set-v1")
            self.assertEqual(document["profile_id"], "AOE-GC-D14-S01")
            self.assertEqual(document["wave_id"], "IW2-004")
            self.assertTrue(document["offline_only"])
            for name in module._FLAGS.keys() - {"offline_only"}:
                self.assertIs(document[name], False)
            self.assertEqual(set(document["effects"].values()), {"none"})


if __name__ == "__main__":
    unittest.main()
