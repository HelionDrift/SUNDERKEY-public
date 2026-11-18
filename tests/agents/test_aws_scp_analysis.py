"""Synthetic supplied-policy reasoning, not AWS permission or qualification evidence."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from dataclasses import FrozenInstanceError
from itertools import product
from unittest.mock import patch

from sunderkey import aws_scp_analysis as scp


def statement(effect="Allow", action="*", resource="*", **extra):
    result = {"Effect": effect, "Action": action, "Resource": resource}
    result.update(extra)
    return result


def policy(policy_id="full-access", statements=None, **extra):
    document = {
        "Version": "2012-10-17",
        "Statement": [statement()] if statements is None else statements,
    }
    document.update(extra)
    return {"policy_id": policy_id, "document": document}


def level(node_id, node_type, policies=None, *, complete=True):
    return {
        "node_id": node_id,
        "node_type": node_type,
        "attachments_complete": complete,
        "policies": [policy()] if policies is None else policies,
    }


def snapshot():
    return {
        "schema_version": 1,
        "organization_id": "organization:synthetic",
        "management_account_id": "111111111111",
        "scp_enabled": True,
        "path": [
            level("root:synthetic", "root"),
            level("ou:workloads", "ou"),
            level("222222222222", "account"),
        ],
    }


def query(query_id="read-object", **changes):
    result = {
        "query_id": query_id,
        "principal_account_id": "222222222222",
        "principal_kind": "iam_role",
        "action": "s3:GetObject",
        "resource": "arn:aws:s3:::synthetic-bucket/reports/one",
        "context": {"values": {}, "absent_keys": []},
    }
    result.update(changes)
    return result


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def readdress(document):
    result = copy.deepcopy(document)
    body = {
        key: value for key, value in result.items() if key not in ("analysis_id", "analysis_sha256")
    }
    digest = (
        "sha256:" + hashlib.sha256(b"sunderkey.aws-scp-analysis.v1\n" + encode(body)).hexdigest()
    )
    result.update(analysis_id="ASA-" + digest[7:39].upper(), analysis_sha256=digest)
    return result


def glob_oracle(pattern, value):
    """Small independent dynamic-programming wildcard oracle for inert tests."""
    previous = [True] + [False] * len(value)
    for token in pattern:
        current = [previous[0] and token == "*"]
        for index, character in enumerate(value, 1):
            current.append(
                previous[index] or current[index - 1]
                if token == "*"
                else previous[index - 1] and (token == "?" or token == character)
            )
        previous = current
    return previous[-1]


class StringAlias(str):
    pass


class IntegerAlias(int):
    pass


class ListAlias(list):
    pass


class BytesAlias(bytes):
    pass


class RecordAlias(scp.AwsScpAnalysis):
    pass


class AwsScpAnalysisTests(unittest.TestCase):
    def analyze(self, model=None, requests=None):
        return scp.analyze_aws_scp(
            snapshot() if model is None else model, [query()] if requests is None else requests
        ).to_dict()

    def result(self, model=None, request=None):
        return self.analyze(model, [query() if request is None else request])["results"][0]

    def condition_model(self, condition, *, effect="Deny"):
        model = snapshot()
        model["path"][1]["policies"].append(
            policy("conditional", [statement(effect, "s3:GetObject", Condition=condition)])
        )
        return model

    def assert_replay_rejected(self, document):
        for parser in (
            scp.AwsScpAnalysis.from_dict,
            lambda value: scp.AwsScpAnalysis.from_json(encode(value)),
            lambda value: scp.AwsScpAnalysis(encode(value).decode("ascii")),
            lambda value: scp.verify_aws_scp_analysis(
                value, snapshot=snapshot(), queries=[query()]
            ),
        ):
            with self.subTest(parser=parser), self.assertRaises(scp.AwsScpAnalysisError):
                parser(document)

    def test_valid_baseline_replays_exact_sources_and_retains_no_effects(self):
        model, requests = snapshot(), [query()]
        record = scp.analyze_aws_scp(model, requests)
        document = record.to_dict()
        self.assertEqual(document["results"][0]["decision"], "not_blocked_by_supplied_scps")
        self.assertEqual(len(document["results"][0]["allow_witnesses"]), 3)
        self.assertEqual(document["results"][0]["missing_allow_level_ids"], [])
        self.assertEqual(document["summary"]["not_blocked_by_supplied_scps"], 1)
        self.assertEqual(document["profile_id"], "AOE-GC-D14-S01")
        self.assertEqual(document["capability_id"], "army.gc.d14.s01")
        self.assertEqual(document["vector_id"], "AV-GC-D14-S01-01")
        self.assertEqual(set(document["effects"].values()), {"none"})
        self.assertEqual(record.analysis_id, document["analysis_id"])
        self.assertEqual(record.analysis_sha256, document["analysis_sha256"])
        self.assertEqual(record.analysis_id, "ASA-DD074F0749A28D679FC2992F2799C434")
        self.assertEqual(
            record.analysis_sha256,
            "sha256:dd074f0749a28d679fc2992f2799c43407e6c82c2197b96bc89b5b4f9ec8f557",
        )
        self.assertEqual(
            document["snapshot_sha256"],
            "sha256:5a0fc495c031de8cbb98d28a37a95d67598ddae1b481a8e81e6b5a9ad4fc3579",
        )
        self.assertEqual(
            document["queries_sha256"],
            "sha256:4a9a2aae02a2be6821f69ab80bef5bfb83d874b2bb1b85a25a1db167a14e8958",
        )
        self.assertEqual(
            document["results"][0]["allow_witnesses"][0]["statement_sha256"],
            "sha256:526c220442b2d0a766f43e286da5790907d78f3ee17e5463c92a340b915191b0",
        )
        self.assertEqual(scp.AwsScpAnalysis.from_dict(document).to_json(), record.to_json())
        self.assertEqual(scp.AwsScpAnalysis.from_json(encode(document)).to_json(), record.to_json())
        self.assertEqual(
            scp.analyze_aws_scp_bytes(
                snapshot_bytes=encode(model), queries_bytes=encode(requests)
            ).to_json(),
            record.to_json(),
        )
        self.assertEqual(
            scp.verify_aws_scp_analysis(record, snapshot=model, queries=requests).to_json(),
            record.to_json(),
        )

    def test_allow_policies_are_or_within_level_not_intersected(self):
        model = snapshot()
        model["path"][1]["policies"] = [
            policy("ec2-only", [statement(action="ec2:Describe*")]),
            policy("s3-only", [statement(action="s3:GetObject")]),
        ]
        result = self.result(model)
        self.assertEqual(result["decision"], "not_blocked_by_supplied_scps")
        self.assertEqual(len(result["allow_witnesses"]), 3)
        self.assertEqual(result["allow_witnesses"][1]["policy_id"], "s3-only")

    def test_all_path_levels_must_allow_and_lower_level_cannot_override(self):
        for index in range(3):
            model = snapshot()
            model["path"][index]["policies"] = [policy("ec2-only", [statement(action="ec2:*")])]
            result = self.result(model)
            with self.subTest(index=index):
                self.assertEqual(result["decision"], "blocked")
                self.assertEqual(
                    result["missing_allow_level_ids"], [model["path"][index]["node_id"]]
                )
                self.assertIn("no_matching_allow_at_every_level", result["reasons"])

    def test_root_deny_overrides_lower_level_allows(self):
        model = snapshot()
        model["path"][0]["policies"].append(policy("root-deny", [statement("Deny", "s3:*")]))
        result = self.result(model)
        self.assertEqual(result["decision"], "blocked")
        self.assertEqual(len(result["allow_witnesses"]), 3)
        self.assertEqual(result["deny_witnesses"][0]["node_id"], "root:synthetic")
        self.assertIn("matching_explicit_deny", result["reasons"])

    def test_deny_at_any_level_is_additive_and_no_matching_deny_is_not_a_finding(self):
        for index in range(3):
            model = snapshot()
            model["path"][index]["policies"].append(
                policy("deny", [statement("Deny", "s3:GetObject")])
            )
            with self.subTest(index=index):
                self.assertEqual(self.result(model)["decision"], "blocked")
                self.assertEqual(
                    self.result(model, query(action="s3:ListBucket"))["decision"],
                    "not_blocked_by_supplied_scps",
                )

    def test_empty_complete_level_blocks_but_incomplete_level_is_inconclusive(self):
        for complete, decision in ((True, "blocked"), (False, "inconclusive")):
            model = snapshot()
            model["path"][1] = level("ou:workloads", "ou", [], complete=complete)
            with self.subTest(complete=complete):
                result = self.result(model)
                self.assertEqual(result["decision"], decision)
                self.assertEqual(result["missing_allow_level_ids"], ["ou:workloads"])

    def test_known_deny_remains_blocked_with_incomplete_or_unsupported_sources(self):
        model = self.condition_model({"NumericGreaterThan": {"aws:MultiFactorAuthAge": "300"}})
        model["path"][0]["attachments_complete"] = False
        model["path"][2]["policies"].append(policy("denied", [statement("Deny", "s3:*")]))
        result = self.result(model)
        self.assertEqual(result["decision"], "blocked")
        self.assertEqual(len(result["deny_witnesses"]), 1)
        self.assertEqual(len(result["unresolved_witnesses"]), 1)
        self.assertIn("incomplete_policy_attachments", result["reasons"])
        self.assertIn("unsupported_source_semantics", result["reasons"])

    def test_action_matching_is_case_insensitive_and_question_star_are_real_patterns(self):
        model = snapshot()
        model["path"][1]["policies"] = [policy("reads", [statement(action="S3:g?tObj*")])]
        self.assertEqual(
            self.result(model, query(action="s3:GETOBJECT"))["decision"],
            "not_blocked_by_supplied_scps",
        )
        self.assertEqual(self.result(model, query(action="s3:GetBucket"))["decision"], "blocked")
        self.assertEqual(
            self.result(model, query(action="s3:GetObj"))["decision"],
            "not_blocked_by_supplied_scps",
        )

    def test_resource_exact_and_tail_patterns_are_case_sensitive_and_cross_slashes(self):
        model = snapshot()
        model["path"][1]["policies"].append(
            policy(
                "denied",
                [statement("Deny", "s3:GetObject", "arn:aws:s3:::synthetic-bucket/*/one?")],
            )
        )
        for resource, decision in (
            ("arn:aws:s3:::synthetic-bucket/a/b/one1", "blocked"),
            ("arn:aws:s3:::synthetic-bucket/a/one", "not_blocked_by_supplied_scps"),
            ("arn:aws:s3:::Synthetic-bucket/a/one1", "not_blocked_by_supplied_scps"),
        ):
            with self.subTest(resource=resource):
                self.assertEqual(self.result(model, query(resource=resource))["decision"], decision)
        exact = snapshot()
        exact["path"][1]["policies"].append(
            policy("denied", [statement("Deny", resource=query()["resource"])])
        )
        self.assertEqual(self.result(exact)["decision"], "blocked")

    def test_resource_star_and_explicit_service_wide_query_are_supported(self):
        model = snapshot()
        model["path"][0]["policies"].append(policy("denied", [statement("Deny", "iam:*")]))
        self.assertEqual(
            self.result(model, query(action="iam:ListRoles", resource="*"))["decision"], "blocked"
        )

    def test_colon_tail_patterns_are_conservative_except_literal_or_plain_trailing_star(self):
        resource = "arn:aws:logs:us-west-2:222222222222:log-group:synthetic"
        for pattern, expected in (
            (resource, "blocked"),
            ("arn:aws:logs:us-west-2:222222222222:log-*", "blocked"),
            ("arn:aws:logs:us-west-2:222222222222:log-?roup*", "inconclusive"),
            ("arn:aws:logs:us-west-2:222222222222:log*synthetic", "inconclusive"),
            ("arn:aws:logs:us-west-2:222222222222:log-group:*", "inconclusive"),
        ):
            model = snapshot()
            model["path"][1]["policies"].append(
                policy("denied", [statement("Deny", resource=pattern)])
            )
            with self.subTest(pattern=pattern):
                self.assertEqual(self.result(model, query(resource=resource))["decision"], expected)

    def test_allow_specific_resource_and_early_arn_wildcard_are_unresolved(self):
        for item in (
            statement("Allow", resource=query()["resource"]),
            statement("Deny", resource="arn:aws:iam::*:role/admin*"),
            statement("Deny", resource="arn:aws:*:::anything"),
        ):
            model = snapshot()
            model["path"][1]["policies"].append(policy("unresolved", [item]))
            with self.subTest(item=item):
                result = self.result(model)
                self.assertEqual(result["decision"], "inconclusive")
                self.assertEqual(len(result["unresolved_witnesses"]), 1)

    def test_string_conditions_and_keys_are_and_values_are_or(self):
        model = self.condition_model(
            {
                "StringEquals": {
                    "aws:RequestedRegion": ["eu-west-1", "us-west-2"],
                    "aws:PrincipalTag/team": "test",
                },
                "StringLike": {"s3:prefix": "reports/*"},
            }
        )
        context = {
            "values": {
                "AWS:RequestedRegion": "us-west-2",
                "aws:PrincipalTag/team": "test",
                "s3:prefix": "reports/a/b",
            },
            "absent_keys": [],
        }
        self.assertEqual(self.result(model, query(context=context))["decision"], "blocked")
        for key, value in (
            ("AWS:RequestedRegion", "us-east-1"),
            ("aws:PrincipalTag/team", "Test"),
            ("s3:prefix", "report/a"),
        ):
            changed = copy.deepcopy(context)
            changed["values"][key] = value
            with self.subTest(key=key):
                self.assertEqual(
                    self.result(model, query(context=changed))["decision"],
                    "not_blocked_by_supplied_scps",
                )

    def test_unknown_context_never_becomes_absent_or_not_blocked(self):
        model = self.condition_model({"StringEquals": {"aws:RequestedRegion": "us-west-2"}})
        self.assertEqual(self.result(model)["decision"], "inconclusive")
        absent = query(context={"values": {}, "absent_keys": ["AWS:RequestedRegion"]})
        self.assertEqual(self.result(model, absent)["decision"], "not_blocked_by_supplied_scps")
        present = query(context={"values": {"aws:RequestedRegion": "us-west-2"}, "absent_keys": []})
        self.assertEqual(self.result(model, present)["decision"], "blocked")

    def test_stringlike_deny_matches_wildcard_characters_in_native_context_values(self):
        for pattern in ("*", "?", "a*?b", "*?", "**", "*internal"):
            model = self.condition_model({"StringLike": {"aws:PrincipalTag/team": pattern}})
            for value in ("*internal", "**", "a*?b", "?", "internal", "ordinary"):
                request = query(
                    context={"values": {"aws:PrincipalTag/team": value}, "absent_keys": []}
                )
                with self.subTest(pattern=pattern, value=value):
                    result = self.result(model, request)
                    self.assertEqual(
                        result["decision"],
                        "blocked"
                        if glob_oracle(pattern, value)
                        else "not_blocked_by_supplied_scps",
                    )
                    self.assertFalse(result["unresolved_witnesses"])

    def test_stringlike_allow_matches_wildcard_characters_in_native_context_values(self):
        for pattern in ("*", "?", "a*?b", "*?", "**", "*internal"):
            model = snapshot()
            model["path"][1]["policies"] = [
                policy(
                    "conditional-allow",
                    [statement(Condition={"StringLike": {"aws:PrincipalTag/team": pattern}})],
                )
            ]
            for value in ("*internal", "**", "a*?b", "?", "internal", "ordinary"):
                request = query(
                    context={"values": {"aws:PrincipalTag/team": value}, "absent_keys": []}
                )
                with self.subTest(pattern=pattern, value=value):
                    result = self.result(model, request)
                    self.assertEqual(
                        result["decision"],
                        "not_blocked_by_supplied_scps"
                        if glob_oracle(pattern, value)
                        else "blocked",
                    )
                    self.assertFalse(result["unresolved_witnesses"])

    def test_bounded_matcher_agrees_with_independent_small_alphabet_oracle(self):
        patterns = ["".join(parts) for size in range(4) for parts in product("a*?", repeat=size)]
        values = ["".join(parts) for size in range(4) for parts in product("a*?b", repeat=size)]
        for pattern in patterns:
            for value in values:
                with self.subTest(pattern=pattern, value=value):
                    self.assertEqual(
                        scp._glob(pattern, value, scp._Budget()), glob_oracle(pattern, value)
                    )

    def test_false_condition_dominates_an_unavailable_key_in_same_and(self):
        model = self.condition_model({"StringEquals": {"a:key": "one", "b:key": "two"}})
        request = query(context={"values": {"a:key": "different"}, "absent_keys": []})
        self.assertEqual(self.result(model, request)["decision"], "not_blocked_by_supplied_scps")

    def test_conditioned_allow_requires_known_true_at_its_level(self):
        model = snapshot()
        model["path"][1]["policies"] = [
            policy(
                "regional",
                [statement(Condition={"StringEquals": {"aws:RequestedRegion": "us-west-2"}})],
            )
        ]
        for context, decision in (
            ({"values": {}, "absent_keys": []}, "inconclusive"),
            ({"values": {}, "absent_keys": ["aws:RequestedRegion"]}, "blocked"),
            (
                {"values": {"aws:RequestedRegion": "us-west-2"}, "absent_keys": []},
                "not_blocked_by_supplied_scps",
            ),
        ):
            with self.subTest(context=context):
                self.assertEqual(self.result(model, query(context=context))["decision"], decision)

    def test_bool_conditions_distinguish_false_true_absent_and_unavailable(self):
        model = self.condition_model({"Bool": {"aws:SecureTransport": "false"}})
        for context, decision in (
            ({"values": {"aws:SecureTransport": "false"}, "absent_keys": []}, "blocked"),
            (
                {"values": {"aws:SecureTransport": "true"}, "absent_keys": []},
                "not_blocked_by_supplied_scps",
            ),
            (
                {"values": {}, "absent_keys": ["aws:SecureTransport"]},
                "not_blocked_by_supplied_scps",
            ),
            ({"values": {}, "absent_keys": []}, "inconclusive"),
            ({"values": {"aws:SecureTransport": "unknown"}, "absent_keys": []}, "inconclusive"),
        ):
            with self.subTest(context=context):
                self.assertEqual(self.result(model, query(context=context))["decision"], decision)

    def test_null_condition_checks_declared_absence_not_unavailable_evidence(self):
        for expected in ("true", "false"):
            model = self.condition_model({"Null": {"aws:TokenIssueTime": expected}})
            absent = query(context={"values": {}, "absent_keys": ["aws:TokenIssueTime"]})
            present = query(
                context={"values": {"aws:TokenIssueTime": "declared"}, "absent_keys": []}
            )
            with self.subTest(expected=expected):
                self.assertEqual(self.result(model)["decision"], "inconclusive")
                self.assertEqual(
                    self.result(model, absent)["decision"],
                    "blocked" if expected == "true" else "not_blocked_by_supplied_scps",
                )
                self.assertEqual(
                    self.result(model, present)["decision"],
                    "blocked" if expected == "false" else "not_blocked_by_supplied_scps",
                )

    def test_unsupported_operators_complements_and_variables_never_become_clean(self):
        items = [
            statement(Condition={"StringNotEquals": {"aws:RequestedRegion": "us-west-2"}}),
            statement(Condition={"StringEqualsIfExists": {"aws:RequestedRegion": "us-west-2"}}),
            statement(Condition={"ForAllValues:StringEquals": {"aws:TagKeys": "one"}}),
            statement(
                Condition={"ArnLike": {"aws:PrincipalArn": "arn:aws:iam::222222222222:role/*"}}
            ),
            statement(Condition={"NumericLessThan": {"aws:MultiFactorAuthAge": "300"}}),
            statement(Condition={"StringEquals": {"aws:username": "${aws:username}"}}),
            {"Effect": "Deny", "NotAction": "iam:*", "Resource": "*"},
            {"Effect": "Deny", "Action": "s3:*", "NotResource": query()["resource"]},
            statement(Principal="*"),
            statement(action="*:GetObject"),
        ]
        for item in items:
            model = snapshot()
            model["path"][1]["policies"].append(policy("unsupported", [item]))
            with self.subTest(item=item):
                result = self.result(model)
                self.assertEqual(result["decision"], "inconclusive")
                self.assertTrue(self.analyze(model)["source_issues"])

    def test_unsupported_policy_version_and_fields_invalidate_its_known_statements(self):
        for extra in ({"Version": "future-version"}, {"FutureField": {"declared": True}}):
            model = snapshot()
            model["path"][1]["policies"] = [policy("unknown", [statement("Deny")], **extra)]
            with self.subTest(extra=extra):
                result = self.result(model)
                self.assertEqual(result["decision"], "inconclusive")
                self.assertEqual(result["deny_witnesses"], [])
                self.assertTrue(result["unresolved_witnesses"])

    def test_principal_exemptions_are_explicit_declarations_not_model_access(self):
        model = snapshot()
        model["path"][0]["policies"].append(policy("all-denied", [statement("Deny")]))
        for request in (
            query(principal_account_id="111111111111"),
            query(principal_kind="service_linked_role"),
        ):
            with self.subTest(request=request):
                result = self.result(model, request)
                self.assertEqual(result["decision"], "not_applicable")
                self.assertEqual(result["allow_witnesses"], [])
                self.assertEqual(result["deny_witnesses"], [])
        for kind in ("root", "iam_user", "iam_role"):
            self.assertEqual(self.result(model, query(principal_kind=kind))["decision"], "blocked")

    def test_foreign_or_unknown_principal_never_uses_selected_member_path(self):
        for request in (
            query(principal_account_id="333333333333"),
            query(principal_account_id=None),
            query(principal_kind="unknown"),
        ):
            with self.subTest(request=request):
                result = self.result(request=request)
                self.assertEqual(result["decision"], "inconclusive")
                self.assertEqual(result["allow_witnesses"], [])
        self.assertIn(
            "principal_outside_supplied_account_path",
            self.result(request=query(principal_account_id="333333333333"))["reasons"],
        )

    def test_disabled_and_unknown_scp_applicability_are_not_permission_grants(self):
        for enabled, decision in ((False, "not_applicable"), (None, "inconclusive")):
            model = snapshot()
            model["scp_enabled"] = enabled
            with self.subTest(enabled=enabled):
                self.assertEqual(self.result(model)["decision"], decision)

    def test_path_order_identity_member_selection_and_exact_flags_reject(self):
        changes = (
            lambda d: d["path"].reverse(),
            lambda d: d["path"][1].update(node_type="account"),
            lambda d: d["path"][1].update(node_id="root:synthetic"),
            lambda d: d["path"][-1].update(node_id="111111111111"),
            lambda d: d["path"].pop(),
            lambda d: d["path"][0].update(attachments_complete=1),
            lambda d: d.update(scp_enabled=1),
            lambda d: d.update(schema_version=True),
            lambda d: d.update(schema_version=1.0),
            lambda d: d.update(management_account_id="111"),
            lambda d: d.update(extra=False),
        )
        for change in changes:
            model = snapshot()
            change(model)
            with self.subTest(change=change), self.assertRaises(scp.AwsScpAnalysisError):
                self.analyze(model)

    def test_duplicate_and_conflicting_policy_identities_reject_but_shared_policy_is_valid(self):
        self.assertEqual(self.result()["decision"], "not_blocked_by_supplied_scps")
        model = snapshot()
        model["path"][0]["policies"].append(policy())
        with self.assertRaisesRegex(scp.AwsScpAnalysisError, "Duplicate policy"):
            self.analyze(model)
        model = snapshot()
        model["path"][1]["policies"][0] = policy(statements=[statement(action="ec2:*")])
        with self.assertRaisesRegex(scp.AwsScpAnalysisError, "conflicting documents"):
            self.analyze(model)
        # Equal Python dictionaries with distinct native JSON bytes are still conflicts.
        model = snapshot()
        model["path"][0]["policies"][0]["document"]["FutureField"] = True
        model["path"][1]["policies"][0]["document"]["FutureField"] = 1
        with self.assertRaisesRegex(scp.AwsScpAnalysisError, "conflicting documents"):
            self.analyze(model)

    def test_malformed_statements_sids_conditions_and_native_values_reject(self):
        for item in (
            {"Action": "*", "Resource": "*"},
            statement(effect=True),
            statement(effect="Permit"),
            statement(action=[]),
            statement(action=[1]),
            statement(resource=[False]),
            {"Effect": "Allow", "Action": "*", "NotAction": "s3:*", "Resource": "*"},
            {"Effect": "Allow", "Action": "*"},
            statement(Condition={}),
            statement(Condition={"Bool": {"aws:SecureTransport": True}}),
            statement(Condition={"Null": {"aws:TokenIssueTime": "TRUE"}}),
            statement(Condition={"StringEquals": {"AWS:Key": "one", "aws:key": "two"}}),
        ):
            model = snapshot()
            model["path"][0]["policies"] = [policy("malformed", [item])]
            with self.subTest(item=item), self.assertRaises(scp.AwsScpAnalysisError):
                self.analyze(model)
        model = snapshot()
        model["path"][0]["policies"] = [
            policy("sids", [statement(Sid="Repeated"), statement(Sid="Repeated")])
        ]
        with self.assertRaisesRegex(scp.AwsScpAnalysisError, "Sids repeat"):
            self.analyze(model)

    def test_query_identifiers_scope_native_context_and_case_collisions_reject(self):
        for changes in (
            {"principal_account_id": 222222222222},
            {"principal_kind": "assumed_unknown_role"},
            {"action": "s3:*"},
            {"resource": "arn:aws:s3:::synthetic/*"},
            {"context": {"values": {"AWS:key": "one", "aws:KEY": "two"}, "absent_keys": []}},
            {"context": {"values": {"aws:key": "one"}, "absent_keys": ["AWS:Key"]}},
            {"context": {"values": {}, "absent_keys": ["AWS:Key", "aws:key"]}},
            {"context": {"values": {"aws:key": True}, "absent_keys": []}},
            {"context": {"values": {"aws:key": ["one"]}, "absent_keys": []}},
        ):
            with self.subTest(changes=changes), self.assertRaises(scp.AwsScpAnalysisError):
                self.result(request=query(**changes))
        with self.assertRaisesRegex(scp.AwsScpAnalysisError, "Query IDs repeat"):
            self.analyze(requests=[query(), query()])

    def test_permutations_preserve_reasoning_but_bind_original_source_order(self):
        model = snapshot()
        model["path"][0]["policies"].extend(
            [
                policy(
                    "denies",
                    [statement("Deny", "ec2:StartInstances"), statement("Deny", "iam:DeleteRole")],
                ),
                policy("s3", [statement(action=["s3:GetObject", "s3:ListBucket"])]),
            ]
        )
        requests = [query("one"), query("two", action="s3:ListBucket")]
        original = self.analyze(model, requests)
        changed = copy.deepcopy(model)
        changed["path"][0]["policies"].reverse()
        changed["path"][0]["policies"][0]["document"]["Statement"][0]["Action"].reverse()
        changed["path"][0]["policies"][1]["document"]["Statement"].reverse()
        other = self.analyze(changed, list(reversed(requests)))
        self.assertEqual(
            [r["decision"] for r in original["results"]], [r["decision"] for r in other["results"]]
        )
        self.assertEqual(original["summary"], other["summary"])
        self.assertNotEqual(original["analysis_sha256"], other["analysis_sha256"])
        with self.assertRaisesRegex(scp.AwsScpAnalysisError, "different supplied inputs"):
            scp.verify_aws_scp_analysis(original, snapshot=changed, queries=requests)

    def test_sources_and_exports_are_owned_and_canonical_parsed_not_raw_provenance(self):
        model, requests = snapshot(), [query()]
        before = encode({"snapshot": model, "queries": requests})
        record = scp.analyze_aws_scp(model, requests)
        canonical = record.to_json()
        self.assertEqual(encode({"snapshot": model, "queries": requests}), before)
        exported = record.to_dict()
        exported["effects"]["execution"] = "allowed"
        exported["snapshot"]["path"][0]["policies"].clear()
        model["path"][1]["policies"].clear()
        requests[0]["context"]["values"]["aws:key"] = "changed"
        self.assertEqual(record.to_json(), canonical)
        with self.assertRaises(FrozenInstanceError):
            record.document_json = "{}"
        pretty_model = json.dumps(snapshot(), indent=2).encode()
        pretty_queries = json.dumps([query()], indent=2).encode()
        self.assertEqual(
            scp.analyze_aws_scp_bytes(
                snapshot_bytes=pretty_model, queries_bytes=pretty_queries
            ).to_json(),
            canonical,
        )

    def test_coherently_rehashed_false_result_rejects_all_public_replay_paths(self):
        document = self.analyze()
        changes = (
            lambda d: d["results"][0].update(decision="blocked"),
            lambda d: d["results"][0]["allow_witnesses"].pop(),
            lambda d: d["results"][0]["allow_witnesses"][0].update(policy_id="forged"),
            lambda d: d["results"][0].update(missing_allow_level_ids=["ou:workloads"]),
            lambda d: d["summary"].update(not_blocked_by_supplied_scps=True),
            lambda d: d["summary"].update(blocked=0.0),
            lambda d: d["effects"].update(qualification="allowed"),
            lambda d: d.update(snapshot_sha256="sha256:" + "a" * 64),
            lambda d: d.update(queries_sha256="sha256:" + "b" * 64),
            lambda d: d["results"][0].update(query_sha256="sha256:" + "c" * 64),
            lambda d: d.update(schema_version=True),
            lambda d: d.update(extra=False),
        )
        for change in changes:
            malformed = copy.deepcopy(document)
            change(malformed)
            with self.subTest(change=change):
                self.assert_replay_rejected(readdress(malformed))

    def test_truthfully_changed_embedded_sources_need_new_results_and_external_replay(self):
        original = self.analyze()
        changed = copy.deepcopy(original)
        changed["snapshot"]["path"][1]["policies"] = []
        self.assert_replay_rejected(readdress(changed))
        current = snapshot()
        current["path"][1]["policies"] = []
        another = scp.analyze_aws_scp(current, [query()])
        self.assertEqual(another.to_dict()["results"][0]["decision"], "blocked")
        with self.assertRaises(scp.AwsScpAnalysisError):
            scp.verify_aws_scp_analysis(another, snapshot=snapshot(), queries=[query()])

    def test_byte_parsers_reject_duplicate_keys_wrong_utf8_floats_and_nonfinite(self):
        raw = encode(snapshot())
        for content in (
            b'{"schema_version":1,' + raw[1:],
            raw.replace(b'"Effect":"Allow"', b'"Effect":"Allow","Effect":"Deny"', 1),
            raw.replace(b'"schema_version":1', b'"schema_version":1.0'),
            raw.replace(b'"schema_version":1', b'"schema_version":NaN'),
            raw.replace(b'"schema_version":1', b'"schema_version":9223372036854775808'),
            b"\xff",
            b"",
            b"[" * 30 + b"0" + b"]" * 30,
            BytesAlias(raw),
        ):
            with self.subTest(content=content[:60]), self.assertRaises(scp.AwsScpAnalysisError):
                scp.analyze_aws_scp_bytes(snapshot_bytes=content, queries_bytes=encode([query()]))
        report = encode(self.analyze())
        with self.assertRaises(scp.AwsScpAnalysisError):
            scp.AwsScpAnalysis.from_json(b'{"schema_version":1,' + report[1:])

    def test_native_aliases_cycles_surrogates_and_costs_reject_before_hashing(self):
        for change in (
            lambda d: d.update(schema_version=IntegerAlias(1)),
            lambda d: d.update(organization_id=StringAlias("organization:synthetic")),
            lambda d: d.update(path=ListAlias(d["path"])),
            lambda d: d.update(organization_id="\ud800"),
            lambda d: d.update(extra=["x"] * (scp.MAX_NODES + 1)),
        ):
            model = snapshot()
            change(model)
            with (
                self.subTest(change=change),
                patch.object(scp.hashlib, "sha256", side_effect=AssertionError("no hash")),
                self.assertRaises(scp.AwsScpAnalysisError),
            ):
                scp.analyze_aws_scp(model, [query()])
        cycle = []
        cycle.append(cycle)
        model = snapshot()
        model["extra"] = cycle
        with (
            patch.object(scp.hashlib, "sha256", side_effect=AssertionError("no hash")),
            self.assertRaises(scp.AwsScpAnalysisError),
        ):
            scp.analyze_aws_scp(model, [query()])

    def test_shared_container_and_escaped_budget_precede_serialization(self):
        shared = ['\\"' * 2048]
        for raw in ([shared] * 500, [None] * (scp.MAX_NODES + 1), [[[[None]]]] * 15000):
            with (
                self.subTest(shape=len(raw)),
                patch.object(scp.json, "dumps", side_effect=AssertionError("no serialization")),
                self.assertRaises(scp.AwsScpAnalysisError),
            ):
                scp.AwsScpAnalysis.from_dict(raw)

    def test_query_and_path_boundaries_are_finite_and_empty_queries_are_valid(self):
        document = self.analyze(
            requests=[query(f"query-{index}") for index in range(scp.MAX_QUERIES)]
        )
        self.assertEqual(len(document["results"]), scp.MAX_QUERIES)
        self.assertEqual(
            self.analyze(requests=[])["summary"], {key: 0 for key in document["summary"]}
        )
        with self.assertRaises(scp.AwsScpAnalysisError):
            self.analyze(requests=[query(f"query-{index}") for index in range(scp.MAX_QUERIES + 1)])
        model = snapshot()
        model["path"][1:2] = [
            level(f"ou:{index}", "ou") for index in range(scp.MAX_PATH_LEVELS - 2)
        ]
        self.assertEqual(self.result(model)["decision"], "not_blocked_by_supplied_scps")
        model["path"].insert(1, level("ou:overflow", "ou"))
        with self.assertRaises(scp.AwsScpAnalysisError):
            self.analyze(model)

    def test_policy_and_statement_accounting_checks_total_not_only_local_lists(self):
        model = snapshot()
        model["path"][0]["policies"] = [policy(f"policy-{i}") for i in range(scp.MAX_POLICIES)]
        model["path"][1]["policies"] = []
        model["path"][2]["policies"] = []
        self.analyze(model, [])
        model["path"][1]["policies"] = [policy("overflow")]
        with self.assertRaisesRegex(scp.AwsScpAnalysisError, "Policy attachment budget"):
            self.analyze(model, [])
        model = snapshot()
        model["path"][0]["policies"] = [
            policy(f"policy-{i}", [statement("Deny", "iam:DeleteRole") for _ in range(128)])
            for i in range(16)
        ]
        model["path"][1]["policies"] = []
        model["path"][2]["policies"] = []
        self.assertEqual(self.result(model)["decision"], "blocked")
        model["path"][1]["policies"] = [policy("overflow")]
        with self.assertRaisesRegex(scp.AwsScpAnalysisError, "Statement matching budget"):
            self.analyze(model, [])

    def test_witness_budget_rejects_instead_of_returning_truncated_results(self):
        model = snapshot()
        model["path"][0]["policies"] = [
            policy("many", [statement(Sid=f"Rule{i}") for i in range(17)])
        ]
        with self.assertRaisesRegex(scp.AwsScpAnalysisError, "Witness budget"):
            self.analyze(model, [query(f"query-{i}") for i in range(128)])

    def test_matching_work_is_charged_with_no_regex_expansion(self):
        model = self.condition_model({"StringLike": {"a:key": "*" + "a" * 100 + "z"}})
        request = query(context={"values": {"a:key": "a" * 500}, "absent_keys": []})
        with (
            patch.object(scp, "MAX_MATCH_WORK", 1000),
            self.assertRaisesRegex(scp.AwsScpAnalysisError, "Matching work budget"),
        ):
            self.result(model, request)

    def test_forged_incomplete_or_reassigned_wrapper_cannot_export_or_replay(self):
        record = scp.analyze_aws_scp(snapshot(), [query()])
        for invalid in (
            object.__new__(scp.AwsScpAnalysis),
            RecordAlias(record.to_json()),
            {"analysis_id": "forged"},
        ):
            with self.subTest(family=type(invalid)), self.assertRaises(scp.AwsScpAnalysisError):
                scp.verify_aws_scp_analysis(invalid, snapshot=snapshot(), queries=[query()])
        missing = object.__new__(scp.AwsScpAnalysis)
        with self.assertRaises(scp.AwsScpAnalysisError):
            missing.to_dict()
        object.__setattr__(missing, "document_json", StringAlias(record.to_json()))
        with self.assertRaises(scp.AwsScpAnalysisError):
            missing.to_dict()
        modified = readdress(record.to_dict())
        modified["effects"]["execution"] = "allowed"
        object.__setattr__(record, "document_json", encode(readdress(modified)).decode())
        with self.assertRaises(scp.AwsScpAnalysisError):
            record.to_json()

    def test_summary_accounts_for_all_declared_outcomes_without_effect_promotion(self):
        model = snapshot()
        model["path"][0]["policies"].append(policy("denied", [statement("Deny", "iam:DeleteRole")]))
        document = self.analyze(
            model,
            [
                query("a"),
                query("b", action="iam:DeleteRole"),
                query("c", principal_account_id="333333333333"),
                query("d", principal_kind="service_linked_role"),
            ],
        )
        self.assertEqual(
            document["summary"],
            {
                "blocked": 1,
                "inconclusive": 1,
                "not_applicable": 1,
                "not_blocked_by_supplied_scps": 1,
            },
        )
        self.assertEqual(sum(document["summary"].values()), 4)
        self.assertEqual(set(document["effects"].values()), {"none"})


if __name__ == "__main__":
    unittest.main()
