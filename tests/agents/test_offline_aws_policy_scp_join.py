"""Inert two-layer AWS policy arithmetic, exact joins and original replay."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from dataclasses import FrozenInstanceError
from unittest.mock import patch

from sunderkey import offline_aws_policy_scp_join as pair

RESOURCE = "arn:aws:s3:::synthetic-bucket/public/one"
ALLOW = "identity_allow_and_scp_not_blocked"
EXPLICIT = "explicit_deny_in_supplied_layer"
MISSING = "missing_allow_in_supplied_layer"


def fixture() -> dict:
    context = {"values": {}, "absent_keys": []}
    identity_query = {
        "query_id": "read-one",
        "action": "s3:GetObject",
        "resource": RESOURCE,
        "action_resource_applicability": True,
        "context": copy.deepcopy(context),
    }
    scp_query = {
        "query_id": "read-one",
        "principal_account_id": "222222222222",
        "principal_kind": "iam_role",
        "action": "s3:GetObject",
        "resource": RESOURCE,
        "context": copy.deepcopy(context),
    }
    full = {
        "policy_id": "full",
        "document": {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        },
    }
    return {
        "schema_version": 1,
        "principal_binding": {
            "principal_ref": "principal:synthetic",
            "principal_account_id": "222222222222",
            "principal_kind": "iam_role",
        },
        "identity_model": {
            "schema_version": 1,
            "principal_ref": "principal:synthetic",
            "attachments_complete": True,
            "policies": [copy.deepcopy(full)],
            "queries": [identity_query],
        },
        "scp_snapshot": {
            "schema_version": 1,
            "organization_id": "organization:synthetic",
            "management_account_id": "111111111111",
            "scp_enabled": True,
            "path": [
                {
                    "node_id": "root:synthetic",
                    "node_type": "root",
                    "attachments_complete": True,
                    "policies": [copy.deepcopy(full)],
                },
                {
                    "node_id": "222222222222",
                    "node_type": "account",
                    "attachments_complete": True,
                    "policies": [copy.deepcopy(full)],
                },
            ],
        },
        "scp_queries": [scp_query],
    }


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def outcome(model: dict) -> dict:
    return pair.analyze_supplied_aws_policy_scp_pair(model).to_dict()["results"][0]


def readdress(document: dict) -> dict:
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = "sha256:" + hashlib.sha256(pair.DOMAIN.encode() + b"\n" + canonical(body)).hexdigest()
    return {"analysis_id": "APJ-" + digest[7:39].upper(), "analysis_sha256": digest, **body}


class AwsPolicyScpJoinTests(unittest.TestCase):
    def test_identity_allow_and_scp_nonblocking_do_not_claim_aws_permission(self) -> None:
        model = fixture()
        record = pair.analyze_supplied_aws_policy_scp_pair(model)
        document = record.to_dict()
        self.assertEqual(document["results"][0]["pair_decision"], ALLOW)
        self.assertEqual(
            document["results"][0]["identity_decision"],
            "allowed_by_supplied_identity_policies",
        )
        self.assertEqual(document["results"][0]["scp_decision"], "not_blocked_by_supplied_scps")
        self.assertTrue(all(value == "none" for value in document["effects"].values()))
        self.assertEqual(document["summary"][ALLOW], 1)
        self.assertEqual(sum(document["summary"][item] for item in pair._DECISIONS), 1)
        self.assertEqual(
            pair.analyze_supplied_aws_policy_scp_pair_bytes(model_bytes=canonical(model)).to_json(),
            record.to_json(),
        )
        self.assertEqual(pair.AwsPolicyScpJoin.from_dict(document).to_json(), record.to_json())
        self.assertEqual(
            pair.AwsPolicyScpJoin.from_json(record.to_json().encode()).to_json(),
            record.to_json(),
        )
        self.assertEqual(
            pair.verify_supplied_aws_policy_scp_pair(record, model=model).to_json(),
            record.to_json(),
        )
        with self.assertRaises(FrozenInstanceError):
            record.document_json = "changed"
        document["results"][0]["pair_decision"] = "changed"
        self.assertEqual(record.to_dict()["results"][0]["pair_decision"], ALLOW)

    def test_identity_deny_wins_over_scp_allow(self) -> None:
        model = fixture()
        model["identity_model"]["policies"][0]["document"]["Statement"].append(
            {"Effect": "Deny", "Action": "s3:GetObject", "Resource": "*"}
        )
        result = outcome(model)
        self.assertEqual(result["pair_decision"], EXPLICIT)
        self.assertEqual(
            result["identity_decision"], "explicit_denial_by_supplied_identity_policies"
        )
        self.assertEqual(result["scp_decision"], "not_blocked_by_supplied_scps")

    def test_scp_explicit_deny_wins_over_identity_allow(self) -> None:
        model = fixture()
        model["scp_snapshot"]["path"][0]["policies"][0]["policy_id"] = "root-deny"
        model["scp_snapshot"]["path"][0]["policies"][0]["document"]["Statement"].append(
            {"Effect": "Deny", "Action": "s3:GetObject", "Resource": "*"}
        )
        result = outcome(model)
        self.assertEqual(result["pair_decision"], EXPLICIT)
        self.assertEqual(result["scp_decision"], "blocked")
        self.assertEqual(result["identity_decision"], "allowed_by_supplied_identity_policies")

    def test_missing_allow_in_either_layer_is_distinct_from_explicit_deny(self) -> None:
        model = fixture()
        model["identity_model"]["policies"] = []
        result = outcome(model)
        self.assertEqual(result["pair_decision"], MISSING)
        self.assertEqual(
            result["identity_decision"], "implicit_denial_by_supplied_identity_policies"
        )
        model = fixture()
        model["scp_snapshot"]["path"][1]["policies"] = []
        result = outcome(model)
        self.assertEqual(result["pair_decision"], MISSING)
        self.assertEqual(result["scp_decision"], "blocked")
        self.assertEqual(result["identity_decision"], "allowed_by_supplied_identity_policies")

    def test_unknown_completeness_and_applicability_withhold_positive_pair(self) -> None:
        for change in ("identity_complete", "scp_complete", "identity_applicable", "scp_enabled"):
            with self.subTest(change=change):
                model = fixture()
                if change == "identity_complete":
                    model["identity_model"]["attachments_complete"] = False
                elif change == "scp_complete":
                    model["scp_snapshot"]["path"][0]["attachments_complete"] = False
                elif change == "identity_applicable":
                    model["identity_model"]["queries"][0]["action_resource_applicability"] = None
                else:
                    model["scp_snapshot"]["scp_enabled"] = None
                self.assertEqual(outcome(model)["pair_decision"], "inconclusive")

    def test_declared_inapplicability_is_separate_from_a_positive_pair(self) -> None:
        model = fixture()
        model["identity_model"]["queries"][0]["action_resource_applicability"] = False
        self.assertEqual(outcome(model)["pair_decision"], "not_applicable")
        model = fixture()
        model["scp_snapshot"]["scp_enabled"] = False
        self.assertEqual(outcome(model)["pair_decision"], "not_applicable")

    def test_principal_account_kind_and_query_joins_reject_truthful_substitutions(self) -> None:
        changes = (
            lambda m: m["principal_binding"].update(principal_ref="principal:other"),
            lambda m: m["principal_binding"].update(principal_account_id="333333333333"),
            lambda m: m["principal_binding"].update(principal_kind="iam_user"),
            lambda m: m["scp_queries"][0].update(principal_account_id="333333333333"),
            lambda m: m["scp_queries"][0].update(principal_kind="iam_user"),
            lambda m: m["scp_queries"][0].update(query_id="another"),
            lambda m: m["scp_queries"][0].update(action="s3:PutObject"),
            lambda m: m["scp_queries"][0].update(resource=RESOURCE + "-other"),
            lambda m: m["scp_queries"][0]["context"]["values"].update(
                {"aws:SecureTransport": "true"}
            ),
        )
        for index, change in enumerate(changes):
            with self.subTest(index=index):
                model = fixture()
                change(model)
                with patch.object(pair.hashlib, "sha256", side_effect=AssertionError("hashed")):
                    with self.assertRaises(pair.AwsPolicyScpJoinError):
                        pair.analyze_supplied_aws_policy_scp_pair(model)

    def test_malformed_join_shapes_refuse_in_own_domain_before_child_hash(self) -> None:
        changes = (
            lambda m: m.update(identity_model=None),
            lambda m: m["identity_model"].update(queries=None),
            lambda m: m.update(scp_snapshot={"path": []}),
            lambda m: m.update(scp_queries=None),
            lambda m: m["identity_model"].update(queries=[{"query_id": []}]),
            lambda m: m.update(scp_queries=[{"query_id": "read-one"}]),
        )
        for index, change in enumerate(changes):
            with self.subTest(index=index):
                model = fixture()
                change(model)
                with patch.object(pair.hashlib, "sha256", side_effect=AssertionError("hashed")):
                    with self.assertRaises(pair.AwsPolicyScpJoinError):
                        pair.analyze_supplied_aws_policy_scp_pair(model)

    def test_extra_or_missing_queries_cannot_be_silently_paired(self) -> None:
        model = fixture()
        model["scp_queries"].append({**copy.deepcopy(model["scp_queries"][0]), "query_id": "extra"})
        with self.assertRaises(pair.AwsPolicyScpJoinError):
            pair.analyze_supplied_aws_policy_scp_pair(model)
        model = fixture()
        model["scp_queries"] = []
        with self.assertRaises(pair.AwsPolicyScpJoinError):
            pair.analyze_supplied_aws_policy_scp_pair(model)
        model = fixture()
        identity_second = copy.deepcopy(model["identity_model"]["queries"][0])
        identity_second["query_id"] = "read-two"
        model["identity_model"]["queries"].append(identity_second)
        model["scp_queries"].append(copy.deepcopy(model["scp_queries"][0]))
        with patch.object(pair.hashlib, "sha256", side_effect=AssertionError("hashed")):
            with self.assertRaises(pair.AwsPolicyScpJoinError):
                pair.analyze_supplied_aws_policy_scp_pair(model)

    def test_coherently_readdressed_false_results_and_subreports_reject(self) -> None:
        model = fixture()
        original = pair.analyze_supplied_aws_policy_scp_pair(model).to_dict()
        mutations = (
            lambda d: d["results"][0].update(pair_decision="explicit_deny_in_supplied_layer"),
            lambda d: d["identity_analysis"]["results"][0].update(decision="inconclusive"),
            lambda d: d["scp_analysis"]["results"][0].update(decision="blocked"),
            lambda d: d["summary"].update(query_count=2),
            lambda d: d["effects"].update(provider_requests="made"),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                forged = copy.deepcopy(original)
                mutate(forged)
                forged = readdress(forged)
                for parse in (
                    pair.AwsPolicyScpJoin.from_dict,
                    lambda d: pair.AwsPolicyScpJoin.from_json(canonical(d)),
                    lambda d: pair.verify_supplied_aws_policy_scp_pair(d, model=model),
                ):
                    with self.assertRaises(pair.AwsPolicyScpJoinError):
                        parse(forged)

    def test_alternate_truthful_model_never_replaces_separate_original(self) -> None:
        original = fixture()
        report = pair.analyze_supplied_aws_policy_scp_pair(original)
        changed = fixture()
        changed["identity_model"]["policies"] = []
        alternate = pair.analyze_supplied_aws_policy_scp_pair(changed)
        self.assertEqual(alternate.to_dict()["results"][0]["pair_decision"], MISSING)
        with self.assertRaises(pair.AwsPolicyScpJoinError):
            pair.verify_supplied_aws_policy_scp_pair(alternate, model=original)
        with self.assertRaises(pair.AwsPolicyScpJoinError):
            pair.verify_supplied_aws_policy_scp_pair(report, model=changed)

    def test_duplicate_raw_keys_and_native_aliases_refuse_before_hashing(self) -> None:
        raw = canonical(fixture()).replace(
            b'"schema_version":1', b'"schema_version":1,"schema_version":1'
        )
        with self.assertRaises(pair.AwsPolicyScpJoinError):
            pair.analyze_supplied_aws_policy_scp_pair_bytes(model_bytes=raw)
        for change in (
            lambda m: m.update(schema_version=True),
            lambda m: m.update(schema_version=1.0),
            lambda m: m["principal_binding"].update(principal_account_id=222222222222),
            lambda m: m["scp_queries"][0].update(principal_kind=1),
        ):
            model = fixture()
            change(model)
            with self.assertRaises(pair.AwsPolicyScpJoinError):
                pair.analyze_supplied_aws_policy_scp_pair(model)
        model = fixture()
        model["principal_binding"]["principal_ref"] = type("TextAlias", (str,), {})(
            "principal:synthetic"
        )
        with patch.object(pair.hashlib, "sha256", side_effect=AssertionError("hashed")):
            with self.assertRaises(pair.AwsPolicyScpJoinError):
                pair.analyze_supplied_aws_policy_scp_pair(model)

    def test_native_cycles_oversized_input_and_depth_refuse_before_hash(self) -> None:
        model = fixture()
        model["extra"] = model
        with patch.object(pair.hashlib, "sha256", side_effect=AssertionError("hashed")):
            with self.assertRaises(pair.AwsPolicyScpJoinError):
                pair.analyze_supplied_aws_policy_scp_pair(model)
        model = fixture()
        model["extra"] = "x" * (pair.MAX_TEXT + 1)
        with patch.object(pair.hashlib, "sha256", side_effect=AssertionError("hashed")):
            with self.assertRaises(pair.AwsPolicyScpJoinError):
                pair.analyze_supplied_aws_policy_scp_pair(model)


if __name__ == "__main__":
    unittest.main()
