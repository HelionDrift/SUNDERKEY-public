"""Native supplied-policy semantics with no GCP access or credential material."""

import ast
import hashlib
import json
import unittest
from copy import deepcopy
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest.mock import patch

from sunderkey import gcp_iam_analysis as module

ORG = "organizations/100"
FOLDER = "folders/200"
PROJECT = "projects/inert-alpha"
BUCKET = "//storage.googleapis.com/projects/_/buckets/inert-alpha"
READER = ORG + "/roles/SyntheticReader"
WRITER = PROJECT + "/roles/SyntheticWriter"
USER = "user:alice@example.test"
SERVICE_ACCOUNT = "serviceAccount:builder@inert-alpha.iam.gserviceaccount.com"
GROUP = "group:readers@example.test"
READ = "storage.objects.get"
WRITE = "storage.objects.create"


def resource(name, kind, parent=None):
    return {"resource_name": name, "kind": kind, "parent_resource_name": parent}


def role(name=READER, permissions=None, *, stage="GA", deleted=False, complete=True):
    return {
        "name": name,
        "included_permissions": [READ] if permissions is None else permissions,
        "stage": stage,
        "deleted": deleted,
        "permissions_complete": complete,
    }


def binding(name=READER, members=None, condition=None):
    return {"role": name, "members": [USER] if members is None else members, "condition": condition}


def policy(name, bindings=None, *, version=1):
    return {
        "resource_name": name,
        "version": version,
        "etag": "synthetic-etag",
        "bindings": [] if bindings is None else bindings,
    }


def condition():
    return {"title": "supplied-condition", "description": "not evaluated", "expression": "true"}


def snapshot():
    rows = [
        resource(ORG, "organization"),
        resource(FOLDER, "folder", ORG),
        resource(PROJECT, "project", FOLDER),
        resource(BUCKET, "resource", PROJECT),
    ]
    return {
        "schema_version": 1,
        "resources": rows,
        "roles": [role()],
        "allow_policies": [policy(row["resource_name"]) for row in rows],
        "coverage": {
            "resource_ancestry_complete": True,
            "allow_policies_complete": True,
            "deny_policies": "none_supplied",
            "principal_access_boundaries": "none_supplied",
        },
    }


def query(
    query_id="query.reader",
    *,
    name=BUCKET,
    permission=READ,
    principal=USER,
    groups=None,
    complete=True,
):
    return {
        "query_id": query_id,
        "resource_name": name,
        "permission": permission,
        "principal": principal,
        "groups": [] if groups is None else groups,
        "group_membership_complete": complete,
    }


def with_binding(model=None, *, at=FOLDER, grant=None):
    model = snapshot() if model is None else model
    selected = next(row for row in model["allow_policies"] if row["resource_name"] == at)
    selected["bindings"].append(binding() if grant is None else grant)
    if selected["bindings"][-1]["condition"] is not None:
        selected["version"] = 3
    return model


def component_fixture():
    """Return only explicit synthetic policies and queries for the closed dispatcher."""
    model = snapshot()
    model["resources"].extend(
        [
            resource("folders/300", "folder", ORG),
            resource("projects/inert-beta", "project", "folders/300"),
        ]
    )
    model["allow_policies"].extend([policy("folders/300"), policy("projects/inert-beta")])
    model["roles"].append(role(WRITER, [WRITE]))
    with_binding(model, grant=binding(members=[GROUP]))
    with_binding(model, at=PROJECT, grant=binding(WRITER, [SERVICE_ACCOUNT], condition()))
    return {
        "snapshot": model,
        "queries": [
            query("inherited-reader", groups=[GROUP]),
            query("sibling-no-grant", name="projects/inert-beta", groups=[GROUP]),
            query("conditional-writer", permission=WRITE, principal=SERVICE_ACCOUNT),
        ],
    }


def _json(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _bytes(value):
    return _json(value).encode("ascii")


def _readdress(document):
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = (
        "sha256:" + hashlib.sha256(module.DOMAIN.encode("ascii") + b"\n" + _bytes(body)).hexdigest()
    )
    return {**body, "analysis_id": "GIA-" + digest[7:39].upper(), "analysis_sha256": digest}


def _native_charge(value):
    if type(value) is str:
        return 2 + 6 * len(value)
    if value is None or type(value) is bool:
        return 7
    if type(value) is int:
        return 22
    if type(value) is list:
        return 2 + sum(_native_charge(child) for child in value)
    return 2 + sum(_native_charge(key) + _native_charge(child) for key, child in value.items())


class GcpIamAnalysisTests(unittest.TestCase):
    def result(self, model=None, queries=None):
        return module.analyze_gcp_iam(
            snapshot() if model is None else model, [query()] if queries is None else queries
        )

    def first(self, model=None, queries=None):
        return self.result(model, queries).to_dict()["results"][0]

    def assert_rejected_before_hash(self, model, queries):
        with patch.object(
            module, "_hash", side_effect=AssertionError("hash must not run")
        ) as hasher:
            with self.assertRaises(module.GcpIamAnalysisError):
                module.analyze_gcp_iam(model, queries)
            hasher.assert_not_called()

    def test_component_fixture_has_real_inheritance_sibling_and_condition_outcomes(self):
        fixture = component_fixture()
        document = self.result(fixture["snapshot"], fixture["queries"]).to_dict()
        outcomes = {row["query_id"]: row["outcome"] for row in document["results"]}
        self.assertEqual(
            outcomes,
            {
                "inherited-reader": "matching_supplied_allow_binding",
                "sibling-no-grant": "no_matching_supplied_allow_binding",
                "conditional-writer": "inconclusive",
            },
        )
        self.assertEqual(
            document["summary"],
            {
                "matching_supplied_allow_binding": 1,
                "no_matching_supplied_allow_binding": 1,
                "inconclusive": 1,
            },
        )

    def test_literal_synthetic_report_and_original_source_identities_are_stable(self):
        fixture = component_fixture()
        document = self.result(fixture["snapshot"], fixture["queries"]).to_dict()
        self.assertEqual(document["analysis_id"], "GIA-F7526094AD3D2F9793BD1EE746C3BCE5")
        self.assertEqual(
            document["analysis_sha256"],
            "sha256:f7526094ad3d2f9793bd1ee746c3bce5848558eeb5895a890ff84190c3105b86",
        )
        self.assertEqual(
            document["snapshot_sha256"],
            "sha256:90ee3f468b38dc265525e972899bda7490b7b9def6c2a7cf1c0554cddda1b8f0",
        )
        self.assertEqual(
            document["queries_sha256"],
            "sha256:413173805dc9503713a734d2b50f9cf0da8e7b24f07af1a6b5ddb28c0dfcd9cc",
        )
        baseline = self.result(with_binding()).to_dict()
        self.assertEqual(baseline["analysis_id"], "GIA-ABD5FE625DC5CBDBE229AA6911C0B743")
        self.assertEqual(
            baseline["analysis_sha256"],
            "sha256:abd5fe625dc5cbdbe229aa6911c0b74388bfe3f8490b8cf2112c1d4dc69ee5fa",
        )
        self.assertEqual(
            baseline["snapshot_sha256"],
            "sha256:f4447e4a08b480d69aa10cc7c34415c4aa4c49c205a4a5f4fa9ae748a2709ec0",
        )
        self.assertEqual(
            baseline["queries_sha256"],
            "sha256:13b508412db2be6388912d05ecf422d145879eaa225c8813836ca5b47efd2c2c",
        )

    def test_folder_allow_is_inherited_with_exact_source_witnesses(self):
        model = with_binding()
        row = self.first(model)
        witness = row["known_allow_witnesses"][0]
        self.assertEqual(row["ancestry"], [ORG, FOLDER, PROJECT, BUCKET])
        self.assertEqual(row["outcome"], "matching_supplied_allow_binding")
        self.assertEqual(witness["policy_resource_name"], FOLDER)
        self.assertEqual(witness["role_name"], READER)
        self.assertEqual(witness["member"], USER)
        self.assertEqual(witness["member_match"], "direct")
        self.assertIs(witness["inherited"], True)
        self.assertEqual(witness["permission"], READ)
        self.assertEqual(
            witness["policy_sha256"],
            module._hash("sunderkey.gcp-iam-allow-policy.v1", model["allow_policies"][1]),
        )
        self.assertEqual(
            witness["binding_sha256"],
            module._hash(
                "sunderkey.gcp-iam-allow-binding.v1", model["allow_policies"][1]["bindings"][0]
            ),
        )
        self.assertEqual(
            witness["role_sha256"], module._hash("sunderkey.gcp-iam-role.v1", model["roles"][0])
        )

    def test_local_binding_is_not_inherited_and_does_not_flow_upward(self):
        model = with_binding(at=BUCKET)
        rows = self.result(model, [query("leaf"), query("parent", name=PROJECT)]).to_dict()[
            "results"
        ]
        leaf, parent = rows
        self.assertEqual(leaf["outcome"], "matching_supplied_allow_binding")
        self.assertIs(leaf["known_allow_witnesses"][0]["inherited"], False)
        self.assertEqual(parent["outcome"], "no_matching_supplied_allow_binding")

    def test_additive_parent_and_local_roles_do_not_intersect_their_permissions(self):
        model = with_binding(at=ORG)
        model["roles"].append(role(WRITER, [WRITE]))
        with_binding(model, at=PROJECT, grant=binding(WRITER))
        document = self.result(model, [query("read"), query("write", permission=WRITE)]).to_dict()
        self.assertEqual(document["summary"]["matching_supplied_allow_binding"], 2)
        self.assertEqual(
            [row["known_allow_witnesses"][0]["role_name"] for row in document["results"]],
            [READER, WRITER],
        )

    def test_conditional_binding_does_not_erase_a_known_unconditional_allow(self):
        model = with_binding()
        with_binding(model, at=PROJECT, grant=binding(condition=condition()))
        row = self.first(model)
        self.assertEqual(row["outcome"], "inconclusive")
        self.assertEqual(row["uncertainty_reasons"], ["condition_unassessed"])
        self.assertEqual(len(row["known_allow_witnesses"]), 1)
        self.assertEqual(row["known_allow_witnesses"][0]["policy_resource_name"], FOLDER)

    def test_group_membership_is_only_the_exact_supplied_active_set(self):
        model = with_binding(grant=binding(members=[GROUP]))
        known = self.first(model, [query(groups=[GROUP])])
        absent = self.first(model)
        unknown = self.first(model, [query(complete=False)])
        self.assertEqual(known["outcome"], "matching_supplied_allow_binding")
        self.assertEqual(known["known_allow_witnesses"][0]["member_match"], "supplied_group")
        self.assertEqual(absent["outcome"], "no_matching_supplied_allow_binding")
        self.assertEqual(unknown["outcome"], "inconclusive")
        self.assertEqual(unknown["uncertainty_reasons"], ["group_membership_incomplete"])

    def test_group_incompleteness_does_not_invent_a_direct_principal_match(self):
        model = with_binding(grant=binding(members=["user:other@example.test"]))
        row = self.first(model, [query(complete=False)])
        self.assertEqual(row["outcome"], "no_matching_supplied_allow_binding")
        self.assertEqual(row["known_allow_witnesses"], [])

    def test_user_and_service_account_names_are_exact_and_not_email_aliases(self):
        for principal, member in (
            (USER, SERVICE_ACCOUNT),
            (SERVICE_ACCOUNT, USER),
            (USER, "user:ALICE@example.test"),
            (USER, "user:alice+alias@example.test"),
        ):
            with self.subTest(principal=principal, member=member):
                row = self.first(
                    with_binding(grant=binding(members=[member])), [query(principal=principal)]
                )
                self.assertEqual(row["outcome"], "no_matching_supplied_allow_binding")
        row = self.first(
            with_binding(grant=binding(members=[SERVICE_ACCOUNT])),
            [query(principal=SERVICE_ACCOUNT)],
        )
        self.assertEqual(row["outcome"], "matching_supplied_allow_binding")

    def test_permissions_are_exact_case_sensitive_names_without_wildcard_inference(self):
        model = with_binding()
        for permission in (WRITE, "storage.objects.Get", "compute.instances.get"):
            with self.subTest(permission=permission):
                self.assertEqual(
                    self.first(model, [query(permission=permission)])["outcome"],
                    "no_matching_supplied_allow_binding",
                )
        for permission in ("*", "storage.*", "storage.objects.*", "storage.objects.g?t"):
            with self.subTest(permission=permission):
                self.assert_rejected_before_hash(model, [query(permission=permission)])
                changed = deepcopy(model)
                changed["roles"][0]["included_permissions"] = [permission]
                self.assert_rejected_before_hash(changed, [query()])

    def test_incomplete_role_permissions_preserve_known_inclusions_but_not_absent_ones(self):
        model = with_binding()
        model["roles"][0]["permissions_complete"] = False
        known = self.first(model)
        absent = self.first(model, [query(permission=WRITE)])
        self.assertEqual(known["outcome"], "matching_supplied_allow_binding")
        self.assertEqual(absent["outcome"], "inconclusive")
        self.assertEqual(absent["uncertainty_reasons"], ["role_permission_coverage_incomplete"])

    def test_version_three_unconditional_binding_still_has_known_allow(self):
        model = with_binding()
        model["allow_policies"][1]["version"] = 3
        self.assertEqual(self.first(model)["outcome"], "matching_supplied_allow_binding")

    def test_conditions_are_not_evaluated_even_when_expression_looks_true(self):
        for expression in ("true", "false", "request.time < timestamp('2099-01-01T00:00:00Z')"):
            with self.subTest(expression=expression):
                declared = condition()
                declared["expression"] = expression
                row = self.first(with_binding(grant=binding(condition=declared)))
                self.assertEqual(row["outcome"], "inconclusive")
                self.assertEqual(row["known_allow_witnesses"], [])
                self.assertEqual(row["uncertainty_reasons"], ["condition_unassessed"])

    def test_explicit_conditions_require_exact_version_three_before_hash(self):
        model = with_binding(grant=binding(condition=condition()))
        for version in (1, 2, 0, True, 3.0):
            with self.subTest(version=version):
                changed = deepcopy(model)
                changed["allow_policies"][1]["version"] = version
                self.assert_rejected_before_hash(changed, [query()])

    def test_withcond_projection_is_guarded_before_even_exact_supplied_role_lookup(self):
        for version in (1, 3):
            for supply_exact in (False, True):
                with self.subTest(version=version, supply_exact=supply_exact):
                    projected = READER + "_withcond_2b17cc25d2cd9e2c54d8"
                    model = with_binding(grant=binding(projected))
                    model["allow_policies"][1]["version"] = version
                    if supply_exact:
                        model["roles"].append(role(projected))
                    row = self.first(model)
                    self.assertEqual(row["outcome"], "inconclusive")
                    self.assertEqual(row["known_allow_witnesses"], [])
                    self.assertEqual(
                        row["uncertainty_reasons"], ["projected_conditional_role_unassessed"]
                    )

    def test_deleted_uid_members_are_never_stripped_into_active_principals(self):
        for member, requested in (
            (USER, query()),
            (SERVICE_ACCOUNT, query(principal=SERVICE_ACCOUNT)),
            (GROUP, query(groups=[GROUP])),
        ):
            with self.subTest(member=member):
                deleted = "deleted:" + member + "?uid=123456789012345678901"
                model = with_binding(grant=binding(members=[deleted]))
                row = self.first(model, [requested])
                self.assertEqual(row["outcome"], "no_matching_supplied_allow_binding")
                self.assertEqual(row["known_allow_witnesses"], [])
                self.assertEqual(
                    self.result(model, [requested]).to_dict()["snapshot"]["allow_policies"][1][
                        "bindings"
                    ][0]["members"],
                    [deleted],
                )

    def test_malformed_deleted_and_unsupported_selectors_are_not_clean_absence(self):
        for member in (
            "deleted:" + USER,
            "deleted:" + USER + "?uid=not-numeric",
            "domain:example.test",
            "allUsers",
            "allAuthenticatedUsers",
            "principal://iam.googleapis.com/locations/global/workforcePools/inert/subject/alice",
            "principalSet://iam.googleapis.com/projects/100/locations/global/workloadIdentityPools/inert/*",
            "serviceaccount:builder@inert-alpha.iam.gserviceaccount.com",
        ):
            with self.subTest(member=member):
                row = self.first(with_binding(grant=binding(members=[member])))
                self.assertEqual(row["outcome"], "inconclusive")
                self.assertEqual(row["known_allow_witnesses"], [])
                self.assertIn("unsupported_member_selector", row["uncertainty_reasons"])

    def test_unsupported_request_principals_do_not_gain_allow_through_groups(self):
        for principal in (
            GROUP,
            "anonymous",
            "deleted:" + USER + "?uid=123",
            "principal://iam.googleapis.com/locations/global/workforcePools/inert/subject/alice",
        ):
            with self.subTest(principal=principal):
                row = self.first(
                    with_binding(grant=binding(members=[GROUP])),
                    [query(principal=principal, groups=[GROUP])],
                )
                self.assertEqual(row["outcome"], "inconclusive")
                self.assertIn("unsupported_query_principal", row["uncertainty_reasons"])
                self.assertEqual(row["known_allow_witnesses"], [])

    def test_disabled_deleted_and_unknown_roles_do_not_claim_active_permissions(self):
        for stage, deleted, outcome in (
            ("DISABLED", False, "no_matching_supplied_allow_binding"),
            ("GA", True, "no_matching_supplied_allow_binding"),
            ("unknown", False, "inconclusive"),
        ):
            with self.subTest(stage=stage, deleted=deleted):
                model = with_binding()
                model["roles"][0].update(stage=stage, deleted=deleted)
                row = self.first(model)
                self.assertEqual(row["outcome"], outcome)
                self.assertEqual(row["known_allow_witnesses"], [])

    def test_supplied_enabled_role_stages_are_not_qualification_results(self):
        for stage in ("ALPHA", "BETA", "GA", "DEPRECATED", "EAP"):
            with self.subTest(stage=stage):
                model = with_binding()
                model["roles"][0]["stage"] = stage
                report = self.result(model).to_dict()
                self.assertEqual(report["results"][0]["outcome"], "matching_supplied_allow_binding")
                self.assertIs(report["qualification_claimed"], False)

    def test_custom_role_owner_must_join_policy_ancestry_not_only_query_ancestry(self):
        model = snapshot()
        model["roles"] = [role(WRITER, [READ])]
        with_binding(model, at=ORG, grant=binding(WRITER))
        row = self.first(model)
        self.assertEqual(row["outcome"], "inconclusive")
        self.assertEqual(row["known_allow_witnesses"], [])
        self.assertIn("custom_role_owner_not_joined", row["uncertainty_reasons"])
        model["allow_policies"][0]["bindings"] = []
        with_binding(model, at=PROJECT, grant=binding(WRITER))
        self.assertEqual(self.first(model)["outcome"], "matching_supplied_allow_binding")

    def test_cross_organization_and_project_custom_roles_are_not_inferred_grantable(self):
        for name in ("organizations/999/roles/Foreign", "projects/inert-beta/roles/Foreign"):
            with self.subTest(name=name):
                model = with_binding(grant=binding(name))
                model["roles"] = [role(name)]
                row = self.first(model)
                self.assertEqual(row["outcome"], "inconclusive")
                self.assertEqual(row["known_allow_witnesses"], [])
                self.assertIn("custom_role_owner_not_joined", row["uncertainty_reasons"])

    def test_predefined_declared_role_uses_exact_permissions_without_custom_owner(self):
        model = with_binding(grant=binding("roles/syntheticReader"))
        model["roles"] = [role("roles/syntheticReader")]
        self.assertEqual(self.first(model)["outcome"], "matching_supplied_allow_binding")

    def test_missing_ancestor_policy_is_unknown_even_when_coverage_claim_is_complete(self):
        model = with_binding()
        model["allow_policies"] = model["allow_policies"][1:]
        row = self.first(model)
        self.assertEqual(row["outcome"], "inconclusive")
        self.assertIn("ancestor_allow_policy_missing", row["uncertainty_reasons"])
        self.assertEqual(len(row["known_allow_witnesses"]), 1)

    def test_empty_ancestor_policies_and_empty_roles_are_declared_no_match_not_denial(self):
        model = snapshot()
        model["roles"] = []
        row = self.first(model)
        self.assertEqual(row["outcome"], "no_matching_supplied_allow_binding")
        self.assertEqual(row["uncertainty_reasons"], [])
        self.assertEqual(row["known_allow_witnesses"], [])

    def test_missing_role_resource_parent_and_dangling_policy_remain_uncertainty(self):
        missing_role = with_binding()
        missing_role["roles"] = []
        self.assertIn("role_definition_missing", self.first(missing_role)["uncertainty_reasons"])
        row = self.first(
            snapshot(), [query(name="//storage.googleapis.com/projects/_/buckets/not-supplied")]
        )
        self.assertIn("resource_or_parent_missing", row["uncertainty_reasons"])
        missing_parent = with_binding(grant=binding("roles/syntheticReader"))
        missing_parent["roles"] = [role("roles/syntheticReader")]
        missing_parent["resources"][1]["parent_resource_name"] = "folders/999"
        row = self.first(missing_parent)
        self.assertIn("resource_or_parent_missing", row["uncertainty_reasons"])
        self.assertEqual(len(row["known_allow_witnesses"]), 1)
        dangling_policy = with_binding()
        dangling_policy["allow_policies"].append(policy("folders/999", [binding()]))
        self.assertIn("policy_resource_missing", self.first(dangling_policy)["uncertainty_reasons"])

    def test_completeness_deny_and_pab_do_not_erase_known_witness_or_claim_effective_access(self):
        for key, value, expected in (
            ("resource_ancestry_complete", False, "resource_ancestry_incomplete"),
            ("allow_policies_complete", False, "allow_policy_coverage_incomplete"),
            ("deny_policies", "present", "deny_policies_not_evaluated"),
            ("deny_policies", "unknown", "deny_policies_not_evaluated"),
            ("principal_access_boundaries", "present", "principal_access_boundaries_not_evaluated"),
            ("principal_access_boundaries", "unknown", "principal_access_boundaries_not_evaluated"),
        ):
            with self.subTest(key=key, value=value):
                model = with_binding()
                model["coverage"][key] = value
                document = self.result(model).to_dict()
                row = document["results"][0]
                self.assertEqual(row["outcome"], "inconclusive")
                self.assertIn(expected, row["uncertainty_reasons"])
                self.assertEqual(len(row["known_allow_witnesses"]), 1)
                self.assertIs(document["effective_access_proven"], False)

    def test_irrelevant_unsupported_member_or_condition_cannot_invent_a_permission(self):
        model = with_binding(grant=binding(members=["allUsers"], condition=condition()))
        row = self.first(model, [query(permission=WRITE)])
        self.assertEqual(row["outcome"], "no_matching_supplied_allow_binding")
        self.assertEqual(row["known_allow_witnesses"], [])

    def test_standalone_project_and_nested_service_resource_are_explicit_ancestry(self):
        model = snapshot()
        model["resources"] = [
            resource(PROJECT, "project"),
            resource(BUCKET, "resource", PROJECT),
            resource("supplied.object", "resource", BUCKET),
        ]
        model["roles"] = [role(WRITER, [READ])]
        model["allow_policies"] = [
            policy(PROJECT, [binding(WRITER)]),
            policy(BUCKET),
            policy("supplied.object"),
        ]
        row = self.first(model, [query(name="supplied.object")])
        self.assertEqual(row["outcome"], "matching_supplied_allow_binding")
        self.assertEqual(row["ancestry"], [PROJECT, BUCKET, "supplied.object"])

    def test_resource_cycles_depth_and_kind_conflicts_reject_before_hash(self):
        cyclic = snapshot()
        cyclic["resources"][1]["parent_resource_name"] = "folders/201"
        cyclic["resources"].append(resource("folders/201", "folder", FOLDER))
        self.assert_rejected_before_hash(cyclic, [query()])
        for index, parent in ((0, PROJECT), (1, BUCKET), (2, BUCKET), (3, ORG)):
            with self.subTest(index=index, parent=parent):
                model = snapshot()
                model["resources"][index]["parent_resource_name"] = parent
                self.assert_rejected_before_hash(model, [query()])
        model = snapshot()
        model["resources"][3]["resource_name"] = "projects/imposter"
        self.assert_rejected_before_hash(model, [query()])

    def test_duplicate_native_source_identity_and_query_rows_reject_before_hash(self):
        for key in ("resources", "roles", "allow_policies"):
            with self.subTest(key=key):
                model = with_binding()
                model[key].append(deepcopy(model[key][0]))
                self.assert_rejected_before_hash(model, [query()])
        model = with_binding()
        model["allow_policies"][1]["bindings"].append(binding())
        self.assert_rejected_before_hash(model, [query()])
        model = with_binding(grant=binding(members=[USER, USER]))
        self.assert_rejected_before_hash(model, [query()])
        model = with_binding()
        model["roles"][0]["included_permissions"].append(READ)
        self.assert_rejected_before_hash(model, [query()])
        self.assert_rejected_before_hash(snapshot(), [query(), query()])
        self.assert_rejected_before_hash(snapshot(), [query(groups=[GROUP, GROUP])])

    def test_all_native_aliases_unknown_fields_and_missing_fields_reject_before_hash(self):
        for schema in (True, False, 1.0, "1"):
            with self.subTest(schema=schema):
                model = snapshot()
                model["schema_version"] = schema
                self.assert_rejected_before_hash(model, [query()])
        for alias in (1, 0, 1.0, "true", None):
            with self.subTest(alias=alias):
                model = snapshot()
                model["roles"][0]["deleted"] = alias
                self.assert_rejected_before_hash(model, [query()])
                model = snapshot()
                model["coverage"]["allow_policies_complete"] = alias
                self.assert_rejected_before_hash(model, [query()])
                self.assert_rejected_before_hash(snapshot(), [query(complete=alias)])
        for key in ("roles", "coverage", "schema_version"):
            model = snapshot()
            del model[key]
            self.assert_rejected_before_hash(model, [query()])
        model = snapshot()
        model["extra"] = "unsupported"
        self.assert_rejected_before_hash(model, [query()])

    def test_native_subclasses_are_not_normalized_before_preflight(self):
        class Text(str):
            def __str__(self):
                raise AssertionError("conversion hook must not run")

        class Integer(int):
            def __int__(self):
                raise AssertionError("conversion hook must not run")

        class Dictionary(dict):
            def items(self):
                raise AssertionError("mapping hook must not run")

        class Sequence(list):
            def __iter__(self):
                raise AssertionError("iteration hook must not run")

        for value in (Text(USER), Integer(1), Dictionary(snapshot()), Sequence([query()])):
            with self.subTest(kind=type(value).__name__):
                if type(value) in (Dictionary, Sequence):
                    self.assert_rejected_before_hash(
                        value if type(value) is Dictionary else snapshot(),
                        value if type(value) is Sequence else [query()],
                    )
                else:
                    model = snapshot()
                    model["schema_version" if type(value) is Integer else "extra"] = value
                    self.assert_rejected_before_hash(model, [query()])
        model = snapshot()
        model[Text("schema_version")] = model.pop("schema_version")
        self.assert_rejected_before_hash(model, [query()])

    def test_native_tree_cycles_repeated_subtrees_and_final_scalar_charges_are_bounded(self):
        cycle = []
        cycle.append(cycle)
        model = snapshot()
        model["extra"] = cycle
        self.assert_rejected_before_hash(model, [query()])
        shared = [True]
        with patch.object(module, "MAX_NODES", 5):
            self.assertEqual(module._capture([shared, shared]), [[True], [True]])
        with patch.object(module, "MAX_NODES", 4):
            with self.assertRaises(module.GcpIamAnalysisError):
                module._capture([shared, shared])
        for value, cost in ((None, 7), (True, 7), (0, 22), ("", 2), ('"\\', 14)):
            with self.subTest(value=value):
                with patch.object(module, "MAX_JSON_BYTES", cost):
                    self.assertEqual(module._capture(value), value)
                with patch.object(module, "MAX_JSON_BYTES", cost - 1):
                    with self.assertRaises(module.GcpIamAnalysisError):
                        module._capture(value)

    def test_large_integer_text_non_ascii_and_escaped_text_fail_before_hash(self):
        for value in (2**100000, "x" * (module.MAX_TEXT + 1), "\ud800", "caf\u00e9"):
            with self.subTest(kind=type(value).__name__):
                model = snapshot()
                model["extra"] = value
                self.assert_rejected_before_hash(model, [query()])
        model = snapshot()
        model["extra"] = '"\\' * 300
        with patch.object(module, "MAX_JSON_BYTES", 1000):
            self.assert_rejected_before_hash(model, [query()])

    def test_duplicate_key_float_nonfinite_and_oversize_byte_inputs_are_closed(self):
        normal = _bytes(snapshot())
        for raw in (
            b'{"schema_version":1,"schema_version":1}',
            b'{"nested":{"x":1,"x":2}}',
            b'{"schema_version":1.0}',
            b'{"schema_version":NaN}',
            b'{"schema_version":Infinity}',
            b'{"schema_version":' + b"9" * 1000 + b"}",
            b'"\\ud800"',
            b"\xff",
            b"",
            bytearray(normal),
        ):
            with self.subTest(raw_type=type(raw).__name__, sample=repr(raw[:50])):
                with self.assertRaises(module.GcpIamAnalysisError):
                    module.analyze_gcp_iam_bytes(
                        snapshot_bytes=raw, queries_bytes=_bytes([query()])
                    )
        with (
            patch.object(module, "MAX_JSON_BYTES", 8),
            patch.object(module.json, "loads", side_effect=AssertionError("decoder must not run")),
        ):
            with self.assertRaises(module.GcpIamAnalysisError):
                module.analyze_gcp_iam_bytes(snapshot_bytes=normal, queries_bytes=b"[]")

    def test_byte_depth_is_checked_before_json_decoder_and_native_depth_before_hash(self):
        raw = b"[" * (module.MAX_DEPTH + 1) + b"0" + b"]" * (module.MAX_DEPTH + 1)
        with patch.object(module.json, "loads", side_effect=AssertionError("decoder must not run")):
            with self.assertRaises(module.GcpIamAnalysisError):
                module.analyze_gcp_iam_bytes(snapshot_bytes=raw, queries_bytes=b"[]")
        deep = 0
        for _ in range(module.MAX_DEPTH + 1):
            deep = [deep]
        model = snapshot()
        model["extra"] = deep
        self.assert_rejected_before_hash(model, [query()])

    def test_raw_node_value_and_escape_budgets_reject_before_decoder_or_hash(self):
        samples = (
            ("MAX_NODES", 2, b"[0,0]"),
            ("MAX_TEXT", 2, b'"abc"'),
            ("MAX_TEXT", 2, b'"\\u0061\\u0062\\u0063"'),
            ("MAX_JSON_BYTES", 7, b'"ab"'),
            ("MAX_JSON_BYTES", 6, b"false"),
            ("MAX_JSON_BYTES", 21, b"0"),
        )
        for name, bound, raw in samples:
            with self.subTest(name=name, raw=raw):
                with (
                    patch.object(module, name, bound),
                    patch.object(
                        module.json, "loads", side_effect=AssertionError("decoder must not run")
                    ) as decoder,
                    patch.object(
                        module, "_hash", side_effect=AssertionError("hash must not run")
                    ) as hasher,
                ):
                    with self.assertRaises(module.GcpIamAnalysisError):
                        module.analyze_gcp_iam_bytes(snapshot_bytes=raw, queries_bytes=b"[]")
                    decoder.assert_not_called()
                    hasher.assert_not_called()
        with patch.object(module, "MAX_NODES", 3):
            self.assertEqual(module._parse_bytes(b"[0,0]"), [0, 0])
        with patch.object(module, "MAX_TEXT", 2):
            self.assertEqual(module._parse_bytes(b'"\\u0061\\u0062"'), "ab")

    def test_signed64_overflow_rejects_in_preflight_and_decoder_integer_callback(self):
        for raw in (b"9223372036854775808", b"-9223372036854775809", b"9" * 1000):
            with self.subTest(raw=raw[:30]):
                with patch.object(
                    module.json, "loads", side_effect=AssertionError("decoder must not run")
                ) as decoder:
                    with self.assertRaises(module.GcpIamAnalysisError):
                        module._parse_bytes(raw)
                    decoder.assert_not_called()
        actual_loads = json.loads
        callbacks = []

        def observe(text, **kwargs):
            callbacks.append(kwargs["parse_int"])
            return actual_loads(text, **kwargs)

        with patch.object(module.json, "loads", side_effect=observe):
            self.assertEqual(
                module._parse_bytes(b"[-9223372036854775808,9223372036854775807]"),
                [-(2**63), 2**63 - 1],
            )
        self.assertEqual(len(callbacks), 1)
        for value in ("9223372036854775808", "-9223372036854775809", "9" * 1000):
            with self.subTest(value=value[:30]):
                with self.assertRaises(module.GcpIamAnalysisError):
                    callbacks[0](value)

    def test_full_query_capacity_and_one_extra_are_exact(self):
        model = snapshot()
        rows = [query(f"query.{index:03d}") for index in range(module.MAX_QUERIES)]
        report = self.result(model, rows).to_dict()
        self.assertEqual(len(report["results"]), module.MAX_QUERIES)
        self.assertEqual(
            report["summary"]["no_matching_supplied_allow_binding"], module.MAX_QUERIES
        )
        rows.append(query("query.extra"))
        self.assert_rejected_before_hash(model, rows)

    def test_full_resource_and_policy_capacity_preserves_declared_empty_policies(self):
        model = snapshot()
        model["resources"] = [resource(ORG, "organization")] + [
            resource(f"projects/inert-{index}", "project", ORG)
            for index in range(module.MAX_RESOURCES - 1)
        ]
        model["allow_policies"] = [policy(row["resource_name"]) for row in model["resources"]]
        model["roles"] = []
        self.assertEqual(
            self.first(model, [query(name="projects/inert-0")])["outcome"],
            "no_matching_supplied_allow_binding",
        )
        model["resources"].append(resource("projects/extra", "project", ORG))
        self.assert_rejected_before_hash(model, [query()])

    def test_exact_maximum_ancestry_and_one_more_are_bounded(self):
        model = snapshot()
        rows = [resource(ORG, "organization")]
        for index in range(module.MAX_ANCESTRY - 1):
            rows.append(resource(f"folders/{1000 + index}", "folder", rows[-1]["resource_name"]))
        model["resources"] = rows
        model["allow_policies"] = [policy(row["resource_name"]) for row in rows]
        model["roles"] = []
        requested = query(name=rows[-1]["resource_name"], permission="resourcemanager.folders.get")
        self.assertEqual(len(self.first(model, [requested])["ancestry"]), module.MAX_ANCESTRY)
        model["resources"].append(resource("folders/9999", "folder", rows[-1]["resource_name"]))
        self.assert_rejected_before_hash(model, [requested])

    def test_member_and_role_permission_aggregate_budgets_are_not_per_binding_only(self):
        model = with_binding(
            grant=binding(
                members=[
                    f"user:user{index}@example.test"
                    for index in range(module.MAX_MEMBER_APPEARANCES)
                ]
            )
        )
        self.assertEqual(self.first(model)["outcome"], "no_matching_supplied_allow_binding")
        with_binding(model, at=PROJECT, grant=binding(members=[USER]))
        self.assert_rejected_before_hash(model, [query()])
        model = snapshot()
        model["roles"][0]["included_permissions"] = [
            f"synthetic.objects.read{index}" for index in range(module.MAX_PERMISSION_ENTRIES)
        ]
        self.assertEqual(self.first(model)["outcome"], "no_matching_supplied_allow_binding")
        model["roles"].append(role("roles/extra", [READ]))
        self.assert_rejected_before_hash(model, [query()])

    def test_matching_work_and_witness_expansion_fail_closed_before_report_hash(self):
        model = with_binding()
        original_hash = module._hash
        for name, value, rows in (
            ("MAX_MATCH_WORK", 0, [query()]),
            ("MAX_WITNESSES", 1, [query("q1"), query("q2")]),
        ):
            with self.subTest(name=name):
                domains = []

                def observe(domain, body):
                    domains.append(domain)
                    return original_hash(domain, body)

                with (
                    patch.object(module, name, value),
                    patch.object(module, "_hash", side_effect=observe),
                ):
                    with self.assertRaises(module.GcpIamAnalysisError):
                        self.result(model, rows)
                self.assertNotIn(module.DOMAIN, domains)
        with patch.object(module, "MAX_WITNESSES", 1):
            self.assertEqual(len(self.first(model)["known_allow_witnesses"]), 1)

    def test_complete_output_budget_is_checked_before_report_serialization_hash(self):
        model = {
            "schema_version": 1,
            "resources": [],
            "roles": [],
            "allow_policies": [],
            "coverage": snapshot()["coverage"],
        }
        source_cost = _native_charge({"snapshot": model, "queries": []})
        domains = []
        original_hash = module._hash

        def observe(domain, body):
            domains.append(domain)
            return original_hash(domain, body)

        with (
            patch.object(module, "MAX_JSON_BYTES", source_cost + 100),
            patch.object(module, "_hash", side_effect=observe),
        ):
            with self.assertRaises(module.GcpIamAnalysisError):
                module.analyze_gcp_iam(model, [])
        self.assertNotIn(module.DOMAIN, domains)

    def test_canonical_round_trips_bytes_repeat_and_detached_outputs_preserve_sources(self):
        model = with_binding()
        rows = [query()]
        saved_model, saved_rows = deepcopy(model), deepcopy(rows)
        report = self.result(model, rows)
        canonical = report.to_json()
        self.assertEqual(self.result(model, rows).to_json(), canonical)
        self.assertEqual(module.GcpIamAnalysis.from_dict(report.to_dict()).to_json(), canonical)
        self.assertEqual(
            module.GcpIamAnalysis.from_json(canonical.encode("ascii")).to_json(), canonical
        )
        self.assertEqual(
            module.analyze_gcp_iam_bytes(
                snapshot_bytes=_bytes(model), queries_bytes=_bytes(rows)
            ).to_json(),
            canonical,
        )
        self.assertEqual(
            module.analyze_gcp_iam_bytes(
                snapshot_bytes=json.dumps(model, indent=2).encode("ascii"),
                queries_bytes=_bytes(rows),
            ).to_json(),
            canonical,
        )
        self.assertEqual(
            module.verify_gcp_iam_analysis(report, snapshot=model, queries=rows).to_json(),
            canonical,
        )
        self.assertEqual((model, rows), (saved_model, saved_rows))
        model["roles"][0]["included_permissions"].append(WRITE)
        rows[0]["principal"] = SERVICE_ACCOUNT
        exported = report.to_dict()
        exported["effects"]["authority"] = "approved"
        exported["snapshot"]["roles"][0]["included_permissions"] = []
        self.assertEqual(report.to_json(), canonical)
        with self.assertRaises(FrozenInstanceError):
            report.document_json = "{}"

    def test_source_order_is_bound_but_semantic_query_and_witness_order_is_deterministic(self):
        model = with_binding()
        with_binding(model, at=PROJECT)
        rows = [query("second"), query("first")]
        original = self.result(model, rows)
        permuted_model, permuted_rows = deepcopy(model), list(reversed(rows))
        for key in ("resources", "roles", "allow_policies"):
            permuted_model[key].reverse()
        permuted = self.result(permuted_model, permuted_rows)
        self.assertEqual(original.to_dict()["results"], permuted.to_dict()["results"])
        self.assertNotEqual(
            original.to_dict()["snapshot_sha256"], permuted.to_dict()["snapshot_sha256"]
        )
        with self.assertRaises(module.GcpIamAnalysisError):
            module.verify_gcp_iam_analysis(original, snapshot=permuted_model, queries=permuted_rows)

    def test_cohashed_false_grant_omission_effect_or_summary_is_not_embedded_replay(self):
        report = self.result().to_dict()
        mutations = []
        false_grant = deepcopy(report)
        false_grant["results"][0]["outcome"] = "matching_supplied_allow_binding"
        mutations.append(false_grant)
        omitted = deepcopy(report)
        omitted["results"] = []
        mutations.append(omitted)
        changed = deepcopy(report)
        changed["effects"]["authority"] = "approved"
        mutations.append(changed)
        changed = deepcopy(report)
        changed["summary"]["no_matching_supplied_allow_binding"] = 0
        mutations.append(changed)
        changed = deepcopy(report)
        changed["snapshot_sha256"] = "sha256:" + "a" * 64
        mutations.append(changed)
        for document in mutations:
            with self.subTest(changed=document):
                rehashed = _readdress(document)
                with self.assertRaises(module.GcpIamAnalysisError):
                    module.GcpIamAnalysis.from_dict(rehashed)
                with self.assertRaises(module.GcpIamAnalysisError):
                    module.GcpIamAnalysis.from_json(_bytes(rehashed))

    def test_valid_changed_embedded_model_cannot_bind_separately_original_sources(self):
        original = snapshot()
        changed = with_binding(deepcopy(original))
        legitimate_other = self.result(changed)
        self.assertEqual(
            legitimate_other.to_dict()["results"][0]["outcome"], "matching_supplied_allow_binding"
        )
        module.GcpIamAnalysis.from_dict(legitimate_other.to_dict())
        for report in (legitimate_other, legitimate_other.to_dict()):
            with self.subTest(kind=type(report).__name__):
                with self.assertRaises(module.GcpIamAnalysisError):
                    module.verify_gcp_iam_analysis(report, snapshot=original, queries=[query()])

    def test_cohashed_aliases_schema_flags_counts_and_nested_queries_do_not_replay(self):
        report = self.result(with_binding()).to_dict()
        for field, alias in (
            ("schema_version", True),
            ("offline_only", 1),
            ("effective_access_proven", 0),
            ("qualification_claimed", 0.0),
        ):
            with self.subTest(field=field, alias=alias):
                changed = deepcopy(report)
                changed[field] = alias
                with self.assertRaises(module.GcpIamAnalysisError):
                    module.GcpIamAnalysis.from_dict(_readdress(changed))
        for alias in (True, 1.0):
            changed = deepcopy(report)
            changed["summary"]["matching_supplied_allow_binding"] = alias
            with self.assertRaises(module.GcpIamAnalysisError):
                module.GcpIamAnalysis.from_dict(_readdress(changed))
        changed = deepcopy(report)
        changed["queries"][0]["group_membership_complete"] = 1
        with self.assertRaises(module.GcpIamAnalysisError):
            module.GcpIamAnalysis.from_dict(_readdress(changed))

    def test_forged_missing_late_changed_and_subclass_wrappers_do_not_gain_export(self):
        report = self.result(with_binding())
        document = report.to_dict()
        document["results"][0]["known_allow_witnesses"] = []
        object.__setattr__(report, "document_json", _json(_readdress(document)))
        for call in (
            report.to_dict,
            report.to_json,
            lambda: report.analysis_id,
            lambda: report.analysis_sha256,
        ):
            with self.assertRaises(module.GcpIamAnalysisError):
                call()
        missing = object.__new__(module.GcpIamAnalysis)
        with self.assertRaises(module.GcpIamAnalysisError):
            missing.to_dict()

        class Subclass(module.GcpIamAnalysis):
            pass

        valid = self.result()
        subclass = Subclass(valid.document_json)
        with self.assertRaises(module.GcpIamAnalysisError):
            module.verify_gcp_iam_analysis(subclass, snapshot=snapshot(), queries=[query()])

    def test_record_constructor_is_canonical_and_json_report_parser_is_duplicate_safe(self):
        report = self.result()
        with self.assertRaises(module.GcpIamAnalysisError):
            module.GcpIamAnalysis(json.dumps(report.to_dict(), indent=2))
        raw = report.to_json().encode("ascii")
        for changed in (
            b'{"schema_version":1,' + raw[1:],
            raw.replace(
                b'"effective_access_proven":false',
                b'"effective_access_proven":false,"effective_access_proven":false',
            ),
        ):
            with self.assertRaises(module.GcpIamAnalysisError):
                module.GcpIamAnalysis.from_json(changed)

    def test_fixed_lane_limits_effects_and_imports_never_claim_provider_qualification(self):
        document = self.result(with_binding()).to_dict()
        self.assertEqual(document["profile_id"], "AOE-GC-D14-S06")
        self.assertEqual(document["capability_id"], "army.gc.d14.s06")
        self.assertEqual(document["vector_id"], "AV-GC-D14-S06-01")
        self.assertEqual(document["wave_id"], "IW2-009")
        self.assertEqual(document["blueprint_sha256"], module.BLUEPRINT_SHA256)
        self.assertEqual(document["source_provenance"], "canonical_parsed_json_not_raw_bytes")
        self.assertEqual(document["input_provenance"], "operator_supplied_unverified")
        self.assertEqual(set(document["effects"].values()), {"none"})
        for field in (
            "effective_access_proven",
            "policy_safety_proven",
            "live_use_approved",
            "qualification_claimed",
        ):
            self.assertIs(document[field], False)
        source = Path(module.__file__).read_text(encoding="ascii")
        parsed = ast.parse(source)
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(parsed)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported.update(
            node.module.split(".")[0]
            for node in ast.walk(parsed)
            if isinstance(node, ast.ImportFrom) and node.module
        )
        self.assertEqual(imported, {"__future__", "hashlib", "json", "re", "dataclasses", "typing"})
        self.assertNotIn("open(", source)


if __name__ == "__main__":
    unittest.main()
