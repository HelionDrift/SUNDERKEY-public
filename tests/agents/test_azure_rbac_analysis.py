"""Synthetic Azure role semantics, not effective permission or qualification evidence."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from dataclasses import FrozenInstanceError
from unittest.mock import patch

from sunderkey import azure_rbac_analysis as rbac

TENANT = "tenant:synthetic"
SUB = "/subscriptions/sub-one"
GROUP = SUB + "/resourceGroups/workloads"
RESOURCE = GROUP + "/providers/Microsoft.Storage/storageAccounts/one"
OPERATION = "Microsoft.Storage/storageAccounts/read"
DATA_OPERATION = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"
MANAGEMENT = "/providers/Microsoft.Management/managementGroups/synthetic"


def scope(scope_id, kind, parent=None):
    return {"scope_id": scope_id, "kind": kind, "parent_scope_id": parent}


def permission(
    actions=None,
    *,
    not_actions=None,
    data_actions=None,
    not_data_actions=None,
    condition=None,
    condition_version=None,
):
    return {
        "actions": ["Microsoft.Storage/*/read"] if actions is None else actions,
        "not_actions": [] if not_actions is None else not_actions,
        "data_actions": [] if data_actions is None else data_actions,
        "not_data_actions": [] if not_data_actions is None else not_data_actions,
        "condition": condition,
        "condition_version": condition_version,
    }


def role(role_id="role:reader", *, permissions=None, available=None, kind="custom"):
    return {
        "role_definition_id": role_id,
        "role_type": kind,
        "assignable_scopes": [SUB] if available is None else available,
        "permissions": [permission()] if permissions is None else permissions,
    }


def assignment(
    assignment_id="assignment:reader",
    *,
    role_id="role:reader",
    principal="principal:alice",
    scope_id=SUB,
    **changes,
):
    value = {
        "assignment_id": assignment_id,
        "tenant_id": TENANT,
        "principal_id": principal,
        "role_definition_id": role_id,
        "scope_id": scope_id,
        "state": "active",
        "condition": None,
        "condition_version": None,
    }
    value.update(changes)
    return value


def snapshot():
    return {
        "schema_version": 1,
        "tenant_id": TENANT,
        "scopes": [
            scope(SUB, "subscription"),
            scope(GROUP, "resource_group", SUB),
            scope(RESOURCE, "resource", GROUP),
        ],
        "role_definitions": [role()],
        "role_assignments": [assignment()],
        "coverage": {
            "role_assignments_complete": True,
            "scope_ancestry_complete": True,
            "deny_assignments": "none_supplied",
        },
    }


def query(query_id="read-account", **changes):
    value = {
        "query_id": query_id,
        "tenant_id": TENANT,
        "principal_id": "principal:alice",
        "group_ids": [],
        "group_membership_complete": True,
        "scope_id": RESOURCE,
        "operation": OPERATION,
        "plane": "control",
    }
    value.update(changes)
    return value


def component_fixture():
    """Public inert fixture with regrant, data-plane separation and a sibling scope."""
    model = snapshot()
    model["role_definitions"][0]["permissions"][0]["not_actions"] = [OPERATION]
    model["role_definitions"].append(role("role:explicit", permissions=[permission([OPERATION])]))
    model["role_assignments"].append(
        assignment("assignment:explicit", role_id="role:explicit", scope_id=GROUP)
    )
    sibling = SUB + "/resourceGroups/sibling"
    sibling_resource = sibling + "/providers/Microsoft.Storage/storageAccounts/two"
    model["scopes"].extend(
        [scope(sibling, "resource_group", SUB), scope(sibling_resource, "resource", sibling)]
    )
    return {
        "snapshot": model,
        "queries": [
            query("control-regrant"),
            query("data-is-separate", operation=DATA_OPERATION, plane="data"),
            query("sibling-no-grant", scope_id=sibling_resource),
        ],
    }


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def readdress(document):
    value = copy.deepcopy(document)
    body = {
        key: item for key, item in value.items() if key not in ("analysis_id", "analysis_sha256")
    }
    digest = (
        "sha256:" + hashlib.sha256(b"sunderkey.azure-rbac-analysis.v1\n" + encode(body)).hexdigest()
    )
    value.update(analysis_id="ARA-" + digest[7:39].upper(), analysis_sha256=digest)
    return value


class NativeStringAlias(str):
    pass


class NativeIntegerAlias(int):
    pass


class NativeListAlias(list):
    def __iter__(self):
        raise AssertionError("Caller iteration hook reached")


class NativeDictAlias(dict):
    def items(self):
        raise AssertionError("Caller mapping hook reached")


class NativeBytesAlias(bytes):
    pass


class AzureRbacAnalysisTests(unittest.TestCase):
    def result(self, model=None, request=None):
        return rbac.analyze_azure_rbac(
            snapshot() if model is None else model,
            [query() if request is None else request],
        ).to_dict()["results"][0]

    def assert_sources_reject(self, model, requests=None):
        with self.assertRaises(rbac.AzureRbacAnalysisError):
            rbac.analyze_azure_rbac(model, [query()] if requests is None else requests)

    def assert_report_rejects(self, document):
        for parser in (
            rbac.AzureRbacAnalysis.from_dict,
            lambda item: rbac.AzureRbacAnalysis.from_json(encode(item)),
            lambda item: rbac.AzureRbacAnalysis(encode(item).decode("ascii")),
            lambda item: rbac.verify_azure_rbac_analysis(
                item, snapshot=snapshot(), queries=[query()]
            ),
        ):
            with self.subTest(parser=parser), self.assertRaises(rbac.AzureRbacAnalysisError):
                parser(document)

    def test_valid_baseline_is_detached_deterministic_and_nonauthorizing(self):
        model, requests = snapshot(), [query()]
        record = rbac.analyze_azure_rbac(model, requests)
        body = record.to_dict()
        self.assertEqual(record.to_json(), rbac.analyze_azure_rbac(model, requests).to_json())
        self.assertEqual(body["results"][0]["outcome"], "matching_supplied_role_grant")
        self.assertEqual(body["results"][0]["uncertainty_reasons"], [])
        witness = body["results"][0]["known_grant_witnesses"][0]
        self.assertEqual(witness["scope_path"], [SUB, GROUP, RESOURCE])
        self.assertEqual(witness["principal_match"], "direct")
        self.assertEqual(
            body["summary"],
            {
                "matching_supplied_role_grant": 1,
                "no_matching_supplied_role_grant": 0,
                "inconclusive": 0,
            },
        )
        self.assertEqual(body["input_provenance"], "operator_supplied_unverified")
        self.assertEqual(body["source_digest_basis"], "canonical_parsed_json")
        self.assertFalse(body["effective_access_verified"])
        self.assertFalse(body["qualification_claimed"])
        self.assertEqual(set(body["effects"].values()), {"none"})
        self.assertEqual(body["profile_id"], "AOE-GC-D14-S04")
        self.assertEqual(body["wave_id"], "IW2-007")

    def test_all_public_roundtrips_repeat_exact_embedded_and_original_sources(self):
        model, requests = snapshot(), [query()]
        record = rbac.analyze_azure_rbac(model, requests)
        for other in (
            rbac.AzureRbacAnalysis.from_dict(record.to_dict()),
            rbac.AzureRbacAnalysis.from_json(record.to_json().encode("ascii")),
            rbac.AzureRbacAnalysis(record.to_json()),
            rbac.analyze_azure_rbac_bytes(
                snapshot_bytes=encode(model), queries_bytes=encode(requests)
            ),
            rbac.verify_azure_rbac_analysis(record, snapshot=model, queries=requests),
            rbac.verify_azure_rbac_analysis(record.to_dict(), snapshot=model, queries=requests),
        ):
            self.assertEqual(other.to_json(), record.to_json())

    def test_fixed_valid_fixture_addresses_are_preserved(self):
        report = rbac.analyze_azure_rbac(snapshot(), [query()]).to_dict()
        self.assertEqual(report["analysis_id"], "ARA-403FE484C9147CB55DFAF4EE94ED93AB")
        self.assertEqual(
            report["analysis_sha256"],
            "sha256:403fe484c9147cb55dfaf4ee94ed93abeaef5858995751a30fdb8cdba18aa8f1",
        )
        self.assertEqual(
            report["snapshot_sha256"],
            "sha256:ef1c98404f12abeec65863d44dda3e5ccaea325d77153eeb680e08b79e37cf7d",
        )
        self.assertEqual(
            report["queries_sha256"],
            "sha256:4c9123e98712b5b4cbcec803decfd93bba1d9b7e340957c32e7becf8e45e54cd",
        )
        result = report["results"][0]
        self.assertEqual(
            result["query_sha256"],
            "sha256:1cb8e85eb55e507368f69f1abd3871fe2c5d449d0980a4ef31ef6439d5522c31",
        )
        self.assertEqual(
            result["known_grant_witnesses"][0]["permission_sha256"],
            "sha256:735c15efcc85bd7f0957f7104a011c199c6894e37028e886c6857102c56ecdce",
        )

    def test_component_fixture_proves_regrant_plane_separation_and_sibling_isolation(self):
        payload = component_fixture()
        report = rbac.analyze_azure_rbac(payload["snapshot"], payload["queries"]).to_dict()
        self.assertEqual(
            [(result["query_id"], result["outcome"]) for result in report["results"]],
            [
                ("control-regrant", "matching_supplied_role_grant"),
                ("data-is-separate", "no_matching_supplied_role_grant"),
                ("sibling-no-grant", "no_matching_supplied_role_grant"),
            ],
        )
        self.assertTrue(all(not result["uncertainty_reasons"] for result in report["results"]))

    def test_control_exclusion_removes_a_matching_role_permission(self):
        model = snapshot()
        model["role_definitions"][0]["permissions"] = [permission(["*"], not_actions=[OPERATION])]
        body = self.result(model)
        self.assertEqual(body["outcome"], "no_matching_supplied_role_grant")
        self.assertEqual(body["known_grant_witnesses"], [])

    def test_second_role_regrants_a_first_role_exclusion(self):
        model = snapshot()
        model["role_definitions"][0]["permissions"] = [permission(["*"], not_actions=[OPERATION])]
        model["role_definitions"].append(
            role("role:explicit", permissions=[permission([OPERATION])])
        )
        model["role_assignments"].append(assignment("assignment:explicit", role_id="role:explicit"))
        body = self.result(model)
        self.assertEqual(body["outcome"], "matching_supplied_role_grant")
        self.assertEqual(
            [item["role_definition_id"] for item in body["known_grant_witnesses"]],
            ["role:explicit"],
        )

    def test_multiple_permission_blocks_do_not_invent_same_role_regrant_semantics(self):
        model = snapshot()
        model["role_definitions"][0]["permissions"] = [
            permission(["*"], not_actions=[OPERATION]),
            permission([OPERATION]),
        ]
        result = self.result(model)
        self.assertEqual(result["outcome"], "inconclusive")
        self.assertEqual(result["known_grant_witnesses"], [])
        self.assertIn("unsupported_multiple_permission_blocks", result["uncertainty_reasons"])

    def test_data_permissions_never_come_from_control_wildcards(self):
        model = snapshot()
        model["role_definitions"][0]["permissions"] = [permission(["*"])]
        self.assertEqual(
            self.result(model, query(operation=DATA_OPERATION, plane="data"))["outcome"],
            "no_matching_supplied_role_grant",
        )

    def test_data_actions_and_not_data_actions_are_separate_subtraction(self):
        model = snapshot()
        block = permission(
            [], data_actions=["Microsoft.Storage/*/read"], not_data_actions=[DATA_OPERATION]
        )
        model["role_definitions"][0]["permissions"] = [block]
        self.assertEqual(
            self.result(model, query(operation=DATA_OPERATION, plane="data"))["outcome"],
            "no_matching_supplied_role_grant",
        )
        block["not_data_actions"] = []
        self.assertEqual(
            self.result(model, query(operation=DATA_OPERATION, plane="data"))["outcome"],
            "matching_supplied_role_grant",
        )
        self.assertEqual(
            self.result(model, query(operation=DATA_OPERATION))["outcome"],
            "no_matching_supplied_role_grant",
        )

    def test_control_exclusions_do_not_subtract_data_permissions(self):
        model = snapshot()
        model["role_definitions"][0]["permissions"] = [
            permission(["*"], not_actions=["*"], data_actions=[DATA_OPERATION])
        ]
        self.assertEqual(
            self.result(model, query(operation=DATA_OPERATION, plane="data"))["outcome"],
            "matching_supplied_role_grant",
        )

    def test_case_insensitive_wildcard_matches_finite_explicit_operations(self):
        for pattern in (
            "*",
            "microsoft.storage/*/READ",
            "Microsoft.Storage/storageAccounts/*",
            "*/read",
        ):
            with self.subTest(pattern=pattern):
                model = snapshot()
                model["role_definitions"][0]["permissions"] = [permission([pattern])]
                self.assertEqual(
                    self.result(model, query(operation=OPERATION.upper()))["outcome"],
                    "matching_supplied_role_grant",
                )
        for pattern in ("Microsoft.Compute/*/read", "Microsoft.Storage/*/write", OPERATION + "x"):
            with self.subTest(pattern=pattern):
                model = snapshot()
                model["role_definitions"][0]["permissions"] = [permission([pattern])]
                self.assertEqual(self.result(model)["outcome"], "no_matching_supplied_role_grant")

    def test_prefix_suffix_wildcard_requires_nonoverlapping_full_match(self):
        budget = rbac._Budget()
        for pattern, value, expected in (
            ("ab*bc", "abc", False),
            ("ab*bc", "abbc", True),
            ("*", "*internal", True),
            ("a*b", "a?b", True),
        ):
            self.assertIs(rbac._matches(pattern, value, budget), expected)

    def test_subscription_grants_do_not_escape_to_siblings_or_prefix_collisions(self):
        for other_sub in ("/subscriptions/sub-one-extra", "/subscriptions/sub-two"):
            with self.subTest(scope=other_sub):
                model = snapshot()
                other_group = other_sub + "/resourceGroups/workloads"
                other_resource = other_group + "/providers/Microsoft.Storage/storageAccounts/one"
                model["scopes"].extend(
                    [
                        scope(other_sub, "subscription"),
                        scope(other_group, "resource_group", other_sub),
                        scope(other_resource, "resource", other_group),
                    ]
                )
                self.assertEqual(
                    self.result(model, query(scope_id=other_resource))["outcome"],
                    "no_matching_supplied_role_grant",
                )

    def test_resource_group_assignment_applies_only_to_descendants(self):
        model = snapshot()
        model["role_assignments"][0]["scope_id"] = GROUP
        self.assertEqual(self.result(model)["outcome"], "matching_supplied_role_grant")
        self.assertEqual(
            self.result(model, query(scope_id=SUB))["outcome"], "no_matching_supplied_role_grant"
        )

    def test_management_group_ancestry_is_explicit_and_siblings_do_not_inherit(self):
        model = snapshot()
        child = "/providers/Microsoft.Management/managementGroups/child"
        sibling = "/providers/Microsoft.Management/managementGroups/sibling"
        model["scopes"].extend(
            [
                scope(MANAGEMENT, "management_group"),
                scope(child, "management_group", MANAGEMENT),
                scope(sibling, "management_group"),
            ]
        )
        model["scopes"][0]["parent_scope_id"] = child
        model["role_definitions"][0]["assignable_scopes"] = [MANAGEMENT]
        model["role_assignments"][0]["scope_id"] = MANAGEMENT
        result = self.result(model)
        self.assertEqual(result["outcome"], "matching_supplied_role_grant")
        self.assertEqual(
            result["known_grant_witnesses"][0]["scope_path"],
            [MANAGEMENT, child, SUB, GROUP, RESOURCE],
        )
        model["scopes"][0]["parent_scope_id"] = sibling
        self.assertEqual(self.result(model)["outcome"], "no_matching_supplied_role_grant")

    def test_nested_and_extension_resources_preserve_declared_parent_paths(self):
        for child in (
            RESOURCE + "/blobServices/default",
            RESOURCE + "/providers/Microsoft.Authorization/locks/one",
        ):
            with self.subTest(child=child):
                model = snapshot()
                model["scopes"].append(scope(child, "resource", RESOURCE))
                model["role_assignments"][0]["scope_id"] = RESOURCE
                self.assertEqual(
                    self.result(model, query(scope_id=child))["outcome"],
                    "matching_supplied_role_grant",
                )

    def test_assignable_scopes_define_availability_not_a_grant(self):
        model = snapshot()
        model["role_assignments"] = []
        self.assertEqual(self.result(model)["outcome"], "no_matching_supplied_role_grant")
        model = snapshot()
        model["role_definitions"][0]["assignable_scopes"] = [GROUP]
        result = self.result(model)
        self.assertEqual(result["outcome"], "inconclusive")
        self.assertEqual(result["known_grant_witnesses"], [])
        self.assertIn(
            "assignment_outside_declared_assignable_scopes", result["uncertainty_reasons"]
        )

    def test_builtin_root_availability_and_custom_root_ambiguity_stay_distinct(self):
        model = snapshot()
        model["role_definitions"][0].update(role_type="built_in", assignable_scopes=["/"])
        self.assertEqual(self.result(model)["outcome"], "matching_supplied_role_grant")
        model["role_definitions"][0]["role_type"] = "custom"
        result = self.result(model)
        self.assertEqual(result["outcome"], "inconclusive")
        self.assertEqual(result["known_grant_witnesses"], [])

    def test_custom_data_role_at_management_group_is_not_an_invented_grant(self):
        model = snapshot()
        model["scopes"].append(scope(MANAGEMENT, "management_group"))
        model["scopes"][0]["parent_scope_id"] = MANAGEMENT
        model["role_definitions"][0].update(
            assignable_scopes=[MANAGEMENT],
            permissions=[permission([OPERATION], data_actions=[DATA_OPERATION])],
        )
        model["role_assignments"][0]["scope_id"] = MANAGEMENT
        for plane in ("control", "data"):
            result = self.result(
                model,
                query(plane=plane, operation=OPERATION if plane == "control" else DATA_OPERATION),
            )
            self.assertEqual(result["outcome"], "inconclusive")
            self.assertEqual(result["known_grant_witnesses"], [])
        model["role_assignments"][0]["scope_id"] = SUB
        self.assertEqual(
            self.result(model, query(plane="data", operation=DATA_OPERATION))["outcome"],
            "matching_supplied_role_grant",
        )

    def test_direct_and_supplied_transitive_group_memberships_are_distinct_witnesses(self):
        model = snapshot()
        model["role_assignments"][0]["principal_id"] = "group:readers"
        self.assertEqual(self.result(model)["outcome"], "no_matching_supplied_role_grant")
        result = self.result(model, query(group_ids=["group:readers"]))
        self.assertEqual(result["outcome"], "matching_supplied_role_grant")
        self.assertEqual(result["known_grant_witnesses"][0]["principal_match"], "supplied_group")
        self.assertEqual(
            result["known_grant_witnesses"][0]["assigned_principal_id"], "group:readers"
        )

    def test_foreign_tenant_query_cannot_use_selected_tenant_roles(self):
        result = self.result(request=query(tenant_id="tenant:other"))
        self.assertEqual(result["outcome"], "inconclusive")
        self.assertEqual(result["known_grant_witnesses"], [])
        self.assertIn("query_tenant_outside_supplied_model", result["uncertainty_reasons"])
        model = snapshot()
        model["role_assignments"][0]["tenant_id"] = "tenant:other"
        self.assert_sources_reject(model)

    def test_case_insensitive_identity_joins_do_not_erase_source_provenance(self):
        model = snapshot()
        assignment_value = model["role_assignments"][0]
        for field in ("tenant_id", "principal_id", "role_definition_id", "scope_id"):
            assignment_value[field] = assignment_value[field].upper()
        result = self.result(model, query(scope_id=RESOURCE.upper()))
        self.assertEqual(result["outcome"], "matching_supplied_role_grant")
        self.assertEqual(result["known_grant_witnesses"][0]["assignment_scope_id"], SUB.upper())

    def test_conditions_and_pim_eligibility_remain_inconclusive_without_witnesses(self):
        for changes in (
            {"condition": "@Resource[tag] == 'one'"},
            {"condition_version": "2.0"},
            {"state": "eligible"},
            {"state": "unknown"},
        ):
            with self.subTest(changes=changes):
                model = snapshot()
                model["role_assignments"][0].update(changes)
                result = self.result(model)
                self.assertEqual(result["outcome"], "inconclusive")
                self.assertEqual(result["known_grant_witnesses"], [])
        for field in ("condition", "condition_version"):
            model = snapshot()
            model["role_definitions"][0]["permissions"][0][field] = "unsupported"
            result = self.result(model)
            self.assertEqual(result["outcome"], "inconclusive")
            self.assertEqual(result["known_grant_witnesses"], [])
            self.assertIn("unsupported_role_condition", result["uncertainty_reasons"])

    def test_deny_declarations_and_incomplete_sources_preserve_known_witnesses(self):
        for field, value in (
            ("deny_assignments", "present"),
            ("deny_assignments", "unknown"),
            ("role_assignments_complete", False),
            ("scope_ancestry_complete", False),
        ):
            with self.subTest(field=field, value=value):
                model = snapshot()
                model["coverage"][field] = value
                result = self.result(model)
                self.assertEqual(result["outcome"], "inconclusive")
                self.assertEqual(len(result["known_grant_witnesses"]), 1)
        result = self.result(request=query(group_membership_complete=False))
        self.assertEqual(result["outcome"], "inconclusive")
        self.assertEqual(len(result["known_grant_witnesses"]), 1)

    def test_dangling_role_scope_and_assignable_references_are_never_silent_clean_results(self):
        cases = []
        model = snapshot()
        model["role_assignments"][0]["role_definition_id"] = "role:missing"
        cases.append(model)
        model = snapshot()
        model["role_assignments"][0]["scope_id"] = "/subscriptions/missing"
        cases.append(model)
        model = snapshot()
        model["role_definitions"][0]["assignable_scopes"] = ["/subscriptions/missing"]
        cases.append(model)
        model = snapshot()
        model["scopes"] = model["scopes"][1:]
        cases.append(model)
        for model in cases:
            with self.subTest(model=model):
                self.assertEqual(self.result(model)["outcome"], "inconclusive")
        self.assertEqual(
            self.result(request=query(scope_id="/subscriptions/missing"))["outcome"], "inconclusive"
        )

    def test_scope_conflicts_cycles_and_false_parent_edges_reject_before_hashing(self):
        cases = []
        model = snapshot()
        model["scopes"].append(scope(SUB.upper(), "subscription"))
        cases.append(model)
        model = snapshot()
        model["scopes"][1]["parent_scope_id"] = "/subscriptions/other"
        cases.append(model)
        model = snapshot()
        model["scopes"][2]["parent_scope_id"] = SUB
        cases.append(model)
        model = snapshot()
        model["scopes"][0]["kind"] = "resource"
        cases.append(model)
        model = snapshot()
        model["scopes"].append(scope(MANAGEMENT, "management_group", MANAGEMENT))
        cases.append(model)
        for model in cases:
            with (
                self.subTest(model=model),
                patch.object(rbac, "_hash", side_effect=AssertionError("hash reached")),
            ):
                self.assert_sources_reject(model)

    def test_empty_or_unrecognized_scope_ancestry_is_explicit_uncertainty(self):
        model = snapshot()
        model["scopes"][2]["parent_scope_id"] = None
        result = self.result(model)
        self.assertEqual(result["outcome"], "inconclusive")
        self.assertIn("unresolved_scope_parent", result["uncertainty_reasons"])
        model["scopes"] = []
        self.assertEqual(self.result(model)["outcome"], "inconclusive")

    def test_duplicate_role_assignment_and_query_identities_reject(self):
        cases = []
        model = snapshot()
        other = role("ROLE:READER", permissions=[permission(["*"])])
        model["role_definitions"].append(other)
        cases.append((model, [query()]))
        model = snapshot()
        model["role_assignments"].append(
            assignment("ASSIGNMENT:READER", principal="principal:other")
        )
        cases.append((model, [query()]))
        cases.append(
            (snapshot(), [query(), query(operation="Microsoft.Storage/storageAccounts/write")])
        )
        for model, requests in cases:
            with self.subTest(model=model):
                self.assert_sources_reject(model, requests)

    def test_duplicate_permission_blocks_patterns_and_groups_reject(self):
        for mutation in ("block", "pattern", "group"):
            with self.subTest(mutation=mutation):
                model, request = snapshot(), query()
                if mutation == "block":
                    model["role_definitions"][0]["permissions"] *= 2
                elif mutation == "pattern":
                    model["role_definitions"][0]["permissions"][0]["actions"] = [
                        OPERATION,
                        OPERATION.upper(),
                    ]
                else:
                    request["group_ids"] = ["group:readers", "GROUP:READERS"]
                self.assert_sources_reject(model, [request])

    def test_unsupported_permission_syntax_remains_inconclusive(self):
        for value in (
            "Microsoft.Storage/?/read",
            "Microsoft.*/*/read",
            "${operation}",
            "unsupported",
        ):
            with self.subTest(value=value):
                model = snapshot()
                model["role_definitions"][0]["permissions"][0]["actions"] = [value]
                result = self.result(model)
                self.assertEqual(result["outcome"], "inconclusive")
                self.assertIn("unsupported_permission_pattern", result["uncertainty_reasons"])
                self.assertEqual(result["known_grant_witnesses"], [])

    def test_unsupported_exclusion_cannot_create_a_known_grant(self):
        model = snapshot()
        model["role_definitions"][0]["permissions"][0]["not_actions"] = ["Microsoft.Storage/?/read"]
        result = self.result(model)
        self.assertEqual(result["outcome"], "inconclusive")
        self.assertEqual(result["known_grant_witnesses"], [])

    def test_unsupported_sources_do_not_hide_a_separate_known_witness(self):
        model = snapshot()
        model["role_definitions"].append(
            role("role:conditional", permissions=[permission(["*"], condition="unknown")])
        )
        model["role_assignments"].append(
            assignment("assignment:conditional", role_id="role:conditional")
        )
        result = self.result(model)
        self.assertEqual(result["outcome"], "inconclusive")
        self.assertEqual(len(result["known_grant_witnesses"]), 1)
        self.assertEqual(result["known_grant_witnesses"][0]["role_definition_id"], "role:reader")

    def test_permuted_sources_preserve_sorted_semantics_but_bind_original_order(self):
        model = snapshot()
        model["role_definitions"].append(role("role:other", permissions=[permission([OPERATION])]))
        model["role_assignments"].append(assignment("assignment:other", role_id="role:other"))
        requests = [query("read-z"), query("read-a")]
        original = rbac.analyze_azure_rbac(model, requests).to_dict()
        for field in ("scopes", "role_definitions", "role_assignments"):
            model[field].reverse()
        permuted = rbac.analyze_azure_rbac(model, list(reversed(requests))).to_dict()
        self.assertEqual(original["results"], permuted["results"])
        self.assertEqual(original["summary"], permuted["summary"])
        self.assertNotEqual(original["snapshot_sha256"], permuted["snapshot_sha256"])
        self.assertNotEqual(original["queries_sha256"], permuted["queries_sha256"])

    def test_all_native_aliases_and_container_hooks_reject_before_hashing(self):
        models = []
        for value in (True, 1.0, "1", NativeIntegerAlias(1)):
            model = snapshot()
            model["schema_version"] = value
            models.append(model)
        model = snapshot()
        model["tenant_id"] = NativeStringAlias(TENANT)
        models.append(model)
        model = snapshot()
        model["role_assignments"] = NativeListAlias(model["role_assignments"])
        models.append(model)
        models.append(NativeDictAlias(snapshot()))
        for model in models:
            with (
                self.subTest(kind=type(model)),
                patch.object(rbac, "_hash", side_effect=AssertionError("hash reached")),
            ):
                self.assert_sources_reject(model)
        for value in (0, 1, 0.0, "true"):
            for field in ("role_assignments_complete", "scope_ancestry_complete"):
                model = snapshot()
                model["coverage"][field] = value
                self.assert_sources_reject(model)

    def test_closed_shapes_and_query_primitive_vocabulary_reject(self):
        for field, value in (
            ("plane", "unknown"),
            ("plane", True),
            ("operation", "*"),
            ("operation", "Microsoft.Storage/*/read"),
            ("operation", OPERATION + "?"),
            ("scope_id", RESOURCE + "/"),
            ("scope_id", "/"),
            ("scope_id", "/subscriptions/.."),
            ("group_membership_complete", 1),
            ("group_ids", ("group:readers",)),
        ):
            with self.subTest(field=field, value=value):
                self.assert_sources_reject(snapshot(), [query(**{field: value})])
        model = snapshot()
        model["unknown"] = None
        self.assert_sources_reject(model)
        model = snapshot()
        del model["role_definitions"][0]["permissions"][0]["condition"]
        self.assert_sources_reject(model)
        model = snapshot()
        model["role_assignments"][0]["condition"] = {"expression": "none"}
        self.assert_sources_reject(model)

    def test_structural_resource_graph_limits_apply_before_serialization(self):
        shared = ["a" * 4096] * 200
        branching = [0]
        for _ in range(5):
            branching = [branching] * 10
        deep = 0
        for _ in range(rbac.MAX_DEPTH + 1):
            deep = [deep]
        cycle = []
        cycle.append(cycle)
        for value in (shared, branching, deep, cycle, 2**1_000_000):
            with (
                self.subTest(kind=type(value)),
                patch.object(rbac, "_canonical", side_effect=AssertionError("dump reached")),
            ):
                self.assert_sources_reject({"invalid": value})

    def test_final_null_boolean_and_integer_charge_cannot_overflow_native_budget(self):
        for value, exact in ((None, 7), (True, 7), (False, 7), (0, 22), (1, 22)):
            with self.subTest(value=value), patch.object(rbac, "MAX_JSON_BYTES", exact):
                self.assertEqual(rbac._capture(value), value)
            with self.subTest(value=value), patch.object(rbac, "MAX_JSON_BYTES", exact - 1):
                with self.assertRaises(rbac.AzureRbacAnalysisError):
                    rbac._capture(value)

    def test_scope_role_assignment_and_query_count_limits_reject_before_hashes(self):
        cases = []
        for field, maximum, factory in (
            (
                "scopes",
                rbac.MAX_SCOPES,
                lambda index: scope(f"/subscriptions/s{index}", "subscription"),
            ),
            ("role_definitions", rbac.MAX_ROLES, lambda index: role(f"role:r{index}")),
            (
                "role_assignments",
                rbac.MAX_ASSIGNMENTS,
                lambda index: assignment(f"assignment:a{index}"),
            ),
        ):
            model = snapshot()
            model[field] = [factory(index) for index in range(maximum + 1)]
            cases.append((model, [query()]))
        cases.append((snapshot(), [query(f"q{index}") for index in range(rbac.MAX_QUERIES + 1)]))
        for model, requests in cases:
            with (
                self.subTest(count=len(requests)),
                patch.object(rbac, "_hash", side_effect=AssertionError("hash reached")),
            ):
                self.assert_sources_reject(model, requests)

    def test_exact_scope_and_query_count_ceilings_remain_valid(self):
        model = snapshot()
        model["scopes"].extend(
            scope(f"/subscriptions/other-{index}", "subscription")
            for index in range(rbac.MAX_SCOPES - len(model["scopes"]))
        )
        self.assertEqual(self.result(model)["outcome"], "matching_supplied_role_grant")
        requests = [query(f"read-{index:03d}") for index in range(rbac.MAX_QUERIES)]
        report = rbac.analyze_azure_rbac(snapshot(), requests).to_dict()
        self.assertEqual(len(report["results"]), rbac.MAX_QUERIES)
        self.assertEqual(report["summary"]["matching_supplied_role_grant"], rbac.MAX_QUERIES)

    def test_scope_ancestry_depth_bound_never_expands_an_unbounded_path(self):
        model = snapshot()
        model["scopes"] = [
            scope(
                f"/providers/Microsoft.Management/managementGroups/g{index}",
                "management_group",
                None
                if index == 0
                else f"/providers/Microsoft.Management/managementGroups/g{index - 1}",
            )
            for index in range(rbac.MAX_SCOPE_DEPTH + 1)
        ]
        self.assert_sources_reject(model)

    def test_permission_and_pattern_aggregate_limits_reject_before_hashes(self):
        for limit in ("blocks", "patterns"):
            model = snapshot()
            if limit == "blocks":
                model["role_definitions"] = [
                    role(
                        f"role:r{index}",
                        permissions=[
                            permission([f"Microsoft.Storage/type{j}/read"]) for j in range(16)
                        ],
                    )
                    for index in range(33)
                ]
            else:
                model["role_definitions"] = [
                    role(
                        f"role:r{index}",
                        permissions=[
                            permission([f"Microsoft.Storage/type{j}/read" for j in range(128)])
                        ],
                    )
                    for index in range(17)
                ]
            with (
                self.subTest(limit=limit),
                patch.object(rbac, "_hash", side_effect=AssertionError("hash reached")),
            ):
                self.assert_sources_reject(model)

    def test_matching_and_witness_budgets_reject_instead_of_truncating(self):
        for field in ("MAX_MATCH_WORK", "MAX_WITNESSES"):
            with self.subTest(field=field), patch.object(rbac, field, 0):
                self.assert_sources_reject(snapshot())
        with patch.object(rbac, "MAX_JSON_BYTES", 1024):
            self.assert_sources_reject(snapshot())

    def test_bounded_bytes_duplicate_keys_floats_and_nonfinite_values_reject(self):
        raw = encode(snapshot())
        invalid = (
            NativeBytesAlias(raw),
            bytearray(raw),
            b"",
            b"\xff",
            b"{}" * (rbac.MAX_JSON_BYTES // 2 + 1),
            raw.replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1'),
            raw.replace(b'"schema_version":1', b'"schema_version":1.0'),
            raw.replace(b'"schema_version":1', b'"schema_version":NaN'),
            b"[" * (rbac.MAX_DEPTH + 1) + b"0" + b"]" * (rbac.MAX_DEPTH + 1),
        )
        for content in invalid:
            with self.subTest(kind=type(content)), self.assertRaises(rbac.AzureRbacAnalysisError):
                rbac.analyze_azure_rbac_bytes(
                    snapshot_bytes=content, queries_bytes=encode([query()])
                )
        nested = raw.replace(b'"actions":', b'"actions":[],"actions":', 1)
        with self.assertRaises(rbac.AzureRbacAnalysisError):
            rbac.analyze_azure_rbac_bytes(snapshot_bytes=nested, queries_bytes=encode([query()]))

    def test_byte_formatting_binds_canonical_parsed_sources_not_raw_whitespace(self):
        compact = rbac.analyze_azure_rbac_bytes(
            snapshot_bytes=encode(snapshot()), queries_bytes=encode([query()])
        )
        pretty = rbac.analyze_azure_rbac_bytes(
            snapshot_bytes=json.dumps(snapshot(), indent=2).encode("ascii"),
            queries_bytes=json.dumps([query()], indent=2).encode("ascii"),
        )
        self.assertEqual(compact.to_json(), pretty.to_json())

    def test_input_and_output_mutation_cannot_change_the_owned_record(self):
        model, requests = snapshot(), [query()]
        record = rbac.analyze_azure_rbac(model, requests)
        expected = record.to_json()
        model["role_assignments"].clear()
        requests[0]["operation"] = "Microsoft.Storage/storageAccounts/write"
        document = record.to_dict()
        document["effects"]["authority"] = "allowed"
        document["snapshot"]["role_assignments"].clear()
        document["results"][0]["known_grant_witnesses"].clear()
        self.assertEqual(record.to_json(), expected)
        with self.assertRaises(FrozenInstanceError):
            record.document_json = "{}"

    def test_cohashed_false_grant_cannot_replay_original_sources(self):
        original = rbac.analyze_azure_rbac(snapshot(), [query()]).to_dict()
        false = copy.deepcopy(original)
        false["results"][0]["known_grant_witnesses"] = []
        false["results"][0]["outcome"] = "no_matching_supplied_role_grant"
        false["summary"] = {
            "matching_supplied_role_grant": 0,
            "no_matching_supplied_role_grant": 1,
            "inconclusive": 0,
        }
        self.assert_report_rejects(readdress(false))
        false = copy.deepcopy(original)
        false["results"][0]["known_grant_witnesses"][0]["role_definition_id"] = "role:other"
        self.assert_report_rejects(readdress(false))

    def test_cohashed_outcome_projection_and_false_effects_reject(self):
        original = rbac.analyze_azure_rbac(snapshot(), [query()]).to_dict()
        for field, value in (
            ("schema_version", True),
            ("schema_version", 1.0),
            ("effective_access_verified", True),
            ("qualification_claimed", 1),
            ("matching_work", True),
            ("source_digest_basis", "raw_bytes"),
        ):
            with self.subTest(field=field):
                false = copy.deepcopy(original)
                false[field] = value
                self.assert_report_rejects(readdress(false))
        false = copy.deepcopy(original)
        false["effects"]["authority"] = "approved"
        self.assert_report_rejects(readdress(false))

    def test_coherent_source_substitution_requires_independent_original_binding(self):
        original = rbac.analyze_azure_rbac(snapshot(), [query()])
        alternate = snapshot()
        alternate["role_definitions"][0]["permissions"][0]["actions"] = ["*"]
        changed = rbac.analyze_azure_rbac(alternate, [query()])
        self.assertNotEqual(original.analysis_sha256, changed.analysis_sha256)
        self.assertEqual(
            rbac.AzureRbacAnalysis.from_dict(changed.to_dict()).to_json(), changed.to_json()
        )
        with self.assertRaises(rbac.AzureRbacAnalysisError):
            rbac.verify_azure_rbac_analysis(changed, snapshot=snapshot(), queries=[query()])
        with self.assertRaises(rbac.AzureRbacAnalysisError):
            rbac.verify_azure_rbac_analysis(original, snapshot=alternate, queries=[query()])

    def test_query_source_substitution_preserves_no_original_report_binding(self):
        record = rbac.analyze_azure_rbac(snapshot(), [query()])
        for changes in (
            {"tenant_id": "tenant:other"},
            {"principal_id": "principal:bob"},
            {"scope_id": SUB},
            {"operation": "Microsoft.Storage/storageAccounts/write"},
            {"plane": "data"},
        ):
            with self.subTest(changes=changes), self.assertRaises(rbac.AzureRbacAnalysisError):
                rbac.verify_azure_rbac_analysis(
                    record, snapshot=snapshot(), queries=[query(**changes)]
                )

    def test_frozen_wrapper_late_mutation_and_missing_slot_reject_on_export(self):
        record = rbac.analyze_azure_rbac(snapshot(), [query()])
        false = record.to_dict()
        false["summary"]["matching_supplied_role_grant"] = 0
        object.__setattr__(record, "document_json", encode(readdress(false)).decode("ascii"))
        for consume in (
            record.to_dict,
            record.to_json,
            lambda: rbac.verify_azure_rbac_analysis(record, snapshot=snapshot(), queries=[query()]),
        ):
            with self.assertRaises(rbac.AzureRbacAnalysisError):
                consume()
        missing = object.__new__(rbac.AzureRbacAnalysis)
        with self.assertRaises(rbac.AzureRbacAnalysisError):
            missing.to_dict()

    def test_malformed_report_byte_and_native_entries_are_bounded_rejections(self):
        report = rbac.analyze_azure_rbac(snapshot(), [query()])
        for content in (
            b"",
            b"\xff",
            encode({"snapshot": snapshot()}),
            report.to_json()
            .encode("ascii")
            .replace(b'"offline_only":true', b'"offline_only":true,"offline_only":true'),
        ):
            with self.subTest(size=len(content)), self.assertRaises(rbac.AzureRbacAnalysisError):
                rbac.AzureRbacAnalysis.from_json(content)
        with self.assertRaises(rbac.AzureRbacAnalysisError):
            rbac.verify_azure_rbac_analysis("{}", snapshot=snapshot(), queries=[query()])


if __name__ == "__main__":
    unittest.main()
