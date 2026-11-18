"""Synthetic policy reasoning, not live Kubernetes authorization evidence."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from dataclasses import FrozenInstanceError
from unittest.mock import patch

from sunderkey import kubernetes_rbac_analysis as rbac


def rule(*, verbs=None, groups=None, resources=None, names=None):
    result = {
        "verbs": ["get"] if verbs is None else verbs,
        "apiGroups": [""] if groups is None else groups,
        "resources": ["pods"] if resources is None else resources,
    }
    if names is not None:
        result["resourceNames"] = names
    return result


def role(name="reader", *, namespace="team-a", rules=None, kind="Role"):
    metadata = {"name": name}
    if kind == "Role":
        metadata["namespace"] = namespace
    return {
        "apiVersion": rbac.RBAC_GROUP + "/v1",
        "kind": kind,
        "metadata": metadata,
        "rules": [rule()] if rules is None else rules,
    }


def subject(name="alice", *, kind="User", namespace=None):
    result = {
        "kind": kind,
        "name": name,
        "apiGroup": "" if kind == "ServiceAccount" else rbac.RBAC_GROUP,
    }
    if namespace is not None:
        result["namespace"] = namespace
    return result


def binding(
    name="read",
    *,
    namespace="team-a",
    role_name="reader",
    role_kind="Role",
    kind="RoleBinding",
    subjects=None,
):
    metadata = {"name": name}
    if kind == "RoleBinding":
        metadata["namespace"] = namespace
    return {
        "apiVersion": rbac.RBAC_GROUP + "/v1",
        "kind": kind,
        "metadata": metadata,
        "roleRef": {"apiGroup": rbac.RBAC_GROUP, "kind": role_kind, "name": role_name},
        "subjects": [subject()] if subjects is None else subjects,
    }


def query(query_id="read-pod", **changes):
    result = {
        "query_id": query_id,
        "principal": "alice",
        "groups": [],
        "namespace": "team-a",
        "resource_scope": "namespaced",
        "api_group": "",
        "resource": "pods",
        "subresource": "",
        "verb": "get",
        "name": "pod-one",
        "field_selector": "",
    }
    result.update(changes)
    return result


def snapshot(*objects):
    return {"objects": list(objects) if objects else [role(), binding()]}


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def readdress(document):
    result = copy.deepcopy(document)
    body = {
        key: value for key, value in result.items() if key not in ("analysis_id", "analysis_sha256")
    }
    digest = (
        "sha256:"
        + hashlib.sha256(b"sunderkey.kubernetes-rbac-analysis.v1\n" + encode(body)).hexdigest()
    )
    result.update(analysis_id="KRA-" + digest[7:39].upper(), analysis_sha256=digest)
    return result


class KubernetesRbacAnalysisTests(unittest.TestCase):
    def analyze(self, model=None, queries=None):
        return rbac.analyze_kubernetes_rbac(
            snapshot() if model is None else model,
            [query()] if queries is None else queries,
        ).to_dict()

    def decisions(self, model, queries):
        return [item["decision"] for item in self.analyze(model, queries)["results"]]

    def test_valid_native_baseline_has_replayable_exact_sources_and_no_effects(self):
        model, queries = snapshot(), [query()]
        record = rbac.analyze_kubernetes_rbac(model, queries)
        document = record.to_dict()
        self.assertEqual(document["results"][0]["decision"], "allow_in_supplied_model")
        witness = document["results"][0]["witnesses"][0]
        self.assertEqual(witness["binding"], ["RoleBinding", "team-a", "read"])
        self.assertEqual(witness["role"], ["Role", "team-a", "reader"])
        self.assertEqual(set(document["effects"].values()), {"none"})
        self.assertEqual(document["profile_id"], "AOE-GC-D15-S04")
        self.assertEqual(
            record.to_dict(), rbac.KubernetesRbacAnalysis.from_dict(document).to_dict()
        )
        self.assertEqual(
            record.to_json(), rbac.KubernetesRbacAnalysis.from_json(encode(document)).to_json()
        )
        self.assertEqual(record.analysis_id, document["analysis_id"])
        self.assertEqual(record.analysis_sha256, document["analysis_sha256"])
        self.assertEqual(record.analysis_id, "KRA-A4BBA69C50728804EB93D3CD74D0CE21")
        self.assertEqual(
            record.analysis_sha256,
            "sha256:a4bba69c50728804eb93d3cd74d0ce217a932227b28763d416eadb040504cedc",
        )
        self.assertEqual(
            document["snapshot_sha256"],
            "sha256:9f2f36657e92e558b9c13ec72c109e6618d2e99fadddb4c83bbaa2a7d4368800",
        )
        self.assertEqual(
            document["queries_sha256"],
            "sha256:fe081bd18e4bf4e4f2a3d32ae8cc3c18659eb7a539879ec7d66ea6ac04538039",
        )
        self.assertEqual(
            witness["rule_sha256"],
            "sha256:6c5bf19316bc3e49924f839ff2707b32987a574119806a35f94788eaaf1f2469",
        )
        self.assertEqual(
            record.to_json(),
            rbac.verify_kubernetes_rbac_analysis(
                record,
                snapshot=model,
                queries=queries,
            ).to_json(),
        )

    def test_rolebinding_clusterrole_is_confined_to_binding_namespace(self):
        model = snapshot(role(kind="ClusterRole"), binding(role_kind="ClusterRole"))
        self.assertEqual(
            self.decisions(
                model,
                [
                    query("a", namespace="team-a"),
                    query("b", namespace="team-b"),
                ],
            ),
            ["allow_in_supplied_model", "no_matching_allow_in_supplied_model"],
        )

    def test_role_reference_never_resolves_same_name_in_another_namespace(self):
        model = snapshot(role(namespace="team-b"), binding())
        document = self.analyze(model)
        self.assertEqual(document["results"][0]["decision"], "inconclusive")
        self.assertEqual(document["source_issues"][0]["reason"], "unresolved_role_reference")
        self.assertEqual(document["results"][0]["witnesses"], [])

    def test_clusterrolebinding_grants_namespaced_and_cluster_attributes(self):
        model = snapshot(
            role(kind="ClusterRole", rules=[rule(resources=["pods", "nodes"])]),
            binding(kind="ClusterRoleBinding", role_kind="ClusterRole"),
        )
        self.assertEqual(
            self.decisions(
                model,
                [
                    query("a", namespace="team-b"),
                    query("b", resource="nodes", resource_scope="cluster", namespace=""),
                ],
            ),
            ["allow_in_supplied_model"] * 2,
        )
        confined = snapshot(role(rules=[rule(resources=["nodes"])]), binding())
        self.assertEqual(
            self.decisions(
                confined,
                [
                    query(resource="nodes", resource_scope="cluster", namespace=""),
                ],
            ),
            ["no_matching_allow_in_supplied_model"],
        )

    def test_supplied_user_and_group_matching_is_exact_and_case_sensitive(self):
        model = snapshot(role(), binding(subjects=[subject("readers", kind="Group")]))
        self.assertEqual(
            self.decisions(
                model,
                [
                    query("a", groups=["readers"]),
                    query("b", groups=["Readers"]),
                    query("c", principal="readers"),
                ],
            ),
            [
                "allow_in_supplied_model",
                "no_matching_allow_in_supplied_model",
                "no_matching_allow_in_supplied_model",
            ],
        )
        self.assertEqual(
            self.decisions(snapshot(), [query(principal="Alice")]),
            ["no_matching_allow_in_supplied_model"],
        )

    def test_serviceaccount_explicit_namespace_and_local_default_are_distinct(self):
        for supplied_namespace, permitted in ((None, "team-a"), ("team-b", "team-b")):
            with self.subTest(namespace=supplied_namespace):
                model = snapshot(
                    role(),
                    binding(
                        subjects=[
                            subject(
                                "runner",
                                kind="ServiceAccount",
                                namespace=supplied_namespace,
                            )
                        ]
                    ),
                )
                self.assertEqual(
                    self.decisions(
                        model,
                        [
                            query("a", principal=f"system:serviceaccount:{permitted}:runner"),
                            query("b", principal="runner"),
                            query("c", principal="system:serviceaccount:other:runner"),
                        ],
                    ),
                    [
                        "allow_in_supplied_model",
                        "no_matching_allow_in_supplied_model",
                        "no_matching_allow_in_supplied_model",
                    ],
                )

    def test_serviceaccount_group_membership_is_not_inferred(self):
        model = snapshot(
            role(),
            binding(
                subjects=[
                    subject("system:serviceaccounts:team-a", kind="Group"),
                ]
            ),
        )
        principal = "system:serviceaccount:team-a:runner"
        self.assertEqual(
            self.decisions(
                model,
                [
                    query("a", principal=principal),
                    query("b", principal=principal, groups=["system:serviceaccounts:team-a"]),
                ],
            ),
            ["no_matching_allow_in_supplied_model", "allow_in_supplied_model"],
        )

    def test_core_api_group_and_wildcards_are_exact_not_substring_matches(self):
        model = snapshot(role(rules=[rule(groups=["apps"], resources=["deployments"])]), binding())
        self.assertEqual(
            self.decisions(
                model,
                [
                    query("a", api_group="apps", resource="deployments"),
                    query("b", api_group="", resource="deployments"),
                    query("c", api_group="myapps", resource="deployments"),
                ],
            ),
            [
                "allow_in_supplied_model",
                "no_matching_allow_in_supplied_model",
                "no_matching_allow_in_supplied_model",
            ],
        )
        wild = snapshot(role(rules=[rule(groups=["*"], verbs=["*"], resources=["*"])]), binding())
        self.assertEqual(
            self.decisions(wild, [query(api_group="custom.example", verb="custom")]),
            ["allow_in_supplied_model"],
        )

    def test_subresource_matching_uses_upstream_star_slash_not_generic_globs(self):
        cases = (
            (["pods"], "pods", "log", False),
            (["pods/log"], "pods", "log", True),
            (["*/log"], "deployments", "log", True),
            (["*/log"], "pods", "", False),
            (["pods/*"], "pods", "log", False),
            (["*/*"], "pods", "log", False),
            (["*"], "pods", "log", True),
        )
        for resources, resource, subresource, allowed in cases:
            with self.subTest(resources=resources, subresource=subresource):
                model = snapshot(role(rules=[rule(resources=resources)]), binding())
                expected = (
                    "allow_in_supplied_model" if allowed else "no_matching_allow_in_supplied_model"
                )
                self.assertEqual(
                    self.decisions(model, [query(resource=resource, subresource=subresource)]),
                    [expected],
                )

    def test_named_resource_and_subresource_create_match_exactly(self):
        model = snapshot(
            role(
                rules=[
                    rule(verbs=["get", "update"], resources=["pods"], names=["pod-one"]),
                    rule(verbs=["create"], resources=["pods/exec"], names=["pod-one"]),
                ]
            ),
            binding(),
        )
        self.assertEqual(
            self.decisions(
                model,
                [
                    query("a"),
                    query("b", name="pod-two"),
                    query("c", verb="create", subresource="exec"),
                    query("d", verb="create", subresource="exec", name="pod-two"),
                ],
            ),
            [
                "allow_in_supplied_model",
                "no_matching_allow_in_supplied_model",
                "allow_in_supplied_model",
                "no_matching_allow_in_supplied_model",
            ],
        )
        literal_star = snapshot(role(rules=[rule(names=["*"])]), binding())
        self.assertEqual(
            self.decisions(literal_star, [query()]), ["no_matching_allow_in_supplied_model"]
        )

    def test_collection_and_top_level_create_cannot_invent_named_grants(self):
        restricted = snapshot(
            role(
                rules=[
                    rule(
                        verbs=["create", "deletecollection", "list", "watch"],
                        names=["pod-one"],
                    )
                ]
            ),
            binding(),
        )
        for verb in ("create", "deletecollection", "list", "watch"):
            with self.subTest(verb=verb):
                self.assertEqual(
                    self.decisions(restricted, [query(verb=verb, name="")]),
                    ["no_matching_allow_in_supplied_model"],
                )
                with self.assertRaises(rbac.KubernetesRbacAnalysisError):
                    self.analyze(restricted, [query(verb=verb)])
        unrestricted = snapshot(
            role(rules=[rule(verbs=["create", "deletecollection", "list", "watch"])]), binding()
        )
        self.assertEqual(
            self.decisions(
                unrestricted,
                [
                    query(str(index), verb=verb, name="")
                    for index, verb in enumerate(("create", "deletecollection", "list", "watch"))
                ],
            ),
            ["allow_in_supplied_model"] * 4,
        )

    def test_selector_bearing_list_watch_is_explicitly_inconclusive(self):
        for verb in ("list", "watch"):
            for names in (None, ["pod-one"]):
                with self.subTest(verb=verb, names=names):
                    model = snapshot(role(rules=[rule(verbs=[verb], names=names)]), binding())
                    result = self.analyze(
                        model,
                        [
                            query(
                                verb=verb,
                                name="",
                                field_selector="metadata.name=pod-one",
                            )
                        ],
                    )["results"][0]
                    self.assertEqual(result["decision"], "inconclusive")
                    self.assertIn("unsupported_field_selector", result["uncertainties"])
                    self.assertEqual(result["witnesses"], [])

    def test_additive_independent_rules_do_not_invent_deny_precedence(self):
        model = snapshot(role(rules=[rule(verbs=["get"]), rule(verbs=["update"])]), binding())
        self.assertEqual(
            self.decisions(model, [query("a"), query("b", verb="update")]),
            ["allow_in_supplied_model"] * 2,
        )
        model["objects"][0]["rules"][0]["effect"] = "Deny"
        with self.assertRaises(rbac.KubernetesRbacAnalysisError):
            self.analyze(model)

    def test_aggregation_never_trusts_supplied_materialized_rules(self):
        aggregate = role(kind="ClusterRole", rules=[rule(resources=["*"])])
        aggregate["aggregationRule"] = {
            "clusterRoleSelectors": [{"matchLabels": {"aggregate": "yes"}}]
        }
        model = snapshot(aggregate, binding(role_kind="ClusterRole"))
        result = self.analyze(model)["results"][0]
        self.assertEqual(result["decision"], "inconclusive")
        self.assertIn("unsupported_aggregation", result["uncertainties"])
        self.assertEqual(result["witnesses"], [])

    def test_known_allow_is_preserved_with_unresolved_source_uncertainty(self):
        aggregate = role("aggregate", kind="ClusterRole")
        aggregate["aggregationRule"] = {"clusterRoleSelectors": [{}]}
        model = snapshot(role(), binding(), aggregate, binding("missing", role_name="absent"))
        result = self.analyze(model)["results"][0]
        self.assertEqual(result["decision"], "allow_in_supplied_model")
        self.assertEqual(
            result["uncertainties"], ["unresolved_role_reference", "unsupported_aggregation"]
        )
        self.assertEqual(len(result["witnesses"]), 1)
        adverse = self.analyze(model, [query(principal="bob")])["results"][0]
        self.assertEqual(adverse["decision"], "inconclusive")

    def test_unknown_scope_and_empty_snapshot_do_not_claim_cluster_denial(self):
        self.assertEqual(
            self.decisions(snapshot(), [query(resource_scope="unknown")]), ["inconclusive"]
        )
        document = self.analyze({"objects": []})
        self.assertEqual(document["results"][0]["decision"], "no_matching_allow_in_supplied_model")
        self.assertIn("not effective cluster denial", " ".join(document["limitations"]))

    def test_duplicate_objects_and_query_ids_are_rejected_before_matching(self):
        for other in (role(), role(rules=[rule(resources=["secrets"])])):
            with self.subTest(other=other):
                with patch.object(
                    rbac, "_rule_matches", side_effect=AssertionError("must not match")
                ):
                    with self.assertRaises(rbac.KubernetesRbacAnalysisError):
                        self.analyze(snapshot(role(), other, binding()))
        with self.assertRaises(rbac.KubernetesRbacAnalysisError):
            self.analyze(queries=[query(), query()])

    def test_conflicting_scopes_and_unknown_fields_are_rejected(self):
        with self.assertRaises(rbac.KubernetesRbacAnalysisError):
            self.analyze(queries=[query("a"), query("b", resource_scope="cluster", namespace="")])
        for location in ("object", "rule", "metadata", "query"):
            with self.subTest(location=location):
                model, queries = snapshot(), [query()]
                target = {
                    "object": model["objects"][0],
                    "rule": model["objects"][0]["rules"][0],
                    "metadata": model["objects"][0]["metadata"],
                    "query": queries[0],
                }[location]
                target["unknown"] = True
                with self.assertRaises(rbac.KubernetesRbacAnalysisError):
                    self.analyze(model, queries)

    def test_subject_api_group_namespace_and_role_reference_forms_are_checked(self):
        invalid = [
            subject(kind="User", namespace="team-a"),
            {**subject(), "apiGroup": ""},
            {**subject("runner", kind="ServiceAccount"), "apiGroup": rbac.RBAC_GROUP},
            subject("Bad.Name", kind="ServiceAccount"),
            subject("a..b", kind="ServiceAccount"),
            {**subject(), "namespace": False},
            {**subject(), "namespace": 0},
            {**subject(), "namespace": None},
            {**subject(), "kind": "Unsupported"},
        ]
        for item in invalid:
            with self.subTest(subject=item):
                with self.assertRaises(rbac.KubernetesRbacAnalysisError):
                    self.analyze(snapshot(role(), binding(subjects=[item])))
        for item in (
            binding(kind="ClusterRoleBinding", role_kind="Role"),
            binding(
                kind="ClusterRoleBinding",
                role_kind="ClusterRole",
                subjects=[subject("runner", kind="ServiceAccount")],
            ),
        ):
            with self.assertRaises(rbac.KubernetesRbacAnalysisError):
                self.analyze(snapshot(role(kind="ClusterRole"), item))
        model = snapshot()
        model["objects"][1]["roleRef"]["apiGroup"] = "other.example"
        with self.assertRaises(rbac.KubernetesRbacAnalysisError):
            self.analyze(model)

    def test_nonresource_rules_never_grant_a_resource_query(self):
        url_rule = {"verbs": ["get"], "nonResourceURLs": ["*"]}
        model = snapshot(
            role(kind="ClusterRole", rules=[url_rule]),
            binding(kind="ClusterRoleBinding", role_kind="ClusterRole"),
        )
        self.assertEqual(self.decisions(model, [query()]), ["no_matching_allow_in_supplied_model"])
        for invalid_rule in (
            url_rule,
            {**url_rule, "resources": ["pods"]},
            {"verbs": []},
            {"verbs": ["get"], "apiGroups": [], "resources": ["pods"]},
        ):
            with self.subTest(rule=invalid_rule):
                with self.assertRaises(rbac.KubernetesRbacAnalysisError):
                    self.analyze(snapshot(role(rules=[invalid_rule]), binding()))

    def test_input_and_exports_are_detached_and_frozen(self):
        model, queries = snapshot(), [query()]
        saved = copy.deepcopy((model, queries))
        record = rbac.analyze_kubernetes_rbac(model, queries)
        original = record.to_json()
        self.assertEqual((model, queries), saved)
        model["objects"][0]["rules"][0]["resources"].append("secrets")
        queries[0]["groups"].append("admin")
        exported = record.to_dict()
        exported["effects"]["qualification"] = "granted"
        exported["snapshot"]["objects"].clear()
        self.assertEqual(record.to_json(), original)
        with self.assertRaises(FrozenInstanceError):
            record.document_json = "{}"

    def test_list_permutation_preserves_reasoning_but_not_false_source_addresses(self):
        model = snapshot(
            role(rules=[rule(), rule(verbs=["update"])]),
            binding(subjects=[subject(), subject("readers", kind="Group")]),
        )
        queries = [query("a", groups=["readers", "other"]), query("b", verb="update")]
        first = self.analyze(model, queries)
        changed_model, changed_queries = copy.deepcopy(model), copy.deepcopy(queries)
        changed_model["objects"].reverse()
        changed_model["objects"][0]["subjects"].reverse()
        changed_model["objects"][1]["rules"].reverse()
        changed_queries.reverse()
        changed_queries[1]["groups"].reverse()
        second = self.analyze(changed_model, changed_queries)
        first_facts = [
            {k: v for k, v in row.items() if k != "query_sha256"} for row in first["results"]
        ]
        second_facts = [
            {k: v for k, v in row.items() if k != "query_sha256"} for row in second["results"]
        ]
        self.assertEqual(first_facts, second_facts)
        self.assertNotEqual(first["snapshot_sha256"], second["snapshot_sha256"])
        self.assertNotEqual(first["queries_sha256"], second["queries_sha256"])
        self.assertEqual(second, self.analyze(changed_model, changed_queries))

    def test_coherently_rehashed_false_allow_cannot_replay(self):
        document = self.analyze({"objects": []})
        document["results"][0]["decision"] = "allow_in_supplied_model"
        document["results"][0]["witnesses"] = [
            {
                "binding": ["RoleBinding", "team-a", "invented"],
                "role": ["Role", "team-a", "invented"],
                "rule_sha256": "sha256:" + "a" * 64,
                "subjects": [subject()],
            }
        ]
        forged = readdress(document)
        self.assertEqual(forged, readdress(forged))
        for parse in (
            rbac.KubernetesRbacAnalysis.from_dict,
            lambda value: rbac.KubernetesRbacAnalysis.from_json(encode(value)),
            lambda value: rbac.verify_kubernetes_rbac_analysis(
                value, snapshot={"objects": []}, queries=[query()]
            ),
        ):
            with self.assertRaises(rbac.KubernetesRbacAnalysisError):
                parse(forged)

    def test_exact_typed_replay_rejects_altered_addresses_effects_and_omissions(self):
        for field, value in (
            ("schema_version", True),
            ("schema_version", 1.0),
            ("analysis_sha256", "sha256:" + "a" * 64),
            ("snapshot_sha256", "sha256:" + "b" * 64),
            ("profile_id", "AOE-GC-D15-S05"),
            ("qualification_effect", "none"),
        ):
            with self.subTest(field=field, value=value):
                changed = self.analyze()
                changed[field] = value
                with self.assertRaises(rbac.KubernetesRbacAnalysisError):
                    rbac.KubernetesRbacAnalysis.from_dict(changed)
        changed = self.analyze()
        del changed["source_issues"]
        with self.assertRaises(rbac.KubernetesRbacAnalysisError):
            rbac.KubernetesRbacAnalysis.from_dict(changed)
        changed = self.analyze()
        changed["effects"]["execution"] = "granted"
        with self.assertRaises(rbac.KubernetesRbacAnalysisError):
            rbac.KubernetesRbacAnalysis.from_dict(readdress(changed))

    def test_explicit_replay_rejects_truthful_different_source_or_query(self):
        model, queries = snapshot(), [query()]
        record = rbac.analyze_kubernetes_rbac(model, queries)
        different_model = snapshot(role(rules=[rule(resources=["secrets"])]), binding())
        different_queries = [query(name="pod-two")]
        for selected_model, selected_queries in (
            (different_model, queries),
            (model, different_queries),
        ):
            with self.assertRaises(rbac.KubernetesRbacAnalysisError):
                rbac.verify_kubernetes_rbac_analysis(
                    record, snapshot=selected_model, queries=selected_queries
                )
            fresh = rbac.analyze_kubernetes_rbac(selected_model, selected_queries)
            self.assertEqual(
                fresh.to_dict(),
                rbac.verify_kubernetes_rbac_analysis(
                    fresh,
                    snapshot=selected_model,
                    queries=selected_queries,
                ).to_dict(),
            )

    def test_byte_parser_has_canonical_content_not_raw_spelling_provenance(self):
        model, queries = snapshot(), [query()]
        compact = rbac.analyze_kubernetes_rbac_bytes(
            snapshot_bytes=encode(model), queries_bytes=encode(queries)
        )
        pretty = rbac.analyze_kubernetes_rbac_bytes(
            snapshot_bytes=json.dumps(model, indent=2).encode(),
            queries_bytes=json.dumps(queries, indent=2).encode(),
        )
        self.assertEqual(compact.to_json(), pretty.to_json())

    def test_duplicate_json_keys_are_rejected_at_every_input_boundary(self):
        duplicates = (
            b'{"objects":[],"objects":[]}',
            b'{"objects":[{"metadata":{"name":"one","name":"two"}}]}',
        )
        for raw in duplicates:
            with self.assertRaises(rbac.KubernetesRbacAnalysisError):
                rbac.analyze_kubernetes_rbac_bytes(
                    snapshot_bytes=raw, queries_bytes=encode([query()])
                )
        with self.assertRaises(rbac.KubernetesRbacAnalysisError):
            rbac.analyze_kubernetes_rbac_bytes(
                snapshot_bytes=encode(snapshot()),
                queries_bytes=b'[{"query_id":"a","query_id":"b"}]',
            )
        raw = encode(self.analyze()).replace(
            b'"qualification":"none"', b'"qualification":"none","qualification":"granted"'
        )
        with self.assertRaises(rbac.KubernetesRbacAnalysisError):
            rbac.KubernetesRbacAnalysis.from_json(raw)

    def test_byte_parser_rejects_non_native_numeric_utf8_depth_and_size_failures(self):
        for raw in (
            b"",
            b"null",
            b"NaN",
            b"1.0",
            b"Infinity",
            b"\xff",
            b'"\\ud800"',
            b"[" * 25 + b"0" + b"]" * 25,
            b" " * (rbac.MAX_JSON_BYTES + 1),
        ):
            with self.subTest(raw=raw[:40]):
                with self.assertRaises(rbac.KubernetesRbacAnalysisError):
                    rbac.analyze_kubernetes_rbac_bytes(
                        snapshot_bytes=raw, queries_bytes=encode([query()])
                    )
        with self.assertRaises(rbac.KubernetesRbacAnalysisError):
            rbac.analyze_kubernetes_rbac_bytes(
                snapshot_bytes=bytearray(encode(snapshot())), queries_bytes=encode([query()])
            )

    def test_native_alias_cycles_and_shared_tree_budget_are_checked_before_hashing(self):
        class Alias(dict):
            def items(self):
                raise AssertionError("alias hooks must not run")

        for model in (
            Alias(snapshot()),
            {"objects": True},
            {"objects": [1]},
            {"objects": [], "extra": 0.0},
        ):
            with self.assertRaises(rbac.KubernetesRbacAnalysisError):
                self.analyze(model)
        cycle = {}
        cycle["cycle"] = cycle
        with self.assertRaises(rbac.KubernetesRbacAnalysisError):
            self.analyze(cycle)
        shared = ["a"] * 10
        with (
            patch.object(rbac, "MAX_NODES", 30),
            patch.object(
                rbac,
                "_hash",
                side_effect=AssertionError("must bound before hashing"),
            ),
        ):
            with self.assertRaises(rbac.KubernetesRbacAnalysisError):
                self.analyze({"objects": [shared] * 4})

    def test_native_semantic_fields_reject_boolean_and_numeric_substitution(self):
        for field in (
            "query_id",
            "principal",
            "namespace",
            "api_group",
            "resource",
            "verb",
            "name",
        ):
            for value in (True, 1, 1.0, None):
                with self.subTest(field=field, value=value):
                    with self.assertRaises(rbac.KubernetesRbacAnalysisError):
                        self.analyze(queries=[query(**{field: value})])
        for field in ("verbs", "apiGroups", "resources", "resourceNames"):
            model = snapshot()
            model["objects"][0]["rules"][0][field] = [True]
            with self.assertRaises(rbac.KubernetesRbacAnalysisError):
                self.analyze(model)

    def test_object_query_and_rule_limits_reject_without_partial_results(self):
        with self.assertRaises(rbac.KubernetesRbacAnalysisError):
            self.analyze({"objects": [role(str(index)) for index in range(rbac.MAX_OBJECTS + 1)]})
        with self.assertRaises(rbac.KubernetesRbacAnalysisError):
            self.analyze(queries=[query(str(index)) for index in range(rbac.MAX_QUERIES + 1)])
        with self.assertRaises(rbac.KubernetesRbacAnalysisError):
            self.analyze(snapshot(role(rules=[rule()] * (rbac.MAX_VALUES + 1)), binding()))

    def test_repeated_role_reference_work_is_bounded_before_matching(self):
        many_rules = [rule(groups=[""] + [f"g{index}" for index in range(32)]) for _ in range(128)]
        model = snapshot(role(rules=many_rules), *(binding(str(index)) for index in range(17)))
        queries = [query(str(index)) for index in range(128)]
        with patch.object(rbac, "_rule_matches", side_effect=AssertionError("must not match")):
            with self.assertRaisesRegex(rbac.KubernetesRbacAnalysisError, "Matching work budget"):
                self.analyze(model, queries)

    def test_witness_limit_rejects_instead_of_silently_truncating(self):
        many_rules = [rule(groups=["", f"g{index}"]) for index in range(128)]
        model = snapshot(role(rules=many_rules), *(binding(str(index)) for index in range(17)))
        with self.assertRaisesRegex(rbac.KubernetesRbacAnalysisError, "Witness budget"):
            self.analyze(model)

    def test_witness_selects_one_deterministic_subject_without_expanding_all_matches(self):
        subjects = [subject(f"group-{index}", kind="Group") for index in range(128)]
        model = snapshot(role(), binding(subjects=subjects))
        queries = [query(groups=[item["name"] for item in subjects])]
        first = self.analyze(model, queries)
        witness = first["results"][0]["witnesses"][0]
        self.assertEqual(len(witness["subjects"]), 1)
        self.assertEqual(witness["subjects"][0]["name"], "group-0")
        model["objects"][1]["subjects"].reverse()
        self.assertEqual(witness, self.analyze(model, queries)["results"][0]["witnesses"][0])


if __name__ == "__main__":
    unittest.main()
