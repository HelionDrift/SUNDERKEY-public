"""Actual supplied Service joins and independently derived finite relational controls."""

from __future__ import annotations

import copy
import hashlib
import itertools
import json
import unittest
from dataclasses import FrozenInstanceError
from unittest.mock import patch

from sunderkey import offline_kubernetes_service_analysis as s


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _pod(name, address, *, namespace="demo", ready=True, labels=None, target=8080):
    return {
        "namespace": namespace,
        "name": name,
        "uid": f"uid-{namespace}-{name}",
        "labels": {"app": "api"} if labels is None else labels,
        "phase": "Running",
        "terminating": False,
        "ip": address,
        "ready": ready,
        "container_ports": [{"name": "web", "protocol": "TCP", "port": target}],
    }


def _slice(service, pod, *, number=8080, name="slice-a"):
    return {
        "namespace": service["namespace"],
        "name": name,
        "uid": f"uid-{name}",
        "address_type": service["ip_family"],
        "service_name": service["name"],
        "managed_by": "endpointslice-controller.k8s.io",
        "owner": {
            "api_version": "v1",
            "kind": "Service",
            "name": service["name"],
            "uid": service["uid"],
            "controller": True,
        },
        "ports": [{"name": "http", "protocol": "TCP", "port": number}],
        "endpoints": [
            {
                "addresses": [pod["ip"]],
                "target_ref": {
                    "kind": "Pod",
                    "namespace": pod["namespace"],
                    "name": pod["name"],
                    "uid": pod["uid"],
                },
                "conditions": {
                    "ready": service["publish_not_ready_addresses"] or pod["ready"],
                    "serving": pod["ready"],
                    "terminating": False,
                },
            }
        ],
    }


def component_fixture():
    """Fresh public inert projection, with two named targets and an unselected namespace."""
    return s.component_fixture()


def _readdress(document):
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = (
        "sha256:"
        + hashlib.sha256(
            s.DOMAIN.encode("ascii") + b"\n" + _canonical(body).encode("ascii")
        ).hexdigest()
    )
    document["analysis_sha256"] = digest
    document["analysis_id"] = "KSE-" + digest[7:39].upper()
    return document


def _tuple_key(row):
    return (
        row["pod_namespace"],
        row["pod_name"],
        row["pod_uid"],
        row["address"],
        row["port_name"],
        row["protocol"],
        row["port"],
    )


class KubernetesServiceAnalysisTests(unittest.TestCase):
    def analyze(self, model=None):
        return s.analyze_supplied_kubernetes_service_endpoints(
            component_fixture() if model is None else model
        )

    def codes(self, report, kind="uncertainties"):
        return {row["code"] for row in report.to_dict()[kind]}

    def test_fresh_fixture_has_literal_addresses_and_actual_named_targets(self):
        report = self.analyze()
        document = report.to_dict()
        self.assertEqual(document["analysis_id"], "KSE-1EE03ABF668C8C665E649CB1B8DF0DF5")
        self.assertEqual(
            document["analysis_sha256"],
            "sha256:1ee03abf668c8c665e649cb1b8df0df515315b6c5ea8626e1dbc2a96017ad598",
        )
        self.assertEqual(
            document["source_model_sha256"],
            "sha256:84c499368cef6462d0b67331195cc98a42a7979c1079bd541c61fed302f49786",
        )
        self.assertEqual(
            document["summary"],
            {
                "status": "consistent_supplied_subset",
                "selected_pod_count": 2,
                "expected_tuple_count": 2,
                "observed_tuple_count": 2,
                "identical_duplicate_tuple_count": 0,
            },
        )
        self.assertEqual(
            [row["port"] for row in document["expected_endpoint_tuples"]], [8080, 9090]
        )
        self.assertEqual(
            [row["serving"] for row in document["expected_endpoint_tuples"]], [True, False]
        )

    def test_native_and_byte_public_apis_share_canonical_projection_identity(self):
        model = component_fixture()
        native = self.analyze(model)
        raw = s.analyze_supplied_kubernetes_service_endpoints_bytes(
            model_bytes=json.dumps(model, indent=2).encode("ascii")
        )
        self.assertEqual(raw.to_json(), native.to_json())
        reordered = {key: model[key] for key in reversed(list(model))}
        self.assertEqual(self.analyze(reordered).to_json(), native.to_json())

    def test_frozen_roundtrips_and_separately_supplied_original_verification(self):
        model = component_fixture()
        report = self.analyze(model)
        self.assertEqual(
            s.KubernetesServiceAnalysis.from_dict(report.to_dict()).to_json(), report.to_json()
        )
        self.assertEqual(
            s.KubernetesServiceAnalysis.from_json(report.to_json()).to_dict(), report.to_dict()
        )
        self.assertEqual(
            s.verify_supplied_kubernetes_service_analysis(report, model=model).to_json(),
            report.to_json(),
        )
        with self.assertRaises(FrozenInstanceError):
            report.document_json = "{}"

    def test_inputs_exports_and_helpers_are_detached(self):
        model = component_fixture()
        report = self.analyze(model)
        before = report.to_json()
        model["pods"].clear()
        exported = report.to_dict()
        exported["source_model"]["pods"].clear()
        exported["expected_endpoint_tuples"].clear()
        self.assertEqual(report.to_json(), before)
        fresh = component_fixture()
        fresh["pods"].clear()
        self.assertEqual(len(component_fixture()["pods"]), 3)

    def test_numeric_targets_do_not_require_a_declared_container_port(self):
        model = component_fixture()
        model["service"]["ports"][0]["target_port"] = 8080
        for pod in model["pods"]:
            pod["container_ports"] = []
        model["endpoint_slices"][1]["ports"][0]["port"] = 8080
        self.assertEqual(
            self.analyze(model).to_dict()["summary"]["status"], "consistent_supplied_subset"
        )

    def test_named_targets_are_protocol_specific_not_just_same_spelling(self):
        model = component_fixture()
        model["pods"][0]["container_ports"].insert(
            0, {"name": "web", "protocol": "UDP", "port": 7070}
        )
        self.assertEqual(self.analyze(model).to_dict()["expected_endpoint_tuples"][0]["port"], 8080)
        model["pods"][0]["container_ports"].pop()
        self.assertIn("named_target_port_missing", self.codes(self.analyze(model)))

    def test_missing_named_target_withholds_absence_and_extra_inference(self):
        model = component_fixture()
        model["pods"][0]["container_ports"] = []
        report = self.analyze(model)
        self.assertIn("named_target_port_missing", self.codes(report))
        self.assertEqual(report.to_dict()["summary"]["status"], "inconclusive")
        self.assertEqual(report.to_dict()["missing_endpoint_tuples"], [])
        self.assertEqual(report.to_dict()["unexpected_endpoint_tuples"], [])

    def test_multiple_named_matches_even_identical_numbers_are_unresolved(self):
        model = component_fixture()
        model["pods"][0]["container_ports"] *= 2
        self.assertIn("named_target_port_ambiguous", self.codes(self.analyze(model)))

    def test_ready_and_serving_remain_distinct_when_publish_not_ready_is_enabled(self):
        model = component_fixture()
        model["service"]["publish_not_ready_addresses"] = True
        model["endpoint_slices"][1]["endpoints"][0]["conditions"]["ready"] = True
        document = self.analyze(model).to_dict()
        self.assertEqual(document["summary"]["status"], "consistent_supplied_subset")
        self.assertTrue(document["expected_endpoint_tuples"][1]["ready"])
        self.assertFalse(document["expected_endpoint_tuples"][1]["serving"])

    def test_condition_contradictions_use_the_exact_joined_pod(self):
        for condition in ("ready", "serving", "terminating"):
            with self.subTest(condition=condition):
                model = component_fixture()
                endpoint = model["endpoint_slices"][0]["endpoints"][0]
                endpoint["conditions"][condition] = not endpoint["conditions"][condition]
                report = self.analyze(model)
                self.assertEqual(
                    report.to_dict()["summary"]["status"], "inconsistent_supplied_subset"
                )
                self.assertIn(
                    f"endpoint_{condition}_differs_from_pod_projection",
                    self.codes(report, "contradictions"),
                )

    def test_null_pod_or_endpoint_conditions_do_not_default_to_current_health(self):
        for field in ("pod", "ready", "serving", "terminating"):
            with self.subTest(field=field):
                model = component_fixture()
                if field == "pod":
                    model["pods"][0]["ready"] = None
                else:
                    model["endpoint_slices"][0]["endpoints"][0]["conditions"][field] = None
                self.assertEqual(self.analyze(model).to_dict()["summary"]["status"], "inconclusive")

    def test_null_pod_address_is_not_a_predicted_controller_omission(self):
        model = component_fixture()
        model["pods"][0]["ip"] = None
        report = self.analyze(model)
        self.assertIn("pod_address_not_declared", self.codes(report))
        self.assertEqual(report.to_dict()["missing_endpoint_tuples"], [])

    def test_namespace_and_equality_selector_both_constrain_pod_membership(self):
        model = component_fixture()
        model["service"]["selector"]["tier"] = "backend"
        model["pods"][0]["labels"]["tier"] = "backend"
        model["pods"][1]["labels"]["tier"] = "wrong"
        document = self.analyze(model).to_dict()
        self.assertEqual([row["name"] for row in document["selected_pods"]], ["api-a"])
        self.assertEqual(document["summary"]["status"], "inconsistent_supplied_subset")

    def test_owned_slice_bindings_are_all_required_without_defaulting(self):
        mutations = [
            ("namespace", "other"),
            ("service_name", "other"),
            ("managed_by", "custom-controller"),
            ("owner.api_version", "v2"),
            ("owner.kind", "Other"),
            ("owner.name", "other"),
            ("owner.uid", "different-service-uid"),
            ("owner.controller", False),
        ]
        for key, value in mutations:
            with self.subTest(key=key):
                model = component_fixture()
                target = model["endpoint_slices"][0]
                parts = key.split(".")
                if len(parts) == 2:
                    target = target[parts[0]]
                target[parts[-1]] = value
                report = self.analyze(model)
                self.assertIn("slice_service_ownership_or_family_not_joined", self.codes(report))
                self.assertEqual(report.to_dict()["summary"]["status"], "inconclusive")

    def test_target_reference_namespace_name_uid_and_kind_are_exact(self):
        for key, value in (
            ("namespace", "other"),
            ("name", "other"),
            ("uid", "other-uid"),
            ("kind", "Other"),
        ):
            with self.subTest(key=key):
                model = component_fixture()
                model["endpoint_slices"][0]["endpoints"][0]["target_ref"][key] = value
                report = self.analyze(model)
                self.assertIn("endpoint_pod_identity_not_joined", self.codes(report))
                self.assertEqual(report.to_dict()["summary"]["status"], "inconclusive")

    def test_known_foreign_pod_or_wrong_ip_is_a_supplied_contradiction(self):
        model = component_fixture()
        model["endpoint_slices"][0] = _slice(model["service"], model["pods"][2])
        self.assertIn(
            "endpoint_pod_not_selected", self.codes(self.analyze(model), "contradictions")
        )
        model = component_fixture()
        model["endpoint_slices"][0]["endpoints"][0]["addresses"] = ["10.0.0.99"]
        self.assertIn(
            "endpoint_address_differs_from_pod", self.codes(self.analyze(model), "contradictions")
        )

    def test_named_or_numeric_resolved_port_mismatch_is_not_normalized(self):
        model = component_fixture()
        model["endpoint_slices"][0]["ports"][0]["port"] = 8081
        report = self.analyze(model)
        self.assertIn(
            "endpoint_port_differs_from_named_or_numeric_target",
            self.codes(report, "contradictions"),
        )
        self.assertEqual(report.to_dict()["summary"]["status"], "inconsistent_supplied_subset")

    def test_missing_extra_and_zero_endpoint_sets_have_honest_statuses(self):
        model = component_fixture()
        model["endpoint_slices"].pop()
        document = self.analyze(model).to_dict()
        self.assertEqual(len(document["missing_endpoint_tuples"]), 1)
        self.assertEqual(document["summary"]["status"], "inconsistent_supplied_subset")
        model = component_fixture()
        model["pods"] = []
        model["endpoint_slices"] = []
        document = self.analyze(model).to_dict()
        self.assertEqual(document["summary"]["status"], "consistent_supplied_subset")
        self.assertEqual(document["summary"]["expected_tuple_count"], 0)
        model = component_fixture()
        model["endpoint_slices"][0]["ports"][0]["name"] = "other"
        self.assertEqual(len(self.analyze(model).to_dict()["unexpected_endpoint_tuples"]), 1)

    def test_each_inventory_completeness_declaration_withholds_set_absence_claims(self):
        for field in ("pods_complete", "endpoint_slices_complete"):
            model = component_fixture()
            model["coverage"][field] = False
            model["endpoint_slices"] = []
            document = self.analyze(model).to_dict()
            self.assertEqual(document["summary"]["status"], "inconclusive")
            self.assertEqual(document["missing_endpoint_tuples"], [])

    def test_identical_duplicates_across_slices_are_one_observation_not_conflict(self):
        model = component_fixture()
        duplicate = copy.deepcopy(model["endpoint_slices"][0])
        duplicate["name"] = "slice-copy"
        duplicate["uid"] = "uid-slice-copy"
        model["endpoint_slices"].append(duplicate)
        document = self.analyze(model).to_dict()
        self.assertEqual(document["summary"]["status"], "consistent_supplied_subset")
        self.assertEqual(document["summary"]["observed_tuple_count"], 2)
        self.assertEqual(document["summary"]["identical_duplicate_tuple_count"], 1)

    def test_conflicting_duplicate_conditions_are_retained_and_inconclusive(self):
        model = component_fixture()
        duplicate = copy.deepcopy(model["endpoint_slices"][0])
        duplicate["name"] = "slice-conflict"
        duplicate["uid"] = "uid-slice-conflict"
        duplicate["endpoints"][0]["conditions"]["ready"] = False
        model["endpoint_slices"].append(duplicate)
        document = self.analyze(model).to_dict()
        self.assertIn(
            "conflicting_duplicate_endpoint_observations", self.codes(self.analyze(model))
        )
        self.assertEqual(document["summary"]["observed_tuple_count"], 3)
        self.assertEqual(document["summary"]["status"], "inconclusive")

    def test_duplicate_pod_address_with_different_identity_is_uncertain(self):
        model = component_fixture()
        model["pods"][1]["ip"] = model["pods"][0]["ip"]
        model["endpoint_slices"] = []
        self.assertIn("pod_address_identity_is_ambiguous", self.codes(self.analyze(model)))

    def test_empty_port_observation_does_not_silently_disappear(self):
        model = component_fixture()
        model["endpoint_slices"][0]["ports"] = []
        report = self.analyze(model)
        self.assertIn("endpoint_has_no_projected_ports", self.codes(report))
        self.assertEqual(report.to_dict()["summary"]["status"], "inconclusive")

    def test_ipv6_subset_and_mismatching_slice_family_are_distinguished(self):
        model = component_fixture()
        model["service"]["ip_family"] = "IPv6"
        model["service"]["cluster_ip"] = "fd00::10"
        for index, pod in enumerate(model["pods"]):
            pod["ip"] = f"fd01::{index + 1}"
        for index, slice_ in enumerate(model["endpoint_slices"]):
            slice_["address_type"] = "IPv6"
            slice_["endpoints"][0]["addresses"] = [model["pods"][index]["ip"]]
        self.assertEqual(
            self.analyze(model).to_dict()["summary"]["status"], "consistent_supplied_subset"
        )
        model["endpoint_slices"][0]["address_type"] = "IPv4"
        model["endpoint_slices"][0]["endpoints"][0]["addresses"] = ["10.0.0.1"]
        self.assertEqual(self.analyze(model).to_dict()["summary"]["status"], "inconclusive")

    def test_multiport_service_joins_each_name_protocol_and_actual_number(self):
        model = component_fixture()
        model["service"]["ports"].append(
            {"name": "dns", "protocol": "UDP", "port": 53, "target_port": 5353}
        )
        for slice_ in model["endpoint_slices"]:
            slice_["ports"].append({"name": "dns", "protocol": "UDP", "port": 5353})
        document = self.analyze(model).to_dict()
        self.assertEqual(document["summary"]["status"], "consistent_supplied_subset")
        self.assertEqual(document["summary"]["expected_tuple_count"], 4)

    def test_source_list_permutation_changes_identity_not_relational_mathematics(self):
        model = component_fixture()
        first = self.analyze(model).to_dict()
        model["pods"].reverse()
        model["endpoint_slices"].reverse()
        second = self.analyze(model).to_dict()
        self.assertNotEqual(first["source_model_sha256"], second["source_model_sha256"])
        for key in (
            "summary",
            "selected_pods",
            "expected_endpoint_tuples",
            "observed_endpoint_tuples",
        ):
            self.assertEqual(first[key], second[key])

    def test_independent_small_label_namespace_port_and_uid_relational_oracle(self):
        cases = 0
        for namespace, label, protocol, ready, publish, target in itertools.product(
            ("demo", "other"),
            ("api", "other"),
            ("TCP", "UDP"),
            (False, True),
            (False, True),
            (8080, "web"),
        ):
            model = component_fixture()
            pod = _pod("only", "10.0.0.20", namespace=namespace, labels={"app": label}, ready=ready)
            pod["container_ports"][0]["protocol"] = protocol
            model["pods"] = [pod]
            model["service"]["ports"][0]["target_port"] = target
            model["service"]["publish_not_ready_addresses"] = publish
            model["endpoint_slices"] = []
            selected = namespace == "demo" and label == "api"
            resolved = isinstance(target, int) or protocol == "TCP"
            if selected and resolved:
                model["endpoint_slices"] = [_slice(model["service"], pod)]
            document = self.analyze(model).to_dict()
            expected = []
            if selected and resolved:
                expected.append((namespace, "only", pod["uid"], "10.0.0.20", "http", "TCP", 8080))
            self.assertEqual(
                [_tuple_key(row) for row in document["expected_endpoint_tuples"]], expected
            )
            self.assertEqual(document["summary"]["selected_pod_count"], int(selected))
            self.assertEqual(
                document["summary"]["status"],
                "inconclusive" if selected and not resolved else "consistent_supplied_subset",
            )
            if expected:
                self.assertEqual(document["expected_endpoint_tuples"][0]["ready"], ready or publish)
                self.assertEqual(document["expected_endpoint_tuples"][0]["serving"], ready)
            cases += 1
        self.assertEqual(cases, 64)

    def test_unsupported_declared_features_withhold_consistency_not_known_witnesses(self):
        for feature in s._UNSUPPORTED:
            model = component_fixture()
            model["unsupported_features"] = [feature]
            document = self.analyze(model).to_dict()
            self.assertEqual(document["summary"]["status"], "inconclusive")
            self.assertEqual(document["summary"]["observed_tuple_count"], 2)

    def test_excluded_service_and_pod_modes_are_closed_subset_rejections(self):
        cases = [
            ("service", "type", "ExternalName"),
            ("service", "cluster_ip", "None"),
            ("service", "selector", {}),
            ("pod", "phase", "Succeeded"),
            ("pod", "terminating", True),
        ]
        for kind, field, value in cases:
            with self.subTest(field=field):
                model = component_fixture()
                target = model["service"] if kind == "service" else model["pods"][0]
                target[field] = value
                with self.assertRaises(s.KubernetesServiceAnalysisError):
                    self.analyze(model)

    def test_duplicate_inventory_names_uids_and_ports_are_rejected_before_hash(self):
        for kind in (
            "pod-name",
            "pod-uid",
            "slice-name",
            "slice-uid",
            "service-port",
            "slice-port",
        ):
            with self.subTest(kind=kind):
                model = component_fixture()
                if kind == "pod-name":
                    model["pods"].append(copy.deepcopy(model["pods"][0]))
                elif kind == "pod-uid":
                    model["pods"][1]["uid"] = model["pods"][0]["uid"]
                elif kind == "slice-name":
                    model["endpoint_slices"].append(copy.deepcopy(model["endpoint_slices"][0]))
                elif kind == "slice-uid":
                    model["endpoint_slices"][1]["uid"] = model["endpoint_slices"][0]["uid"]
                elif kind == "service-port":
                    model["service"]["ports"] *= 2
                else:
                    model["endpoint_slices"][0]["ports"] *= 2
                with (
                    patch.object(s, "_digest", side_effect=AssertionError("hash")),
                    self.assertRaises(s.KubernetesServiceAnalysisError),
                ):
                    self.analyze(model)

    def test_native_aliases_wrong_types_and_subclasses_do_not_normalize(self):
        class Text(str):
            pass

        class Integer(int):
            pass

        class Mapping(dict):
            pass

        cases = [
            lambda m: m.update(schema_version=True),
            lambda m: m.update(schema_version=1.0),
            lambda m: m["coverage"].update(pods_complete=1),
            lambda m: m["pods"][0].update(ready=1),
            lambda m: m["service"]["ports"][0].update(target_port=True),
            lambda m: m["service"]["ports"][0].update(port=80.0),
            lambda m: m["service"].update(name=Text("api")),
            lambda m: m.update(schema_version=Integer(1)),
            lambda m: m.update(coverage=Mapping(m["coverage"])),
            lambda m: m["service"].update(ports=1),
            lambda m: m["pods"][0].update(container_ports=1),
            lambda m: m["endpoint_slices"][0].update(ports=1),
        ]
        for mutate in cases:
            model = component_fixture()
            mutate(model)
            with (
                patch.object(s, "_digest", side_effect=AssertionError("hash")),
                self.assertRaises(s.KubernetesServiceAnalysisError),
            ):
                self.analyze(model)

    def test_closed_port_arrays_reject_null_int_bool_with_domain_errors(self):
        for family, value in itertools.product(("service", "pod", "slice"), (None, 1, False)):
            with self.subTest(family=family, value=value):
                model = component_fixture()
                if family == "service":
                    model["service"]["ports"] = value
                elif family == "pod":
                    model["pods"][0]["container_ports"] = value
                else:
                    model["endpoint_slices"][0]["ports"] = value
                with patch.object(s, "_digest", side_effect=AssertionError("hash")) as digest:
                    try:
                        self.analyze(model)
                    except Exception as exc:
                        self.assertIsInstance(exc, s.KubernetesServiceAnalysisError)
                    else:
                        self.fail("Malformed closed port array was accepted")
                self.assertEqual(digest.call_count, 0)

    def test_all_replay_export_and_original_verify_work_is_funded_before_hashes(self):
        model = component_fixture()
        report = self.analyze(model)
        text = report.to_json()
        document = report.to_dict()
        operations = {
            "from_dict": lambda: s.KubernetesServiceAnalysis.from_dict(document),
            "from_json": lambda: s.KubernetesServiceAnalysis.from_json(text),
            "to_dict": report.to_dict,
            "to_json": report.to_json,
            "original_verify": lambda: s.verify_supplied_kubernetes_service_analysis(
                report, model=model
            ),
        }
        real_charge = s._Budget.charge
        for name, operation in operations.items():
            with self.subTest(operation=name):
                observed = []

                def observe(budget, amount, observed=observed):
                    real_charge(budget, amount)
                    observed.append(budget.used)

                with patch.object(s._Budget, "charge", observe):
                    valid = operation()
                self.assertTrue(observed)
                required = observed[-1]
                with patch.object(s, "MAX_WORK", required - 1):
                    with patch.object(
                        s, "_digest", side_effect=AssertionError("early hash")
                    ) as digest:
                        try:
                            operation()
                        except Exception as exc:
                            self.assertIsInstance(exc, s.KubernetesServiceAnalysisError)
                        else:
                            self.fail("Insufficient cumulative work was accepted")
                    self.assertEqual(digest.call_count, 0)
                with patch.object(s, "MAX_WORK", required):
                    exact = operation()
                if isinstance(valid, s.KubernetesServiceAnalysis):
                    self.assertEqual(exact.document_json, text)
                else:
                    self.assertEqual(exact, valid)

    def test_coherently_rehashed_false_outputs_effects_and_native_counts_are_denied(self):
        valid = self.analyze().to_dict()
        for field in ("summary", "tuple", "effect", "claim", "schema", "count"):
            with self.subTest(field=field):
                document = copy.deepcopy(valid)
                if field == "summary":
                    document["summary"]["status"] = "inconclusive"
                elif field == "tuple":
                    document["expected_endpoint_tuples"][0]["port"] = 9999
                elif field == "effect":
                    document["effects"]["routing"] = "allowed"
                elif field == "claim":
                    document["claims"]["current_readiness_proven"] = True
                elif field == "schema":
                    document["schema_version"] = True
                else:
                    document["summary"]["selected_pod_count"] = 2.0
                _readdress(document)
                with self.assertRaises(s.KubernetesServiceAnalysisError):
                    s.KubernetesServiceAnalysis.from_dict(document)
                with self.assertRaises(s.KubernetesServiceAnalysisError):
                    s.KubernetesServiceAnalysis.from_json(_canonical(document))

    def test_valid_alternate_embedded_source_is_not_the_separately_supplied_original(self):
        original = component_fixture()
        alternate = copy.deepcopy(original)
        alternate["service"]["publish_not_ready_addresses"] = True
        alternate["endpoint_slices"][1]["endpoints"][0]["conditions"]["ready"] = True
        report = self.analyze(alternate)
        self.assertEqual(
            s.KubernetesServiceAnalysis.from_json(report.to_json()).to_json(), report.to_json()
        )
        with self.assertRaises(s.KubernetesServiceAnalysisError):
            s.verify_supplied_kubernetes_service_analysis(report, model=original)

    def test_late_wrapper_mutation_missing_slot_and_wrong_family_deny(self):
        report = self.analyze()
        object.__setattr__(report, "document_json", "{}")
        for call in (report.to_dict, report.to_json):
            with self.assertRaises(s.KubernetesServiceAnalysisError):
                call()
        missing = object.__new__(s.KubernetesServiceAnalysis)
        with self.assertRaises(s.KubernetesServiceAnalysisError):
            missing.to_dict()
        with self.assertRaises(s.KubernetesServiceAnalysisError):
            s.verify_supplied_kubernetes_service_analysis({}, model=component_fixture())

    def test_raw_duplicate_keys_aliases_floats_and_nonfinite_deny_before_hash(self):
        content = _canonical(component_fixture())
        cases = [
            content.replace('"schema_version":1', '"schema_version":1,"schema_version":1'),
            content.replace('"schema_version":1', '"schema_version":1,"schema_\\u0076ersion":1'),
            content.replace('"schema_version":1', '"schema_version":1.0'),
            content.replace('"schema_version":1', '"schema_version":NaN'),
            content.replace('"schema_version":1', '"schema_version":Infinity'),
            content.replace('"schema_version":1', '"schema_version":true'),
        ]
        for text in cases:
            with (
                patch.object(s, "_digest", side_effect=AssertionError("hash")),
                self.assertRaises(s.KubernetesServiceAnalysisError),
            ):
                s.analyze_supplied_kubernetes_service_endpoints_bytes(
                    model_bytes=text.encode("ascii")
                )

    def test_raw_lexical_string_depth_nodes_and_integer_limits_precede_decoder(self):
        cases = [
            b"[" * 20 + b"0" + b"]" * 20,
            b"[" + b"0," * s.MAX_MODEL_NODES + b"0]",
            b'"' + b"a" * (s.MAX_STRING_BYTES + 1) + b'"',
            b"9223372036854775808",
            b"-9223372036854775809",
            b"--0",
            b"---1",
            b"9" * 21,
        ]
        for content in cases:
            with (
                patch.object(s.json, "loads", side_effect=AssertionError("decoder")),
                patch.object(s, "_digest", side_effect=AssertionError("hash")),
                self.assertRaises(s.KubernetesServiceAnalysisError),
            ):
                s.analyze_supplied_kubernetes_service_endpoints_bytes(model_bytes=content)

    def test_cycles_repeated_native_subtrees_and_escaped_size_are_charged_before_hash(self):
        model = component_fixture()
        model["pods"].append(model)
        with self.assertRaises(s.KubernetesServiceAnalysisError):
            self.analyze(model)
        shared = {"a": "b"}
        with (
            patch.object(s, "MAX_MODEL_NODES", 10),
            patch.object(s, "_digest", side_effect=AssertionError("hash")),
            self.assertRaises(s.KubernetesServiceAnalysisError),
        ):
            self.analyze([shared, shared, shared])
        with (
            patch.object(s, "MAX_MODEL_BYTES", 10),
            patch.object(s, "_canonical", side_effect=AssertionError("dump")),
            self.assertRaises(s.KubernetesServiceAnalysisError),
        ):
            self.analyze("\\" * 5)

    def test_genuine_aggregate_endpoint_and_tuple_limits_precede_hash(self):
        model = component_fixture()
        model["endpoint_slices"][0]["endpoints"] *= 129
        model["endpoint_slices"][1]["endpoints"] *= 128
        with (
            patch.object(s, "_digest", side_effect=AssertionError("hash")),
            self.assertRaises(s.KubernetesServiceAnalysisError),
        ):
            self.analyze(model)
        model = component_fixture()
        with (
            patch.object(s, "MAX_TUPLES", 1),
            patch.object(s, "_digest", side_effect=AssertionError("hash")),
            self.assertRaises(s.KubernetesServiceAnalysisError),
        ):
            self.analyze(model)

    def test_full_retained_output_and_work_cost_deny_before_first_hash(self):
        model = component_fixture()
        source_bytes = len(_canonical(model))
        report_bytes = len(self.analyze(model).to_json())
        self.assertGreater(report_bytes, source_bytes)
        with (
            patch.object(s, "MAX_REPORT_BYTES", report_bytes - 1),
            patch.object(s, "_digest", side_effect=AssertionError("hash")),
            self.assertRaises(s.KubernetesServiceAnalysisError),
        ):
            self.analyze(model)
        with (
            patch.object(s, "MAX_WORK", 100),
            patch.object(s, "_digest", side_effect=AssertionError("hash")),
            self.assertRaises(s.KubernetesServiceAnalysisError),
        ):
            self.analyze(model)

    def test_genuine_bounded_source_exhausts_production_retained_output_before_hash(self):
        model = component_fixture()
        model["pods"] = [_pod(f"pod-{index}", f"10.1.0.{index + 1}") for index in range(s.MAX_PODS)]
        for pod in model["pods"]:
            pod["container_ports"] = []
        model["service"]["ports"] = [
            {
                "name": f"port-{index}",
                "protocol": "TCP",
                "port": 1000 + index,
                "target_port": 2000 + index,
            }
            for index in range(12)
        ]
        model["endpoint_slices"] = []
        _, size, nodes = s._capture(model, s._Budget())
        self.assertLess(size, s.MAX_MODEL_BYTES)
        self.assertLess(nodes, s.MAX_MODEL_NODES)
        s._validate(model, s._Budget())
        self.assertLess(len(model["pods"]) * len(model["service"]["ports"]), s.MAX_TUPLES)
        with (
            patch.object(s, "_digest", side_effect=AssertionError("hash")) as digest,
            self.assertRaisesRegex(s.KubernetesServiceAnalysisError, "retained result budget"),
        ):
            self.analyze(model)
        self.assertEqual(digest.call_count, 0)

    def test_domain_byte_native_and_nonqualifying_boundaries_remain_explicit(self):
        for content in (bytearray(b"{}"), b"", b"\xff", b" " * (s.MAX_MODEL_BYTES + 1)):
            with self.assertRaises(s.KubernetesServiceAnalysisError):
                s.analyze_supplied_kubernetes_service_endpoints_bytes(model_bytes=content)
        document = self.analyze().to_dict()
        self.assertEqual(set(document["effects"].values()), {"none"})
        self.assertEqual(set(document["claims"].values()), {False})
        self.assertEqual(document["component_id"], s.COMPONENT_ID)
        self.assertEqual(document["profile_id"], "AOE-GC-D15-S07")


if __name__ == "__main__":
    unittest.main()
