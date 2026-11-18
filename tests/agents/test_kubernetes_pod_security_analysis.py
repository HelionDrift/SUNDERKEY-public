"""Independent finite controls for the supplied Linux Pod five-control profile."""

from __future__ import annotations

import copy
import hashlib
import itertools
import json
import unittest
from unittest.mock import patch

from sunderkey import kubernetes_pod_security_analysis as m

_ROLES = ("containers", "init_containers", "ephemeral_containers")


def component_fixture() -> dict:
    """Fresh public-only declarations, not a cluster Pod or runtime observation."""
    return {
        "schema_version": 1,
        "benchmark_version": "kubernetes-v1.34-linux-restricted-core",
        "pod": {
            "pod_ref": "pod:synthetic-restricted-core",
            "os_name": "linux",
            "host_users": None,
            "security_context": {
                "run_as_non_root": True,
                "run_as_user": 1000,
                "seccomp_profile": {"type": "RuntimeDefault", "localhost_profile": None},
            },
            "containers": [_container("container:application")],
            "init_containers": [_container("container:init")],
            "ephemeral_containers": [_container("container:ephemeral")],
        },
    }


def _container(reference: str) -> dict:
    return {
        "container_ref": reference,
        "security_context": {
            "run_as_non_root": None,
            "run_as_user": None,
            "seccomp_profile": None,
            "allow_privilege_escalation": False,
            "capabilities": {"add": [], "drop": ["ALL"]},
        },
    }


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _readdress(document: dict) -> dict:
    payload = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = hashlib.sha256(
        m.REPORT_DOMAIN.encode("ascii") + b"\x00" + _json(payload).encode("ascii")
    )
    hexdigest = digest.hexdigest()
    document["analysis_id"] = "PSA-" + hexdigest[:32].upper()
    document["analysis_sha256"] = "sha256:" + hexdigest
    return document


def _body(model: dict) -> dict:
    return m.analyze_supplied_kubernetes_pod_security(model).to_dict()


def _control(body: dict, control_id: str) -> dict:
    return next(item for item in body["controls"] if item["control_id"] == control_id)


def _set_path(model: dict, path: tuple, value: object) -> None:
    target = model
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value


class PodSecurityAnalysisTests(unittest.TestCase):
    def test_original_fixture_and_literal_report_identity(self) -> None:
        model = component_fixture()
        report = m.analyze_supplied_kubernetes_pod_security(model)
        body = report.to_dict()
        self.assertEqual(body["outcome"], "satisfies_supported_controls")
        self.assertEqual(body["summary"]["container_count"], 3)
        self.assertEqual(body["summary"]["evaluated_check_count"], 21)
        self.assertEqual(body["summary"]["work_steps"], 24)
        self.assertEqual(body["summary"]["violation_count"], 0)
        self.assertEqual(body["source_model"], model)
        self.assertEqual(report.analysis_id, "PSA-A5D9854B996C8ECFFFB7A75C5D2BC2AE")
        self.assertEqual(
            report.analysis_sha256,
            "sha256:a5d9854b996c8ecfffb7a75c5d2bc2ae7068c2e66e0eca5b0970d689daf1d2f2",
        )
        self.assertEqual(
            body["model_sha256"],
            "sha256:92587c6b6eb5f862b15555068ff56c270bad0233d74be0155f700bdd1f6612d8",
        )
        expected_model = (
            "sha256:"
            + hashlib.sha256(
                m.MODEL_DOMAIN.encode("ascii") + b"\x00" + _json(model).encode("ascii")
            ).hexdigest()
        )
        self.assertEqual(body["model_sha256"], expected_model)
        self.assertEqual(_readdress(copy.deepcopy(body)), body)
        self.assertEqual(m.PodSecurityAnalysis.from_json(report.to_json()).to_dict(), body)

    def test_all_three_roles_are_checked_and_source_order_is_preserved(self) -> None:
        model = component_fixture()
        model["pod"]["containers"].append(_container("container:application-second"))
        model["pod"]["containers"][0]["security_context"]["capabilities"]["drop"] = ["CHOWN", "ALL"]
        body = _body(model)
        self.assertEqual(body["source_model"], model)
        checks = _control(body, "allow_privilege_escalation")["checks"]
        self.assertEqual(
            [item["source_path"] for item in checks],
            [
                "pod.containers[0].security_context.allow_privilege_escalation",
                "pod.containers[1].security_context.allow_privilege_escalation",
                "pod.init_containers[0].security_context.allow_privilege_escalation",
                "pod.ephemeral_containers[0].security_context.allow_privilege_escalation",
            ],
        )
        self.assertEqual(body["summary"]["container_count"], 4)

    def test_independent_non_root_nullable_truth_table(self) -> None:
        for role, parent, child in itertools.product(
            _ROLES, (None, False, True), (None, False, True)
        ):
            with self.subTest(role=role, parent=parent, child=child):
                model = component_fixture()
                model["pod"]["security_context"]["run_as_non_root"] = parent
                for family in _ROLES:
                    model["pod"][family][0]["security_context"]["run_as_non_root"] = True
                model["pod"][role][0]["security_context"]["run_as_non_root"] = child
                observed = _control(_body(model), "run_as_non_root")
                effective = parent if child is None else child
                expected_bad = parent is False or effective is not True
                self.assertEqual(observed["outcome"], "violated" if expected_bad else "satisfied")
                site = f"pod.{role}[0].security_context.run_as_non_root"
                check = next(check for check in observed["checks"] if check["source_path"] == site)
                self.assertIs(check["effective_value"], effective)
                expected_path = "pod.security_context.run_as_non_root" if child is None else site
                self.assertEqual(check["effective_source_path"], expected_path)

    def test_independent_uid_nullable_truth_table(self) -> None:
        for role, parent, child in itertools.product(_ROLES, (None, 0, 1000), (None, 0, 2000)):
            with self.subTest(role=role, parent=parent, child=child):
                model = component_fixture()
                model["pod"]["security_context"]["run_as_user"] = parent
                for family in _ROLES:
                    model["pod"][family][0]["security_context"]["run_as_user"] = 3000
                model["pod"][role][0]["security_context"]["run_as_user"] = child
                observed = _control(_body(model), "run_as_user")
                self.assertEqual(
                    observed["outcome"], "violated" if parent == 0 or child == 0 else "satisfied"
                )

    def test_declared_nonzero_uid_does_not_certify_image_uid(self) -> None:
        model = component_fixture()
        model["pod"]["security_context"]["run_as_user"] = None
        body = _body(model)
        self.assertEqual(_control(body, "run_as_user")["outcome"], "satisfied")
        self.assertFalse(body["flags"]["image_uid_verified"])
        model["pod"]["security_context"]["run_as_user"] = (1 << 63) - 1
        self.assertEqual(_body(model)["outcome"], "satisfies_supported_controls")

    def test_independent_seccomp_fallback_truth_table(self) -> None:
        profiles = (
            None,
            {"type": "RuntimeDefault", "localhost_profile": None},
            {"type": "Localhost", "localhost_profile": "profiles/synthetic.json"},
            {"type": "Unconfined", "localhost_profile": None},
        )
        for role, parent, child in itertools.product(_ROLES, profiles, profiles):
            with self.subTest(role=role, parent=parent, child=child):
                model = component_fixture()
                model["pod"]["security_context"]["seccomp_profile"] = copy.deepcopy(parent)
                for family in _ROLES:
                    model["pod"][family][0]["security_context"]["seccomp_profile"] = {
                        "type": "RuntimeDefault",
                        "localhost_profile": None,
                    }
                model["pod"][role][0]["security_context"]["seccomp_profile"] = copy.deepcopy(child)
                effective = parent if child is None else child
                bad = (parent is not None and parent["type"] == "Unconfined") or (
                    effective is None or effective["type"] == "Unconfined"
                )
                control = _control(_body(model), "seccomp_profile")
                self.assertEqual(control["outcome"], "violated" if bad else "satisfied")
                path = f"pod.{role}[0].security_context.seccomp_profile"
                check = next(check for check in control["checks"] if check["source_path"] == path)
                self.assertEqual(check["effective_value"], effective)
                self.assertEqual(
                    check["effective_source_path"],
                    "pod.security_context.seccomp_profile" if child is None else path,
                )

    def test_explicit_bad_pod_values_are_not_masked_by_safer_children(self) -> None:
        for field, bad, good in (
            ("run_as_non_root", False, True),
            ("run_as_user", 0, 1000),
            (
                "seccomp_profile",
                {"type": "Unconfined", "localhost_profile": None},
                {"type": "RuntimeDefault", "localhost_profile": None},
            ),
        ):
            with self.subTest(field=field):
                model = component_fixture()
                model["pod"]["security_context"][field] = bad
                for role in _ROLES:
                    model["pod"][role][0]["security_context"][field] = copy.deepcopy(good)
                control = _control(_body(model), field)
                self.assertEqual(control["outcome"], "violated")
                self.assertEqual(control["checks"][0]["reason"], "explicit_pod_value_forbidden")
                self.assertTrue(
                    all(check["outcome"] == "satisfied" for check in control["checks"][1:])
                )

    def test_privilege_escalation_is_explicit_per_container_without_inheritance(self) -> None:
        for role, value in itertools.product(_ROLES, (None, False, True)):
            with self.subTest(role=role, value=value):
                model = component_fixture()
                model["pod"][role][0]["security_context"]["allow_privilege_escalation"] = value
                self.assertEqual(
                    _control(_body(model), "allow_privilege_escalation")["outcome"],
                    "satisfied" if value is False else "violated",
                )

    def test_capability_drop_and_add_independent_finite_oracle(self) -> None:
        for role, drop, add in itertools.product(
            _ROLES,
            ([], ["ALL"], ["all"], ["CHOWN", "ALL"]),
            ([], ["NET_BIND_SERVICE"], ["SYS_ADMIN"], ["net_bind_service"]),
        ):
            with self.subTest(role=role, drop=drop, add=add):
                model = component_fixture()
                model["pod"][role][0]["security_context"]["capabilities"] = {
                    "drop": drop,
                    "add": add,
                }
                expected = "ALL" in drop and all(name == "NET_BIND_SERVICE" for name in add)
                self.assertEqual(
                    _control(_body(model), "capabilities")["outcome"],
                    "satisfied" if expected else "violated",
                )

    def test_unset_capabilities_does_not_satisfy_drop_all(self) -> None:
        model = component_fixture()
        model["pod"]["containers"][0]["security_context"]["capabilities"] = None
        control = _control(_body(model), "capabilities")
        self.assertEqual(control["outcome"], "violated")
        self.assertEqual(control["checks"][0]["reason"], "drop_all_required")

    def test_capability_spelling_and_availability_are_not_certified(self) -> None:
        model = component_fixture()
        caps = model["pod"]["containers"][0]["security_context"]["capabilities"]
        caps["drop"] = ["arbitrary-not-certified", "ALL"]
        caps["add"] = ["NET_BIND_SERVICE"]
        body = _body(model)
        self.assertEqual(body["outcome"], "satisfies_supported_controls")
        self.assertFalse(body["flags"]["capability_availability_verified"])
        self.assertEqual(
            body["source_model"]["pod"]["containers"][0]["security_context"]["capabilities"], caps
        )

    def test_non_linux_and_user_namespaces_globally_withhold_checks(self) -> None:
        for os_name, host_users in itertools.product(
            ("linux", "windows", "unknown"), (None, True, False)
        ):
            with self.subTest(os=os_name, host_users=host_users):
                model = component_fixture()
                model["pod"]["os_name"] = os_name
                model["pod"]["host_users"] = host_users
                body = _body(model)
                unsupported = os_name != "linux" or host_users is False
                self.assertEqual(
                    body["outcome"],
                    "unsupported" if unsupported else "satisfies_supported_controls",
                )
                if unsupported:
                    self.assertEqual(body["summary"]["evaluated_check_count"], 0)
                    self.assertTrue(
                        all(
                            item["outcome"] == "not_assessed" and not item["checks"]
                            for item in body["controls"]
                        )
                    )

    def test_unknown_and_contradictory_seccomp_configurations_are_unsupported(self) -> None:
        for profile in (
            {"type": "FutureType", "localhost_profile": None},
            {"type": "Localhost", "localhost_profile": None},
            {"type": "RuntimeDefault", "localhost_profile": "profiles/inert.json"},
            {"type": "Unconfined", "localhost_profile": "profiles/inert.json"},
        ):
            for at_pod in (True, False):
                with self.subTest(profile=profile, at_pod=at_pod):
                    model = component_fixture()
                    context = (
                        model["pod"]["security_context"]
                        if at_pod
                        else model["pod"]["containers"][0]["security_context"]
                    )
                    context["seccomp_profile"] = profile
                    body = _body(model)
                    self.assertEqual(body["outcome"], "unsupported")
                    self.assertEqual(body["summary"]["evaluated_check_count"], 0)
                    self.assertEqual(
                        body["unsupported_reasons"][0]["code"],
                        "seccomp_configuration_outside_subset",
                    )

    def test_native_nullable_boolean_slots_refuse_integer_and_float_aliases(self) -> None:
        paths = (
            ("pod", "host_users"),
            ("pod", "security_context", "run_as_non_root"),
            ("pod", "containers", 0, "security_context", "run_as_non_root"),
            ("pod", "containers", 0, "security_context", "allow_privilege_escalation"),
        )
        for path, value in itertools.product(paths, (0, 1, 0.0, 1.0, "false", [], {})):
            with self.subTest(path=path, value=value):
                model = component_fixture()
                _set_path(model, path, value)
                with (
                    patch.object(m, "_digest", side_effect=AssertionError("hash reached")),
                    self.assertRaises(m.PodSecurityAnalysisError),
                ):
                    m.analyze_supplied_kubernetes_pod_security(model)

    def test_native_uid_slots_refuse_boolean_float_negative_and_overflow(self) -> None:
        for path, value in itertools.product(
            (
                ("pod", "security_context", "run_as_user"),
                ("pod", "init_containers", 0, "security_context", "run_as_user"),
            ),
            (False, True, 0.0, 1.0, -1, 1 << 63, 1 << 100000, "1000", [], {}),
        ):
            with self.subTest(path=path, type=type(value).__name__):
                model = component_fixture()
                _set_path(model, path, value)
                with (
                    patch.object(m, "_digest", side_effect=AssertionError("hash reached")),
                    self.assertRaises(m.PodSecurityAnalysisError),
                ):
                    m.analyze_supplied_kubernetes_pod_security(model)

    def test_schema_version_and_os_require_the_exact_native_family(self) -> None:
        for value in (True, False, 1.0, "1", None, 0, 2, []):
            model = component_fixture()
            model["schema_version"] = value
            with self.subTest(version=value), self.assertRaises(m.PodSecurityAnalysisError):
                m.analyze_supplied_kubernetes_pod_security(model)
        for value in (None, True, 1, [], {}, "LINUX", "darwin"):
            model = component_fixture()
            model["pod"]["os_name"] = value
            with self.subTest(os=value), self.assertRaises(m.PodSecurityAnalysisError):
                m.analyze_supplied_kubernetes_pod_security(model)

    def test_native_subclasses_and_tuple_normalization_are_rejected_before_hash(self) -> None:
        class Text(str):
            pass

        class Number(int):
            pass

        class Items(list):
            pass

        class Mapping(dict):
            pass

        cases = (
            (("pod", "pod_ref"), Text("pod:synthetic-restricted-core")),
            (("pod", "security_context", "run_as_user"), Number(1000)),
            (("pod", "containers"), Items(component_fixture()["pod"]["containers"])),
            (("pod", "security_context"), Mapping(component_fixture()["pod"]["security_context"])),
            (("pod", "containers"), tuple(component_fixture()["pod"]["containers"])),
        )
        for path, value in cases:
            model = component_fixture()
            _set_path(model, path, value)
            with (
                self.subTest(path=path, type=type(value).__name__),
                patch.object(m, "_digest", side_effect=AssertionError("hash reached")),
                self.assertRaises(m.PodSecurityAnalysisError),
            ):
                m.analyze_supplied_kubernetes_pod_security(model)

    def test_missing_and_unknown_fields_are_not_defaulted_or_ignored(self) -> None:
        for path in (
            (),
            ("pod",),
            ("pod", "security_context"),
            ("pod", "containers", 0),
            ("pod", "containers", 0, "security_context"),
            ("pod", "security_context", "seccomp_profile"),
            ("pod", "containers", 0, "security_context", "capabilities"),
        ):
            for operation in ("missing", "unknown"):
                with self.subTest(path=path, operation=operation):
                    model = component_fixture()
                    target = model
                    for key in path:
                        target = target[key]
                    if operation == "missing":
                        target.pop(next(iter(target)))
                    else:
                        target["unselected"] = None
                    with self.assertRaises(m.PodSecurityAnalysisError):
                        m.analyze_supplied_kubernetes_pod_security(model)

    def test_container_counts_unique_references_and_all_roles_are_required(self) -> None:
        for bad in ("empty", "duplicate", "too_many", "missing_role"):
            model = component_fixture()
            if bad == "empty":
                model["pod"]["containers"] = []
            elif bad == "duplicate":
                model["pod"]["init_containers"][0]["container_ref"] = "container:application"
            elif bad == "too_many":
                model["pod"]["containers"] = [_container(f"container:{i}") for i in range(63)]
            else:
                del model["pod"]["ephemeral_containers"]
            with self.subTest(bad=bad), self.assertRaises(m.PodSecurityAnalysisError):
                m.analyze_supplied_kubernetes_pod_security(model)
        model = component_fixture()
        model["pod"]["containers"] = [_container(f"container:{i}") for i in range(62)]
        self.assertEqual(_body(model)["summary"]["container_count"], 64)
        model["pod"]["init_containers"] = []
        model["pod"]["ephemeral_containers"] = []
        self.assertEqual(_body(model)["summary"]["container_count"], 62)

    def test_capability_arrays_require_unique_bounded_native_strings(self) -> None:
        for value in (
            ["ALL", "ALL"],
            ["ALL", 1],
            [""],
            ["  "],
            None,
            (),
            [f"X{i}" for i in range(65)],
        ):
            model = component_fixture()
            model["pod"]["containers"][0]["security_context"]["capabilities"]["drop"] = value
            with (
                self.subTest(value_type=type(value).__name__),
                self.assertRaises(m.PodSecurityAnalysisError),
            ):
                m.analyze_supplied_kubernetes_pod_security(model)
        model = component_fixture()
        model["pod"]["containers"][0]["security_context"]["capabilities"]["drop"] = [
            "ALL",
            *[f"X{i}" for i in range(63)],
        ]
        self.assertEqual(_body(model)["outcome"], "satisfies_supported_controls")

    def test_seccomp_exact_nullable_shapes_and_native_strings(self) -> None:
        for value in (
            True,
            "RuntimeDefault",
            [],
            {},
            {"type": "RuntimeDefault"},
            {"type": 1, "localhost_profile": None},
            {"type": "Localhost", "localhost_profile": True},
            {"type": "Localhost", "localhost_profile": ""},
        ):
            model = component_fixture()
            model["pod"]["security_context"]["seccomp_profile"] = value
            with self.subTest(value=value), self.assertRaises(m.PodSecurityAnalysisError):
                m.analyze_supplied_kubernetes_pod_security(model)

    def test_native_string_depth_node_and_cycle_guards_precede_serialization(self) -> None:
        dag: object = "x"
        for _ in range(15):
            dag = [dag, dag]
        deep: object = 0
        for _ in range(16):
            deep = [deep]
        cycle: list = []
        cycle.append(cycle)
        string_model = component_fixture()
        string_model["pod"]["pod_ref"] = "x" * 257
        for value in (dag, deep, cycle, string_model):
            with (
                self.subTest(value_type=type(value).__name__),
                patch.object(m.json, "dumps", side_effect=AssertionError("serialization reached")),
                self.assertRaises(m.PodSecurityAnalysisError),
            ):
                m.analyze_supplied_kubernetes_pod_security(value)
        model = component_fixture()
        model["pod"]["pod_ref"] = "x" * 256
        self.assertEqual(_body(model)["outcome"], "satisfies_supported_controls")

    def test_native_nonprintable_strings_and_nonnative_keys_are_denied(self) -> None:
        for value in ("a\nb", "a\x7fb", "caf\u00e9", "a\x00b"):
            model = component_fixture()
            model["pod"]["pod_ref"] = value
            with self.subTest(value=repr(value)), self.assertRaises(m.PodSecurityAnalysisError):
                m.analyze_supplied_kubernetes_pod_security(model)
        model = component_fixture()
        model[True] = None
        with self.assertRaises(m.PodSecurityAnalysisError):
            m.analyze_supplied_kubernetes_pod_security(model)

    def test_native_aggregate_bytes_account_for_quotes_backslashes_and_punctuation(self) -> None:
        model = component_fixture()
        model["pod"]["pod_ref"] = '"\\' * 128
        exact = len(_json(model).encode("ascii"))
        with (
            patch.object(m, "MAX_DOCUMENT_BYTES", exact - 1),
            patch.object(m.json, "dumps", side_effect=AssertionError("serialization reached")),
            self.assertRaises(m.PodSecurityAnalysisError),
        ):
            m.analyze_supplied_kubernetes_pod_security(model)
        captured, _, size = m._capture(model)
        self.assertEqual(size, exact)
        self.assertEqual(captured, model)

    def test_cumulative_report_and_work_bounds_precede_any_digest(self) -> None:
        model = component_fixture()
        model["pod"]["containers"] = [_container(f"container:{i}") for i in range(64)]
        model["pod"]["init_containers"] = []
        model["pod"]["ephemeral_containers"] = []
        for container in model["pod"]["containers"]:
            container["security_context"]["capabilities"]["drop"] = [
                "ALL",
                *[f"X{i}-" + "a" * 100 for i in range(63)],
            ]
        self.assertLess(len(_json(model)), m.MAX_DOCUMENT_BYTES)
        with (
            patch.object(m, "_digest", side_effect=AssertionError("hash reached")),
            self.assertRaisesRegex(m.PodSecurityAnalysisError, "cumulative output budget"),
        ):
            m.analyze_supplied_kubernetes_pod_security(model)
        with (
            patch.object(m, "MAX_WORK", 5),
            patch.object(m, "_digest", side_effect=AssertionError("hash reached")),
            self.assertRaisesRegex(m.PodSecurityAnalysisError, "work budget"),
        ):
            m.analyze_supplied_kubernetes_pod_security(component_fixture())

    def test_raw_json_roundtrip_and_printable_escapes(self) -> None:
        model = component_fixture()
        model["pod"]["pod_ref"] = 'pod:"\\/synthetic'
        canonical = _json(model)
        escaped = canonical.replace("synthetic", "\\u0073ynthetic").replace("/", "\\/")
        expected = _body(model)
        self.assertEqual(
            m.analyze_supplied_kubernetes_pod_security_bytes(
                model_bytes=escaped.encode("ascii")
            ).to_dict(),
            expected,
        )
        self.assertEqual(m.PodSecurityAnalysis.from_json(_json(expected)).to_dict(), expected)

    def test_raw_depth_node_integer_and_string_bounds_precede_decoder(self) -> None:
        for raw in (
            "[" * 16 + "0" + "]" * 16,
            "[" + ",".join("0" for _ in range(m.MAX_NODES)) + "]",
            '{"schema_version":9223372036854775808}',
            '{"schema_version":' + "9" * 10000 + "}",
            '{"pod_ref":"' + "\\u0061" * 257 + '"}',
            '{"schema_version":1.0}',
            '{"schema_version":NaN}',
        ):
            with (
                self.subTest(prefix=raw[:50]),
                patch.object(m.json, "loads", side_effect=AssertionError("decoder reached")),
                self.assertRaises(m.PodSecurityAnalysisError),
            ):
                m.analyze_supplied_kubernetes_pod_security_bytes(model_bytes=raw.encode("ascii"))

    def test_raw_malformed_integer_signs_use_the_domain_error(self) -> None:
        for token in (
            "--1",
            "---1",
            "--0",
            "+1",
            "-+1",
            "-",
            "01",
            "-01",
            "-0",
            "0x1",
            "1e0",
            "Infinity",
        ):
            with self.subTest(token=token), self.assertRaises(m.PodSecurityAnalysisError):
                m.analyze_supplied_kubernetes_pod_security_bytes(
                    model_bytes=('{"schema_version":' + token + "}").encode("ascii")
                )
        with self.assertRaises(m.PodSecurityAnalysisError):
            m.analyze_supplied_kubernetes_pod_security_bytes(model_bytes=b'{"schema_version":-1}')

    def test_duplicate_missing_invalid_and_oversize_raw_documents(self) -> None:
        raw = _json(component_fixture())
        for supplied in (
            raw.replace('"schema_version":1', '"schema_version":1,"schema_version":1').encode(
                "ascii"
            ),
            b"",
            b"{",
            b"[]}",
            b'{"schema_version":true}',
            b'{"pod_ref":"\\n"}',
            b"x" * (m.MAX_DOCUMENT_BYTES + 1),
            b"\xff",
            bytearray(raw.encode("ascii")),
            raw,
        ):
            with (
                self.subTest(value_type=type(supplied).__name__),
                self.assertRaises(m.PodSecurityAnalysisError),
            ):
                m.analyze_supplied_kubernetes_pod_security_bytes(model_bytes=supplied)
        body = _body(component_fixture())
        duplicate = _json(body).replace(
            '"schema_version":1', '"schema_version":1,"schema_version":1', 1
        )
        with self.assertRaises(m.PodSecurityAnalysisError):
            m.PodSecurityAnalysis.from_json(duplicate)

    def test_source_and_output_ownership_are_detached(self) -> None:
        model = component_fixture()
        original = copy.deepcopy(model)
        report = m.analyze_supplied_kubernetes_pod_security(model)
        body = report.to_dict()
        model["pod"]["security_context"]["run_as_non_root"] = False
        body["source_model"]["pod"]["containers"].clear()
        body["controls"][0]["checks"].clear()
        self.assertEqual(report.to_dict()["source_model"], original)
        parsed_input = report.to_dict()
        replayed = m.PodSecurityAnalysis.from_dict(parsed_input)
        parsed_input["flags"]["qualification_claimed"] = True
        self.assertFalse(replayed.to_dict()["flags"]["qualification_claimed"])
        verified = m.verify_supplied_kubernetes_pod_security_analysis(report, model=original)
        self.assertIsNot(verified, report)
        self.assertEqual(verified.to_dict(), report.to_dict())

    def test_coherently_rehashed_report_cannot_promote_outcome_or_effects(self) -> None:
        for mutation in (
            "outcome",
            "check",
            "effective",
            "summary",
            "flags",
            "effects",
            "exclusions",
            "unknown",
        ):
            document = _body(component_fixture())
            if mutation == "outcome":
                document["outcome"] = "production_qualified"
            elif mutation == "check":
                document["controls"][0]["checks"][0]["reason"] = "forged"
            elif mutation == "effective":
                document["controls"][0]["checks"][1]["effective_value"] = False
            elif mutation == "summary":
                document["summary"]["work_steps"] += 1
            elif mutation == "flags":
                document["flags"]["full_pss_verified"] = True
            elif mutation == "effects":
                document["effects"]["authorization"] = "granted"
            elif mutation == "exclusions":
                document["exclusions"].clear()
            else:
                document["unselected"] = None
            with self.subTest(mutation=mutation), self.assertRaises(m.PodSecurityAnalysisError):
                m.PodSecurityAnalysis.from_dict(_readdress(document))
        bad_model = component_fixture()
        bad_model["pod"]["security_context"]["run_as_user"] = 0
        truthful = _body(bad_model)
        truthful["outcome"] = "satisfies_supported_controls"
        with self.assertRaises(m.PodSecurityAnalysisError):
            m.PodSecurityAnalysis.from_dict(_readdress(truthful))

    def test_coherently_rehashed_report_native_aliases_are_rejected(self) -> None:
        for path, value in (
            (("schema_version",), True),
            (("schema_version",), 1.0),
            (("flags", "source_authenticated"), 0),
            (("summary", "violation_count"), False),
            (("bounds", "maximum_containers"), 64.0),
        ):
            document = _body(component_fixture())
            _set_path(document, path, value)
            with (
                self.subTest(path=path, value=value),
                self.assertRaises(m.PodSecurityAnalysisError),
            ):
                m.PodSecurityAnalysis.from_dict(_readdress(document))

    def test_source_replay_rejects_a_different_valid_model(self) -> None:
        original = component_fixture()
        different = component_fixture()
        different["pod"]["security_context"]["run_as_user"] = 2000
        report = m.analyze_supplied_kubernetes_pod_security(different)
        self.assertEqual(
            m.PodSecurityAnalysis.from_dict(report.to_dict()).to_dict(), report.to_dict()
        )
        with self.assertRaises(m.PodSecurityAnalysisError):
            m.verify_supplied_kubernetes_pod_security_analysis(report, model=original)
        document = report.to_dict()
        document["model_sha256"] = _body(original)["model_sha256"]
        with self.assertRaises(m.PodSecurityAnalysisError):
            m.PodSecurityAnalysis.from_dict(_readdress(document))

    def test_separate_original_native_validation_precedes_report_hash_replay(self) -> None:
        report = m.analyze_supplied_kubernetes_pod_security(component_fixture())
        for value in (True, 1.0, 1 << 100000):
            model = component_fixture()
            model["pod"]["security_context"]["run_as_user"] = value
            with (
                self.subTest(type=type(value).__name__),
                patch.object(m, "_digest", side_effect=AssertionError("hash reached")),
                self.assertRaises(m.PodSecurityAnalysisError),
            ):
                m.verify_supplied_kubernetes_pod_security_analysis(report, model=model)

    def test_wrapper_native_family_and_late_forgery_are_rechecked(self) -> None:
        report = m.analyze_supplied_kubernetes_pod_security(component_fixture())
        with self.assertRaises(AttributeError):
            report._document_json = "{}"
        incomplete = object.__new__(m.PodSecurityAnalysis)
        with self.assertRaises(m.PodSecurityAnalysisError):
            incomplete.to_dict()
        document = report.to_dict()
        document["flags"]["cluster_admission_proven"] = True
        object.__setattr__(report, "_document_json", _json(_readdress(document)))
        with self.assertRaises(m.PodSecurityAnalysisError):
            report.to_dict()
        with self.assertRaises(m.PodSecurityAnalysisError):
            m.verify_supplied_kubernetes_pod_security_analysis(document, model=component_fixture())

        class Derived(m.PodSecurityAnalysis):
            pass

        with self.assertRaises(m.PodSecurityAnalysisError):
            Derived.from_dict(_body(component_fixture()))

    def test_fixed_scope_coordinates_exclusions_and_no_effects(self) -> None:
        body = _body(component_fixture())
        self.assertEqual(body["profile_id"], "AOE-GC-D15-S05")
        self.assertEqual(body["capability_id"], "army.gc.d15.s05")
        self.assertEqual(body["vector_id"], "AV-GC-D15-S05-01")
        self.assertEqual(body["wave_id"], "IW2-007")
        self.assertEqual(
            body["blueprint_sha256"],
            "sha256:234e287aec5569750d2e7b4a4e30b213a37c2656bfb56cabf975ee2b676a0510",
        )
        self.assertEqual(
            [item["control_id"] for item in body["controls"]],
            [
                "run_as_non_root",
                "run_as_user",
                "allow_privilege_escalation",
                "seccomp_profile",
                "capabilities",
            ],
        )
        self.assertIs(body["flags"].pop("offline_only"), True)
        self.assertTrue(
            all(type(value) is bool and value is False for value in body["flags"].values())
        )
        self.assertTrue(all(value == "none" for value in body["effects"].values()))
        self.assertIn("all_other_baseline_and_restricted_controls", body["exclusions"])
        self.assertEqual(body["benchmark_version"], "kubernetes-v1.34-linux-restricted-core")


if __name__ == "__main__":
    unittest.main()
