"""Unsigned GCP acceptance planning has no runtime or qualification effect."""

from __future__ import annotations

import copy
import dataclasses
import json
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from sunderkey.assessment_transport_contracts import BrowserAction
from sunderkey.authorized_browser_runtime import AuthorizedBrowserPolicy
from sunderkey.candidate_backend_conformance import build_containment_conformance_suite_catalog
from sunderkey.candidate_backend_host_preflight import build_containment_backend_deployment_binding
from sunderkey.deployment_manifests import DeploymentManifest
from sunderkey.deployment_profile_contracts import DeploymentProfile
from sunderkey.enterprise_identity_contracts import SsoTrustPolicy
from sunderkey.execution_control_runtime import ExecutionBinding
from sunderkey.gcp_acceptance_checklist import (
    DOMAIN,
    HOST_FIELDS,
    MAX_DOCUMENT_BYTES,
    QUEUE_ORDER,
    SERVICES,
    GcpAcceptanceChecklist,
    GcpAcceptanceChecklistError,
    GcpAcceptancePrerequisites,
    GcpContainmentPrerequisite,
    _canonical,
    _digest,
    build_gcp_acceptance_checklist,
    verify_gcp_acceptance_checklist,
)
from sunderkey.health_state_contracts import HealthContext, ProbeDefinition, ProbeKind
from sunderkey.persistence_port_contracts import postgresql_production_capabilities
from tests.agents import test_gcp_resource_bindings as resource_test
from tests.agents.test_candidate_backend_host_preflight_phase157 import (
    attestation,
    binaries,
    configurations,
)

SHA = "sha256:" + "1" * 64
PROJECT = resource_test.PROJECT


def prerequisites(*, worker_ref: str) -> GcpAcceptancePrerequisites:
    catalog = build_containment_conformance_suite_catalog()
    bindings = []
    for isolation_class in SERVICES[:2]:
        backend = attestation(isolation_class)
        binding = build_containment_backend_deployment_binding(
            catalog=catalog,
            attestation=backend,
            host_id=f"host.test.{isolation_class}",
            architecture="x86_64",
            service_identity_id=f"service.test.{isolation_class}",
            binary_components=binaries(isolation_class),
            configuration_components=configurations(),
        )
        bindings.append(GcpContainmentPrerequisite(backend, binding))
    browser = AuthorizedBrowserPolicy(
        binding=ExecutionBinding(
            "tenantref:synthetic",
            "context:synthetic",
            SHA,
            "scope:synthetic",
            SHA,
            "target:synthetic",
            SHA,
            "session:synthetic",
            "lease:synthetic",
            1,
        ),
        execution_policy_id="policy:synthetic",
        execution_policy_sha256=SHA,
        session_id="session:synthetic",
        principal_label="principal:synthetic",
        allowed_actions=tuple(BrowserAction),
        max_actions=1,
        max_navigations=1,
        max_total_bytes=4096,
        max_screenshots=1,
        max_action_milliseconds=1000,
        max_session_milliseconds=2000,
        max_selector_length=128,
    )
    context = HealthContext(
        "tenantref:synthetic", "missionref:synthetic", worker_ref, "1.0.0", "1.0.0"
    )
    health = tuple(
        ProbeDefinition(
            context,
            f"proberef:synthetic-{kind.value}",
            "dependencyref:synthetic",
            "1.0.0",
            kind,
            True,
            1,
            5,
            1,
            1,
            "2026-09-27T12:00:00Z",
        )
        for kind in ProbeKind
    )
    return GcpAcceptancePrerequisites(
        DeploymentManifest.build("high_availability_postgresql"),
        catalog,
        tuple(bindings),
        postgresql_production_capabilities(),
        browser,
        SsoTrustPolicy(
            "tenantref:synthetic",
            "https://identity.example.invalid",
            "sunderkey",
            ("mfa",),
            True,
            300,
            600,
        ),
        health,
    )


def declared_hosts() -> dict:
    result = {}
    for isolation_class in SERVICES[:2]:
        result[isolation_class] = dict(
            zip(
                HOST_FIELDS,
                (
                    PROJECT,
                    f"synthetic-{isolation_class.replace('_', '-')}",
                    "us-west3-a",
                    "synthetic-machine-type",
                    f"projects/{PROJECT}/global/images/synthetic-pinned-image",
                    SHA,
                    "x86_64",
                    f"host.test.{isolation_class}",
                    f"service.test.{isolation_class}",
                    "principalref:synthetic-custody",
                    SHA if isolation_class == "microvm" else None,
                    SHA if isolation_class == "microvm" else None,
                ),
                strict=True,
            )
        )
    return result


def readdress(raw: dict) -> GcpAcceptanceChecklist:
    body = {
        key: value for key, value in raw.items() if key not in {"checklist_id", "checklist_sha256"}
    }
    digest = _digest({"domain": DOMAIN, "checklist": body})
    return GcpAcceptanceChecklist.from_dict(
        {
            **body,
            "checklist_id": "GAC-" + digest[7:39].upper(),
            "checklist_sha256": digest,
        }
    )


class GcpAcceptanceChecklistTests(unittest.TestCase):
    def setUp(self) -> None:
        resource_fixture = resource_test.GcpResourceBindingTests()
        resource_fixture.setUp()
        self.plan = resource_fixture.plan()
        self.sources = resource_fixture.sources
        self.prerequisites = prerequisites(worker_ref=self.sources["deployment_profile"].worker_ref)
        self.hosts = {"oci_container": None, "microvm": None}

    def build(self, **overrides) -> GcpAcceptanceChecklist:
        values = {
            "prerequisites": self.prerequisites,
            "host_declarations": self.hosts,
            **self.sources,
        }
        values.update(overrides)
        return build_gcp_acceptance_checklist(self.plan, **values)

    def verify(self, checklist: GcpAcceptanceChecklist, **overrides) -> dict:
        values = {
            "prerequisites": self.prerequisites,
            "host_declarations": self.hosts,
            **self.sources,
        }
        values.update(overrides)
        return verify_gcp_acceptance_checklist(checklist, self.plan, **values)

    def test_deterministic_native_json_round_trip_and_source_replay(self) -> None:
        checklist = self.build()
        self.assertEqual(checklist, self.build())
        self.assertEqual(
            checklist, GcpAcceptanceChecklist.from_dict(json.loads(checklist.document_json))
        )
        report = self.verify(checklist)
        self.assertEqual(report["status"], "valid_unsigned_offline_checklist")
        self.assertIs(report["observed_live_acceptance"], False)
        self.assertIs(report["qualified_readiness"], False)
        self.assertEqual(set(report["effects"].values()), {"none"})

    def test_declared_contexts_join_revalidated_tenant_and_worker_sources(self) -> None:
        raw = self.build().to_dict()
        sources = raw["source_bindings"]
        expected_tenant = self.sources["regional_binding"].tenant_ref
        self.assertEqual(sources["identity"]["document"]["tenant_id"], expected_tenant)
        self.assertEqual(
            sources["browser"]["document"]["body"]["binding"]["tenant_id"], expected_tenant
        )
        for row in sources["health"]:
            self.assertEqual(row["document"]["context"]["tenant_ref"], expected_tenant)
            self.assertEqual(
                row["document"]["context"]["worker_ref"],
                self.sources["deployment_profile"].worker_ref,
            )

    def test_independently_valid_foreign_tenant_or_worker_sources_are_denied(self) -> None:
        checklist = self.build()
        browser = self.prerequisites.browser_policy
        cases = {
            "SSO tenant": dataclasses.replace(
                self.prerequisites,
                oidc_policy=dataclasses.replace(
                    self.prerequisites.oidc_policy, tenant_id="tenantref:other"
                ),
            ),
            "Browser tenant": dataclasses.replace(
                self.prerequisites,
                browser_policy=dataclasses.replace(
                    browser,
                    binding=dataclasses.replace(browser.binding, tenant_id="tenantref:other"),
                    policy_id="",
                    policy_sha256="",
                ),
            ),
        }
        for name, field, value in (
            ("Health tenant", "tenant_ref", "tenantref:other"),
            ("Health worker", "worker_ref", "workerref:other"),
        ):
            cases[name] = dataclasses.replace(
                self.prerequisites,
                health_definitions=tuple(
                    dataclasses.replace(
                        row, context=dataclasses.replace(row.context, **{field: value})
                    )
                    for row in self.prerequisites.health_definitions
                ),
            )
        for name, alternate in cases.items():
            with self.subTest(source=name):
                if name.startswith("Health"):
                    for definition in alternate.health_definitions:
                        self.assertEqual(
                            ProbeDefinition.from_dict(definition.to_dict()), definition
                        )
                with self.assertRaisesRegex(GcpAcceptanceChecklistError, name):
                    self.build(prerequisites=alternate)
                with self.assertRaisesRegex(GcpAcceptanceChecklistError, name):
                    self.verify(checklist, prerequisites=alternate)

    def test_consistent_alternate_tenant_and_worker_still_require_exact_plan_sources(self) -> None:
        from sunderkey.gcp_resource_bindings import build_gcp_resource_binding_plan

        original = self.build()
        profile = dataclasses.replace(
            self.sources["deployment_profile"], worker_ref="workerref:other"
        )
        region = dataclasses.replace(self.sources["regional_binding"], tenant_ref="tenantref:other")
        alternate_sources = {
            **self.sources,
            "deployment_profile": profile,
            "regional_binding": region,
        }
        inputs = resource_test.synthetic_inputs()
        alternate_plan = build_gcp_resource_binding_plan(inputs, **alternate_sources)
        browser = self.prerequisites.browser_policy
        alternate_prerequisites = dataclasses.replace(
            self.prerequisites,
            oidc_policy=dataclasses.replace(
                self.prerequisites.oidc_policy, tenant_id=region.tenant_ref
            ),
            browser_policy=dataclasses.replace(
                browser,
                binding=dataclasses.replace(browser.binding, tenant_id=region.tenant_ref),
                policy_id="",
                policy_sha256="",
            ),
            health_definitions=tuple(
                dataclasses.replace(
                    row,
                    context=dataclasses.replace(
                        row.context, tenant_ref=region.tenant_ref, worker_ref=profile.worker_ref
                    ),
                )
                for row in self.prerequisites.health_definitions
            ),
        )
        values = {
            "prerequisites": alternate_prerequisites,
            "host_declarations": self.hosts,
            **alternate_sources,
        }
        alternate = build_gcp_acceptance_checklist(alternate_plan, **values)
        self.assertEqual(
            verify_gcp_acceptance_checklist(alternate, alternate_plan, **values)["status"],
            "valid_unsigned_offline_checklist",
        )
        with self.assertRaises(GcpAcceptanceChecklistError):
            self.build(prerequisites=alternate_prerequisites, **alternate_sources)
        with self.assertRaises(GcpAcceptanceChecklistError):
            verify_gcp_acceptance_checklist(original, alternate_plan, **values)

    def test_existing_checks_evidence_outputs_and_dependency_order_are_preserved(self) -> None:
        raw = self.build().to_dict()
        rows = {row["service"]: row for row in raw["services"]}
        self.assertEqual(tuple(rows), SERVICES)
        self.assertEqual(len(rows["oci_container"]["required_positive_evidence"]), 18)
        self.assertEqual(len(rows["microvm"]["required_positive_evidence"]), 20)
        for name in SERVICES[:2]:
            self.assertIn("metadata_endpoint_denied", rows[name]["required_negative_evidence"])
            self.assertIn("deadline_and_cancel_stop", rows[name]["required_negative_evidence"])
            self.assertIn("cgroup_v2", rows[name]["required_host_preflight_checks"])
        for row in rows.values():
            self.assertIs(row["observed_acceptance"], False)
            self.assertIn("cleanup_and_residual_evidence", row["required_outputs"])
            self.assertIn("bounded_redacted_runtime_outputs", row["required_outputs"])
        self.assertEqual(tuple(row["queue_id"] for row in raw["dependency_order"]), QUEUE_ORDER)
        for index, row in enumerate(raw["dependency_order"]):
            self.assertEqual(row["requires"], ["WQ-015" if index == 0 else QUEUE_ORDER[index - 1]])
            self.assertTrue(row["required_evidence"])
            self.assertIs(row["gate_completed"], False)

    def test_missing_hosts_and_both_missing_binding_classes_have_no_fallback(self) -> None:
        empty = dataclasses.replace(self.prerequisites, containment_bindings=())
        blockers = self.build(prerequisites=empty).to_dict()["blocker_codes"]
        for name in SERVICES[:2]:
            self.assertIn(f"{name}_host_declaration_missing", blockers)
            self.assertIn(f"{name}_deployment_binding_missing", blockers)
        with self.assertRaises(GcpAcceptanceChecklistError):
            self.build(host_declarations={"oci_container": None})

    def test_complete_declarations_do_not_resolve_cloud_sql_or_live_acceptance(self) -> None:
        hosts = declared_hosts()
        raw = self.build(host_declarations=hosts).to_dict()
        self.assertFalse(
            any(code.endswith("_host_declaration_missing") for code in raw["blocker_codes"])
        )
        self.assertIn("managed_sql_manifest_mapping_required", raw["blocker_codes"])
        self.assertIn("provider_host_capabilities_unverified", raw["blocker_codes"])
        self.assertIn("host_preflight_observations_missing", raw["blocker_codes"])
        self.assertIs(raw["observed_live_acceptance"], False)
        self.assertIs(raw["qualified_readiness"], False)
        self.verify(self.build(host_declarations=hosts), host_declarations=hosts)

    def test_explicit_missing_coordinates_remain_named_blockers(self) -> None:
        hosts = declared_hosts()
        for key in ("zone", "machine_type", "os_image"):
            hosts["microvm"][key] = None
        raw = self.build(host_declarations=hosts).to_dict()
        for key in ("zone", "machine_type", "os_image"):
            self.assertIn(f"microvm_{key}_missing", raw["blocker_codes"])
            self.assertIs(raw["host_declarations"]["microvm"][key], None)

    def test_invalid_or_substituted_host_coordinates_are_rejected(self) -> None:
        for field, value in (
            ("zone", "us-central1-a"),
            ("project_id", "undeclared-synthetic"),
            ("service_account_ref", "principalref:undeclared"),
            ("host_id", "host.unrelated"),
            ("architecture", "unsupported"),
            ("os_image", "projects/synthetic/global/images/family/moving"),
            ("os_image_sha256", "latest"),
            ("machine_type", True),
        ):
            with self.subTest(field=field):
                hosts = declared_hosts()
                hosts["oci_container"][field] = value
                with self.assertRaises(GcpAcceptanceChecklistError):
                    self.build(host_declarations=hosts)

    def test_source_subclasses_and_missing_required_prerequisites_fail_before_hooks(self) -> None:
        class UnsupportedManifest(DeploymentManifest):
            def to_dict(self):
                raise AssertionError("Unsupported source hook called")

        source = self.prerequisites.deployment_manifest
        unsupported = UnsupportedManifest(
            source.profile_id, source.profile_sha256, source.profile_type, source.document_json
        )
        for value in (None, unsupported, DeploymentManifest.build("local_sqlite_asgi")):
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(GcpAcceptanceChecklistError):
                    self.build(
                        prerequisites=dataclasses.replace(
                            self.prerequisites, deployment_manifest=value
                        )
                    )

    def test_native_schema_guards_run_before_existing_source_parsers(self) -> None:
        for field, parser in (
            ("deployment_manifest", DeploymentManifest),
            ("containment_catalog", type(self.prerequisites.containment_catalog)),
        ):
            original = getattr(self.prerequisites, field)
            raw = original.to_dict()
            raw["schema_version"] = True
            source = dataclasses.replace(original, document_json=json.dumps(raw))
            with self.subTest(field=field), patch.object(parser, "from_dict") as replay:
                with self.assertRaises(GcpAcceptanceChecklistError):
                    self.build(
                        prerequisites=dataclasses.replace(self.prerequisites, **{field: source})
                    )
                replay.assert_not_called()

    def test_native_boolean_counter_and_string_aliases_are_denied_before_replay(self) -> None:
        class Alias(str):
            def __eq__(self, other):
                raise AssertionError("Alias equality must not be called")

            __hash__ = str.__hash__

        for field, change in (
            ("browser_policy", {"max_actions": True}),
            ("browser_policy", {"policy_id": Alias(self.prerequisites.browser_policy.policy_id)}),
            ("oidc_policy", {"require_mfa": 1}),
            ("oidc_policy", {"clock_skew_seconds": False}),
            ("postgres_capabilities", {"max_concurrent_workers": 10000.0}),
        ):
            original = copy.deepcopy(getattr(self.prerequisites, field))
            for key, value in change.items():
                object.__setattr__(original, key, value)
            with self.subTest(field=field, change=tuple(change)):
                with self.assertRaises(GcpAcceptanceChecklistError):
                    self.build(
                        prerequisites=dataclasses.replace(self.prerequisites, **{field: original})
                    )
        hosts = {Alias("oci_container"): None, "microvm": None}
        with self.assertRaises(GcpAcceptanceChecklistError):
            self.build(host_declarations=hosts)

    def test_source_enum_aliases_are_denied_before_value_or_serialization_hooks(self) -> None:
        class Alias:
            @property
            def value(self):
                raise AssertionError("Unsupported source enum value hook called")

        source = copy.deepcopy(self.prerequisites.health_definitions[0])
        object.__setattr__(source, "kind", Alias())
        with patch.object(ProbeDefinition, "to_dict") as hook:
            with self.assertRaises(GcpAcceptanceChecklistError):
                self.build(
                    prerequisites=dataclasses.replace(
                        self.prerequisites, health_definitions=(source,)
                    )
                )
            hook.assert_not_called()
        postgres_type = type(self.prerequisites.postgres_capabilities)
        for field in ("backend", "deployment_classes", "isolation_levels"):
            source = copy.deepcopy(self.prerequisites.postgres_capabilities)
            value = Alias() if field == "backend" else (Alias(),)
            object.__setattr__(source, field, value)
            with self.subTest(field=field), patch.object(postgres_type, "to_dict") as hook:
                with self.assertRaises(GcpAcceptanceChecklistError):
                    self.build(
                        prerequisites=dataclasses.replace(
                            self.prerequisites, postgres_capabilities=source
                        )
                    )
                hook.assert_not_called()
        for field in ("deployment_kind", "ingress_mode", "egress_mode", "update_channel"):
            source = copy.deepcopy(self.sources["deployment_profile"])
            object.__setattr__(source, field, Alias())
            with self.subTest(field=field), patch.object(DeploymentProfile, "to_dict") as hook:
                with self.assertRaises(GcpAcceptanceChecklistError):
                    self.build(deployment_profile=source)
                hook.assert_not_called()
        for field in ("supported_capabilities", "credential_delivery_modes"):
            source = copy.deepcopy(self.sources["deployment_profile"])
            holder = (
                source.credential_constraints if field == "credential_delivery_modes" else source
            )
            attribute = "allowed_modes" if field == "credential_delivery_modes" else field
            object.__setattr__(holder, attribute, (Alias(),))
            with self.subTest(field=field), patch.object(DeploymentProfile, "to_dict") as hook:
                with self.assertRaises(GcpAcceptanceChecklistError):
                    self.build(deployment_profile=source)
                hook.assert_not_called()

    def test_health_count_boolean_context_and_missing_kind_controls(self) -> None:
        source = copy.deepcopy(self.prerequisites.health_definitions[0])
        for field, value in (("interval_seconds", True), ("required", 1)):
            altered = copy.deepcopy(source)
            object.__setattr__(altered, field, value)
            with self.subTest(field=field), patch.object(ProbeDefinition, "from_dict") as replay:
                with self.assertRaises(GcpAcceptanceChecklistError):
                    self.build(
                        prerequisites=dataclasses.replace(
                            self.prerequisites, health_definitions=(altered,)
                        )
                    )
                replay.assert_not_called()
        limited = dataclasses.replace(self.prerequisites, health_definitions=(source,))
        blockers = self.build(prerequisites=limited).to_dict()["blocker_codes"]
        self.assertIn("health_required_readiness_definition_missing", blockers)
        wrong_context = dataclasses.replace(
            source,
            context=HealthContext(
                "tenantref:other", "missionref:synthetic", "workerref:synthetic", "1.0.0", "1.0.0"
            ),
        )
        with self.assertRaises(GcpAcceptanceChecklistError):
            self.build(
                prerequisites=dataclasses.replace(
                    self.prerequisites, health_definitions=(source, wrong_context)
                )
            )

    def test_source_wrapper_mutation_duplicate_and_unsupported_classes_are_denied(self) -> None:
        pair = self.prerequisites.containment_bindings[0]
        for field, value in (
            ("isolation_class", "other"),
            ("binding_sha256", "sha256:" + "2" * 64),
        ):
            bad_binding = dataclasses.replace(pair.binding, **{field: value})
            bad_pair = dataclasses.replace(pair, binding=bad_binding)
            with self.subTest(field=field), self.assertRaises(GcpAcceptanceChecklistError):
                self.build(
                    prerequisites=dataclasses.replace(
                        self.prerequisites, containment_bindings=(bad_pair,)
                    )
                )
        with self.assertRaises(GcpAcceptanceChecklistError):
            self.build(
                prerequisites=dataclasses.replace(
                    self.prerequisites, containment_bindings=(pair, pair)
                )
            )
        catalog = copy.deepcopy(self.prerequisites.containment_catalog)
        catalog.suites[0]["probe_ids"].clear()
        with self.assertRaises(GcpAcceptanceChecklistError):
            self.build(
                prerequisites=dataclasses.replace(self.prerequisites, containment_catalog=catalog)
            )

    def test_current_verifier_denies_valid_substituted_sources_and_rehashed_checklist(self) -> None:
        checklist = self.build()
        new_policy = dataclasses.replace(
            self.prerequisites.oidc_policy, issuer="https://other.example.invalid"
        )
        new_prerequisites = dataclasses.replace(self.prerequisites, oidc_policy=new_policy)
        self.build(prerequisites=new_prerequisites)
        with self.assertRaises(GcpAcceptanceChecklistError):
            self.verify(checklist, prerequisites=new_prerequisites)
        raw = checklist.to_dict()
        row = raw["source_bindings"]["identity"]
        row["document"] = new_policy.to_dict()
        row["document_sha256"] = _digest(row["document"])
        row["source_id"] = new_policy.record_id
        substituted = readdress(raw)
        self.assertEqual(substituted.to_dict()["parsing_scope"], "content_integrity_only")
        with self.assertRaises(GcpAcceptanceChecklistError):
            self.verify(substituted)

    def test_tampered_embedded_source_hash_and_qualification_gates_cannot_be_readdressed(
        self,
    ) -> None:
        checklist = self.build()
        for mutation in ("source", "live", "qualified", "effect", "gate", "schema", "requirements"):
            raw = checklist.to_dict()
            if mutation == "source":
                raw["source_bindings"]["identity"]["document"]["issuer"] = "unbound"
            elif mutation in {"live", "qualified"}:
                raw["observed_live_acceptance" if mutation == "live" else "qualified_readiness"] = (
                    True
                )
            elif mutation == "effect":
                raw["effects"]["deployment"] = "allowed"
            elif mutation == "gate":
                raw["dependency_order"][0]["gate_completed"] = True
            elif mutation == "schema":
                raw["schema_version"] = True
            else:
                raw["services"][0]["required_negative_evidence"].remove("metadata_endpoint_denied")
            with self.subTest(mutation=mutation), self.assertRaises(GcpAcceptanceChecklistError):
                readdress(raw)

    def test_outputs_are_detached_and_mutations_do_not_change_sources_or_plan(self) -> None:
        hosts = declared_hosts()
        before = _canonical(hosts)
        checklist = self.build(host_declarations=hosts)
        first = checklist.to_dict()
        first["source_bindings"]["containment_catalog"]["document"]["suites"][0][
            "probe_ids"
        ].clear()
        first["host_declarations"]["oci_container"]["zone"] = "changed"
        report = self.verify(checklist, host_declarations=hosts)
        report["blocker_codes"].clear()
        report["effects"].clear()
        self.verify(checklist, host_declarations=hosts)
        self.assertEqual(_canonical(hosts), before)
        self.assertEqual(len(self.prerequisites.containment_catalog.suites[0]["probe_ids"]), 18)
        self.assertEqual(self.plan.to_dict()["primary_region"], "us-west3")

    def test_untrusted_structure_bytes_native_keys_and_health_count_are_bounded(self) -> None:
        source = self.prerequisites.deployment_manifest
        with patch.object(DeploymentManifest, "from_dict") as replay:
            with self.assertRaises(GcpAcceptanceChecklistError):
                self.build(
                    prerequisites=dataclasses.replace(
                        self.prerequisites,
                        deployment_manifest=dataclasses.replace(
                            source, document_json=" " * (MAX_DOCUMENT_BYTES + 1)
                        ),
                    )
                )
            replay.assert_not_called()
        for value in (
            [],
            {"oci_container": None, "microvm": None, "extra": None},
            {"oci_container": {"zone": "us-west3-a"}, "microvm": None},
        ):
            with (
                self.subTest(kind=type(value).__name__),
                self.assertRaises(GcpAcceptanceChecklistError),
            ):
                self.build(host_declarations=value)
        with self.assertRaises(GcpAcceptanceChecklistError):
            self.build(
                prerequisites=dataclasses.replace(
                    self.prerequisites,
                    health_definitions=self.prerequisites.health_definitions * 17,
                )
            )

    def test_shared_graph_byte_expansion_is_rejected_before_json_serialization(self) -> None:
        leaf = ["x" * 8192] * 256
        hosts = {"oci_container": [leaf] * 256, "microvm": None}
        with patch("sunderkey.gcp_acceptance_checklist.json.dumps") as serialize:
            with self.assertRaisesRegex(GcpAcceptanceChecklistError, "aggregate serialized-byte"):
                self.build(host_declarations=hosts)
            serialize.assert_not_called()

    def test_escaped_string_punctuation_and_bounded_integer_byte_charges_are_exact(self) -> None:
        raw = {"quoted\\key": ['"\\', True, False, None, -(2**63), 2**63 - 1]}
        expected = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        with patch("sunderkey.gcp_acceptance_checklist.MAX_DOCUMENT_BYTES", len(expected)):
            self.assertEqual(_canonical(raw), expected)
        with (
            patch("sunderkey.gcp_acceptance_checklist.MAX_DOCUMENT_BYTES", len(expected) - 1),
            patch("sunderkey.gcp_acceptance_checklist.json.dumps") as serialize,
        ):
            with self.assertRaisesRegex(GcpAcceptanceChecklistError, "aggregate serialized-byte"):
                _canonical(raw)
            serialize.assert_not_called()

    def test_import_and_composition_do_not_read_files_or_call_runtime_boundaries(self) -> None:
        import sunderkey.gcp_acceptance_checklist as module

        code = compile(Path(module.__file__).read_text(encoding="utf-8"), module.__file__, "exec")
        name = "sunderkey._gcp_acceptance_import_test"
        isolated = types.ModuleType(name)
        isolated.__package__ = "sunderkey"
        with (
            patch.dict(sys.modules, {name: isolated}),
            patch("builtins.open", side_effect=AssertionError("file IO")),
            patch.object(Path, "read_bytes", side_effect=AssertionError("file IO")),
            patch.object(Path, "read_text", side_effect=AssertionError("file IO")),
            patch(
                "sunderkey.candidate_backend_host_preflight.assess_containment_host_preflight",
                side_effect=AssertionError("host probe"),
            ),
            patch(
                "sunderkey.candidate_backend_conformance.build_conformance_observation",
                side_effect=AssertionError("invented observation"),
            ),
            patch(
                "sunderkey.enterprise_identity_runtime.verify_pinned_oidc_jws",
                side_effect=AssertionError("identity operation"),
            ),
        ):
            exec(code, isolated.__dict__)
            self.verify(self.build())


if __name__ == "__main__":
    unittest.main()
