"""Phase 169 repository-only microVM containment fixture tests."""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import replace
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover
    Draft202012Validator = None

from scripts.build_candidate_adapter_catalog import load_blueprints
from sunderkey.candidate_adapter_runner import (
    MICROVM_GUARANTEES,
    ContainmentBackendAttestation,
    ContainmentLimits,
    prepare_containment_execution_plan,
)
from sunderkey.candidate_adapter_sdk import AdapterInvocation, load_candidate_adapter_catalog
from sunderkey.candidate_backend_conformance import (
    load_containment_conformance_suite_catalog,
)
from sunderkey.candidate_backend_host_preflight import (
    assess_containment_host_preflight,
    build_containment_backend_deployment_binding,
    build_containment_host_snapshot,
    compute_provider_binary_bundle_sha256,
    compute_provider_configuration_bundle_sha256,
)
from sunderkey.candidate_implementation_strategy import load_candidate_implementation_strategy
from sunderkey.errors import QualificationError
from sunderkey.local_microvm_containment import (
    LocalMicrovmContainmentFixtureReceipt,
    LocalMicrovmContainmentObservation,
    LocalMicrovmExecutionSpec,
    build_local_microvm_containment_fixture,
    build_local_microvm_execution_spec,
    validate_external_host_preflight,
)
from sunderkey.reference_adapters import build_reference_adapters

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_DIR = ROOT / "registry"
SCHEMA = REGISTRY_DIR / "schemas" / "local-microvm-containment-fixture-v1.schema.json"
ZERO_SHA = "sha256:" + "0" * 64
ONE_SHA = "sha256:" + "1" * 64
TWO_SHA = "sha256:" + "2" * 64
THREE_SHA = "sha256:" + "3" * 64
FOUR_SHA = "sha256:" + "4" * 64
FIVE_SHA = "sha256:" + "5" * 64


def binary_components() -> list[dict[str, str]]:
    return [
        {
            "name": "firecracker",
            "version": "test-1.10.1",
            "sha256": ZERO_SHA,
            "source_url": "https://example.invalid/firecracker",
            "license_spdx": "Apache-2.0",
        },
        {
            "name": "jailer",
            "version": "test-1.10.1",
            "sha256": ONE_SHA,
            "source_url": "https://example.invalid/jailer",
            "license_spdx": "Apache-2.0",
        },
    ]


def configuration_components() -> list[dict[str, str]]:
    return [
        {
            "name": "containment-policy",
            "sha256": TWO_SHA,
            "media_type": "application/json",
        },
        {
            "name": "runtime-policy",
            "sha256": THREE_SHA,
            "media_type": "application/toml",
        },
    ]


class LocalMicrovmContainmentPhase169Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        strategy = load_candidate_implementation_strategy(
            REGISTRY_DIR / "candidate-implementation-strategy-v1.json"
        )
        candidate_catalog = load_candidate_adapter_catalog(
            REGISTRY_DIR / "candidate-adapters-reference-v1.json",
            strategy,
            load_blueprints(),
            ROOT,
        )
        cls.adapter = build_reference_adapters(candidate_catalog)["AOE-GC-D14-S01"]
        cls.invocation = AdapterInvocation(
            invocation_id="INV-MICROVM-FIXTURE-001",
            mission_id="MISSION-SYNTHETIC-MICROVM-001",
            authority_ref="AUTH-SYNTHETIC-MICROVM-001",
            profile_id=cls.adapter.manifest.profile_id,
            vector_id=cls.adapter.manifest.vector_id,
            target_id="TARGET-SYNTHETIC-MICROVM-001",
            scope_id="SCOPE-SYNTHETIC-MICROVM-001",
            action_tier="R0",
            environment="synthetic",
            dry_run=True,
            credential_refs=(),
            input_data={"statements": []},
        )
        cls.conformance_catalog = load_containment_conformance_suite_catalog(
            REGISTRY_DIR / "candidate-containment-conformance-suites-v1.json"
        )
        cls.attestation = ContainmentBackendAttestation.build(
            backend_id="containment.fixture.microvm",
            backend_version="test-1.10.1",
            isolation_class="microvm",
            executable_sha256=compute_provider_binary_bundle_sha256(binary_components(), "microvm"),
            configuration_sha256=compute_provider_configuration_bundle_sha256(
                configuration_components()
            ),
            source_url="https://example.invalid/firecracker-fixture",
            license_spdx="Apache-2.0",
            host_os="linux",
            guarantees=tuple(sorted(MICROVM_GUARANTEES)),
        )
        cls.limits = ContainmentLimits(
            timeout_seconds=45,
            memory_mib=512,
            cpu_millis=1500,
            process_count=24,
            output_bytes=524_288,
            workspace_bytes=8_388_608,
        )
        cls.plan = prepare_containment_execution_plan(
            cls.adapter.manifest,
            cls.invocation,
            cls.attestation,
            cls.limits,
            issued_at="2026-09-20T12:00:00Z",
            expires_at="2026-09-20T12:00:45Z",
        )
        cls.binding = build_containment_backend_deployment_binding(
            catalog=cls.conformance_catalog,
            attestation=cls.attestation,
            host_id="host.fixture.microvm",
            architecture="x86_64",
            service_identity_id="service.fixture.microvm",
            binary_components=binary_components(),
            configuration_components=configuration_components(),
        )

    def spec(self, **overrides) -> LocalMicrovmExecutionSpec:
        values = {
            "plan": self.plan,
            "binding": self.binding,
            "vm_id": "sunderkey-fixture-001",
            "kernel_path": "/var/lib/sunderkey/images/vmlinux-6.12",
            "kernel_sha256": FOUR_SHA,
            "rootfs_path": "/var/lib/sunderkey/images/rootfs.ext4",
            "rootfs_sha256": FIVE_SHA,
            "overlay_path": "/var/lib/sunderkey/overlays/fixture-001.ext4",
            "firecracker_path": "/usr/bin/firecracker",
            "jailer_path": "/usr/bin/jailer",
            "chroot_base_dir": "/var/lib/sunderkey/jailer",
            "jailer_uid": 62000,
            "jailer_gid": 62000,
            "vcpu_count": 2,
            "log_bytes": 131_072,
        }
        values.update(overrides)
        return build_local_microvm_execution_spec(**values)

    def test_spec_is_deterministic_content_addressed_and_nonqualifying(self) -> None:
        first = self.spec()
        second = self.spec()
        self.assertEqual(first, second)
        self.assertEqual(first.spec_id, second.spec_id)
        raw = first.to_dict()
        self.assertEqual(
            raw["status"], "specification_pending_external_host_preflight_nonqualifying"
        )
        self.assertEqual(raw["host_preflight_contract"]["observed_status"], "not_observed_fixture")
        self.assertIsNone(raw["host_preflight_contract"]["observed_report_id"])
        for field in (
            "qualification_effect",
            "routing_effect",
            "deployment_effect",
            "target_authority_effect",
        ):
            self.assertEqual(raw[field], "none")

    def test_spec_encodes_exact_firecracker_isolation_and_artifact_pins(self) -> None:
        raw = self.spec().to_dict()
        self.assertEqual(raw["runtime_kind"], "jailed_firecracker")
        self.assertEqual(raw["host_requirements"]["kvm_device_path"], "/dev/kvm")
        self.assertTrue(raw["host_requirements"]["kvm_access_required"])
        self.assertEqual(raw["jailer_policy"]["seccomp_level"], 2)
        self.assertEqual(raw["jailer_policy"]["uid"], 62000)
        self.assertEqual(raw["jailer_policy"]["service_identity_id"], "service.fixture.microvm")
        self.assertTrue(raw["machine_configuration"]["single_tenant"])
        self.assertTrue(raw["artifact_policy"]["base_rootfs"]["read_only"])
        self.assertTrue(raw["artifact_policy"]["ephemeral_overlay"]["ephemeral"])
        self.assertEqual(raw["artifact_policy"]["kernel"]["sha256"], FOUR_SHA)
        self.assertEqual(raw["artifact_policy"]["base_rootfs"]["sha256"], FIVE_SHA)

    def test_spec_encodes_deny_all_and_exact_runner_limits(self) -> None:
        raw = self.spec().to_dict()
        self.assertEqual(raw["network_policy"]["mode"], "deny_all")
        self.assertEqual(raw["network_policy"]["interfaces"], [])
        self.assertEqual(raw["credential_policy"]["mode"], "deny_all")
        self.assertEqual(raw["credential_policy"]["allowed_references"], [])
        resources = raw["resource_limits"]
        self.assertEqual(resources["cpu_millis"], self.limits.cpu_millis)
        self.assertEqual(resources["memory_mib"], self.limits.memory_mib)
        self.assertEqual(resources["pid_limit"], self.limits.process_count)
        self.assertEqual(resources["output_bytes"], self.limits.output_bytes)
        self.assertEqual(resources["timeout_seconds"], self.limits.timeout_seconds)
        self.assertEqual(resources["overlay_bytes"], self.limits.workspace_bytes)

    def test_lifecycle_and_logging_require_fail_closed_external_enforcement(self) -> None:
        raw = self.spec().to_dict()
        lifecycle = raw["lifecycle_policy"]
        self.assertTrue(lifecycle["cancellation_required"])
        self.assertTrue(lifecycle["teardown_required"])
        self.assertTrue(lifecycle["residual_effect_observation_required"])
        self.assertEqual(lifecycle["teardown_failure_disposition"], "failed_closed")
        self.assertEqual(raw["logging_policy"]["maximum_bytes"], 131_072)
        self.assertEqual(raw["logging_policy"]["destination"], "content_addressed_receipt_only")

    def test_exact_field_parsing_and_content_tampering_fail_closed(self) -> None:
        spec = self.spec()
        self.assertEqual(LocalMicrovmExecutionSpec.from_dict(spec.to_dict()), spec)
        extra = spec.to_dict()
        extra["unexpected"] = True
        with self.assertRaisesRegex(QualificationError, "fields are invalid"):
            LocalMicrovmExecutionSpec.from_dict(extra)
        changed = spec.to_dict()
        changed["artifact_policy"]["kernel"]["sha256"] = ZERO_SHA
        with self.assertRaisesRegex(QualificationError, "identity does not match"):
            LocalMicrovmExecutionSpec.from_dict(changed)

    def test_jailer_argv_substitution_and_unsafe_paths_fail_closed(self) -> None:
        changed = self.spec().to_dict()
        changed["jailer_argv"][-1] = "no-file=999999"
        with self.assertRaisesRegex(QualificationError, "arguments are invalid"):
            LocalMicrovmExecutionSpec.from_dict(changed)
        with self.assertRaisesRegex(QualificationError, "POSIX"):
            self.spec(kernel_path="C:/images/vmlinux")
        with self.assertRaisesRegex(QualificationError, "allowed range"):
            self.spec(jailer_uid=0)

    def test_resource_budget_ceilings_and_cross_field_consistency_fail_closed(self) -> None:
        with self.assertRaisesRegex(QualificationError, "log limit"):
            self.spec(log_bytes=self.limits.output_bytes + 1)
        with self.assertRaisesRegex(QualificationError, "vCPU"):
            self.spec(vcpu_count=9)
        changed = self.spec().to_dict()
        changed["resource_limits"]["memory_mib"] = 1024
        with self.assertRaisesRegex(QualificationError, "budgets are inconsistent"):
            LocalMicrovmExecutionSpec.from_dict(changed)

    def test_fixture_receipt_is_content_addressed_and_records_no_execution(self) -> None:
        receipt = build_local_microvm_containment_fixture(self.spec())
        duplicate = build_local_microvm_containment_fixture(self.spec())
        self.assertEqual(receipt, duplicate)
        raw = receipt.to_dict()
        self.assertFalse(raw["host_preflight_passed"])
        self.assertFalse(raw["runtime_execution_performed"])
        self.assertFalse(raw["external_containment_proven"])
        self.assertEqual(raw["teardown_status"], "not_started")
        self.assertEqual(raw["residual_effect_observation_status"], "not_observed")
        self.assertEqual(raw["residual_effects"], [])
        self.assertEqual(len(receipt.observations), 4)
        self.assertEqual(LocalMicrovmContainmentFixtureReceipt.from_dict(raw), receipt)

    def test_fixture_observation_and_receipt_tampering_fail_closed(self) -> None:
        receipt = build_local_microvm_containment_fixture(self.spec())
        observation = receipt.observations[0]
        self.assertEqual(
            LocalMicrovmContainmentObservation.from_dict(observation.to_dict()), observation
        )
        changed = receipt.to_dict()
        changed["observations"][0]["assertions"].append("invented_assertion")
        with self.assertRaisesRegex(QualificationError, "assertions are invalid"):
            LocalMicrovmContainmentFixtureReceipt.from_dict(changed)
        changed = receipt.to_dict()
        changed["runtime_execution_performed"] = True
        with self.assertRaisesRegex(QualificationError, "boundary is invalid"):
            LocalMicrovmContainmentFixtureReceipt.from_dict(changed)

    def test_blocked_host_preflight_cannot_admit_fixture_spec(self) -> None:
        snapshot = build_containment_host_snapshot(
            host_id="host.fixture.microvm",
            collected_at="2026-09-20T12:01:00Z",
            os_name="linux",
            architecture="x86_64",
            kernel_release="6.12.0-fixture",
            service_identity_id="service.fixture.microvm",
            binary_components=[
                {**item, "path": f"/usr/bin/{item['name']}"} for item in binary_components()
            ],
            configuration_components=configuration_components(),
            cgroup_version="v2",
            seccomp_enabled=True,
            rootless_provider=False,
            user_namespace_enabled=False,
            kvm_access=False,
            dedicated_jailer_uid_gid=True,
            single_tenant_vm=True,
            bounded_logging=True,
            host_hardening=True,
        )
        report = assess_containment_host_preflight(
            binding=self.binding,
            snapshot=snapshot,
            catalog=self.conformance_catalog,
            attestation=self.attestation,
        )
        self.assertEqual(report.status, "blocked_pending_host_remediation")
        with self.assertRaisesRegex(QualificationError, "does not admit"):
            validate_external_host_preflight(self.spec(), report)

    def test_plan_and_binding_substitution_fail_closed(self) -> None:
        wrong_attestation = ContainmentBackendAttestation.build(
            backend_id="containment.fixture.microvm.other",
            backend_version="test-1.10.1",
            isolation_class="microvm",
            executable_sha256=compute_provider_binary_bundle_sha256(binary_components(), "microvm"),
            configuration_sha256=compute_provider_configuration_bundle_sha256(
                configuration_components()
            ),
            source_url="https://example.invalid/firecracker-fixture-other",
            license_spdx="Apache-2.0",
            host_os="linux",
            guarantees=tuple(sorted(MICROVM_GUARANTEES)),
        )
        wrong_plan = prepare_containment_execution_plan(
            self.adapter.manifest,
            self.invocation,
            wrong_attestation,
            self.limits,
            issued_at="2026-09-20T12:00:00Z",
            expires_at="2026-09-20T12:00:45Z",
        )
        with self.assertRaisesRegex(QualificationError, "attestations differ"):
            self.spec(plan=wrong_plan)
        tampered = replace(
            self.plan,
            document_json=self.plan.document_json.replace("microvm", "changed"),
        )
        with self.assertRaises(QualificationError):
            self.spec(plan=tampered)
        mismatched_plan = replace(self.plan, plan_id="CEP-" + "0" * 32)
        with self.assertRaisesRegex(QualificationError, "object does not match"):
            self.spec(plan=mismatched_plan)
        mismatched_binding = replace(self.binding, binding_id="CBD-" + "0" * 32)
        with self.assertRaisesRegex(QualificationError, "object does not match"):
            self.spec(binding=mismatched_binding)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_draft_2020_12_schema_validates_all_artifacts_and_rejects_extra_fields(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        spec = self.spec()
        receipt = build_local_microvm_containment_fixture(spec)
        validator.validate(spec.to_dict())
        validator.validate(receipt.observations[0].to_dict())
        validator.validate(receipt.to_dict())
        invalid = copy.deepcopy(receipt.to_dict())
        invalid["unrecognized"] = "rejected"
        self.assertTrue(list(validator.iter_errors(invalid)))

    def test_public_package_exports_local_microvm_boundary(self) -> None:
        import sunderkey

        self.assertIs(
            sunderkey.LocalMicrovmContainmentFixtureReceipt,
            LocalMicrovmContainmentFixtureReceipt,
        )
        self.assertIs(sunderkey.LocalMicrovmExecutionSpec, LocalMicrovmExecutionSpec)
        self.assertIs(
            sunderkey.build_local_microvm_containment_fixture,
            build_local_microvm_containment_fixture,
        )
        self.assertIs(
            sunderkey.build_local_microvm_execution_spec,
            build_local_microvm_execution_spec,
        )


if __name__ == "__main__":
    unittest.main()
