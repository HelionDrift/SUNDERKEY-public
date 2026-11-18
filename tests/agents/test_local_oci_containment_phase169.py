"""Phase 169 repository-only local OCI containment tests."""

from __future__ import annotations

import ast
import copy
import json
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from scripts.build_candidate_adapter_catalog import load_blueprints
from sunderkey.candidate_adapter_runner import (
    MICROVM_GUARANTEES,
    OCI_GUARANTEES,
    ContainmentBackendAttestation,
    ContainmentLimits,
    prepare_containment_execution_plan,
)
from sunderkey.candidate_adapter_sdk import (
    AdapterInvocation,
    load_candidate_adapter_catalog,
)
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
from sunderkey.candidate_implementation_strategy import (
    load_candidate_implementation_strategy,
)
from sunderkey.errors import QualificationError
from sunderkey.local_oci_containment import (
    LocalOciContainmentFixture,
    LocalOciExecutionSpec,
    build_local_oci_containment_fixture,
)
from sunderkey.qualification import _canonical_sha256
from sunderkey.reference_adapters import build_reference_adapters

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "registry"
SCHEMA = REGISTRY / "schemas" / "local-oci-containment-fixture-v1.schema.json"
MODULE = ROOT / "src" / "sunderkey" / "local_oci_containment.py"
DOC = ROOT / "docs" / "local-oci-containment.md"
ZERO_SHA = "sha256:" + "0" * 64
ONE_SHA = "sha256:" + "1" * 64
TWO_SHA = "sha256:" + "2" * 64
THREE_SHA = "sha256:" + "3" * 64
FOUR_SHA = "sha256:" + "4" * 64
IMAGE = "registry.example.invalid/sunderkey/candidate@" + FOUR_SHA


def binaries(isolation_class: str) -> list[dict[str, str]]:
    names = ("podman",) if isolation_class == "oci_container" else ("firecracker", "jailer")
    return [
        {
            "name": name,
            "version": "test-1",
            "sha256": (ZERO_SHA, ONE_SHA)[index],
            "source_url": f"https://example.invalid/{name}",
            "license_spdx": "Apache-2.0",
        }
        for index, name in enumerate(names)
    ]


def configurations() -> list[dict[str, str]]:
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


def attestation(isolation_class: str) -> ContainmentBackendAttestation:
    guarantees = OCI_GUARANTEES if isolation_class == "oci_container" else MICROVM_GUARANTEES
    return ContainmentBackendAttestation.build(
        backend_id=f"containment.local.{isolation_class.replace('_', '-')}",
        backend_version="test-1",
        isolation_class=isolation_class,
        executable_sha256=compute_provider_binary_bundle_sha256(
            binaries(isolation_class), isolation_class
        ),
        configuration_sha256=compute_provider_configuration_bundle_sha256(configurations()),
        source_url="https://example.invalid/local-containment",
        license_spdx="Apache-2.0",
        host_os="linux",
        guarantees=tuple(sorted(guarantees)),
    )


class LocalOciContainmentPhase169Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.conformance_catalog = load_containment_conformance_suite_catalog(
            REGISTRY / "candidate-containment-conformance-suites-v1.json"
        )
        strategy = load_candidate_implementation_strategy(
            REGISTRY / "candidate-implementation-strategy-v1.json"
        )
        candidate_catalog = load_candidate_adapter_catalog(
            REGISTRY / "candidate-adapters-reference-v1.json",
            strategy,
            load_blueprints(),
            ROOT,
        )
        cls.adapter = build_reference_adapters(candidate_catalog)["AOE-GB-D06-S09"]

    def invocation(self, isolation_class: str = "oci_container") -> AdapterInvocation:
        del isolation_class
        return AdapterInvocation(
            invocation_id="INV-LOCAL-OCI-001",
            mission_id="MISSION-SYNTHETIC-001",
            authority_ref="AUTH-SYNTHETIC-001",
            profile_id=self.adapter.manifest.profile_id,
            vector_id=self.adapter.manifest.vector_id,
            target_id="TARGET-SYNTHETIC-001",
            scope_id="SCOPE-SYNTHETIC-001",
            action_tier="R0",
            environment="synthetic",
            dry_run=True,
            credential_refs=(),
            input_data={"exchanges": []},
        )

    def contracts(self, isolation_class: str = "oci_container", *, rootless: bool = True):
        selected_attestation = attestation(isolation_class)
        selected_binding = build_containment_backend_deployment_binding(
            catalog=self.conformance_catalog,
            attestation=selected_attestation,
            host_id=f"host.local.{isolation_class.replace('_', '-')}",
            architecture="x86_64",
            service_identity_id=f"service.local.{isolation_class.replace('_', '-')}",
            binary_components=binaries(isolation_class),
            configuration_components=configurations(),
        )
        selected_snapshot = build_containment_host_snapshot(
            host_id=f"host.local.{isolation_class.replace('_', '-')}",
            collected_at="2026-09-20T18:00:00Z",
            os_name="linux",
            architecture="x86_64",
            kernel_release="6.12.0-test",
            service_identity_id=f"service.local.{isolation_class.replace('_', '-')}",
            binary_components=[
                {**item, "path": f"/usr/bin/{item['name']}"} for item in binaries(isolation_class)
            ],
            configuration_components=configurations(),
            cgroup_version="v2",
            seccomp_enabled=True,
            rootless_provider=rootless if isolation_class == "oci_container" else False,
            user_namespace_enabled=isolation_class == "oci_container",
            kvm_access=isolation_class == "microvm",
            dedicated_jailer_uid_gid=isolation_class == "microvm",
            single_tenant_vm=isolation_class == "microvm",
            bounded_logging=isolation_class == "microvm",
            host_hardening=isolation_class == "microvm",
        )
        selected_preflight = assess_containment_host_preflight(
            binding=selected_binding,
            snapshot=selected_snapshot,
            catalog=self.conformance_catalog,
            attestation=selected_attestation,
        )
        selected_invocation = self.invocation(isolation_class)
        selected_plan = prepare_containment_execution_plan(
            self.adapter.manifest,
            selected_invocation,
            selected_attestation,
            ContainmentLimits(
                timeout_seconds=60,
                memory_mib=256,
                cpu_millis=750,
                process_count=12,
                output_bytes=65_536,
                workspace_bytes=1_048_576,
            ),
            issued_at="2026-09-20T18:00:00Z",
            expires_at="2026-09-20T18:01:00Z",
        )
        return (
            selected_invocation,
            selected_attestation,
            selected_plan,
            selected_binding,
            selected_snapshot,
            selected_preflight,
        )

    def fixture(self, isolation_class: str = "oci_container", *, rootless: bool = True):
        invocation, selected_attestation, plan, binding, snapshot, preflight = self.contracts(
            isolation_class, rootless=rootless
        )
        return build_local_oci_containment_fixture(
            manifest=self.adapter.manifest,
            invocation=invocation,
            attestation=selected_attestation,
            plan=plan,
            catalog=self.conformance_catalog,
            binding=binding,
            snapshot=snapshot,
            preflight=preflight,
            image_reference=IMAGE,
            seccomp_profile_sha256=ZERO_SHA,
        )

    def test_fixture_is_deterministic_content_addressed_and_round_trips(self) -> None:
        first = self.fixture()
        second = self.fixture()
        self.assertEqual(first, second)
        self.assertEqual(first.fixture_sha256, second.fixture_sha256)
        self.assertEqual(LocalOciContainmentFixture.from_dict(first.to_dict()), first)
        self.assertEqual(
            LocalOciExecutionSpec.from_dict(first.specification.to_dict()),
            first.specification,
        )
        self.assertEqual(len(first.observations), 3)
        self.assertEqual(len({item.observation_sha256 for item in first.observations}), 3)

    def test_exact_podman_spec_encodes_every_required_containment_control(self) -> None:
        spec = self.fixture().specification.to_dict()
        argv = spec["command_argv"]
        for argument in (
            "--rm=true",
            "--pull=never",
            "--network=none",
            "--read-only=true",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--userns=auto:size=65536",
            "--user=65532:65532",
            "--pids-limit=12",
            "--memory=256m",
            "--memory-swap=256m",
            "--cpus=0.750",
            "--log-driver=none",
            "--stop-timeout=1",
        ):
            self.assertIn(argument, argv)
        self.assertEqual(argv[-3], IMAGE)
        self.assertEqual(spec["security_policy"]["credential_mode"], "deny_all")
        self.assertEqual(spec["security_policy"]["host_bind_mounts"], [])
        self.assertEqual(spec["security_policy"]["host_devices"], [])
        self.assertEqual(spec["workspace_policy"]["maximum_bytes"], 1_048_576)
        self.assertTrue(spec["workspace_policy"]["cleanup_required"])

    def test_fixture_never_claims_runtime_or_external_containment(self) -> None:
        raw = self.fixture().to_dict()
        self.assertFalse(raw["runtime_execution_performed"])
        self.assertFalse(raw["external_containment_proven"])
        self.assertEqual(raw["status"], "deterministic_repository_fixture_nonqualifying")
        for record in [raw, raw["specification"], *raw["observations"]]:
            for field in (
                "qualification_effect",
                "routing_effect",
                "deployment_effect",
                "target_authority_effect",
            ):
                self.assertEqual(record[field], "none")

    def test_unpinned_or_tagged_image_is_rejected(self) -> None:
        args = self.contracts()
        for image in (
            "registry.example.invalid/sunderkey/candidate:latest",
            "candidate@" + FOUR_SHA,
            "registry.example.invalid/sunderkey/candidate@sha256:1234",
        ):
            with (
                self.subTest(image=image),
                self.assertRaisesRegex(QualificationError, "digest pinned"),
            ):
                build_local_oci_containment_fixture(
                    manifest=self.adapter.manifest,
                    invocation=args[0],
                    attestation=args[1],
                    plan=args[2],
                    catalog=self.conformance_catalog,
                    binding=args[3],
                    snapshot=args[4],
                    preflight=args[5],
                    image_reference=image,
                    seccomp_profile_sha256=ZERO_SHA,
                )

    def test_blocked_preflight_and_microvm_contracts_are_rejected(self) -> None:
        with self.assertRaisesRegex(QualificationError, "passing host preflight"):
            self.fixture(rootless=False)
        with self.assertRaisesRegex(QualificationError, "requires OCI"):
            self.fixture("microvm")

    def test_exact_fields_and_security_tampering_are_rejected(self) -> None:
        spec = self.fixture().specification.to_dict()
        extra = copy.deepcopy(spec)
        extra["unexpected"] = True
        with self.assertRaisesRegex(QualificationError, "fields"):
            LocalOciExecutionSpec.from_dict(extra)
        changed = copy.deepcopy(spec)
        changed["security_policy"]["network_mode"] = "host"
        with self.assertRaisesRegex(QualificationError, "security policy"):
            LocalOciExecutionSpec.from_dict(changed)
        changed = copy.deepcopy(spec)
        changed["command_argv"].remove("--cap-drop=ALL")
        with self.assertRaisesRegex(QualificationError, "command arguments"):
            LocalOciExecutionSpec.from_dict(changed)

    def test_budget_ceiling_and_policy_substitution_are_rejected(self) -> None:
        spec = self.fixture().specification.to_dict()
        changed = copy.deepcopy(spec)
        changed["limits"]["output_bytes"] = 16_777_217
        with self.assertRaisesRegex(QualificationError, "outside the allowed range"):
            LocalOciExecutionSpec.from_dict(changed)
        changed = copy.deepcopy(spec)
        changed["workspace_policy"]["maximum_bytes"] += 1
        with self.assertRaisesRegex(QualificationError, "workspace policy"):
            LocalOciExecutionSpec.from_dict(changed)
        changed = copy.deepcopy(spec)
        changed["cancellation_policy"]["fail_closed"] = False
        with self.assertRaisesRegex(QualificationError, "cancellation policy"):
            LocalOciExecutionSpec.from_dict(changed)

    def test_rehashed_observation_substitution_is_rejected(self) -> None:
        fixture = self.fixture()
        raw = fixture.to_dict()
        observation = raw["observations"][1]
        observation["assertions"].append("runtime_boundary_substituted")
        observation["assertions"].sort()
        body = {
            key: value
            for key, value in observation.items()
            if key not in {"observation_id", "observation_sha256"}
        }
        digest = _canonical_sha256(
            {
                "domain": "sunderkey.local-oci-containment-observation.v1",
                "observation": body,
            }
        )
        observation["observation_sha256"] = digest
        observation["observation_id"] = "OCO-" + digest.removeprefix("sha256:")[:32].upper()
        with self.assertRaisesRegex(QualificationError, "not canonical"):
            LocalOciContainmentFixture.from_dict(raw)

    def test_identity_tampering_is_rejected(self) -> None:
        raw = self.fixture().to_dict()
        raw["fixture_sha256"] = ONE_SHA
        with self.assertRaisesRegex(QualificationError, "identity"):
            LocalOciContainmentFixture.from_dict(raw)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_draft_2020_12_schema_validates_fixture_and_rejects_extra_fields(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        fixture = self.fixture().to_dict()
        validator.validate(fixture)
        fixture["unexpected"] = True
        self.assertTrue(list(validator.iter_errors(fixture)))

    def test_module_has_no_runtime_or_network_imports(self) -> None:
        tree = ast.parse(MODULE.read_text(encoding="utf-8"))
        imported = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertTrue(
            {"subprocess", "socket", "requests", "urllib", "httpx", "podman"}.isdisjoint(imported)
        )

    def test_artifacts_have_no_markers_or_forbidden_unicode(self) -> None:
        markers = (
            "generated " + "by",
            "written by " + "ai",
            "as an " + "ai",
            "chat" + "gpt",
            "co" + "dex",
            "clau" + "de",
            "gem" + "ini",
            "co-authored" + "-by",
        )
        for path in (MODULE, Path(__file__), SCHEMA, DOC):
            with self.subTest(path=path):
                content = path.read_text(encoding="utf-8")
                self.assertNotIn("\N{EN DASH}", content)
                self.assertNotIn("\N{EM DASH}", content)
                lowered = content.lower()
                self.assertFalse(any(marker in lowered for marker in markers))

    def test_public_package_exports_local_oci_boundary(self) -> None:
        import sunderkey

        self.assertIs(sunderkey.LocalOciContainmentFixture, LocalOciContainmentFixture)
        self.assertIs(sunderkey.LocalOciExecutionSpec, LocalOciExecutionSpec)
        self.assertIs(
            sunderkey.build_local_oci_containment_fixture,
            build_local_oci_containment_fixture,
        )


if __name__ == "__main__":
    unittest.main()
