"""Phase 164 deployment profile and restricted worker contract coverage."""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import sunderkey

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.deployment_profile_contracts import (
    NO_EFFECTS,
    Capability,
    CredentialConstraints,
    CredentialDeliveryMode,
    DeploymentAdmissionRequest,
    DeploymentAdmissionResult,
    DeploymentKind,
    DeploymentProfile,
    DeploymentProfileError,
    EvidenceCustodyPolicy,
    EvidenceExportManifest,
    RevocationSnapshot,
    SignedMissionBundle,
    StopCleanupPolicy,
    TrustRootPin,
    build_standard_profile,
    canonical_json,
    evaluate_deployment_admission,
    parse_contract,
    standard_deployment_profiles,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "deployment-profile-contract-v1.schema.json"
FILES = (
    ROOT / "src" / "sunderkey" / "deployment_profile_contracts.py",
    Path(__file__),
    SCHEMA,
    ROOT / "docs" / "deployment-profile-contracts.md",
)
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64
DIGEST_D = "sha256:" + "d" * 64


class DeploymentProfileContractsPhase164Tests(unittest.TestCase):
    def test_public_package_exports_are_available(self) -> None:
        self.assertIs(
            sunderkey.evaluate_deployment_admission,
            evaluate_deployment_admission,
        )
        self.assertIs(
            sunderkey.standard_deployment_profiles,
            standard_deployment_profiles,
        )

    def profile(
        self, kind: DeploymentKind = DeploymentKind.CUSTOMER_HOSTED_WORKER
    ) -> DeploymentProfile:
        return build_standard_profile(kind)

    def request(
        self,
        profile: DeploymentProfile | None = None,
        **changes: object,
    ) -> DeploymentAdmissionRequest:
        selected = profile or self.profile()
        values: dict[str, object] = {
            "profile_id": selected.profile_id,
            "profile_sha256": selected.profile_sha256,
            "mission_bundle": SignedMissionBundle(
                bundle_ref="bundleref:mission-2026-09-20",
                bundle_sha256=DIGEST_A,
                signature_ref="signatureref:mission-2026-09-20",
                signing_trust_root_ref="trustref:mission-and-revocation-root-v1",
                tenant_ref="tenantref:example",
                assessment_ref="assessmentref:authorized-001",
                scope_ref="scoperef:signed-scope-001",
                scope_sha256=DIGEST_B,
                issued_at="2026-09-20T10:00:00Z",
                expires_at="2026-09-20T20:00:00Z",
            ),
            "revocation_snapshot": RevocationSnapshot(
                snapshot_ref="snapshotref:revocations-2026-09-20",
                snapshot_sha256=DIGEST_C,
                signature_ref="signatureref:revocations-2026-09-20",
                signing_trust_root_ref="trustref:mission-and-revocation-root-v1",
                captured_at="2026-09-20T11:00:00Z",
                expires_at="2026-09-20T20:00:00Z",
            ),
            "evidence_export_manifest": EvidenceExportManifest(
                manifest_ref="manifestref:required-evidence-export",
                manifest_sha256=DIGEST_D,
                signature_ref="signatureref:evidence-export-v1",
                signing_trust_root_ref="trustref:update-and-export-root-v1",
                evidence_store_ref="storeref:encrypted-local-evidence",
            ),
            "requested_capabilities": (
                Capability.API_ASSESSMENT,
                Capability.EVIDENCE_COLLECTION,
            ),
            "requested_tool_refs": ("toolref:http-adapter",),
            "credential_mode": (
                CredentialDeliveryMode.OFFLINE_SEALED_REFERENCE
                if selected.deployment_kind is DeploymentKind.DISCONNECTED_OPERATION
                else CredentialDeliveryMode.BROKERED_EPHEMERAL_REFERENCE
            ),
            "requested_credential_lease_seconds": 600,
            "worker_clock_at": "2026-09-20T12:00:00Z",
            "last_online_at": "2026-09-20T11:30:00Z",
        }
        values.update(changes)
        return DeploymentAdmissionRequest(**values)

    def test_all_five_standard_profiles_are_deterministic_and_immutable(self) -> None:
        profiles = standard_deployment_profiles()
        self.assertEqual({profile.deployment_kind for profile in profiles}, set(DeploymentKind))
        self.assertEqual(profiles, standard_deployment_profiles())
        for profile in profiles:
            with self.subTest(kind=profile.deployment_kind.value):
                self.assertEqual(profile, DeploymentProfile.from_json(profile.to_json()))
                self.assertEqual(profile, parse_contract(profile.to_dict()))
                self.assertEqual(profile.to_dict()["effects"], dict(NO_EFFECTS))
                self.assertGreaterEqual(len(profile.trust_roots), 2)
                self.assertGreaterEqual(len(profile.version_pins), 2)
                with self.assertRaises(FrozenInstanceError):
                    profile.maximum_offline_seconds = 4  # type: ignore[misc]

    def test_profile_network_modes_are_topology_specific(self) -> None:
        expected = {
            "managed_service": (
                "managed_control_plane",
                "restricted_allowlist",
                "managed_signed_channel",
            ),
            "customer_hosted_worker": (
                "mutual_tls_control_plane",
                "customer_proxy",
                "customer_signed_mirror",
            ),
            "private_cloud": (
                "private_control_plane",
                "private_allowlist",
                "private_signed_mirror",
            ),
            "restricted_network": (
                "customer_relay",
                "customer_relay",
                "relayed_signed_bundle",
            ),
            "disconnected_operation": (
                "signed_removable_media",
                "evidence_removable_media",
                "offline_signed_bundle",
            ),
        }
        for profile in standard_deployment_profiles():
            actual = (
                profile.ingress_mode.value,
                profile.egress_mode.value,
                profile.update_channel.value,
            )
            self.assertEqual(actual, expected[profile.deployment_kind.value])

    def test_compatible_request_remains_unverified_and_nonqualifying(self) -> None:
        profile = self.profile()
        request = self.request(profile)
        result = evaluate_deployment_admission(
            profile,
            request,
            evaluated_at="2026-09-20T12:00:00Z",
        )
        self.assertEqual(result.status.value, "contract_compatible_unverified")
        self.assertEqual(result.blocker_codes, ("live_deployment_verification_required",))
        self.assertEqual(result.to_dict()["authorization_effect"], "none")
        self.assertEqual(result.to_dict()["deployment_effect"], "none")
        self.assertEqual(result.to_dict()["qualification_effect"], "none")
        self.assertEqual(result, DeploymentAdmissionResult.from_json(result.to_json()))
        self.assertEqual(request, DeploymentAdmissionRequest.from_json(request.to_json()))
        self.assertEqual(result, parse_contract(result.to_dict()))

    def test_disconnected_request_is_bounded_by_offline_validity(self) -> None:
        profile = self.profile(DeploymentKind.DISCONNECTED_OPERATION)
        request = self.request(
            profile,
            worker_clock_at="2026-09-22T12:00:00Z",
            last_online_at="2026-09-20T11:30:00Z",
        )
        result = evaluate_deployment_admission(
            profile,
            request,
            evaluated_at="2026-09-22T12:00:00Z",
        )
        self.assertEqual(result.status.value, "denied")
        self.assertIn("offline_validity_expired", result.blocker_codes)
        self.assertIn("mission_bundle_not_current", result.blocker_codes)
        self.assertIn("revocation_snapshot_not_current", result.blocker_codes)

    def test_expired_bundle_revocation_snapshot_and_clock_fail_closed(self) -> None:
        profile = self.profile()
        request = self.request(
            profile,
            worker_clock_at="2026-09-21T12:00:00Z",
        )
        result = evaluate_deployment_admission(
            profile,
            request,
            evaluated_at="2026-09-21T12:00:00Z",
        )
        self.assertEqual(result.status.value, "denied")
        self.assertIn("mission_bundle_not_current", result.blocker_codes)
        self.assertIn("revocation_snapshot_not_current", result.blocker_codes)

        skewed = self.request(profile, worker_clock_at="2026-09-20T12:10:00Z")
        result = evaluate_deployment_admission(
            profile,
            skewed,
            evaluated_at="2026-09-20T12:00:00Z",
        )
        self.assertIn("worker_clock_out_of_bounds", result.blocker_codes)

    def test_unsupported_capability_tool_and_credential_mode_are_denied(self) -> None:
        baseline = self.profile()
        limited = replace(
            baseline,
            supported_capabilities=(Capability.PASSIVE_DISCOVERY,),
            tool_allowlist=("toolref:http-adapter",),
            credential_constraints=CredentialConstraints(
                (CredentialDeliveryMode.NONE,),
                60,
            ),
        )
        request = self.request(
            limited,
            requested_capabilities=(Capability.CLOUD_CONTROL_PLANE,),
            requested_tool_refs=("toolref:kernel-adapter",),
            credential_mode=CredentialDeliveryMode.BROKERED_EPHEMERAL_REFERENCE,
            requested_credential_lease_seconds=600,
        )
        result = evaluate_deployment_admission(
            limited,
            request,
            evaluated_at="2026-09-20T12:00:00Z",
        )
        self.assertEqual(result.status.value, "denied")
        self.assertIn("unsupported_capability", result.blocker_codes)
        self.assertIn("tool_not_allowlisted", result.blocker_codes)
        self.assertIn("credential_delivery_forbidden", result.blocker_codes)
        self.assertIn("credential_lease_exceeds_profile", result.blocker_codes)

    def test_profile_and_custody_bindings_fail_closed(self) -> None:
        profile = self.profile()
        other = self.profile(DeploymentKind.PRIVATE_CLOUD)
        request = self.request(
            profile,
            profile_id=other.profile_id,
            profile_sha256=other.profile_sha256,
            evidence_export_manifest=EvidenceExportManifest(
                manifest_ref="manifestref:wrong-export",
                manifest_sha256=DIGEST_D,
                signature_ref="signatureref:evidence-export-v1",
                signing_trust_root_ref="trustref:update-and-export-root-v1",
                evidence_store_ref="storeref:wrong-store",
            ),
        )
        result = evaluate_deployment_admission(
            profile,
            request,
            evaluated_at="2026-09-20T12:00:00Z",
        )
        self.assertIn("profile_binding_mismatch", result.blocker_codes)
        self.assertIn("evidence_export_manifest_mismatch", result.blocker_codes)
        self.assertIn("evidence_store_mismatch", result.blocker_codes)

    def test_forbidden_network_and_offline_credential_claims_are_rejected(self) -> None:
        profile = self.profile()
        with self.assertRaisesRegex(DeploymentProfileError, "forbidden network claim"):
            replace(profile, ingress_mode="signed_removable_media")
        disconnected = self.profile(DeploymentKind.DISCONNECTED_OPERATION)
        with self.assertRaisesRegex(DeploymentProfileError, "online credential"):
            replace(
                disconnected,
                credential_constraints=CredentialConstraints(
                    (CredentialDeliveryMode.BROKERED_EPHEMERAL_REFERENCE,),
                    60,
                ),
            )

    def test_missing_trust_stop_and_export_requirements_are_rejected(self) -> None:
        profile = self.profile()
        with self.assertRaisesRegex(DeploymentProfileError, "trust root purposes"):
            replace(
                profile,
                trust_roots=(
                    TrustRootPin(
                        "trustref:mission-only",
                        DIGEST_A,
                        ("mission_bundle",),
                    ),
                    TrustRootPin(
                        "trustref:update-only",
                        DIGEST_B,
                        ("update_bundle",),
                    ),
                ),
            )
        with self.assertRaisesRegex(DeploymentProfileError, "stop, cleanup"):
            StopCleanupPolicy(
                "stopref:stop",
                "cleanupref:cleanup",
                "restorationref:restore",
                30,
                stop_supported=False,
            )
        with self.assertRaisesRegex(DeploymentProfileError, "custody and export"):
            EvidenceCustodyPolicy(
                "storeref:local",
                "manifestref:export",
                "trustref:export",
                export_required=False,
            )

    def test_raw_secrets_and_moving_versions_are_rejected(self) -> None:
        with self.assertRaisesRegex(DeploymentProfileError, "raw secret"):
            canonical_json({"credentialref": "password=hunter2"})
        raw = self.profile().to_dict()
        raw["version_pins"][0]["exact_version"] = "latest"
        with self.assertRaises(DeploymentProfileError):
            DeploymentProfile.from_dict(raw)

    def test_content_addresses_detect_tampering_and_unknown_fields(self) -> None:
        raw = copy.deepcopy(self.profile().to_dict())
        raw["maximum_clock_skew_seconds"] = 121
        with self.assertRaisesRegex(DeploymentProfileError, "content address"):
            DeploymentProfile.from_dict(raw)
        raw = copy.deepcopy(self.request().to_dict())
        raw["unexpected"] = True
        with self.assertRaisesRegex(DeploymentProfileError, "fields"):
            DeploymentAdmissionRequest.from_dict(raw)
        with self.assertRaisesRegex(DeploymentProfileError, "unsupported"):
            parse_contract({"kind": "sunderkey.deployment-unknown.v1"})

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_schema_accepts_all_contracts_and_rejects_unknown_fields(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        profile = self.profile()
        request = self.request(profile)
        result = evaluate_deployment_admission(
            profile,
            request,
            evaluated_at="2026-09-20T12:00:00Z",
        )
        for document in (profile.to_dict(), request.to_dict(), result.to_dict()):
            with self.subTest(kind=document["kind"]):
                validator.validate(document)
                changed = copy.deepcopy(document)
                changed["unexpected"] = True
                self.assertTrue(list(validator.iter_errors(changed)))

    def test_increment_has_no_unicode_dashes_or_authorship_markers(self) -> None:
        marker_fragments = (
            "generated " + "by",
            "written " + "by " + "an " + "ai",
            "as " + "an " + "ai",
            "chat" + "gpt",
            "co-authored" + "-by",
        )
        for path in FILES:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("\u2013", text, path)
            self.assertNotIn("\u2014", text, path)
            lowered = text.lower()
            for marker in marker_fragments:
                self.assertNotIn(marker, lowered, path)

    def test_module_imports_no_runtime_clients(self) -> None:
        source = FILES[0].read_text(encoding="utf-8")
        forbidden = (
            "import " + "socket",
            "import " + "requests",
            "import " + "urllib",
            "import " + "subprocess",
            "import " + "sqlite3",
            "import " + "psycopg",
            "from " + "cryptography",
        )
        for marker in forbidden:
            self.assertNotIn(marker, source)


if __name__ == "__main__":
    unittest.main()
