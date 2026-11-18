from __future__ import annotations

import copy
import json
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from jsonschema import Draft202012Validator, FormatChecker

import sunderkey.asset_reconciliation as asset_module
from sunderkey.asset_reconciliation import (
    NO_EFFECTS,
    SOURCE_CONFIDENCE_CAP_BPS,
    AssetIdentifier,
    AssetObservation,
    AssetReconciliationError,
    AssetReconciliationSnapshot,
    AttributeClaim,
    IdentifierKind,
    OwnershipClaim,
    SourceKind,
    load_asset_observations,
    load_asset_reconciliation_snapshot,
    reconcile_asset_observations,
    verify_asset_reconciliation_snapshot_from_sources,
)

ROOT = Path(__file__).resolve().parents[2]
DIGESTS = tuple(f"sha256:{index:064x}" for index in range(1, 20))

NATIVE = {
    SourceKind.CMDB: IdentifierKind.CMDB_CI_ID,
    SourceKind.CLOUD: IdentifierKind.CLOUD_RESOURCE_ID,
    SourceKind.DIRECTORY: IdentifierKind.DIRECTORY_OBJECT_ID,
    SourceKind.ENDPOINT: IdentifierKind.ENDPOINT_DEVICE_ID,
    SourceKind.VULNERABILITY: IdentifierKind.VULNERABILITY_ASSET_ID,
    SourceKind.EXTERNAL: IdentifierKind.EXTERNAL_ASSET_ID,
}


def identifier(kind: IdentifierKind | str, value: str, namespace: str = "corp") -> AssetIdentifier:
    return AssetIdentifier(kind=kind, namespace=namespace, value=value)


def observation(
    source: SourceKind,
    record: str,
    *,
    shared: tuple[AssetIdentifier, ...] = (),
    tenant: str = "tenant:alpha",
    observed_at: str = "2026-09-20T10:00:00Z",
    expires_at: str = "2026-09-22T10:00:00Z",
    confidence: int | None = None,
    claims: tuple[AttributeClaim, ...] = (),
    ownership: tuple[OwnershipClaim, ...] = (),
    digest_index: int = 1,
) -> AssetObservation:
    return AssetObservation(
        tenant_id=tenant,
        source_kind=source,
        source_system=f"{source.value}_source",
        source_record_id=record,
        observed_at=observed_at,
        expires_at=expires_at,
        confidence_bps=(SOURCE_CONFIDENCE_CAP_BPS[source] if confidence is None else confidence),
        provenance_sha256=DIGESTS[digest_index],
        identifiers=(identifier(NATIVE[source], record, f"{source.value}_source"), *shared),
        claims=claims,
        ownership=ownership,
    )


class AssetReconciliationPhase208Tests(unittest.TestCase):
    def test_nested_observation_record_subclasses_cannot_change_source_meaning(self) -> None:
        class MisleadingIdentifier(AssetIdentifier):
            def to_dict(self):
                return identifier(IdentifierKind.CMDB_CI_ID, "ci:one", "cmdb_source").to_dict()

        base = observation(SourceKind.CMDB, "ci:one")
        with self.assertRaisesRegex(AssetReconciliationError, "exact records"):
            AssetObservation(
                tenant_id=base.tenant_id,
                source_kind=base.source_kind,
                source_system=base.source_system,
                source_record_id=base.source_record_id,
                observed_at=base.observed_at,
                expires_at=base.expires_at,
                confidence_bps=base.confidence_bps,
                provenance_sha256=base.provenance_sha256,
                identifiers=(MisleadingIdentifier(
                    IdentifierKind.CMDB_CI_ID, "cmdb_source", "ci:two"
                ),),
            )

    def six_source_observations(self) -> tuple[AssetObservation, ...]:
        shared = (identifier(IdentifierKind.FQDN, "APP.Example.COM."),)
        return tuple(
            observation(source, f"record-{index}", shared=shared, digest_index=index)
            for index, source in enumerate(SourceKind, start=1)
        )

    def test_all_six_sources_reconcile_to_one_tenant_isolated_asset(self) -> None:
        snapshot = reconcile_asset_observations(
            "tenant:alpha", "2026-09-21T10:00:00Z", self.six_source_observations()
        )

        self.assertEqual(len(snapshot.assets), 1)
        self.assertEqual(snapshot.observation_count, 6)
        self.assertEqual(dict(snapshot.source_counts), {item.value: 1 for item in SourceKind})
        self.assertEqual(snapshot.assets[0].confidence_bps, 9800)
        self.assertEqual(snapshot.assets[0].freshness.value, "current")
        self.assertIn(
            "app.example.com",
            {item.value for item in snapshot.assets[0].identifiers},
        )
        self.assertEqual(snapshot.to_dict()["effects"], NO_EFFECTS)
        self.assertFalse(snapshot.to_dict()["effects"]["active_probing"])
        self.assertEqual(snapshot.to_dict()["effects"]["authority"], "none")

    def test_input_order_is_deterministic_and_snapshot_is_content_addressed(self) -> None:
        observations = self.six_source_observations()
        first = reconcile_asset_observations("tenant:alpha", "2026-09-21T10:00:00Z", observations)
        second = reconcile_asset_observations(
            "tenant:alpha", "2026-09-21T10:00:00Z", tuple(reversed(observations))
        )
        self.assertEqual(first, second)
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(
            AssetReconciliationSnapshot.from_dict(first.to_dict()).to_dict(), first.to_dict()
        )

        tampered = copy.deepcopy(first.to_dict())
        tampered["assets"][0]["confidence_bps"] = 1
        tampered["assets"][0]["confidence_band"] = "low"
        with self.assertRaisesRegex(AssetReconciliationError, "confidence"):
            AssetReconciliationSnapshot.from_dict(tampered)

        noncanonical = copy.deepcopy(first.to_dict())
        noncanonical["assets"][0]["identifiers"].reverse()
        with self.assertRaisesRegex(AssetReconciliationError, "canonical"):
            AssetReconciliationSnapshot.from_dict(noncanonical)

    def test_stored_snapshot_requires_complete_source_replay(self) -> None:
        import sunderkey

        self.assertIs(
            sunderkey.verify_asset_reconciliation_snapshot_from_sources,
            verify_asset_reconciliation_snapshot_from_sources,
        )
        observations = self.six_source_observations()
        snapshot = reconcile_asset_observations(
            "tenant:alpha", "2026-09-21T10:00:00Z", observations
        )
        self.assertEqual(
            verify_asset_reconciliation_snapshot_from_sources(snapshot, observations),
            snapshot,
        )
        self.assertEqual(
            verify_asset_reconciliation_snapshot_from_sources(
                snapshot, tuple(reversed(observations))
            ),
            snapshot,
        )
        with self.assertRaisesRegex(AssetReconciliationError, "source replay"):
            verify_asset_reconciliation_snapshot_from_sources(snapshot, observations[:-1])
        alternate = reconcile_asset_observations(
            "tenant:alpha", "2026-09-21T10:00:00Z", observations[:-1]
        )
        with self.assertRaisesRegex(AssetReconciliationError, "source replay"):
            verify_asset_reconciliation_snapshot_from_sources(alternate, observations)

    def test_source_native_identifier_and_confidence_caps_fail_closed(self) -> None:
        with self.assertRaisesRegex(AssetReconciliationError, "require"):
            AssetObservation(
                tenant_id="tenant:alpha",
                source_kind=SourceKind.CLOUD,
                source_system="cloud_source",
                source_record_id="cloud-1",
                observed_at="2026-09-20T10:00:00Z",
                expires_at="2026-09-22T10:00:00Z",
                confidence_bps=9000,
                provenance_sha256=DIGESTS[1],
                identifiers=(identifier(IdentifierKind.FQDN, "app.example.com"),),
            )
        with self.assertRaisesRegex(AssetReconciliationError, "source-kind cap"):
            observation(SourceKind.EXTERNAL, "external-1", confidence=7001)

    def test_tenant_and_future_observations_are_rejected(self) -> None:
        cross_tenant = (
            observation(SourceKind.CMDB, "ci-1"),
            observation(SourceKind.CLOUD, "cloud-1", tenant="tenant:beta"),
        )
        with self.assertRaisesRegex(AssetReconciliationError, "cross tenant"):
            reconcile_asset_observations("tenant:alpha", "2026-09-21T10:00:00Z", cross_tenant)
        future = observation(
            SourceKind.CMDB,
            "ci-2",
            observed_at="2026-09-22T10:00:00Z",
            expires_at="2026-09-23T10:00:00Z",
        )
        with self.assertRaisesRegex(AssetReconciliationError, "after reconciliation"):
            reconcile_asset_observations("tenant:alpha", "2026-09-21T10:00:00Z", (future,))

    def test_ip_and_hostname_are_corroborating_and_do_not_merge_assets(self) -> None:
        left = observation(
            SourceKind.CMDB,
            "ci-left",
            shared=(
                identifier(IdentifierKind.HOSTNAME, "server-1"),
                identifier(IdentifierKind.IP_ADDRESS, "192.0.2.10"),
            ),
        )
        right = observation(
            SourceKind.CLOUD,
            "cloud-right",
            shared=(
                identifier(IdentifierKind.HOSTNAME, "SERVER-1"),
                identifier(IdentifierKind.IP_ADDRESS, "192.0.2.10"),
            ),
            digest_index=2,
        )
        snapshot = reconcile_asset_observations(
            "tenant:alpha", "2026-09-21T10:00:00Z", (left, right)
        )
        self.assertEqual(len(snapshot.assets), 2)

    def test_current_claim_and_owner_conflicts_are_explicit(self) -> None:
        shared = (identifier(IdentifierKind.FQDN, "asset.example.com"),)
        left = observation(
            SourceKind.CMDB,
            "ci-1",
            shared=shared,
            claims=(AttributeClaim("environment", "production"),),
            ownership=(OwnershipClaim("team:blue", "2026-09-01T00:00:00Z"),),
            confidence=9000,
            digest_index=1,
        )
        right = observation(
            SourceKind.CLOUD,
            "cloud-1",
            shared=shared,
            claims=(AttributeClaim("environment", "staging"),),
            ownership=(OwnershipClaim("team:green", "2026-09-01T00:00:00Z"),),
            confidence=8500,
            digest_index=2,
        )
        snapshot = reconcile_asset_observations(
            "tenant:alpha", "2026-09-21T10:00:00Z", (left, right)
        )
        self.assertEqual(
            {item.kind for item in snapshot.conflicts},
            {"attribute_disagreement", "ownership_disagreement"},
        )
        self.assertEqual(snapshot.assets[0].confidence_bps, 8000)
        self.assertEqual(snapshot.assets[0].confidence_band.value, "high")
        self.assertEqual(len(snapshot.assets[0].ownership_history), 2)

    def test_stale_only_assets_have_explicit_freshness_and_confidence_cap(self) -> None:
        stale = observation(
            SourceKind.CMDB,
            "ci-stale",
            expires_at="2026-09-20T12:00:00Z",
            confidence=9000,
        )
        snapshot = reconcile_asset_observations("tenant:alpha", "2026-09-21T10:00:00Z", (stale,))
        self.assertEqual(snapshot.assets[0].freshness.value, "stale")
        self.assertEqual(snapshot.assets[0].confidence_bps, 5000)
        self.assertEqual(snapshot.assets[0].provenance[0].freshness.value, "stale")

    def test_verified_prior_snapshot_preserves_id_and_ownership_history(self) -> None:
        first_observation = observation(
            SourceKind.CMDB,
            "ci-1",
            shared=(identifier(IdentifierKind.FQDN, "asset.example.com"),),
            ownership=(OwnershipClaim("team:blue", "2026-09-01T00:00:00Z"),),
        )
        first = reconcile_asset_observations(
            "tenant:alpha", "2026-09-20T12:00:00Z", (first_observation,)
        )
        second_observation = observation(
            SourceKind.CLOUD,
            "cloud-new-higher-priority",
            shared=(identifier(IdentifierKind.FQDN, "asset.example.com"),),
            observed_at="2026-09-21T11:00:00Z",
            expires_at="2026-09-23T10:00:00Z",
            ownership=(OwnershipClaim("team:green", "2026-09-21T00:00:00Z"),),
            digest_index=2,
        )
        second = reconcile_asset_observations(
            "tenant:alpha",
            "2026-09-21T12:00:00Z",
            (second_observation,),
            prior_snapshot=first,
        )
        self.assertEqual(second.assets[0].asset_id, first.assets[0].asset_id)
        self.assertEqual(second.assets[0].prior_asset_ids, (first.assets[0].asset_id,))
        self.assertEqual(
            {item.owner_ref for item in second.assets[0].ownership_history},
            {"team:blue", "team:green"},
        )

    def test_ambiguous_prior_merge_is_never_silent(self) -> None:
        first = reconcile_asset_observations(
            "tenant:alpha",
            "2026-09-20T12:00:00Z",
            (
                observation(SourceKind.CMDB, "ci-a", digest_index=1),
                observation(SourceKind.CLOUD, "cloud-b", digest_index=2),
            ),
        )
        merged = reconcile_asset_observations(
            "tenant:alpha",
            "2026-09-21T12:00:00Z",
            (
                observation(
                    SourceKind.CMDB,
                    "ci-a",
                    shared=(identifier(IdentifierKind.FQDN, "merged.example.com"),),
                    observed_at="2026-09-21T10:00:00Z",
                    expires_at="2026-09-23T10:00:00Z",
                    digest_index=3,
                ),
                observation(
                    SourceKind.CLOUD,
                    "cloud-b",
                    shared=(identifier(IdentifierKind.FQDN, "merged.example.com"),),
                    observed_at="2026-09-21T10:00:00Z",
                    expires_at="2026-09-23T10:00:00Z",
                    digest_index=4,
                ),
            ),
            prior_snapshot=first,
        )
        self.assertEqual(len(merged.assets), 1)
        self.assertEqual(merged.conflicts[0].kind, "prior_identity_merge")
        self.assertEqual(
            set(merged.assets[0].prior_asset_ids), {item.asset_id for item in first.assets}
        )
        self.assertNotIn(merged.assets[0].asset_id, {item.asset_id for item in first.assets})

    def test_current_claims_do_not_silently_retain_stale_values(self) -> None:
        shared = (identifier(IdentifierKind.FQDN, "asset.example.com"),)
        stale = observation(
            SourceKind.CMDB,
            "ci-1",
            shared=shared,
            expires_at="2026-09-20T12:00:00Z",
            claims=(AttributeClaim("environment", "retired"),),
        )
        current = observation(
            SourceKind.CLOUD,
            "cloud-1",
            shared=shared,
            observed_at="2026-09-21T09:00:00Z",
            expires_at="2026-09-23T10:00:00Z",
            claims=(AttributeClaim("environment", "production"),),
            digest_index=2,
        )
        snapshot = reconcile_asset_observations(
            "tenant:alpha", "2026-09-21T10:00:00Z", (stale, current)
        )
        self.assertEqual(snapshot.assets[0].claims, (AttributeClaim("environment", "production"),))

    def test_boolean_schema_numbers_fail_runtime_validation(self) -> None:
        snapshot = reconcile_asset_observations(
            "tenant:alpha",
            "2026-09-21T10:00:00Z",
            (observation(SourceKind.CMDB, "ci-1"),),
        ).to_dict()
        snapshot["schema_version"] = True
        with self.assertRaisesRegex(AssetReconciliationError, "schema_version"):
            AssetReconciliationSnapshot.from_dict(snapshot)

        snapshot = reconcile_asset_observations(
            "tenant:alpha",
            "2026-09-21T10:00:00Z",
            (observation(SourceKind.CMDB, "ci-1"),),
        ).to_dict()
        snapshot["source_counts"]["cmdb"] = True
        with self.assertRaisesRegex(AssetReconciliationError, "source_counts"):
            AssetReconciliationSnapshot.from_dict(snapshot)

    def test_policy_and_snapshot_schemas_validate_artifacts(self) -> None:
        policy = json.loads(
            (ROOT / "registry" / "asset-reconciliation-policy-v1.json").read_text(encoding="utf-8")
        )
        policy_schema = json.loads(
            (
                ROOT / "registry" / "schemas" / "asset-reconciliation-policy-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        Draft202012Validator(policy_schema, format_checker=FormatChecker()).validate(policy)

        snapshot_schema = json.loads(
            (
                ROOT / "registry" / "schemas" / "asset-reconciliation-snapshot-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        snapshot = reconcile_asset_observations(
            "tenant:alpha", "2026-09-21T10:00:00Z", self.six_source_observations()
        )
        Draft202012Validator(snapshot_schema, format_checker=FormatChecker()).validate(
            snapshot.to_dict()
        )

    def test_secret_like_claims_and_effect_tampering_are_rejected(self) -> None:
        with self.assertRaisesRegex(AssetReconciliationError, "secret material"):
            AttributeClaim("api_token", "not-stored")
        with self.assertRaisesRegex(AssetReconciliationError, "secret material"):
            AttributeClaim("description", "password=hunter2")

        snapshot = reconcile_asset_observations(
            "tenant:alpha",
            "2026-09-21T10:00:00Z",
            (observation(SourceKind.CMDB, "ci-1"),),
        )
        active = copy.deepcopy(snapshot.to_dict())
        active["effects"]["active_probing"] = True
        with self.assertRaisesRegex(AssetReconciliationError, "passive-only"):
            AssetReconciliationSnapshot.from_dict(active)

    def test_file_loaders_reject_duplicates_and_round_trip_exact_documents(self) -> None:
        observations = self.six_source_observations()
        snapshot = reconcile_asset_observations(
            "tenant:alpha", "2026-09-21T10:00:00Z", observations
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            observation_path = root / "observations.json"
            snapshot_path = root / "snapshot.json"
            duplicate_path = root / "duplicate.json"
            observation_path.write_text(
                json.dumps([item.to_dict() for item in observations]), encoding="utf-8"
            )
            snapshot_path.write_text(json.dumps(snapshot.to_dict()), encoding="utf-8")
            duplicate_path.write_text('[{"tenant_id":"a","tenant_id":"b"}]', encoding="utf-8")

            self.assertEqual(load_asset_observations(observation_path), observations)
            self.assertEqual(load_asset_reconciliation_snapshot(snapshot_path), snapshot)
            with self.assertRaisesRegex(AssetReconciliationError, "duplicate JSON key"):
                load_asset_observations(duplicate_path)

    def test_file_loader_rejects_nonregular_and_growth_after_size_check(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "observations.json"
            source.write_bytes(b"[]")
            with self.assertRaisesRegex(AssetReconciliationError, "regular file"):
                load_asset_observations(Path(directory))
            with patch.object(
                Path,
                "stat",
                return_value=SimpleNamespace(st_mode=stat.S_IFIFO, st_size=0),
            ):
                with self.assertRaisesRegex(AssetReconciliationError, "regular file"):
                    asset_module._load_json_path(source, "asset file")

            original_fdopen = asset_module.os.fdopen

            def grow_before_read(descriptor, *args, **kwargs):
                with source.open("ab") as stream:
                    stream.write(b"x" * 40)
                return original_fdopen(descriptor, *args, **kwargs)

            with patch.object(asset_module, "MAX_DOCUMENT_BYTES", 32):
                with patch.object(asset_module.os, "fdopen", side_effect=grow_before_read):
                    with self.assertRaisesRegex(AssetReconciliationError, "byte limit"):
                        asset_module._load_json_path(source, "asset file")

    def test_public_package_exports_preserve_contract_identity(self) -> None:
        import sunderkey

        self.assertIs(sunderkey.AssetObservation, AssetObservation)
        self.assertIs(sunderkey.reconcile_asset_observations, reconcile_asset_observations)

    def test_module_has_no_network_or_process_execution_imports(self) -> None:
        source = (ROOT / "src" / "sunderkey" / "asset_reconciliation.py").read_text(
            encoding="utf-8"
        )
        for prohibited in (
            "import requests",
            "import socket",
            "import subprocess",
            "import urllib",
            "http.client",
            "aiohttp",
        ):
            self.assertNotIn(prohibited, source)


if __name__ == "__main__":
    unittest.main()
