"""Source-closed, hypothesis-only passive asset world projection tests."""

from __future__ import annotations

import copy
import unittest
from unittest.mock import patch

from sunderkey.asset_reconciliation import (
    AssetIdentifier,
    AssetObservation,
    AttributeClaim,
    IdentifierKind,
    SourceKind,
    reconcile_asset_observations,
)
from sunderkey.attack_world_model import AttackWorldSnapshot
from sunderkey.offline_asset_world_projection import (
    EFFECTS,
    OfflineAssetWorldProjectionError,
    project_offline_assets_to_world,
    verify_offline_asset_world_projection,
)
import sunderkey.offline_asset_world_projection as projection_module

SNAPSHOT_AT = "2026-09-21T10:00:00Z"
PROJECTION_AT = "2026-09-21T11:00:00Z"
SCOPE = "scope:asset-review"


def observation(
    source: SourceKind,
    record_id: str,
    *,
    fqdn: str,
    digest_char: str,
    expires_at: str = "2026-09-22T10:00:00Z",
    claims: tuple[AttributeClaim, ...] = (),
    observed_at: str = "2026-09-20T10:00:00Z",
) -> AssetObservation:
    native_kind = {
        SourceKind.CMDB: IdentifierKind.CMDB_CI_ID,
        SourceKind.CLOUD: IdentifierKind.CLOUD_RESOURCE_ID,
    }[source]
    return AssetObservation(
        tenant_id="tenant:alpha",
        source_kind=source,
        source_system=source.value + "_fixture",
        source_record_id=record_id,
        observed_at=observed_at,
        expires_at=expires_at,
        confidence_bps=8000,
        provenance_sha256="sha256:" + digest_char * 64,
        identifiers=(
            AssetIdentifier(native_kind, source.value, record_id),
            AssetIdentifier(IdentifierKind.FQDN, "dns", fqdn),
        ),
        claims=claims,
    )


class OfflineAssetWorldProjectionTests(unittest.TestCase):
    def sources(self) -> tuple[AssetObservation, ...]:
        return (
            observation(SourceKind.CMDB, "current-1", fqdn="current.example", digest_char="a"),
            observation(
                SourceKind.CLOUD,
                "stale-1",
                fqdn="stale.example",
                digest_char="b",
                expires_at="2026-09-20T12:00:00Z",
            ),
            observation(
                SourceKind.CMDB,
                "conflict-1",
                fqdn="conflict.example",
                digest_char="c",
                claims=(AttributeClaim("environment", "production"),),
            ),
            observation(
                SourceKind.CLOUD,
                "conflict-2",
                fqdn="conflict.example",
                digest_char="d",
                claims=(AttributeClaim("environment", "staging"),),
            ),
        )

    def test_only_current_nonconflicted_asset_becomes_zero_confidence_hypothesis(self) -> None:
        source = self.sources()
        snapshot = reconcile_asset_observations("tenant:alpha", SNAPSHOT_AT, source)
        packet = project_offline_assets_to_world(
            snapshot=snapshot, observations=source, scope_ref=SCOPE, as_of=PROJECTION_AT
        )
        world = AttackWorldSnapshot.from_dict(packet["world_snapshot"])
        self.assertEqual(packet["projected_asset_count"], 1)
        self.assertEqual(len(packet["withheld_assets"]), 2)
        self.assertEqual(
            {row["reason"] for row in packet["withheld_assets"]},
            {"unresolved_conflict", "stale_or_expired_source"},
        )
        self.assertEqual(len(world.nodes), 1)
        self.assertEqual(world.edges, ())
        self.assertEqual(world.nodes[0].evidence.confidence, 0.0)
        self.assertEqual(world.nodes[0].evidence.verification_state.value, "hypothesis")
        self.assertEqual(world.nodes[0].scope_refs, (SCOPE,))
        self.assertEqual(packet["operational_effects"], EFFECTS)
        self.assertFalse(packet["flags"]["positive_use_approved"])
        self.assertEqual(
            verify_offline_asset_world_projection(
                packet, snapshot=snapshot, observations=source, scope_ref=SCOPE,
                as_of=PROJECTION_AT,
            ),
            packet,
        )

    def test_expired_after_snapshot_is_withheld_at_projection_time(self) -> None:
        source = (
            observation(
                SourceKind.CMDB, "expires-soon", fqdn="soon.example", digest_char="e",
                expires_at="2026-09-21T10:30:00Z",
            ),
        )
        snapshot = reconcile_asset_observations("tenant:alpha", SNAPSHOT_AT, source)
        packet = project_offline_assets_to_world(
            snapshot=snapshot, observations=source, scope_ref=SCOPE, as_of=PROJECTION_AT
        )
        self.assertEqual(packet["projected_asset_count"], 0)
        self.assertEqual(packet["withheld_assets"][0]["reason"], "stale_or_expired_source")
        self.assertEqual(packet["world_snapshot"]["nodes"], [])

    def test_raw_source_substitution_and_coherent_replacement_fail_replay(self) -> None:
        original = (
            observation(SourceKind.CMDB, "ci-1", fqdn="app.example", digest_char="1"),
        )
        snapshot = reconcile_asset_observations("tenant:alpha", SNAPSHOT_AT, original)
        packet = project_offline_assets_to_world(
            snapshot=snapshot, observations=original, scope_ref=SCOPE, as_of=PROJECTION_AT
        )
        altered = (
            observation(SourceKind.CMDB, "ci-1", fqdn="app.example", digest_char="2"),
        )
        with self.assertRaisesRegex(OfflineAssetWorldProjectionError, "source chain replay"):
            verify_offline_asset_world_projection(
                packet, snapshot=snapshot, observations=altered,
                scope_ref=SCOPE, as_of=PROJECTION_AT,
            )
        alternate_snapshot = reconcile_asset_observations("tenant:alpha", SNAPSHOT_AT, altered)
        with self.assertRaisesRegex(OfflineAssetWorldProjectionError, "source replay differs"):
            verify_offline_asset_world_projection(
                packet, snapshot=alternate_snapshot, observations=altered,
                scope_ref=SCOPE, as_of=PROJECTION_AT,
            )

    def test_complete_prior_chain_is_required_for_descendant(self) -> None:
        first_source = (
            observation(SourceKind.CMDB, "ci-1", fqdn="app.example", digest_char="1"),
        )
        first = reconcile_asset_observations(
            "tenant:alpha", "2026-09-20T11:00:00Z", first_source
        )
        later_source = (
            observation(
                SourceKind.CLOUD, "cloud-1", fqdn="app.example", digest_char="2",
                observed_at="2026-09-21T09:00:00Z",
            ),
        )
        later = reconcile_asset_observations(
            "tenant:alpha", SNAPSHOT_AT, later_source, prior_snapshot=first
        )
        packet = project_offline_assets_to_world(
            snapshot=later, observations=later_source, scope_ref=SCOPE,
            as_of=PROJECTION_AT, prior_sources=((first, first_source),),
        )
        self.assertEqual(len(packet["source_chain"]), 2)
        self.assertEqual(packet["projected_asset_count"], 1)
        with self.assertRaisesRegex(OfflineAssetWorldProjectionError, "source chain replay"):
            verify_offline_asset_world_projection(
                packet, snapshot=later, observations=later_source,
                scope_ref=SCOPE, as_of=PROJECTION_AT,
            )
        self.assertEqual(
            verify_offline_asset_world_projection(
                packet, snapshot=later, observations=later_source,
                scope_ref=SCOPE, as_of=PROJECTION_AT,
                prior_sources=((first, first_source),),
            ),
            packet,
        )

    def test_tampering_scope_and_effects_cannot_replay(self) -> None:
        source = (
            observation(SourceKind.CMDB, "ci-1", fqdn="app.example", digest_char="1"),
        )
        snapshot = reconcile_asset_observations("tenant:alpha", SNAPSHOT_AT, source)
        packet = project_offline_assets_to_world(
            snapshot=snapshot, observations=source, scope_ref=SCOPE, as_of=PROJECTION_AT
        )
        for field, value in (
            ("scope_ref", "scope:other"),
            ("operational_effects", {**EFFECTS, "authority": "approved"}),
            ("projected_asset_count", 2),
        ):
            changed = copy.deepcopy(packet)
            changed[field] = value
            with self.subTest(field=field):
                with self.assertRaisesRegex(OfflineAssetWorldProjectionError, "replay differs"):
                    verify_offline_asset_world_projection(
                        changed, snapshot=snapshot, observations=source,
                        scope_ref=SCOPE, as_of=PROJECTION_AT,
                    )
        cyclic = copy.deepcopy(packet)
        cyclic["extra"] = cyclic
        with self.assertRaisesRegex(OfflineAssetWorldProjectionError, "Cyclic"):
            verify_offline_asset_world_projection(
                cyclic, snapshot=snapshot, observations=source,
                scope_ref=SCOPE, as_of=PROJECTION_AT,
            )

    def test_invalid_scope_and_projection_window_fail_closed(self) -> None:
        source = (
            observation(SourceKind.CMDB, "ci-1", fqdn="app.example", digest_char="1"),
        )
        snapshot = reconcile_asset_observations("tenant:alpha", SNAPSHOT_AT, source)
        for scope, instant in (
            ("asset-review", PROJECTION_AT),
            (SCOPE, "2026-09-20T10:00:00Z"),
            (SCOPE, "2026-09-23T11:00:00Z"),
        ):
            with self.subTest(scope=scope, instant=instant):
                with self.assertRaises(OfflineAssetWorldProjectionError):
                    project_offline_assets_to_world(
                        snapshot=snapshot, observations=source,
                        scope_ref=scope, as_of=instant,
                    )

    def test_aggregate_raw_source_byte_ceiling_precedes_replay(self) -> None:
        source = (
            observation(SourceKind.CMDB, "ci-1", fqdn="app.example", digest_char="1"),
        )
        snapshot = reconcile_asset_observations("tenant:alpha", SNAPSHOT_AT, source)
        with patch.object(projection_module, "MAX_SOURCE_BYTES", 100):
            with self.assertRaisesRegex(OfflineAssetWorldProjectionError, "source byte limit"):
                project_offline_assets_to_world(
                    snapshot=snapshot, observations=source,
                    scope_ref=SCOPE, as_of=PROJECTION_AT,
                )


if __name__ == "__main__":
    unittest.main()
