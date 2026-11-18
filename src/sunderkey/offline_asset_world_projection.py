"""Project replayed passive asset records into hypothesis-only world nodes."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta
from typing import Any

from .asset_reconciliation import (
    AssetObservation,
    AssetReconciliationError,
    AssetReconciliationSnapshot,
    FreshnessState,
    verify_asset_reconciliation_snapshot_from_sources,
)
from .attack_world_model import (
    AttackNode,
    AttackWorldModelError,
    AttackWorldSnapshot,
    EvidenceBinding,
    VerificationState,
    build_attack_world_snapshot,
)

DOMAIN = "sunderkey.offline-asset-world-projection.v1"
MAX_ASSETS = 256
MAX_SOURCE_OBSERVATIONS = 4096
MAX_SOURCE_BYTES = 16 * 1024 * 1024
MAX_LINEAGE_DEPTH = 8
MAX_REPORT_BYTES = 1_048_576
MAX_REPORT_NODES = 65_536
MAX_REPORT_DEPTH = 24
MAX_PROJECTION_AGE = timedelta(hours=24)
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
SCOPE_RE = re.compile(r"scope:[A-Za-z0-9][A-Za-z0-9._:/-]{0,190}\Z")
EFFECTS = dict.fromkeys(
    (
        "authority", "target", "network", "credential", "process", "execution",
        "routing", "qualification", "publication", "deployment", "assignment",
    ),
    "none",
)
AssetSourceEntry = tuple[AssetReconciliationSnapshot, tuple[AssetObservation, ...]]


class OfflineAssetWorldProjectionError(ValueError):
    """The source chain, projection, or replay boundary failed closed."""


def _instant(value: Any, label: str) -> datetime:
    if type(value) is not str or UTC_RE.fullmatch(value) is None:
        raise OfflineAssetWorldProjectionError(f"{label} must be second-precision UTC")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise OfflineAssetWorldProjectionError(f"{label} is invalid") from exc


def _capture(value: Any) -> tuple[dict[str, Any], str]:
    """Copy bounded exact-native JSON; only world confidence may be a zero float."""
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_REPORT_NODES or depth > MAX_REPORT_DEPTH:
            raise OfflineAssetWorldProjectionError("Projection report node/depth limit exceeded")
        kind = type(item)
        if kind in (dict, list):
            if id(item) in active:
                raise OfflineAssetWorldProjectionError("Cyclic projection report refused")
            active.add(id(item))
            try:
                if kind is dict:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise OfflineAssetWorldProjectionError("Projection keys must be text")
                        visit(key, depth + 1)
                        visit(child, depth + 1)
                else:
                    for child in item:
                        visit(child, depth + 1)
            finally:
                active.remove(id(item))
        elif kind is str:
            if len(item) > 512 or any(0xD800 <= ord(char) <= 0xDFFF for char in item):
                raise OfflineAssetWorldProjectionError("Projection text is invalid or oversized")
        elif kind is int:
            if not -(1 << 63) <= item < 1 << 63:
                raise OfflineAssetWorldProjectionError("Projection integer exceeds signed 64-bit")
        elif kind is float:
            if item != 0.0:
                raise OfflineAssetWorldProjectionError("Only zero world confidence is permitted")
        elif kind is not bool and item is not None:
            raise OfflineAssetWorldProjectionError("Projection value is not exact native JSON")

    visit(value, 1)
    text = json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    )
    if len(text) > MAX_REPORT_BYTES:
        raise OfflineAssetWorldProjectionError("Projection report byte limit exceeded")
    parsed = json.loads(text)
    if type(parsed) is not dict:
        raise OfflineAssetWorldProjectionError("Projection report must be an object")
    return parsed, text


def _digest(body: dict[str, Any]) -> str:
    encoded = json.dumps(body, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256((DOMAIN + "\n" + encoded).encode("ascii")).hexdigest()


def _source_digest(
    observations: tuple[AssetObservation, ...], *, remaining_bytes: int
) -> tuple[str, int]:
    """Hash a canonical source array incrementally under one aggregate byte budget."""
    hasher = hashlib.sha256()
    hasher.update((DOMAIN + "\n").encode("ascii"))
    prefix = b'{"source_observations":['
    suffix = b"]}"
    hasher.update(prefix)
    used = len(prefix) + len(suffix)
    for index, item in enumerate(sorted(observations, key=lambda row: row.provenance_key)):
        encoded = json.dumps(
            item.to_dict(), ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode("ascii")
        used += len(encoded) + int(index > 0)
        if used > remaining_bytes:
            raise OfflineAssetWorldProjectionError("Asset source byte limit exceeded")
        if index:
            hasher.update(b",")
        hasher.update(encoded)
    if used > remaining_bytes:
        raise OfflineAssetWorldProjectionError("Asset source byte limit exceeded")
    hasher.update(suffix)
    return "sha256:" + hasher.hexdigest(), used


def _sources(
    snapshot: AssetReconciliationSnapshot,
    observations: tuple[AssetObservation, ...],
    prior_sources: tuple[AssetSourceEntry, ...],
) -> list[dict[str, Any]]:
    if type(snapshot) is not AssetReconciliationSnapshot or type(observations) is not tuple:
        raise OfflineAssetWorldProjectionError(
            "Typed asset snapshot and observation tuple required"
        )
    if type(prior_sources) is not tuple or len(prior_sources) > MAX_LINEAGE_DEPTH:
        raise OfflineAssetWorldProjectionError("Prior source chain is invalid or oversized")
    chain = (*prior_sources, (snapshot, observations))
    if any(
        type(entry) is not tuple
        or len(entry) != 2
        or type(entry[0]) is not AssetReconciliationSnapshot
        or type(entry[1]) is not tuple
        for entry in chain
    ):
        raise OfflineAssetWorldProjectionError("Prior source entry is invalid")
    if sum(len(entry[1]) for entry in chain) > MAX_SOURCE_OBSERVATIONS:
        raise OfflineAssetWorldProjectionError("Asset source observation limit exceeded")
    if any(
        len(entry[0].assets) > MAX_ASSETS
        or any(type(item) is not AssetObservation for item in entry[1])
        for entry in chain
    ):
        raise OfflineAssetWorldProjectionError("Asset source type or asset count is invalid")
    previous: AssetReconciliationSnapshot | None = None
    bindings: list[dict[str, Any]] = []
    source_bytes = 0
    for current, source_rows in chain:
        source_sha256, size = _source_digest(
            source_rows, remaining_bytes=MAX_SOURCE_BYTES - source_bytes
        )
        source_bytes += size
        try:
            verify_asset_reconciliation_snapshot_from_sources(
                current, source_rows, prior_snapshot=previous
            )
        except AssetReconciliationError as exc:
            raise OfflineAssetWorldProjectionError("Asset source chain replay failed") from exc
        bindings.append(
            {
                "snapshot_sha256": current.snapshot_sha256,
                "source_sha256": source_sha256,
                "observation_count": len(source_rows),
            }
        )
        previous = current
    return bindings


def project_offline_assets_to_world(
    *,
    snapshot: AssetReconciliationSnapshot,
    observations: tuple[AssetObservation, ...],
    scope_ref: str,
    as_of: str,
    prior_sources: tuple[AssetSourceEntry, ...] = (),
) -> dict[str, Any]:
    """Replay every raw source, then create only zero-confidence asset hypotheses."""
    if type(scope_ref) is not str or SCOPE_RE.fullmatch(scope_ref) is None:
        raise OfflineAssetWorldProjectionError("scope_ref must be a bounded scope label")
    projected_at = _instant(as_of, "as_of")
    if type(snapshot) is not AssetReconciliationSnapshot:
        raise OfflineAssetWorldProjectionError("Typed asset snapshot required")
    snapshot_at = _instant(snapshot.as_of, "snapshot as_of")
    if projected_at < snapshot_at or projected_at > snapshot_at + MAX_PROJECTION_AGE:
        raise OfflineAssetWorldProjectionError("Projection time is outside the source window")
    bindings = _sources(snapshot, observations, prior_sources)
    conflicts = {item.asset_id for item in snapshot.conflicts}
    nodes: list[AttackNode] = []
    withheld: list[dict[str, str]] = []
    for asset in snapshot.assets:
        current = [
            record for record in asset.provenance
            if _instant(record.observed_at, "provenance observed_at") <= projected_at
            < _instant(record.expires_at, "provenance expires_at")
        ]
        if asset.asset_id in conflicts:
            withheld.append({"asset_id": asset.asset_id, "reason": "unresolved_conflict"})
            continue
        if asset.freshness is not FreshnessState.CURRENT or not current:
            withheld.append({"asset_id": asset.asset_id, "reason": "stale_or_expired_source"})
            continue
        expiry = min(_instant(row.expires_at, "provenance expires_at") for row in current)
        expiry = min(expiry, projected_at + MAX_PROJECTION_AGE)
        try:
            nodes.append(
                AttackNode(
                    node_id="asset:" + asset.asset_id,
                    node_kind="asset",
                    label=asset.asset_id,
                    scope_refs=(scope_ref,),
                    technique_refs=(),
                    evidence=EvidenceBinding(
                        provenance_artifact_digest=snapshot.snapshot_sha256,
                        observed_at=as_of,
                        expires_at=expiry.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        confidence=0.0,
                        verification_state="hypothesis",
                        source_kind="caller_supplied_asset_snapshot",
                    ),
                )
            )
        except AttackWorldModelError as exc:
            raise OfflineAssetWorldProjectionError(
                "Hypothesis-only world construction failed"
            ) from exc
    try:
        world = build_attack_world_snapshot(nodes, ())
        AttackWorldSnapshot.from_dict(world.to_dict())
    except AttackWorldModelError as exc:
        raise OfflineAssetWorldProjectionError("Asset world snapshot is invalid") from exc
    if world.edges or any(
        node.evidence.verification_state is not VerificationState.HYPOTHESIS
        or node.evidence.confidence != 0.0
        for node in world.nodes
    ):
        raise OfflineAssetWorldProjectionError("Nonhypothetical asset world fact refused")
    body = {
        "schema_version": 1,
        "scope_ref": scope_ref,
        "as_of": as_of,
        "tenant_id": snapshot.tenant_id,
        "asset_snapshot_sha256": snapshot.snapshot_sha256,
        "source_chain": bindings,
        "world_snapshot": world.to_dict(),
        "projected_asset_count": len(nodes),
        "withheld_assets": withheld,
        "flags": {
            "caller_time_trusted": False,
            "scope_equivalence_proven": False,
            "source_authenticated": False,
            "verified_path_created": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(EFFECTS),
    }
    _capture(body)
    digest = _digest(body)
    return _capture(
        {
            **body,
            "projection_id": "OAW-" + digest[7:39].upper(),
            "projection_sha256": digest,
        }
    )[0]


def verify_offline_asset_world_projection(
    packet: Any,
    *,
    snapshot: AssetReconciliationSnapshot,
    observations: tuple[AssetObservation, ...],
    scope_ref: str,
    as_of: str,
    prior_sources: tuple[AssetSourceEntry, ...] = (),
) -> dict[str, Any]:
    """Rebuild the packet from the separate raw asset sources and complete lineage."""
    supplied, text = _capture(packet)
    expected = project_offline_assets_to_world(
        snapshot=snapshot,
        observations=observations,
        scope_ref=scope_ref,
        as_of=as_of,
        prior_sources=prior_sources,
    )
    if text != _capture(expected)[1]:
        raise OfflineAssetWorldProjectionError("Asset world projection source replay differs")
    return supplied
