"""Source-replayed, passive review of asset identity and disappearance between snapshots."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from typing import Any

from sunderkey.asset_reconciliation import (
    AssetObservation,
    AssetReconciliationSnapshot,
    verify_asset_reconciliation_snapshot_from_sources,
)

DOMAIN = "sunderkey.asset-lifecycle-review.v1"
NO_EFFECTS = {
    "active_probing": False,
    "asset_retirement": False,
    "authority": "none",
    "deployment": "none",
    "qualification": "none",
    "routing": "none",
    "target_interaction": False,
}


class AssetLifecycleReviewError(ValueError):
    """The supplied snapshots, source replay, or lifecycle review are invalid."""


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AssetLifecycleReviewError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def build_asset_lifecycle_review(
    prior_snapshot: AssetReconciliationSnapshot,
    current_snapshot: AssetReconciliationSnapshot,
    prior_observations: Sequence[AssetObservation],
    current_observations: Sequence[AssetObservation],
    *,
    prior_predecessor_snapshot: AssetReconciliationSnapshot | None = None,
) -> dict[str, Any]:
    """Review every prior asset after exact caller-supplied source replay.

    A missing observation is only a review candidate. It is never a tombstone
    or permission to retire a record from any operational inventory.
    """

    if (
        type(prior_snapshot) is not AssetReconciliationSnapshot
        or type(current_snapshot) is not AssetReconciliationSnapshot
        or not isinstance(prior_observations, Sequence)
        or not isinstance(current_observations, Sequence)
        or any(type(item) is not AssetObservation for item in prior_observations)
        or any(type(item) is not AssetObservation for item in current_observations)
        or (
            prior_predecessor_snapshot is not None
            and type(prior_predecessor_snapshot) is not AssetReconciliationSnapshot
        )
    ):
        raise AssetLifecycleReviewError("lifecycle inputs must be exact records")
    try:
        if prior_predecessor_snapshot is not None:
            AssetReconciliationSnapshot.from_dict(prior_predecessor_snapshot.to_dict())
        prior_snapshot = verify_asset_reconciliation_snapshot_from_sources(
            prior_snapshot, prior_observations, prior_snapshot=prior_predecessor_snapshot
        )
        current_snapshot = verify_asset_reconciliation_snapshot_from_sources(
            current_snapshot, current_observations, prior_snapshot=prior_snapshot
        )
    except (TypeError, AttributeError, ValueError) as exc:
        raise AssetLifecycleReviewError(
            "asset snapshots do not match supplied source replay"
        ) from exc
    if prior_snapshot.tenant_id != current_snapshot.tenant_id:
        raise AssetLifecycleReviewError("asset snapshots cross tenant boundaries")
    current_by_id = {asset.asset_id: asset for asset in current_snapshot.assets}
    successors: dict[str, set[str]] = {asset.asset_id: set() for asset in prior_snapshot.assets}
    for current in current_snapshot.assets:
        for prior_id in current.prior_asset_ids:
            if prior_id in successors:
                successors[prior_id].add(current.asset_id)
    current_source_kinds = {name for name, _ in current_snapshot.source_counts}
    entries: list[dict[str, Any]] = []
    for prior in prior_snapshot.assets:
        linked = successors[prior.asset_id]
        if prior.asset_id in current_by_id:
            linked.add(prior.asset_id)
        successor_ids = sorted(linked)
        prior_source_kinds = sorted({record.source_kind.value for record in prior.provenance})
        missing_source_kinds = sorted(set(prior_source_kinds) - current_source_kinds)
        merged_successor = any(
            len(current_by_id[asset_id].prior_asset_ids) > 1
            for asset_id in successor_ids
        )
        if len(successor_ids) > 1 or merged_successor:
            disposition = "ambiguous_continuity"
        elif successor_ids and successor_ids[0] == prior.asset_id:
            disposition = "retained"
        elif successor_ids:
            disposition = "identity_reassigned"
        elif missing_source_kinds:
            disposition = "unobserved_with_source_gap"
        else:
            disposition = "unobserved_with_class_overlap"
        entries.append(
            {
                "prior_asset_id": prior.asset_id,
                "disposition": disposition,
                "successor_asset_ids": successor_ids,
                "prior_source_kinds": prior_source_kinds,
                "missing_source_kinds": missing_source_kinds,
                "review_required": disposition != "retained" or bool(missing_source_kinds),
                "tombstone_review_candidate": disposition.startswith("unobserved"),
                "tombstone_applied": False,
            }
        )
    body = {
        "schema_version": 1,
        "tenant_id": prior_snapshot.tenant_id,
        "prior_snapshot_sha256": prior_snapshot.snapshot_sha256,
        "current_snapshot_sha256": current_snapshot.snapshot_sha256,
        "prior_predecessor_snapshot_sha256": (
            prior_predecessor_snapshot.snapshot_sha256
            if prior_predecessor_snapshot is not None else None
        ),
        "as_of": current_snapshot.as_of,
        "entries": entries,
        "summary": {
            "prior_asset_count": len(entries),
            "review_required_count": sum(item["review_required"] for item in entries),
            "tombstone_candidate_count": sum(
                item["tombstone_review_candidate"] for item in entries
            ),
            "retired_asset_count": 0,
        },
        "effects": dict(NO_EFFECTS),
    }
    digest = hashlib.sha256((DOMAIN + "\0" + _canonical(body)).encode("utf-8")).hexdigest()
    return {"review_id": f"ALR-{digest[:32].upper()}", "review_sha256": f"sha256:{digest}", **body}


def verify_asset_lifecycle_review(
    raw: Any,
    prior_snapshot: AssetReconciliationSnapshot,
    current_snapshot: AssetReconciliationSnapshot,
    prior_observations: Sequence[AssetObservation],
    current_observations: Sequence[AssetObservation],
    *,
    prior_predecessor_snapshot: AssetReconciliationSnapshot | None = None,
) -> dict[str, Any]:
    """Reject a self-hashed review that omits or substitutes any supplied source."""

    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise AssetLifecycleReviewError("review is not UTF-8") from exc
    if isinstance(raw, str):
        try:
            raw = json.loads(raw, object_pairs_hook=_unique_pairs)
        except (ValueError, TypeError) as exc:
            raise AssetLifecycleReviewError("review is not valid JSON") from exc
    if type(raw) is not dict:
        raise AssetLifecycleReviewError("review must be an object")
    expected = build_asset_lifecycle_review(
        prior_snapshot,
        current_snapshot,
        prior_observations,
        current_observations,
        prior_predecessor_snapshot=prior_predecessor_snapshot,
    )
    try:
        matched = _canonical(raw) == _canonical(expected)
    except (TypeError, ValueError) as exc:
        raise AssetLifecycleReviewError("review is not canonical JSON") from exc
    if not matched:
        raise AssetLifecycleReviewError("review differs from complete supplied source replay")
    return expected
