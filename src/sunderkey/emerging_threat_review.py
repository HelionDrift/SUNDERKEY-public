"""Offline, metadata-only emerging-threat applicability review."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

DOMAIN = "sunderkey.emerging-threat-review.v1"
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
OPAQUE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
PRODUCT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+:-]{0,127}\Z")
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+:-]{0,63}\Z")
MAX_SOURCE_BYTES = 1_000_000
MAX_MATCHERS = 32
MAX_VERSIONS = 128
MAX_ASSETS = 2048
EFFECTS = {
    "authorization": "none",
    "content_publication": "none",
    "network": "none",
    "qualification": "none",
    "target_interaction": "none",
    "test_execution": "none",
}


class EmergingThreatReviewError(ValueError):
    """Invalid source metadata or a report that does not reproduce."""


def _canonical(value: Any) -> bytes:
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, RecursionError) as exc:
        raise EmergingThreatReviewError("source is not bounded JSON") from exc
    if len(encoded) > MAX_SOURCE_BYTES:
        raise EmergingThreatReviewError("source exceeds byte bound")
    return encoded


def _sha(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if (
        type(value) is not dict
        or any(type(key) is not str for key in value)
        or set(value) != keys
    ):
        raise EmergingThreatReviewError(f"{label} fields are invalid")
    return value


def _label(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise EmergingThreatReviewError(f"{label} is invalid")
    return value


def _utc(value: Any, label: str) -> datetime:
    if type(value) is not str or re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
        value,
    ) is None:
        raise EmergingThreatReviewError(f"{label} must be whole-second UTC")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EmergingThreatReviewError(f"{label} is not a calendar time") from exc
    if parsed.tzinfo != timezone.utc:
        raise EmergingThreatReviewError(f"{label} is not UTC")
    return parsed


def _advisory(value: Any, review_at: datetime) -> dict[str, Any]:
    source = _exact(value, {
        "schema_version", "advisory_id", "source_kind", "source_ref",
        "source_sha256", "published_at", "expires_at", "affected",
        "validation_content_sha256",
    }, "advisory")
    if type(source["schema_version"]) is not int or source["schema_version"] != 1:
        raise EmergingThreatReviewError("advisory version is invalid")
    _label(source["advisory_id"], OPAQUE_RE, "advisory ID")
    if (
        type(source["source_kind"]) is not str
        or source["source_kind"] not in ("vendor", "public_bulletin", "operator")
    ):
        raise EmergingThreatReviewError("source kind is invalid")
    _label(source["source_ref"], OPAQUE_RE, "source reference")
    _label(source["source_sha256"], SHA256_RE, "source digest")
    published = _utc(source["published_at"], "published_at")
    expires = _utc(source["expires_at"], "expires_at")
    if published > review_at or expires <= published:
        raise EmergingThreatReviewError("advisory time order is invalid")
    content_digest = source["validation_content_sha256"]
    if content_digest is not None:
        _label(content_digest, SHA256_RE, "validation content digest")
    affected = source["affected"]
    if type(affected) is not list or not 1 <= len(affected) <= MAX_MATCHERS:
        raise EmergingThreatReviewError("affected product list is invalid")
    previous = None
    for item in affected:
        entry = _exact(item, {"product_key", "exact_versions"}, "affected product")
        product = _label(entry["product_key"], PRODUCT_RE, "product key")
        if previous is not None and product <= previous:
            raise EmergingThreatReviewError("affected products must be sorted and unique")
        previous = product
        versions = entry["exact_versions"]
        if type(versions) is not list or not 1 <= len(versions) <= MAX_VERSIONS:
            raise EmergingThreatReviewError("affected versions are invalid")
        prior_version = None
        for version in versions:
            _label(version, VERSION_RE, "exact version")
            if prior_version is not None and version <= prior_version:
                raise EmergingThreatReviewError("affected versions must be sorted and unique")
            prior_version = version
    return source


def _inventory(value: Any, review_at: datetime) -> dict[str, Any]:
    source = _exact(value, {"schema_version", "snapshot_id", "recorded_at", "assets"},
                    "inventory")
    if type(source["schema_version"]) is not int or source["schema_version"] != 1:
        raise EmergingThreatReviewError("inventory version is invalid")
    _label(source["snapshot_id"], OPAQUE_RE, "snapshot ID")
    if _utc(source["recorded_at"], "recorded_at") > review_at:
        raise EmergingThreatReviewError("inventory is newer than the review")
    assets = source["assets"]
    if type(assets) is not list or len(assets) > MAX_ASSETS:
        raise EmergingThreatReviewError("asset list is invalid")
    previous = None
    for item in assets:
        asset = _exact(item, {
            "asset_id", "product_key", "version", "scope_state", "ownership_state",
        }, "asset")
        asset_id = _label(asset["asset_id"], OPAQUE_RE, "asset ID")
        if previous is not None and asset_id <= previous:
            raise EmergingThreatReviewError("assets must be sorted and unique")
        previous = asset_id
        _label(asset["product_key"], PRODUCT_RE, "product key")
        if asset["version"] is not None:
            _label(asset["version"], VERSION_RE, "asset version")
        if (
            type(asset["scope_state"]) is not str
            or asset["scope_state"] not in ("in_scope", "out_of_scope", "unknown")
        ):
            raise EmergingThreatReviewError("scope state is invalid")
        if (
            type(asset["ownership_state"]) is not str
            or asset["ownership_state"] not in ("confirmed", "unknown")
        ):
            raise EmergingThreatReviewError("ownership state is invalid")
    return source


def _disposition(
    asset: dict[str, Any], affected: dict[str, set[str]], expired: bool,
    stale_inventory: bool,
) -> str:
    if expired:
        return "expired_no_selection"
    if stale_inventory:
        return "stale_inventory_no_selection"
    if asset["scope_state"] == "out_of_scope":
        return "out_of_scope"
    if asset["scope_state"] != "in_scope" or asset["ownership_state"] != "confirmed":
        return "scope_or_owner_unknown"
    versions = affected.get(asset["product_key"])
    if versions is None:
        return "product_not_declared_affected"
    if asset["version"] is None:
        return "version_unknown"
    if asset["version"] not in versions:
        return "version_not_declared_affected"
    return "declared_exact_match_review_only"


def build_emerging_threat_review(
    advisory: Any, inventory: Any, review_at: str,
    maximum_inventory_age_seconds: int = 604_800,
) -> dict[str, Any]:
    """Classify declared exact matches without importing content or granting use."""

    now = _utc(review_at, "review_at")
    if (
        type(maximum_inventory_age_seconds) is not int
        or not 1 <= maximum_inventory_age_seconds <= 604_800
    ):
        raise EmergingThreatReviewError("maximum inventory age is invalid")
    checked_advisory = _advisory(advisory, now)
    checked_inventory = _inventory(inventory, now)
    advisory_sha256 = _sha(checked_advisory)
    inventory_sha256 = _sha(checked_inventory)
    affected = {
        item["product_key"]: set(item["exact_versions"])
        for item in checked_advisory["affected"]
    }
    expired = now >= _utc(checked_advisory["expires_at"], "expires_at")
    inventory_age_seconds = int(
        (now - _utc(checked_inventory["recorded_at"], "recorded_at")).total_seconds()
    )
    stale_inventory = inventory_age_seconds > maximum_inventory_age_seconds
    assets = [{
        "asset_id": item["asset_id"],
        "disposition": _disposition(item, affected, expired, stale_inventory),
    } for item in checked_inventory["assets"]]
    body = {
        "schema_version": 1,
        "advisory_id": checked_advisory["advisory_id"],
        "advisory_sha256": advisory_sha256,
        "inventory_sha256": inventory_sha256,
        "review_at": review_at,
        "advisory_state": "expired" if expired else "declared_current_at_review",
        "inventory_state": (
            "stale" if stale_inventory else "declared_within_age_limit"
        ),
        "inventory_age_seconds": inventory_age_seconds,
        "maximum_inventory_age_seconds": maximum_inventory_age_seconds,
        "source_provenance": "asserted_not_authenticated",
        "inventory_provenance": "caller_supplied_not_authenticated",
        "validation_content_state": (
            "hash_only_quarantined" if checked_advisory["validation_content_sha256"]
            else "not_supplied"
        ),
        "applicability_basis": "exact_declared_product_and_version_only",
        "assets": assets,
        "candidate_count": sum(
            item["disposition"] == "declared_exact_match_review_only"
            for item in assets
        ),
        "review_status": "independent_review_required",
        "qualification_effect": "none",
        "effects": dict(EFFECTS),
    }
    digest = "sha256:" + hashlib.sha256(
        DOMAIN.encode("ascii") + b"\0" + _canonical(body)
    ).hexdigest()
    return {
        **body,
        "review_id": "ETR-" + digest[7:39].upper(),
        "review_sha256": digest,
    }


def verify_emerging_threat_review(
    advisory: Any, inventory: Any, review_at: str, result: Any,
    maximum_inventory_age_seconds: int = 604_800,
) -> dict[str, str]:
    """Replay original metadata and reject a substituted report."""

    expected = build_emerging_threat_review(
        advisory, inventory, review_at, maximum_inventory_age_seconds
    )
    if type(result) is not dict or _canonical(result) != _canonical(expected):
        raise EmergingThreatReviewError("emerging-threat review does not reproduce")
    return {
        "status": "valid",
        "review_id": expected["review_id"],
        "review_sha256": expected["review_sha256"],
        "qualification_effect": "none",
    }
