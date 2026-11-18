"""Review declared decoy and tripwire lifecycle metadata without deployment."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any

DOMAIN = "sunderkey.deception-lifecycle-review.v1"
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
TIME_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
MAX_EVENTS = 256
MAX_BYTES = 1_000_000
EFFECTS = {
    "alert_delivery": "none",
    "authorization": "none",
    "deception_placement": "none",
    "notification": "none",
    "qualification": "none",
    "target_interaction": "none",
    "token_issuance": "none",
}


class DeceptionLifecycleReviewError(ValueError):
    """A declared lifecycle or replayed report is invalid."""


def _canonical(value: Any) -> bytes:
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, RecursionError) as exc:
        raise DeceptionLifecycleReviewError("lifecycle is not JSON") from exc
    if len(encoded) > MAX_BYTES:
        raise DeceptionLifecycleReviewError("lifecycle exceeds byte bound")
    return encoded


def _sha(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if (
        type(value) is not dict
        or any(type(key) is not str for key in value)
        or set(value) != keys
    ):
        raise DeceptionLifecycleReviewError(f"{label} fields are invalid")
    return value


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or IDENTIFIER_RE.fullmatch(value) is None:
        raise DeceptionLifecycleReviewError(f"{label} is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or SHA256_RE.fullmatch(value) is None:
        raise DeceptionLifecycleReviewError(f"{label} is invalid")
    return value


def _utc(value: Any, label: str) -> datetime:
    if type(value) is not str or TIME_RE.fullmatch(value) is None:
        raise DeceptionLifecycleReviewError(f"{label} must be whole-second UTC")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DeceptionLifecycleReviewError(f"{label} is not a calendar time") from exc
    if result.tzinfo != timezone.utc:
        raise DeceptionLifecycleReviewError(f"{label} is not UTC")
    return result


def _plan(value: Any, as_of: datetime) -> dict[str, Any]:
    plan = _exact(value, {
        "schema_version", "plan_ref", "asset_ref", "owner_ref", "scope_sha256",
        "owner_approval_sha256", "token_class", "token_sha256",
        "removal_procedure_sha256", "removal_test_sha256", "created_at",
        "expires_at",
    }, "plan")
    if type(plan["schema_version"]) is not int or plan["schema_version"] != 1:
        raise DeceptionLifecycleReviewError("plan version is invalid")
    for field in ("plan_ref", "asset_ref", "owner_ref"):
        _identifier(plan[field], field)
    for field in (
        "scope_sha256", "owner_approval_sha256", "token_sha256",
        "removal_procedure_sha256", "removal_test_sha256",
    ):
        _digest(plan[field], field)
    if type(plan["token_class"]) is not str or (
        plan["token_class"] != "nonprivileged_unique_marker"
    ):
        raise DeceptionLifecycleReviewError("token class is unsupported")
    created = _utc(plan["created_at"], "created_at")
    expires = _utc(plan["expires_at"], "expires_at")
    if created > as_of or not timedelta(0) < expires - created <= timedelta(days=30):
        raise DeceptionLifecycleReviewError("plan time window is invalid")
    return plan


def _events(value: Any, plan: dict[str, Any], as_of: datetime) -> list[dict[str, Any]]:
    if type(value) is not list or len(value) > MAX_EVENTS:
        raise DeceptionLifecycleReviewError("event list is invalid")
    created = _utc(plan["created_at"], "created_at")
    expires = _utc(plan["expires_at"], "expires_at")
    previous_time = created
    seen_ids: set[str] = set()
    seen_alert_refs: set[str] = set()
    state = "unplaced"
    for index, item in enumerate(value):
        event = _exact(item, {
            "event_id", "kind", "at", "evidence_sha256", "token_sha256",
            "related_alert_ref",
        }, f"event {index}")
        event_id = _identifier(event["event_id"], "event ID")
        if event_id in seen_ids:
            raise DeceptionLifecycleReviewError("event IDs must be unique")
        seen_ids.add(event_id)
        at = _utc(event["at"], "event time")
        if not previous_time < at <= as_of:
            raise DeceptionLifecycleReviewError("events must be strictly chronological")
        previous_time = at
        _digest(event["evidence_sha256"], "event evidence")
        _digest(event["token_sha256"], "event token")
        if event["token_sha256"] != plan["token_sha256"]:
            raise DeceptionLifecycleReviewError("event token digest differs from plan")
        kind = event["kind"]
        if type(kind) is not str or kind not in {
            "placement", "alert", "revocation", "cleanup",
        }:
            raise DeceptionLifecycleReviewError("event kind is invalid")
        if kind == "alert":
            alert_ref = _identifier(event["related_alert_ref"], "alert reference")
            if alert_ref in seen_alert_refs:
                raise DeceptionLifecycleReviewError("alert references must be unique")
            seen_alert_refs.add(alert_ref)
        elif event["related_alert_ref"] is not None:
            raise DeceptionLifecycleReviewError("non-alert event has alert reference")
        if kind == "placement" and state == "unplaced":
            if at >= expires:
                raise DeceptionLifecycleReviewError("placement is at or after expiry")
            state = "active"
        elif kind == "alert" and state in ("active", "revoked", "cleaned", "cleanup_disputed"):
            if state == "cleaned":
                state = "cleanup_disputed"
        elif kind == "revocation" and state == "active":
            state = "revoked"
        elif kind == "cleanup" and state in ("active", "revoked"):
            state = "cleaned"
        else:
            raise DeceptionLifecycleReviewError("event violates lifecycle ordering")
    return value


def build_deception_lifecycle_review(
    plan: Any, events: Any, as_of: str,
) -> dict[str, Any]:
    """Replay declared placement, alert, revocation, and cleanup metadata."""

    now = _utc(as_of, "as_of")
    checked_plan = _plan(plan, now)
    checked_events = _events(events, checked_plan, now)
    expired = now >= _utc(checked_plan["expires_at"], "expires_at")
    kinds = [item["kind"] for item in checked_events]
    expires_at = _utc(checked_plan["expires_at"], "expires_at")
    placed = "placement" in kinds
    cleaned = "cleanup" in kinds
    revoked = "revocation" in kinds
    revocation_index = kinds.index("revocation") if revoked else len(kinds)
    cleanup_index = kinds.index("cleanup") if cleaned else len(kinds)
    post_revocation_alerts = sum(
        kind == "alert" for kind in kinds[revocation_index + 1:]
    )
    post_cleanup_alerts = sum(kind == "alert" for kind in kinds[cleanup_index + 1:])
    if post_cleanup_alerts:
        state = "declared_cleanup_disputed"
    elif cleaned:
        state = "declared_cleaned"
    elif revoked:
        state = "declared_revoked_cleanup_due"
    elif expired and placed:
        state = "declared_expired_cleanup_due"
    elif placed:
        state = "declared_active"
    else:
        state = "unplaced"
    body = {
        "schema_version": 1,
        "plan_ref": checked_plan["plan_ref"],
        "plan_sha256": _sha(checked_plan),
        "events_sha256": _sha(checked_events),
        "as_of": as_of,
        "declared_state": state,
        "declared_alert_count": kinds.count("alert"),
        "declared_post_revocation_alert_count": post_revocation_alerts,
        "declared_post_cleanup_alert_count": post_cleanup_alerts,
        "declared_late_alert_count": sum(
            item["kind"] == "alert" and _utc(item["at"], "event time") >= expires_at
            for item in checked_events
        ),
        "placement_receipt_asserted": placed,
        "cleanup_receipt_asserted": cleaned,
        "cleanup_due": bool(post_cleanup_alerts) or (
            placed and not cleaned and (expired or revoked)
        ),
        "owner_approval_verified": False,
        "removal_test_verified": False,
        "token_privilege_verified": False,
        "alert_delivery_verified": False,
        "source_provenance": "caller_asserted_not_authenticated",
        "review_status": "independent_review_required",
        "qualification_effect": "none",
        "effects": dict(EFFECTS),
    }
    digest = hashlib.sha256(DOMAIN.encode() + b"\0" + _canonical(body)).hexdigest()
    return {
        **body,
        "review_id": "DLR-" + digest[:32].upper(),
        "review_sha256": "sha256:" + digest,
    }


def verify_deception_lifecycle_review(
    plan: Any, events: Any, as_of: str, result: Any,
) -> dict[str, str]:
    """Reject source or report substitution without authenticating any receipt."""

    expected = build_deception_lifecycle_review(plan, events, as_of)
    if type(result) is not dict or _canonical(result) != _canonical(expected):
        raise DeceptionLifecycleReviewError("deception lifecycle review does not reproduce")
    return {
        "status": "valid",
        "review_id": expected["review_id"],
        "review_sha256": expected["review_sha256"],
        "qualification_effect": "none",
    }
