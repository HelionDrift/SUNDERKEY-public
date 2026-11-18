"""Reconcile a supplied coupon-redemption sequence offline."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "supplied_coupon_redemption_timeline"
PROFILE_ID = "AOE-GB-D09-S07"
CAPABILITY_ID = "army.gb.d09.s07"
VECTOR_ID = "AV-GB-D09-S07-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D09-S07"
WAVE_ID = "IW2-007"
COMMANDER_ID = "AOE-GB-D09-CMD"
GROUP_OWNER_ID = "AOE-HQ-04"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:1037d994fdc86a96fea23d9ab693275ac891a10419ff655b322a24cc3d43dc0e"
SEMANTICS_PROFILE = "supplied-coupon-redemption-timeline-v1"
DOMAIN = "sunderkey.offline-coupon-redemption-timeline.v1"
MAX_EVENTS = 512
MAX_LIMIT = 1_000_000
MAX_DOCUMENT_BYTES = 524_288
MAX_NATIVE_NODES = 16_384
MAX_NATIVE_DEPTH = 12
MAX_STRING_LENGTH = 256
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_COUPON = re.compile(r"coupon:sha256:[0-9a-f]{64}\Z")
_ACTOR = re.compile(r"actor:sha256:[0-9a-f]{64}\Z")
_ORDER = re.compile(r"order:sha256:[0-9a-f]{64}\Z")
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "credential",
        "execution",
        "filesystem",
        "network",
        "order_write",
        "payment",
        "publication",
        "qualification",
        "target",
    ),
    "none",
)


class CouponRedemptionTimelineError(ValueError):
    """The supplied redemption model or replay document was refused."""


def _canonical(value: Any) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise CouponRedemptionTimelineError("Native document structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_STRING_LENGTH:
                raise CouponRedemptionTimelineError("Native document string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise CouponRedemptionTimelineError("Native document integer bound exceeded")
            return
        if family not in (dict, list):
            raise CouponRedemptionTimelineError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise CouponRedemptionTimelineError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise CouponRedemptionTimelineError("Native JSON text keys are required")
                    visit(key, depth + 1)
                    visit(child, depth + 1)
            else:
                for child in item:
                    visit(child, depth + 1)
        finally:
            active.remove(id(item))

    visit(value, 1)
    encoded = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    if len(encoded) > MAX_DOCUMENT_BYTES:
        raise CouponRedemptionTimelineError("Document byte bound exceeded")
    return encoded


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise CouponRedemptionTimelineError(f"{label} fields are invalid")


def _opaque(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise CouponRedemptionTimelineError(f"Opaque {label} reference is invalid")
    return value


def _plan(model: Any) -> dict:
    model = json.loads(_canonical(model))
    _fields(
        model,
        {
            "schema_version",
            "semantics_profile",
            "coupon_ref",
            "global_limit",
            "per_actor_limit",
            "events",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise CouponRedemptionTimelineError("Schema version is invalid")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise CouponRedemptionTimelineError("Semantics profile is invalid")
    _opaque(model["coupon_ref"], _COUPON, "coupon")
    for field in ("global_limit", "per_actor_limit"):
        value = model[field]
        if type(value) is not int or not 1 <= value <= MAX_LIMIT:
            raise CouponRedemptionTimelineError(f"{field} is invalid")
    events = model["events"]
    if type(events) is not list or not 1 <= len(events) <= MAX_EVENTS:
        raise CouponRedemptionTimelineError("Event count is invalid")
    ids: set[str] = set()
    for event in events:
        _fields(
            event,
            {
                "event_id",
                "actor_ref",
                "order_ref",
                "result",
                "declared_global_after",
                "declared_actor_after",
            },
            "event",
        )
        event_id = event["event_id"]
        if type(event_id) is not str or _ID.fullmatch(event_id) is None or event_id in ids:
            raise CouponRedemptionTimelineError("Event identifier is invalid or duplicate")
        ids.add(event_id)
        _opaque(event["actor_ref"], _ACTOR, "actor")
        _opaque(event["order_ref"], _ORDER, "order")
        if event["result"] not in ("accepted", "rejected"):
            raise CouponRedemptionTimelineError("Event result is invalid")
        for field in ("declared_global_after", "declared_actor_after"):
            if type(event[field]) is not int or not 0 <= event[field] <= MAX_EVENTS:
                raise CouponRedemptionTimelineError(f"{field} is invalid")
    return model


def _derive(model: Any) -> dict:
    plan = _plan(model)
    global_count = 0
    actor_counts: dict[str, int] = {}
    accepted_orders: set[str] = set()
    rows = []
    for position, event in enumerate(plan["events"]):
        flags = []
        actor = event["actor_ref"]
        count = actor_counts.get(actor, 0)
        if event["result"] == "accepted":
            if event["order_ref"] in accepted_orders:
                flags.append("duplicate_accepted_order_label")
            accepted_orders.add(event["order_ref"])
            global_count += 1
            count += 1
            actor_counts[actor] = count
            if global_count > plan["global_limit"]:
                flags.append("accepted_beyond_global_limit")
            if count > plan["per_actor_limit"]:
                flags.append("accepted_beyond_actor_limit")
        if event["declared_global_after"] != global_count:
            flags.append("declared_global_count_mismatch")
        if event["declared_actor_after"] != count:
            flags.append("declared_actor_count_mismatch")
        rows.append(
            {
                "position": position,
                "event_id": event["event_id"],
                "actor_ref": actor,
                "order_ref": event["order_ref"],
                "expected_global_after": global_count,
                "expected_actor_after": count,
                "anomaly_flags": sorted(flags),
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": plan,
        "events": rows,
        "final_expected_global_count": global_count,
        "flags": {
            "coupon_policy_authenticated": False,
            "event_source_authenticated": False,
            "actor_identity_proven": False,
            "real_redemption_proven": False,
            "economic_impact_proven": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Coupon limits, actor and order labels, outcomes, and event order are caller-supplied.",
            "An accepted event increments only the local projection, even above a supplied limit.",
            "Duplicate order labels and limit anomalies do not prove a live coupon defect.",
            "No coupon, order, payment, credential, service, or target is contacted or changed.",
        ],
    }
    digest = (
        "sha256:" + hashlib.sha256((DOMAIN + "\n" + _canonical(body)).encode("ascii")).hexdigest()
    )
    return json.loads(
        _canonical(
            {**body, "analysis_id": "CRT-" + digest[7:39].upper(), "analysis_sha256": digest}
        )
    )


@dataclass(frozen=True, slots=True, init=False)
class CouponRedemptionTimeline:
    """Replay-checked local projection of supplied coupon events."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise CouponRedemptionTimelineError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        if _canonical(document) != _canonical(expected):
            raise CouponRedemptionTimelineError("Report differs from embedded model replay")
        object.__setattr__(self, "_document_json", _canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_coupon_redemptions(model: Any) -> CouponRedemptionTimeline:
    """Derive only a supplied coupon-count timeline."""
    return CouponRedemptionTimeline(_derive(model))


def verify_supplied_coupon_redemptions(report: Any, *, model: Any) -> CouponRedemptionTimeline:
    """Recompute the report from current supplied model bytes."""
    if type(report) is not CouponRedemptionTimeline:
        raise CouponRedemptionTimelineError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != _canonical(expected):
        raise CouponRedemptionTimelineError("Report differs from supplied model replay")
    return CouponRedemptionTimeline(expected)


__all__ = [
    "COMPONENT_ID",
    "PROFILE_ID",
    "CouponRedemptionTimeline",
    "CouponRedemptionTimelineError",
    "analyze_supplied_coupon_redemptions",
    "verify_supplied_coupon_redemptions",
]
