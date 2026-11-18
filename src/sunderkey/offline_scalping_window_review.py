"""Replay supplied allocation-window records without contacting a marketplace."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "supplied_scalping_window_review"
PROFILE_ID = "AOE-GB-D09-S09"
CAPABILITY_ID = "army.gb.d09.s09"
VECTOR_ID = "AV-GB-D09-S09-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D09-S09"
WAVE_ID = "IW2-009"
COMMANDER_ID = "AOE-GB-D09-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:b56bcba48752c40872990d59c5888767fb37d081ab00fd5c0111e1a502347d90"
SEMANTICS_PROFILE = "supplied-scalping-window-review-v1"
DOMAIN = "sunderkey.offline-scalping-window-review.v1"
MAX_EVENTS = 512
MAX_DOCUMENT_BYTES = 524_288
MAX_NATIVE_NODES = 16_384
MAX_NATIVE_DEPTH = 12
MAX_STRING_LENGTH = 256
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_ITEM = re.compile(r"item:sha256:[0-9a-f]{64}\Z")
_ACTOR = re.compile(r"actor:sha256:[0-9a-f]{64}\Z")
_EFFECTS = dict.fromkeys(
    (
        "allocation",
        "authority",
        "credential",
        "execution",
        "filesystem",
        "network",
        "publication",
        "qualification",
        "target",
    ),
    "none",
)


class ScalpingWindowReviewError(ValueError):
    """The supplied allocation-window model or report was refused."""


def _canonical(value: Any) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise ScalpingWindowReviewError("Native document structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_STRING_LENGTH:
                raise ScalpingWindowReviewError("Native document string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise ScalpingWindowReviewError("Native document integer bound exceeded")
            return
        if family not in (dict, list):
            raise ScalpingWindowReviewError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise ScalpingWindowReviewError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise ScalpingWindowReviewError("Native JSON text keys are required")
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
        raise ScalpingWindowReviewError("Document byte bound exceeded")
    return encoded


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise ScalpingWindowReviewError(f"{label} fields are invalid")


def _plan(model: Any) -> dict:
    model = json.loads(_canonical(model))
    _fields(
        model,
        {
            "schema_version",
            "semantics_profile",
            "item_ref",
            "window_seconds",
            "maximum_allowed_per_actor",
            "events",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise ScalpingWindowReviewError("Schema version is invalid")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise ScalpingWindowReviewError("Semantics profile is invalid")
    if type(model["item_ref"]) is not str or _ITEM.fullmatch(model["item_ref"]) is None:
        raise ScalpingWindowReviewError("Opaque item reference is required")
    if type(model["window_seconds"]) is not int or not 1 <= model["window_seconds"] <= 86_400:
        raise ScalpingWindowReviewError("Window size is invalid")
    limit = model["maximum_allowed_per_actor"]
    if type(limit) is not int or not 1 <= limit <= MAX_EVENTS:
        raise ScalpingWindowReviewError("Per-actor limit is invalid")
    events = model["events"]
    if type(events) is not list or not 1 <= len(events) <= MAX_EVENTS:
        raise ScalpingWindowReviewError("Event count is invalid")
    event_ids: set[str] = set()
    previous_second = -1
    for event in events:
        _fields(
            event,
            {"event_id", "actor_ref", "second", "result", "declared_allowed_in_window"},
            "event",
        )
        event_id = event["event_id"]
        if type(event_id) is not str or _ID.fullmatch(event_id) is None or event_id in event_ids:
            raise ScalpingWindowReviewError("Event identifier is invalid or duplicate")
        event_ids.add(event_id)
        if type(event["actor_ref"]) is not str or _ACTOR.fullmatch(event["actor_ref"]) is None:
            raise ScalpingWindowReviewError("Opaque actor reference is required")
        second = event["second"]
        if type(second) is not int or not previous_second <= second <= 2_147_483_647:
            raise ScalpingWindowReviewError("Event second is invalid or out of order")
        previous_second = second
        if event["result"] not in ("allowed", "blocked"):
            raise ScalpingWindowReviewError("Result is invalid")
        declared = event["declared_allowed_in_window"]
        if type(declared) is not int or not 0 <= declared <= MAX_EVENTS:
            raise ScalpingWindowReviewError("Declared count is invalid")
    return model


def _derive(model: Any) -> dict:
    plan = _plan(model)
    counts: dict[tuple[str, int], int] = {}
    rows = []
    for position, event in enumerate(plan["events"]):
        bucket = event["second"] // plan["window_seconds"]
        key = (event["actor_ref"], bucket)
        count = counts.get(key, 0)
        flags = []
        if event["result"] == "allowed":
            count += 1
            counts[key] = count
            if count > plan["maximum_allowed_per_actor"]:
                flags.append("allowed_above_supplied_actor_window_limit")
        if event["declared_allowed_in_window"] != count:
            flags.append("declared_window_count_mismatch")
        rows.append(
            {
                "position": position,
                "event_id": event["event_id"],
                "window_index": bucket,
                "expected_allowed_in_window": count,
                "anomaly_flags": sorted(flags),
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": plan,
        "events": rows,
        "flags": {
            "item_or_actor_authenticated": False,
            "request_or_allocation_proven": False,
            "clock_or_order_proven": False,
            "bot_identity_proven": False,
            "scalping_or_control_failure_proven": False,
            "economic_impact_proven": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Item, actor labels, timestamps, results, limits, and order are caller-supplied.",
            "Fixed-window arithmetic does not identify automation or a real allocation.",
            "A mismatch does not prove a bot, scalping, control failure, or impact.",
            "No item, account, marketplace, service, network, or target is contacted.",
        ],
    }
    digest = (
        "sha256:" + hashlib.sha256((DOMAIN + "\n" + _canonical(body)).encode("ascii")).hexdigest()
    )
    return json.loads(
        _canonical(
            {**body, "analysis_id": "SWR-" + digest[7:39].upper(), "analysis_sha256": digest}
        )
    )


@dataclass(frozen=True, slots=True, init=False)
class ScalpingWindowReview:
    """Replay-checked local projection of supplied per-actor windows."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise ScalpingWindowReviewError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        if _canonical(document) != _canonical(expected):
            raise ScalpingWindowReviewError("Report differs from embedded model replay")
        object.__setattr__(self, "_document_json", _canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_scalping_windows(model: Any) -> ScalpingWindowReview:
    """Reconcile only supplied per-actor fixed-window labels."""
    return ScalpingWindowReview(_derive(model))


def verify_supplied_scalping_windows(report: Any, *, model: Any) -> ScalpingWindowReview:
    """Recompute the report from current supplied model bytes."""
    if type(report) is not ScalpingWindowReview:
        raise ScalpingWindowReviewError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != _canonical(expected):
        raise ScalpingWindowReviewError("Report differs from supplied model replay")
    return ScalpingWindowReview(expected)
