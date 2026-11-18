"""Replay a supplied auction bid timeline without contacting a marketplace."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "supplied_auction_bid_timeline"
PROFILE_ID = "AOE-GB-D09-S08"
CAPABILITY_ID = "army.gb.d09.s08"
VECTOR_ID = "AV-GB-D09-S08-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D09-S08"
WAVE_ID = "IW2-008"
COMMANDER_ID = "AOE-GB-D09-CMD"
GROUP_OWNER_ID = "AOE-HQ-04"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:ab2a2805c5e7a99ee106d302708565d3fbcbbc80d476b3665a7e13c2b0535e5f"
SEMANTICS_PROFILE = "supplied-auction-bid-timeline-v1"
DOMAIN = "sunderkey.offline-auction-bid-timeline.v1"
MAX_EVENTS = 512
MAX_AMOUNT = 10_000_000_000_000_000
MAX_DOCUMENT_BYTES = 524_288
MAX_NATIVE_NODES = 16_384
MAX_NATIVE_DEPTH = 12
MAX_STRING_LENGTH = 256
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_LISTING = re.compile(r"listing:sha256:[0-9a-f]{64}\Z")
_BIDDER = re.compile(r"bidder:sha256:[0-9a-f]{64}\Z")
_CURRENCY = re.compile(r"[A-Z]{3}\Z")
_EFFECTS = dict.fromkeys(
    (
        "auction_write",
        "authority",
        "credential",
        "execution",
        "filesystem",
        "network",
        "payment",
        "publication",
        "qualification",
        "target",
    ),
    "none",
)


class AuctionBidTimelineError(ValueError):
    """The supplied bid model or replay document was refused."""


def _canonical(value: Any) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise AuctionBidTimelineError("Native document structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_STRING_LENGTH:
                raise AuctionBidTimelineError("Native document string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise AuctionBidTimelineError("Native document integer bound exceeded")
            return
        if family not in (dict, list):
            raise AuctionBidTimelineError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise AuctionBidTimelineError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise AuctionBidTimelineError("Native JSON text keys are required")
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
        raise AuctionBidTimelineError("Document byte bound exceeded")
    return encoded


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise AuctionBidTimelineError(f"{label} fields are invalid")


def _amount(value: Any, label: str, *, positive: bool = False) -> int:
    if type(value) is not int or not int(positive) <= value <= MAX_AMOUNT:
        raise AuctionBidTimelineError(f"{label} amount is invalid")
    return value


def _bidder(value: Any, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if type(value) is not str or _BIDDER.fullmatch(value) is None:
        raise AuctionBidTimelineError("Opaque bidder reference is invalid")
    return value


def _plan(model: Any) -> dict:
    model = json.loads(_canonical(model))
    _fields(
        model,
        {
            "schema_version",
            "semantics_profile",
            "listing_ref",
            "currency_label",
            "reserve_minor",
            "minimum_increment_minor",
            "events",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise AuctionBidTimelineError("Schema version is invalid")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise AuctionBidTimelineError("Semantics profile is invalid")
    if type(model["listing_ref"]) is not str or _LISTING.fullmatch(model["listing_ref"]) is None:
        raise AuctionBidTimelineError("Opaque listing reference is required")
    if (
        type(model["currency_label"]) is not str
        or _CURRENCY.fullmatch(model["currency_label"]) is None
    ):
        raise AuctionBidTimelineError("Currency label is invalid")
    _amount(model["reserve_minor"], "reserve")
    _amount(model["minimum_increment_minor"], "minimum increment", positive=True)
    events = model["events"]
    if type(events) is not list or not 1 <= len(events) <= MAX_EVENTS:
        raise AuctionBidTimelineError("Bid event count is invalid")
    event_ids: set[str] = set()
    for event in events:
        _fields(
            event,
            {
                "event_id",
                "bidder_ref",
                "bid_minor",
                "result",
                "declared_leader_ref",
                "declared_leading_bid_minor",
            },
            "event",
        )
        event_id = event["event_id"]
        if type(event_id) is not str or _ID.fullmatch(event_id) is None or event_id in event_ids:
            raise AuctionBidTimelineError("Event identifier is invalid or duplicate")
        event_ids.add(event_id)
        _bidder(event["bidder_ref"])
        _amount(event["bid_minor"], "bid", positive=True)
        if event["result"] not in ("accepted", "rejected"):
            raise AuctionBidTimelineError("Bid result is invalid")
        _bidder(event["declared_leader_ref"], optional=True)
        _amount(event["declared_leading_bid_minor"], "declared leading bid")
        if (event["declared_leader_ref"] is None) != (event["declared_leading_bid_minor"] == 0):
            raise AuctionBidTimelineError("Declared leader and amount are inconsistent")
    return model


def _derive(model: Any) -> dict:
    plan = _plan(model)
    leader: str | None = None
    leading_amount = 0
    rows = []
    for position, event in enumerate(plan["events"]):
        flags = []
        local_increment_met = event["bid_minor"] >= leading_amount + plan["minimum_increment_minor"]
        if event["result"] == "accepted":
            if not local_increment_met:
                flags.append("accepted_below_supplied_minimum_increment")
            leader = event["bidder_ref"]
            leading_amount = event["bid_minor"]
        elif local_increment_met:
            flags.append("rejected_despite_supplied_increment")
        if event["declared_leader_ref"] != leader:
            flags.append("declared_leader_mismatch")
        if event["declared_leading_bid_minor"] != leading_amount:
            flags.append("declared_leading_bid_mismatch")
        rows.append(
            {
                "position": position,
                "event_id": event["event_id"],
                "expected_leader_ref": leader,
                "expected_leading_bid_minor": leading_amount,
                "local_increment_met": local_increment_met,
                "anomaly_flags": sorted(flags),
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": plan,
        "events": rows,
        "final_expected_leader_ref": leader,
        "final_expected_leading_bid_minor": leading_amount,
        "supplied_reserve_met": leader is not None and leading_amount >= plan["reserve_minor"],
        "flags": {
            "listing_source_authenticated": False,
            "bidder_identity_proven": False,
            "event_order_proven": False,
            "auction_policy_authenticated": False,
            "real_winner_proven": False,
            "marketplace_defect_proven": False,
            "economic_impact_proven": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Listing, bids, outcomes, reserve, increment, and event order are caller-supplied.",
            "Local leading bid and reserve comparison do not establish a real auction winner.",
            "A mismatch does not prove marketplace behavior, fraud, or economic impact.",
            "No listing, auction, bidder, payment, credential, service, or target is contacted.",
        ],
    }
    digest = (
        "sha256:" + hashlib.sha256((DOMAIN + "\n" + _canonical(body)).encode("ascii")).hexdigest()
    )
    return json.loads(
        _canonical(
            {**body, "analysis_id": "ABT-" + digest[7:39].upper(), "analysis_sha256": digest}
        )
    )


@dataclass(frozen=True, slots=True, init=False)
class AuctionBidTimeline:
    """Replay-checked local projection of supplied bid events."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise AuctionBidTimelineError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        if _canonical(document) != _canonical(expected):
            raise AuctionBidTimelineError("Report differs from embedded model replay")
        object.__setattr__(self, "_document_json", _canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_auction_bids(model: Any) -> AuctionBidTimeline:
    """Derive only a supplied leading-bid projection."""
    return AuctionBidTimeline(_derive(model))


def verify_supplied_auction_bids(report: Any, *, model: Any) -> AuctionBidTimeline:
    """Recompute the report from current supplied model bytes."""
    if type(report) is not AuctionBidTimeline:
        raise AuctionBidTimelineError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != _canonical(expected):
        raise AuctionBidTimelineError("Report differs from supplied model replay")
    return AuctionBidTimeline(expected)


__all__ = [
    "COMPONENT_ID",
    "PROFILE_ID",
    "AuctionBidTimeline",
    "AuctionBidTimelineError",
    "analyze_supplied_auction_bids",
    "verify_supplied_auction_bids",
]
