"""Reconcile a supplied debit timeline without performing a transaction."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "supplied_debit_idempotency_timeline"
PROFILE_ID = "AOE-GB-D09-S03"
CAPABILITY_ID = "army.gb.d09.s03"
VECTOR_ID = "AV-GB-D09-S03-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D09-S03"
WAVE_ID = "IW2-003"
COMMANDER_ID = "AOE-GB-D09-CMD"
GROUP_OWNER_ID = "AOE-HQ-04"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:ef219092c626c94ae4e89f31db3ee7ff11d8b66c0e66f01ce7432b6544f31858"
SEMANTICS_PROFILE = "supplied-debit-idempotency-timeline-v1"
DOMAIN = "sunderkey.offline-debit-idempotency-timeline.v1"
MAX_EVENTS = 512
MAX_AMOUNT = 10_000_000_000_000_000
MAX_DOCUMENT_BYTES = 262_144
MAX_NATIVE_NODES = 16_384
MAX_NATIVE_DEPTH = 12
MAX_STRING_LENGTH = 256
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_ACCOUNT = re.compile(r"account:sha256:[0-9a-f]{64}\Z")
_CURRENCY = re.compile(r"[A-Z]{3}\Z")
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "credential",
        "execution",
        "financial_transaction",
        "filesystem",
        "ledger_write",
        "network",
        "payment",
        "publication",
        "qualification",
        "target",
    ),
    "none",
)


class DebitIdempotencyTimelineError(ValueError):
    """The supplied event model or replay document was refused."""


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise DebitIdempotencyTimelineError(f"{label} fields are invalid")


def _identifier(value: Any, label: str) -> None:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise DebitIdempotencyTimelineError(f"{label} identifier is invalid")


def _amount(value: Any, label: str, *, positive: bool = False) -> int:
    if type(value) is not int or not int(positive) <= value <= MAX_AMOUNT:
        raise DebitIdempotencyTimelineError(f"{label} amount is invalid")
    return value


def _canonical(value: Any) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise DebitIdempotencyTimelineError("Native document structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_STRING_LENGTH:
                raise DebitIdempotencyTimelineError("Native document string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise DebitIdempotencyTimelineError("Native document integer bound exceeded")
            return
        if family not in (dict, list):
            raise DebitIdempotencyTimelineError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise DebitIdempotencyTimelineError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise DebitIdempotencyTimelineError("Native JSON text keys are required")
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
        raise DebitIdempotencyTimelineError("Document byte bound exceeded")
    return encoded


def _plan(model: Any) -> dict:
    model = json.loads(_canonical(model))
    _fields(
        model,
        {
            "schema_version",
            "semantics_profile",
            "account_ref",
            "currency_label",
            "initial_balance_minor",
            "events",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise DebitIdempotencyTimelineError("Schema version is invalid")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise DebitIdempotencyTimelineError("Semantics profile is invalid")
    if type(model["account_ref"]) is not str or _ACCOUNT.fullmatch(model["account_ref"]) is None:
        raise DebitIdempotencyTimelineError("Opaque account reference is required")
    if (
        type(model["currency_label"]) is not str
        or _CURRENCY.fullmatch(model["currency_label"]) is None
    ):
        raise DebitIdempotencyTimelineError("Currency label is invalid")
    _amount(model["initial_balance_minor"], "initial balance")
    events = model["events"]
    if type(events) is not list or not 1 <= len(events) <= MAX_EVENTS:
        raise DebitIdempotencyTimelineError("Event count is invalid")
    ids: set[str] = set()
    for event in events:
        _fields(
            event,
            {
                "event_id",
                "command_id",
                "amount_minor",
                "result",
                "declared_balance_after_minor",
                "source_id",
            },
            "event",
        )
        for field in ("event_id", "command_id", "source_id"):
            _identifier(event[field], field)
        if event["event_id"] in ids:
            raise DebitIdempotencyTimelineError("Duplicate event identifier")
        ids.add(event["event_id"])
        _amount(event["amount_minor"], "debit", positive=True)
        _amount(event["declared_balance_after_minor"], "declared balance")
        if type(event["result"]) is not str or event["result"] not in ("accepted", "rejected"):
            raise DebitIdempotencyTimelineError("Event result is invalid")
    return model


def _derive(model: Any) -> dict:
    plan = _plan(model)
    balance = plan["initial_balance_minor"]
    accepted_commands: set[str] = set()
    events = []
    for index, event in enumerate(plan["events"]):
        flags = []
        if event["result"] == "accepted":
            if event["command_id"] in accepted_commands:
                flags.append("duplicate_accepted_command")
            accepted_commands.add(event["command_id"])
            if event["amount_minor"] > balance:
                flags.append("accepted_debit_exceeds_declared_available_balance")
            balance -= event["amount_minor"]
        if event["declared_balance_after_minor"] != balance:
            flags.append("declared_balance_mismatch")
        if not -(MAX_AMOUNT * MAX_EVENTS) <= balance <= MAX_AMOUNT:
            raise DebitIdempotencyTimelineError("Derived balance exceeds hard bound")
        events.append(
            {
                "position": index,
                "event_id": event["event_id"],
                "command_id": event["command_id"],
                "source_id": event["source_id"],
                "expected_balance_after_minor": balance,
                "anomaly_flags": sorted(flags),
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": plan,
        "events": events,
        "final_expected_balance_minor": balance,
        "flags": {
            "event_source_authenticated": False,
            "event_order_proven": False,
            "real_account_balance_proven": False,
            "concurrent_race_proven": False,
            "double_spend_proven": False,
            "economic_impact_proven": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Event order, outcomes, balances and account labels are caller-supplied.",
            "Duplicate accepted command labels are review signals, not race proof.",
            "A negative derived balance does not prove a real overdraft or double spend.",
            "No ledger, payment, account, credential or target is contacted or changed.",
        ],
    }
    digest = (
        "sha256:" + hashlib.sha256((DOMAIN + "\n" + _canonical(body)).encode("ascii")).hexdigest()
    )
    return json.loads(
        _canonical(
            {**body, "analysis_id": "DIT-" + digest[7:39].upper(), "analysis_sha256": digest}
        )
    )


@dataclass(frozen=True, slots=True, init=False)
class DebitIdempotencyTimeline:
    """Replay-checked supplied debit sequence with no financial effect."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise DebitIdempotencyTimelineError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        if _canonical(document) != _canonical(expected):
            raise DebitIdempotencyTimelineError("Report differs from embedded model replay")
        object.__setattr__(self, "_document_json", _canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_debit_timeline(model: Any) -> DebitIdempotencyTimeline:
    """Compare caller-declared event outcomes with a local debit model."""
    return DebitIdempotencyTimeline(_derive(model))


def verify_supplied_debit_timeline(report: Any, *, model: Any) -> DebitIdempotencyTimeline:
    """Independently replay current supplied event input."""
    if type(report) is not DebitIdempotencyTimeline:
        raise DebitIdempotencyTimelineError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != _canonical(expected):
        raise DebitIdempotencyTimelineError("Report differs from supplied model replay")
    return DebitIdempotencyTimeline(expected)


__all__ = [
    "COMPONENT_ID",
    "PROFILE_ID",
    "DebitIdempotencyTimeline",
    "DebitIdempotencyTimelineError",
    "analyze_supplied_debit_timeline",
    "verify_supplied_debit_timeline",
]
