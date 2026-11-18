"""Reconcile a supplied cross-channel balance timeline without service access."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "supplied_cross_channel_balance"
PROFILE_ID = "AOE-GB-D09-S12"
CAPABILITY_ID = "army.gb.d09.s12"
VECTOR_ID = "AV-GB-D09-S12-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D09-S12"
WAVE_ID = "IW2-012"
COMMANDER_ID = "AOE-GB-D09-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:07e3e6d67456ce2497bdb7c6c754350bffd7931e4983cff6b90062b8cbad61c6"
SEMANTICS_PROFILE = "supplied-cross-channel-balance-v1"
DOMAIN = "sunderkey.offline-cross-channel-balance.v1"
MAX_EVENTS = 512
MAX_AMOUNT = 10_000_000_000_000
MAX_DOCUMENT_BYTES = 524_288
MAX_NATIVE_NODES = 16_384
MAX_NATIVE_DEPTH = 12
MAX_STRING_LENGTH = 256
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_ACCOUNT = re.compile(r"account:sha256:[0-9a-f]{64}\Z")
_TRANSACTION = re.compile(r"transaction:sha256:[0-9a-f]{64}\Z")
_CURRENCY = re.compile(r"[A-Z]{3}\Z")
_EFFECTS = dict.fromkeys(
    (
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


class CrossChannelBalanceError(ValueError):
    """The supplied balance model or report was refused."""


def _canonical(value: Any) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise CrossChannelBalanceError("Native document structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_STRING_LENGTH:
                raise CrossChannelBalanceError("Native document string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise CrossChannelBalanceError("Native document integer bound exceeded")
            return
        if family not in (dict, list):
            raise CrossChannelBalanceError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise CrossChannelBalanceError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise CrossChannelBalanceError("Native JSON text keys are required")
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
        raise CrossChannelBalanceError("Document byte bound exceeded")
    return encoded


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise CrossChannelBalanceError(f"{label} fields are invalid")


def _amount(value: Any, label: str, *, positive: bool = False) -> int:
    if type(value) is not int or not int(positive) <= value <= MAX_AMOUNT:
        raise CrossChannelBalanceError(f"{label} amount is invalid")
    return value


def _plan(model: Any) -> dict:
    model = json.loads(_canonical(model))
    _fields(
        model,
        {
            "schema_version",
            "semantics_profile",
            "account_ref",
            "currency_label",
            "opening_balance_minor",
            "events",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise CrossChannelBalanceError("Schema version is invalid")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise CrossChannelBalanceError("Semantics profile is invalid")
    if type(model["account_ref"]) is not str or _ACCOUNT.fullmatch(model["account_ref"]) is None:
        raise CrossChannelBalanceError("Opaque account reference is required")
    if (
        type(model["currency_label"]) is not str
        or _CURRENCY.fullmatch(model["currency_label"]) is None
    ):
        raise CrossChannelBalanceError("Currency label is invalid")
    _amount(model["opening_balance_minor"], "opening balance")
    events = model["events"]
    if type(events) is not list or not 1 <= len(events) <= MAX_EVENTS:
        raise CrossChannelBalanceError("Event count is invalid")
    event_ids: set[str] = set()
    for event in events:
        _fields(
            event,
            {
                "event_id",
                "channel_id",
                "transaction_ref",
                "kind",
                "amount_minor",
                "result",
                "declared_balance_minor",
            },
            "event",
        )
        event_id = event["event_id"]
        if type(event_id) is not str or _ID.fullmatch(event_id) is None or event_id in event_ids:
            raise CrossChannelBalanceError("Event identifier is invalid or duplicate")
        event_ids.add(event_id)
        if type(event["channel_id"]) is not str or _ID.fullmatch(event["channel_id"]) is None:
            raise CrossChannelBalanceError("Channel identifier is invalid")
        if (
            type(event["transaction_ref"]) is not str
            or _TRANSACTION.fullmatch(event["transaction_ref"]) is None
        ):
            raise CrossChannelBalanceError("Opaque transaction reference is required")
        if event["kind"] not in ("debit", "credit"):
            raise CrossChannelBalanceError("Entry kind is invalid")
        _amount(event["amount_minor"], "entry", positive=True)
        if event["result"] not in ("accepted", "rejected"):
            raise CrossChannelBalanceError("Result is invalid")
        balance = event["declared_balance_minor"]
        if (
            type(balance) is not int
            or not -MAX_EVENTS * MAX_AMOUNT <= balance <= (MAX_EVENTS + 1) * MAX_AMOUNT
        ):
            raise CrossChannelBalanceError("Declared balance is invalid")
    return model


def _derive(model: Any) -> dict:
    plan = _plan(model)
    balance = plan["opening_balance_minor"]
    accepted_transactions: dict[str, str] = {}
    rows = []
    for position, event in enumerate(plan["events"]):
        flags = []
        if event["result"] == "accepted":
            previous_channel = accepted_transactions.get(event["transaction_ref"])
            if previous_channel is not None:
                flags.append("duplicate_accepted_transaction_reference")
                if previous_channel != event["channel_id"]:
                    flags.append("cross_channel_duplicate_reference")
            else:
                accepted_transactions[event["transaction_ref"]] = event["channel_id"]
            if event["kind"] == "debit":
                balance -= event["amount_minor"]
            else:
                balance += event["amount_minor"]
        if event["declared_balance_minor"] != balance:
            flags.append("declared_balance_mismatch")
        rows.append(
            {
                "position": position,
                "event_id": event["event_id"],
                "expected_balance_minor": balance,
                "anomaly_flags": sorted(flags),
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": plan,
        "events": rows,
        "final_expected_balance_minor": balance,
        "flags": {
            "account_or_channel_authenticated": False,
            "transaction_identity_proven": False,
            "event_order_proven": False,
            "currency_semantics_proven": False,
            "duplicate_economic_effect_proven": False,
            "economic_impact_proven": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Account, channels, references, outcomes, amounts, currency, and order are supplied.",
            "Repeated references are review signals, not proof of duplicate settlement.",
            "Local arithmetic does not establish a real balance, defect, or impact.",
            "No account, channel, payment, credential, service, network, or target is contacted.",
        ],
    }
    digest = (
        "sha256:" + hashlib.sha256((DOMAIN + "\n" + _canonical(body)).encode("ascii")).hexdigest()
    )
    return json.loads(
        _canonical(
            {**body, "analysis_id": "CCB-" + digest[7:39].upper(), "analysis_sha256": digest}
        )
    )


@dataclass(frozen=True, slots=True, init=False)
class CrossChannelBalance:
    """Replay-checked local projection of supplied channel events."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise CrossChannelBalanceError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        if _canonical(document) != _canonical(expected):
            raise CrossChannelBalanceError("Report differs from embedded model replay")
        object.__setattr__(self, "_document_json", _canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_cross_channel_balance(model: Any) -> CrossChannelBalance:
    """Reconcile only the supplied channel sequence."""
    return CrossChannelBalance(_derive(model))


def verify_supplied_cross_channel_balance(report: Any, *, model: Any) -> CrossChannelBalance:
    """Recompute the report from current supplied model bytes."""
    if type(report) is not CrossChannelBalance:
        raise CrossChannelBalanceError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != _canonical(expected):
        raise CrossChannelBalanceError("Report differs from supplied model replay")
    return CrossChannelBalance(expected)
