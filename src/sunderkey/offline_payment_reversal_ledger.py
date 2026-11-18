"""Reconcile a supplied payment reversal ledger without payment access."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "supplied_payment_reversal_ledger"
PROFILE_ID = "AOE-GB-D09-S04"
CAPABILITY_ID = "army.gb.d09.s04"
VECTOR_ID = "AV-GB-D09-S04-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D09-S04"
WAVE_ID = "IW2-004"
COMMANDER_ID = "AOE-GB-D09-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:82faa1b9deb1aba6acea1788ad0cd5c296d0dd2dad3aaba1ec139f2aefa44b2f"
SEMANTICS_PROFILE = "supplied-payment-reversal-ledger-v1"
DOMAIN = "sunderkey.offline-payment-reversal-ledger.v1"
MAX_EVENTS = 512
MAX_AMOUNT = 10_000_000_000_000
MAX_DOCUMENT_BYTES = 524_288
MAX_NATIVE_NODES = 16_384
MAX_NATIVE_DEPTH = 12
MAX_STRING_LENGTH = 256
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_PAYMENT = re.compile(r"payment:sha256:[0-9a-f]{64}\Z")
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


class PaymentReversalLedgerError(ValueError):
    """The supplied ledger or report was refused."""


def _canonical(value: Any) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise PaymentReversalLedgerError("Native document structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_STRING_LENGTH:
                raise PaymentReversalLedgerError("Native document string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise PaymentReversalLedgerError("Native document integer bound exceeded")
            return
        if family not in (dict, list):
            raise PaymentReversalLedgerError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise PaymentReversalLedgerError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise PaymentReversalLedgerError("Native JSON text keys are required")
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
        raise PaymentReversalLedgerError("Document byte bound exceeded")
    return encoded


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise PaymentReversalLedgerError(f"{label} fields are invalid")


def _amount(value: Any, label: str, *, positive: bool = False) -> int:
    if type(value) is not int or not int(positive) <= value <= MAX_AMOUNT:
        raise PaymentReversalLedgerError(f"{label} amount is invalid")
    return value


def _plan(model: Any) -> dict:
    model = json.loads(_canonical(model))
    _fields(
        model,
        {
            "schema_version",
            "semantics_profile",
            "payment_ref",
            "currency_label",
            "captured_minor",
            "events",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise PaymentReversalLedgerError("Schema version is invalid")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise PaymentReversalLedgerError("Semantics profile is invalid")
    if type(model["payment_ref"]) is not str or _PAYMENT.fullmatch(model["payment_ref"]) is None:
        raise PaymentReversalLedgerError("Opaque payment reference is required")
    if (
        type(model["currency_label"]) is not str
        or _CURRENCY.fullmatch(model["currency_label"]) is None
    ):
        raise PaymentReversalLedgerError("Currency label is invalid")
    _amount(model["captured_minor"], "captured", positive=True)
    events = model["events"]
    if type(events) is not list or not 1 <= len(events) <= MAX_EVENTS:
        raise PaymentReversalLedgerError("Event count is invalid")
    event_ids: set[str] = set()
    for event in events:
        _fields(
            event,
            {"event_id", "kind", "amount_minor", "result", "declared_remaining_minor"},
            "event",
        )
        event_id = event["event_id"]
        if type(event_id) is not str or _ID.fullmatch(event_id) is None or event_id in event_ids:
            raise PaymentReversalLedgerError("Event identifier is invalid or duplicate")
        event_ids.add(event_id)
        if event["kind"] not in ("refund", "chargeback"):
            raise PaymentReversalLedgerError("Reversal kind is invalid")
        _amount(event["amount_minor"], "reversal", positive=True)
        if event["result"] not in ("accepted", "rejected"):
            raise PaymentReversalLedgerError("Result is invalid")
        remaining = event["declared_remaining_minor"]
        if type(remaining) is not int or not -MAX_EVENTS * MAX_AMOUNT <= remaining <= MAX_AMOUNT:
            raise PaymentReversalLedgerError("Declared remaining amount is invalid")
    return model


def _derive(model: Any) -> dict:
    plan = _plan(model)
    remaining = plan["captured_minor"]
    rows = []
    for position, event in enumerate(plan["events"]):
        flags = []
        if event["result"] == "accepted":
            remaining -= event["amount_minor"]
            if remaining < 0:
                flags.append("accepted_reversals_exceed_supplied_capture")
        if event["declared_remaining_minor"] != remaining:
            flags.append("declared_remaining_mismatch")
        rows.append(
            {
                "position": position,
                "event_id": event["event_id"],
                "expected_remaining_minor": remaining,
                "anomaly_flags": sorted(flags),
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": plan,
        "events": rows,
        "final_expected_remaining_minor": remaining,
        "flags": {
            "payment_source_authenticated": False,
            "capture_or_reversal_proven": False,
            "event_order_proven": False,
            "currency_semantics_proven": False,
            "economic_impact_proven": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Capture, reversal outcomes, amounts, currency, and event order are caller-supplied.",
            "Local remaining-balance arithmetic is not a payment processor or settlement record.",
            "A mismatch does not prove a refund defect, chargeback outcome, or economic impact.",
            "No payment, account, credential, service, network, or target is contacted.",
        ],
    }
    digest = (
        "sha256:" + hashlib.sha256((DOMAIN + "\n" + _canonical(body)).encode("ascii")).hexdigest()
    )
    return json.loads(
        _canonical(
            {**body, "analysis_id": "PRL-" + digest[7:39].upper(), "analysis_sha256": digest}
        )
    )


@dataclass(frozen=True, slots=True, init=False)
class PaymentReversalLedger:
    """Replay-checked local projection of supplied reversal events."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise PaymentReversalLedgerError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        if _canonical(document) != _canonical(expected):
            raise PaymentReversalLedgerError("Report differs from embedded model replay")
        object.__setattr__(self, "_document_json", _canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_payment_reversals(model: Any) -> PaymentReversalLedger:
    """Reconcile only the supplied capture and reversal sequence."""
    return PaymentReversalLedger(_derive(model))


def verify_supplied_payment_reversals(report: Any, *, model: Any) -> PaymentReversalLedger:
    """Recompute the report from current supplied model bytes."""
    if type(report) is not PaymentReversalLedger:
        raise PaymentReversalLedgerError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != _canonical(expected):
        raise PaymentReversalLedgerError("Report differs from supplied model replay")
    return PaymentReversalLedger(expected)
