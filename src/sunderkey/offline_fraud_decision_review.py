"""Compare supplied coarse fraud decisions with supplied policy floors."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "supplied_fraud_decision_review"
PROFILE_ID = "AOE-GB-D09-S10"
CAPABILITY_ID = "army.gb.d09.s10"
VECTOR_ID = "AV-GB-D09-S10-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D09-S10"
WAVE_ID = "IW2-010"
COMMANDER_ID = "AOE-GB-D09-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:66ad93d35f4c7901d709aece724acd5a0d9f33bebec1bda2e26b18b313459759"
SEMANTICS_PROFILE = "supplied-fraud-decision-review-v1"
DOMAIN = "sunderkey.offline-fraud-decision-review.v1"
MAX_EVENTS = 512
MAX_DOCUMENT_BYTES = 524_288
MAX_NATIVE_NODES = 16_384
MAX_NATIVE_DEPTH = 12
MAX_STRING_LENGTH = 256
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_POLICY = re.compile(r"policy:sha256:[0-9a-f]{64}\Z")
_SUBJECT = re.compile(r"subject:sha256:[0-9a-f]{64}\Z")
_BANDS = ("low", "medium", "high")
_ACTIONS = {"allow": 0, "challenge": 1, "block": 2}
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


class FraudDecisionReviewError(ValueError):
    """The supplied decision model or report was refused."""


def _canonical(value: Any) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise FraudDecisionReviewError("Native document structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_STRING_LENGTH:
                raise FraudDecisionReviewError("Native document string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise FraudDecisionReviewError("Native document integer bound exceeded")
            return
        if family not in (dict, list):
            raise FraudDecisionReviewError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise FraudDecisionReviewError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise FraudDecisionReviewError("Native JSON text keys are required")
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
        raise FraudDecisionReviewError("Document byte bound exceeded")
    return encoded


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise FraudDecisionReviewError(f"{label} fields are invalid")


def _action(value: Any, label: str) -> str:
    if type(value) is not str or value not in _ACTIONS:
        raise FraudDecisionReviewError(f"{label} is invalid")
    return value


def _plan(model: Any) -> dict:
    model = json.loads(_canonical(model))
    _fields(
        model,
        {"schema_version", "semantics_profile", "policy_ref", "minimum_action_by_band", "events"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise FraudDecisionReviewError("Schema version is invalid")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise FraudDecisionReviewError("Semantics profile is invalid")
    if type(model["policy_ref"]) is not str or _POLICY.fullmatch(model["policy_ref"]) is None:
        raise FraudDecisionReviewError("Opaque policy reference is required")
    floors = model["minimum_action_by_band"]
    _fields(floors, set(_BANDS), "policy floors")
    for band in _BANDS:
        _action(floors[band], "Policy floor")
    events = model["events"]
    if type(events) is not list or not 1 <= len(events) <= MAX_EVENTS:
        raise FraudDecisionReviewError("Decision count is invalid")
    event_ids: set[str] = set()
    for event in events:
        _fields(
            event,
            {"event_id", "subject_ref", "risk_band", "declared_minimum_action", "decision"},
            "event",
        )
        event_id = event["event_id"]
        if type(event_id) is not str or _ID.fullmatch(event_id) is None or event_id in event_ids:
            raise FraudDecisionReviewError("Event identifier is invalid or duplicate")
        event_ids.add(event_id)
        if (
            type(event["subject_ref"]) is not str
            or _SUBJECT.fullmatch(event["subject_ref"]) is None
        ):
            raise FraudDecisionReviewError("Opaque subject reference is required")
        if type(event["risk_band"]) is not str or event["risk_band"] not in _BANDS:
            raise FraudDecisionReviewError("Risk band is invalid")
        _action(event["declared_minimum_action"], "Declared floor")
        _action(event["decision"], "Decision")
    return model


def _derive(model: Any) -> dict:
    plan = _plan(model)
    rows = []
    for position, event in enumerate(plan["events"]):
        expected_floor = plan["minimum_action_by_band"][event["risk_band"]]
        flags = []
        if event["declared_minimum_action"] != expected_floor:
            flags.append("declared_floor_mismatch")
        if _ACTIONS[event["decision"]] < _ACTIONS[expected_floor]:
            flags.append("decision_below_supplied_policy_floor")
        rows.append(
            {
                "position": position,
                "event_id": event["event_id"],
                "expected_minimum_action": expected_floor,
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
            "policy_source_authenticated": False,
            "risk_band_or_subject_proven": False,
            "decision_observed": False,
            "override_context_known": False,
            "fraud_or_evasion_proven": False,
            "control_effectiveness_proven": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Policy floors, coarse risk bands, subject labels, and decisions are caller-supplied.",
            "The model contains no scoring features, evasion sequence, or production rule detail.",
            "A mismatch does not prove fraud, a bypass, or live control effectiveness.",
            "No account, payment, credential, service, network, or target is contacted.",
        ],
    }
    digest = (
        "sha256:" + hashlib.sha256((DOMAIN + "\n" + _canonical(body)).encode("ascii")).hexdigest()
    )
    return json.loads(
        _canonical(
            {**body, "analysis_id": "FDR-" + digest[7:39].upper(), "analysis_sha256": digest}
        )
    )


@dataclass(frozen=True, slots=True, init=False)
class FraudDecisionReview:
    """Replay-checked local comparison of supplied decisions and floors."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise FraudDecisionReviewError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        if _canonical(document) != _canonical(expected):
            raise FraudDecisionReviewError("Report differs from embedded model replay")
        object.__setattr__(self, "_document_json", _canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_fraud_decisions(model: Any) -> FraudDecisionReview:
    """Compare only coarse supplied decision labels."""
    return FraudDecisionReview(_derive(model))


def verify_supplied_fraud_decisions(report: Any, *, model: Any) -> FraudDecisionReview:
    """Recompute the report from current supplied model bytes."""
    if type(report) is not FraudDecisionReview:
        raise FraudDecisionReviewError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != _canonical(expected):
        raise FraudDecisionReviewError("Report differs from supplied model replay")
    return FraudDecisionReview(expected)
