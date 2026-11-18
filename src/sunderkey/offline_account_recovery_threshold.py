"""Compare supplied account-recovery factor labels without using credentials."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "supplied_account_recovery_threshold"
PROFILE_ID = "AOE-GB-D09-S05"
CAPABILITY_ID = "army.gb.d09.s05"
VECTOR_ID = "AV-GB-D09-S05-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D09-S05"
WAVE_ID = "IW2-005"
COMMANDER_ID = "AOE-GB-D09-CMD"
GROUP_OWNER_ID = "AOE-HQ-04"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:157c77f47f6700b583e2d4e175d70a30031d9f4c7288849623dc1520fc543320"
SEMANTICS_PROFILE = "supplied-account-recovery-threshold-v1"
DOMAIN = "sunderkey.offline-account-recovery-threshold.v1"
MAX_FACTORS = 64
MAX_PRESENTED_FACTORS = 8
MAX_EVENTS = 256
MAX_DOCUMENT_BYTES = 524_288
MAX_NATIVE_NODES = 16_384
MAX_NATIVE_DEPTH = 12
MAX_STRING_LENGTH = 256
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_ACCOUNT = re.compile(r"account:sha256:[0-9a-f]{64}\Z")
_FACTOR = re.compile(r"factor:sha256:[0-9a-f]{64}\Z")
_EFFECTS = dict.fromkeys(
    (
        "account_write",
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


class AccountRecoveryThresholdError(ValueError):
    """The supplied recovery model or replay document was refused."""


def _canonical(value: Any) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise AccountRecoveryThresholdError("Native document structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_STRING_LENGTH:
                raise AccountRecoveryThresholdError("Native document string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise AccountRecoveryThresholdError("Native document integer bound exceeded")
            return
        if family not in (dict, list):
            raise AccountRecoveryThresholdError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise AccountRecoveryThresholdError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise AccountRecoveryThresholdError("Native JSON text keys are required")
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
        raise AccountRecoveryThresholdError("Document byte bound exceeded")
    return encoded


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise AccountRecoveryThresholdError(f"{label} fields are invalid")


def _opaque(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise AccountRecoveryThresholdError(f"Opaque {label} reference is invalid")
    return value


def _plan(model: Any) -> dict:
    model = json.loads(_canonical(model))
    _fields(
        model,
        {
            "schema_version",
            "semantics_profile",
            "account_ref",
            "enrolled_factor_refs",
            "required_factor_count",
            "attempts",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise AccountRecoveryThresholdError("Schema version is invalid")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise AccountRecoveryThresholdError("Semantics profile is invalid")
    _opaque(model["account_ref"], _ACCOUNT, "account")
    factors = model["enrolled_factor_refs"]
    if type(factors) is not list or not 1 <= len(factors) <= MAX_FACTORS:
        raise AccountRecoveryThresholdError("Enrolled factor count is invalid")
    enrolled = {_opaque(item, _FACTOR, "factor") for item in factors}
    if len(enrolled) != len(factors):
        raise AccountRecoveryThresholdError("Duplicate enrolled factor reference")
    required = model["required_factor_count"]
    if type(required) is not int or not 1 <= required <= min(len(enrolled), MAX_PRESENTED_FACTORS):
        raise AccountRecoveryThresholdError("Required factor count is invalid")
    attempts = model["attempts"]
    if type(attempts) is not list or not 1 <= len(attempts) <= MAX_EVENTS:
        raise AccountRecoveryThresholdError("Attempt count is invalid")
    ids: set[str] = set()
    for attempt in attempts:
        _fields(
            attempt,
            {"attempt_id", "presented_factor_refs", "result", "declared_reset_performed"},
            "attempt",
        )
        attempt_id = attempt["attempt_id"]
        if type(attempt_id) is not str or _ID.fullmatch(attempt_id) is None or attempt_id in ids:
            raise AccountRecoveryThresholdError("Attempt identifier is invalid or duplicate")
        ids.add(attempt_id)
        presented = attempt["presented_factor_refs"]
        if type(presented) is not list or len(presented) > MAX_PRESENTED_FACTORS:
            raise AccountRecoveryThresholdError("Presented factor count is invalid")
        unique = {_opaque(item, _FACTOR, "presented factor") for item in presented}
        if len(unique) != len(presented):
            raise AccountRecoveryThresholdError("Duplicate presented factor reference")
        if attempt["result"] not in ("accepted", "rejected"):
            raise AccountRecoveryThresholdError("Attempt result is invalid")
        if type(attempt["declared_reset_performed"]) is not bool:
            raise AccountRecoveryThresholdError("Declared reset flag is invalid")
    return model


def _derive(model: Any) -> dict:
    plan = _plan(model)
    enrolled = set(plan["enrolled_factor_refs"])
    rows = []
    for position, attempt in enumerate(plan["attempts"]):
        presented = set(attempt["presented_factor_refs"])
        enrolled_presented = presented & enrolled
        threshold_met = len(enrolled_presented) >= plan["required_factor_count"]
        flags = []
        if attempt["result"] == "accepted" and not threshold_met:
            flags.append("accepted_below_supplied_factor_threshold")
        if attempt["result"] == "rejected" and threshold_met:
            flags.append("rejected_despite_supplied_factor_threshold")
        if attempt["result"] == "accepted" and presented - enrolled:
            flags.append("accepted_with_unenrolled_factor_label")
        if attempt["declared_reset_performed"] != (attempt["result"] == "accepted"):
            flags.append("declared_reset_result_mismatch")
        rows.append(
            {
                "position": position,
                "attempt_id": attempt["attempt_id"],
                "enrolled_presented_count": len(enrolled_presented),
                "unrecognized_presented_count": len(presented - enrolled),
                "supplied_threshold_met": threshold_met,
                "anomaly_flags": sorted(flags),
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": plan,
        "attempts": rows,
        "flags": {
            "account_identity_proven": False,
            "factor_possession_proven": False,
            "factor_enrollment_authenticated": False,
            "recovery_policy_authenticated": False,
            "reset_observed": False,
            "kyc_assessed": False,
            "account_takeover_proven": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Account, enrolled factors, threshold, outcomes and reset flags are caller-supplied.",
            "Digest-shaped factor labels are not credentials and do not prove possession.",
            "Threshold anomalies do not prove deployed recovery behavior or takeover.",
            "No KYC, account, credential, service, or target is contacted or changed.",
        ],
    }
    digest = (
        "sha256:" + hashlib.sha256((DOMAIN + "\n" + _canonical(body)).encode("ascii")).hexdigest()
    )
    return json.loads(
        _canonical(
            {**body, "analysis_id": "ART-" + digest[7:39].upper(), "analysis_sha256": digest}
        )
    )


@dataclass(frozen=True, slots=True, init=False)
class AccountRecoveryThreshold:
    """Replay-checked local comparison of supplied recovery factor labels."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise AccountRecoveryThresholdError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        if _canonical(document) != _canonical(expected):
            raise AccountRecoveryThresholdError("Report differs from embedded model replay")
        object.__setattr__(self, "_document_json", _canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_account_recovery(model: Any) -> AccountRecoveryThreshold:
    """Derive only a supplied recovery-factor threshold comparison."""
    return AccountRecoveryThreshold(_derive(model))


def verify_supplied_account_recovery(report: Any, *, model: Any) -> AccountRecoveryThreshold:
    """Recompute the report from current supplied model bytes."""
    if type(report) is not AccountRecoveryThreshold:
        raise AccountRecoveryThresholdError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != _canonical(expected):
        raise AccountRecoveryThresholdError("Report differs from supplied model replay")
    return AccountRecoveryThreshold(expected)


__all__ = [
    "COMPONENT_ID",
    "PROFILE_ID",
    "AccountRecoveryThreshold",
    "AccountRecoveryThresholdError",
    "analyze_supplied_account_recovery",
    "verify_supplied_account_recovery",
]
