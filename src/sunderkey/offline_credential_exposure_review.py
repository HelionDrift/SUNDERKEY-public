"""Bind opaque credential-exposure triage to an inert specialist model."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from .credential_exposure_triage import (
    CredentialExposureSignal,
    ExposureReviewConsent,
    plan_credential_exposure_review,
)

COMPONENT_ID = "supplied_credential_exposure_review"
PROFILE_ID = "AOE-GA-D01-S08"
CAPABILITY_ID = "army.ga.d01.s08"
VECTOR_ID = "AV-GA-D01-S08-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D01-S08"
WAVE_ID = "IW2-008"
COMMANDER_ID = "AOE-GA-D01-CMD"
GROUP_OWNER_ID = "AOE-HQ-03"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:5ff0f55d5fe6ad8e6d4b5e652a78d0f0e7d1ffed92972311c30bc74175760500"
SEMANTICS_PROFILE = "supplied-opaque-credential-exposure-v1"
DOMAIN = "sunderkey.offline-credential-exposure-review.v1"
MAX_SIGNALS = 128
MAX_CONSENTS = 128
MAX_DOCUMENT_BYTES = 262_144
MAX_NATIVE_NODES = 16_384
MAX_NATIVE_DEPTH = 12
MAX_STRING_LENGTH = 256
_SIGNAL_FIELDS = {
    "event_id",
    "tenant_id",
    "scope_sha256",
    "principal_ref",
    "credential_ref",
    "feed_ref",
    "source_sha256",
    "observed_at",
    "expires_at",
    "kind",
}
_CONSENT_FIELDS = {
    "tenant_id",
    "scope_sha256",
    "principal_ref",
    "allowed_kinds",
    "issued_at",
    "expires_at",
    "source_sha256",
}
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "credential_access",
        "execution",
        "feed_access",
        "login",
        "network",
        "password_audit",
        "publication",
        "qualification",
        "rotation",
        "secret_resolution",
    ),
    "none",
)


class CredentialExposurePartialError(ValueError):
    """The bounded opaque input or current replay did not validate."""


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise CredentialExposurePartialError(f"{label} fields are invalid")


def _canonical(value: Any) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise CredentialExposurePartialError("Native document structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_STRING_LENGTH:
                raise CredentialExposurePartialError("Native document string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise CredentialExposurePartialError("Native document integer bound exceeded")
            return
        if family not in (dict, list):
            raise CredentialExposurePartialError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise CredentialExposurePartialError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise CredentialExposurePartialError("Native JSON text keys are required")
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
        raise CredentialExposurePartialError("Document byte bound exceeded")
    return encoded


def _plan(model: Any) -> tuple[dict, tuple, tuple]:
    _fields(
        model,
        {
            "schema_version",
            "semantics_profile",
            "tenant_id",
            "scope_sha256",
            "reviewed_at",
            "signals",
            "consents",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise CredentialExposurePartialError("Schema version is invalid")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise CredentialExposurePartialError("Semantics profile is invalid")
    signals = model["signals"]
    consents = model["consents"]
    if type(signals) is not list or not 1 <= len(signals) <= MAX_SIGNALS:
        raise CredentialExposurePartialError("Signal count is invalid")
    if type(consents) is not list or len(consents) > MAX_CONSENTS:
        raise CredentialExposurePartialError("Consent count is invalid")
    native = json.loads(_canonical(model))
    typed_signals = []
    typed_consents = []
    for signal in native["signals"]:
        _fields(signal, _SIGNAL_FIELDS, "signal")
        typed_signals.append(CredentialExposureSignal(**signal))
    for consent in native["consents"]:
        _fields(consent, _CONSENT_FIELDS, "consent")
        if type(consent["allowed_kinds"]) is not list:
            raise CredentialExposurePartialError("Consent allowed kinds must be a list")
        typed_consents.append(
            ExposureReviewConsent(**{**consent, "allowed_kinds": tuple(consent["allowed_kinds"])})
        )
    return native, tuple(typed_signals), tuple(typed_consents)


def _derive(model: Any) -> dict:
    native, signals, consents = _plan(model)
    review = plan_credential_exposure_review(
        tenant_id=native["tenant_id"],
        scope_sha256=native["scope_sha256"],
        reviewed_at=native["reviewed_at"],
        signals=signals,
        consents=consents,
    )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": native,
        "review_plan": review.to_dict(),
        "flags": {
            "feed_authenticated": False,
            "consent_authenticated": False,
            "opaque_reference_origin_proven": False,
            "credential_validity_proven": False,
            "compromise_proven": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Signals, consent, timestamps and source digests are caller-supplied.",
            "Opaque references must originate from random identifiers, not secret bytes.",
            "A review candidate does not prove consent, credential validity or compromise.",
            "No feed, login, password audit, credential, rotation or target is used.",
        ],
    }
    digest = (
        "sha256:" + hashlib.sha256((DOMAIN + "\n" + _canonical(body)).encode("ascii")).hexdigest()
    )
    return json.loads(
        _canonical(
            {**body, "analysis_id": "CER-" + digest[7:39].upper(), "analysis_sha256": digest}
        )
    )


@dataclass(frozen=True, slots=True, init=False)
class CredentialExposurePartial:
    """Replay-checked, metadata-only specialist report with no secret access."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise CredentialExposurePartialError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        if _canonical(document) != _canonical(expected):
            raise CredentialExposurePartialError("Report differs from embedded model replay")
        object.__setattr__(self, "_document_json", _canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_credential_exposure(model: Any) -> CredentialExposurePartial:
    """Screen caller-supplied opaque signals for review only."""
    return CredentialExposurePartial(_derive(model))


def verify_supplied_credential_exposure(report: Any, *, model: Any) -> CredentialExposurePartial:
    """Independently rederive the report from the current supplied model."""
    if type(report) is not CredentialExposurePartial:
        raise CredentialExposurePartialError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != _canonical(expected):
        raise CredentialExposurePartialError("Report differs from supplied model replay")
    return CredentialExposurePartial(expected)


__all__ = [
    "COMPONENT_ID",
    "PROFILE_ID",
    "CredentialExposurePartial",
    "CredentialExposurePartialError",
    "analyze_supplied_credential_exposure",
    "verify_supplied_credential_exposure",
]
