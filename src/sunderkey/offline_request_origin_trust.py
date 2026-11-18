"""Project supplied request-origin and anti-forgery negative predicates offline."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "supplied_request_origin_trust"
PROFILE_ID = "AOE-GE-D23-S09"
CAPABILITY_ID = "army.ge.d23.s09"
VECTOR_ID = "AV-GE-D23-S09-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D23-S09"
WAVE_ID = "IW2-023"
COMMANDER_ID = "AOE-GE-D23-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:bb34f9e29726c609e3f19961f109f68685bff34afb4828afc80d28932b3cdb9f"
SEMANTICS_PROFILE = "supplied-request-origin-trust-predicates-v1"
DOMAIN = "sunderkey.offline-request-origin-trust.v1"
MAX_DOCUMENT_BYTES = 32_768
MAX_OBSERVATIONS = 128
MAX_ALLOWED_ORIGINS = 16
MAX_NATIVE_NODES = 2_048
MAX_NATIVE_DEPTH = 10
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_ORIGIN = re.compile(
    r"https://(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
    r"(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*"
    r"(?::[1-9][0-9]{0,4})?\Z"
)
_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_OUTCOMES = frozenset({"accepted", "rejected", "unknown"})
_EFFECTS = dict.fromkeys(
    (
        "authority", "credential", "execution", "filesystem", "network",
        "publication", "qualification", "target",
    ),
    "none",
)


class RequestOriginTrustError(ValueError):
    """A supplied request model or replay report was refused."""


def _canonical(value: Any) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise RequestOriginTrustError("Native structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_DOCUMENT_BYTES:
                raise RequestOriginTrustError("Native string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise RequestOriginTrustError("Native integer bound exceeded")
            return
        if family not in (dict, list):
            raise RequestOriginTrustError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise RequestOriginTrustError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise RequestOriginTrustError("Native JSON text keys are required")
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
        raise RequestOriginTrustError("Document byte bound exceeded")
    return encoded


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise RequestOriginTrustError(f"{label} fields are invalid")


def _origin(value: Any) -> str:
    if type(value) is not str or _ORIGIN.fullmatch(value) is None:
        raise RequestOriginTrustError("Canonical HTTPS origin is required")
    if ":" in value.removeprefix("https://"):
        port = int(value.rsplit(":", 1)[1])
        if not 1 <= port <= 65_535:
            raise RequestOriginTrustError("Origin port is outside range")
    return value


def _model(value: Any) -> dict:
    model = json.loads(_canonical(value))
    _fields(
        model,
        {"schema_version", "semantics_profile", "source_id", "policy", "observations"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise RequestOriginTrustError("Schema version is invalid")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise RequestOriginTrustError("Semantics profile is invalid")
    if type(model["source_id"]) is not str or _ID.fullmatch(model["source_id"]) is None:
        raise RequestOriginTrustError("Source identifier is invalid")
    policy = model["policy"]
    _fields(
        policy,
        {"declaration_complete", "origin_required", "csrf_token_required", "allowed_origins"},
        "policy",
    )
    for field in ("declaration_complete", "origin_required", "csrf_token_required"):
        if type(policy[field]) is not bool:
            raise RequestOriginTrustError(f"{field} must be boolean")
    allowed = policy["allowed_origins"]
    if type(allowed) is not list or not 1 <= len(allowed) <= MAX_ALLOWED_ORIGINS:
        raise RequestOriginTrustError("Allowed origin count is invalid")
    if allowed != sorted(set(_origin(item) for item in allowed)):
        raise RequestOriginTrustError("Allowed origins must be sorted and unique")
    observations = model["observations"]
    if type(observations) is not list or not 1 <= len(observations) <= MAX_OBSERVATIONS:
        raise RequestOriginTrustError("Observation count is invalid")
    identifiers: set[str] = set()
    for item in observations:
        _fields(
            item,
            {
                "observation_id", "method", "origin", "capture_complete",
                "csrf_token_present", "declared_outcome",
            },
            "observation",
        )
        identifier = item["observation_id"]
        if type(identifier) is not str or _ID.fullmatch(identifier) is None:
            raise RequestOriginTrustError("Observation identifier is invalid")
        if identifier in identifiers:
            raise RequestOriginTrustError("Observation identifier is repeated")
        identifiers.add(identifier)
        if type(item["method"]) is not str or item["method"] not in _METHODS:
            raise RequestOriginTrustError("Only declared state-changing methods are supported")
        if item["origin"] is not None:
            _origin(item["origin"])
        for field in ("capture_complete", "csrf_token_present"):
            if type(item[field]) is not bool:
                raise RequestOriginTrustError(f"{field} must be boolean")
        if type(item["declared_outcome"]) is not str or item["declared_outcome"] not in _OUTCOMES:
            raise RequestOriginTrustError("Declared outcome is invalid")
    return model


def _derive(value: Any) -> dict:
    model = _model(value)
    policy = model["policy"]
    observations = []
    for item in sorted(model["observations"], key=lambda row: row["observation_id"]):
        negative = []
        if policy["origin_required"] and item["origin"] is None:
            negative.append("required_origin_absent")
        elif item["origin"] is not None and item["origin"] not in policy["allowed_origins"]:
            negative.append("origin_not_declared_allowed")
        if policy["csrf_token_required"] and not item["csrf_token_present"]:
            negative.append("required_token_absent")
        if not policy["declaration_complete"] or not item["capture_complete"]:
            disposition = "unresolved_declaration_or_capture"
        elif item["declared_outcome"] == "unknown":
            disposition = "unresolved_outcome"
        elif not negative:
            disposition = "no_declared_negative_invariant"
        elif item["declared_outcome"] == "accepted":
            disposition = "candidate_declared_trust_boundary_conflict"
        else:
            disposition = "declared_reject_consistent"
        observations.append(
            {
                "observation_id": item["observation_id"],
                "negative_predicates": negative,
                "disposition": disposition,
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": model,
        "observation_count": len(observations),
        "projections": observations,
        "flags": {
            "origin_policy_verified": False,
            "csrf_token_validity_verified": False,
            "target_request_outcome_verified": False,
            "request_forgery_verified": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Origins use a narrow lexical HTTPS representation, not browser equivalence.",
            "Policy and observed outcomes are unverified caller assertions.",
            "No token value is accepted or validated.",
            "A declared conflict does not prove request forgery or target behavior.",
            "No file, credential, network, process, or target is accessed.",
        ],
    }
    digest = "sha256:" + hashlib.sha256(
        (DOMAIN + "\n" + _canonical(body)).encode("ascii")
    ).hexdigest()
    return json.loads(_canonical({
        **body, "analysis_id": "ROT-" + digest[7:39].upper(), "analysis_sha256": digest
    }))


@dataclass(frozen=True, slots=True, init=False)
class RequestOriginTrust:
    """Immutable report replayed from a supplied request and policy model."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise RequestOriginTrustError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        if _canonical(document) != _canonical(expected):
            raise RequestOriginTrustError("Report differs from embedded source replay")
        object.__setattr__(self, "_document_json", _canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_request_origin_trust(model: Any) -> RequestOriginTrust:
    """Project supplied negative predicates without sending a request."""
    return RequestOriginTrust(_derive(model))


def verify_supplied_request_origin_trust(
    report: Any, *, model: Any
) -> RequestOriginTrust:
    if type(report) is not RequestOriginTrust:
        raise RequestOriginTrustError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != _canonical(expected):
        raise RequestOriginTrustError("Report differs from supplied source replay")
    return RequestOriginTrust(expected)
