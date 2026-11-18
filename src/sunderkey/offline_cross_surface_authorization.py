"""Compare supplied authorization decisions across exact shared opaque references."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "supplied_cross_surface_authorization"
PROFILE_ID = "AOE-GE-D23-S07"
CAPABILITY_ID = "army.ge.d23.s07"
VECTOR_ID = "AV-GE-D23-S07-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D23-S07"
WAVE_ID = "IW2-021"
COMMANDER_ID = "AOE-GE-D23-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:62e3b0b9c3dd88d09b6cd3ec3e1548babce7cc824fb6e6fbb37dbfde9c750f23"
SEMANTICS_PROFILE = "supplied-cross-surface-authorization-decisions-v1"
DOMAIN = "sunderkey.offline-cross-surface-authorization.v1"
MAX_DOCUMENT_BYTES = 32_768
MAX_DECISIONS = 256
MAX_SURFACES = 8
MAX_NATIVE_NODES = 2_048
MAX_NATIVE_DEPTH = 10
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_REF = re.compile(r"ref:[A-Za-z0-9][A-Za-z0-9._:-]{0,123}\Z")
_OUTCOMES = frozenset({"allowed", "denied", "unknown"})
_EFFECTS = dict.fromkeys(
    (
        "authority", "credential", "execution", "filesystem", "network",
        "publication", "qualification", "target",
    ),
    "none",
)


class CrossSurfaceAuthorizationError(ValueError):
    """A supplied authorization model or replay report was refused."""


def _canonical(value: Any) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise CrossSurfaceAuthorizationError("Native structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_DOCUMENT_BYTES:
                raise CrossSurfaceAuthorizationError("Native string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise CrossSurfaceAuthorizationError("Native integer bound exceeded")
            return
        if family not in (dict, list):
            raise CrossSurfaceAuthorizationError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise CrossSurfaceAuthorizationError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise CrossSurfaceAuthorizationError("Native JSON text keys are required")
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
        raise CrossSurfaceAuthorizationError("Document byte bound exceeded")
    return encoded


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise CrossSurfaceAuthorizationError(f"{label} fields are invalid")


def _reference(value: Any, label: str) -> str:
    if type(value) is not str or _REF.fullmatch(value) is None:
        raise CrossSurfaceAuthorizationError(f"{label} must be an opaque ref label")
    return value


def _model(value: Any) -> dict:
    model = json.loads(_canonical(value))
    _fields(
        model,
        {
            "schema_version", "semantics_profile", "source_id",
            "identity_mapping_complete", "decisions",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise CrossSurfaceAuthorizationError("Schema version is invalid")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise CrossSurfaceAuthorizationError("Semantics profile is invalid")
    if type(model["source_id"]) is not str or _ID.fullmatch(model["source_id"]) is None:
        raise CrossSurfaceAuthorizationError("Source identifier is invalid")
    if type(model["identity_mapping_complete"]) is not bool:
        raise CrossSurfaceAuthorizationError("Mapping completeness must be boolean")
    decisions = model["decisions"]
    if type(decisions) is not list or not 2 <= len(decisions) <= MAX_DECISIONS:
        raise CrossSurfaceAuthorizationError("Decision count is invalid")
    identifiers: set[str] = set()
    surface_keys: set[tuple[str, str, str, str]] = set()
    surfaces: set[str] = set()
    for item in decisions:
        _fields(
            item,
            {
                "decision_id", "surface_id", "principal_ref", "action_ref",
                "resource_ref", "outcome",
            },
            "decision",
        )
        for field in ("decision_id", "surface_id"):
            if type(item[field]) is not str or _ID.fullmatch(item[field]) is None:
                raise CrossSurfaceAuthorizationError(f"{field} is invalid")
        for field in ("principal_ref", "action_ref", "resource_ref"):
            _reference(item[field], field)
        if type(item["outcome"]) is not str or item["outcome"] not in _OUTCOMES:
            raise CrossSurfaceAuthorizationError("Decision outcome is invalid")
        if item["decision_id"] in identifiers:
            raise CrossSurfaceAuthorizationError("Decision identifier is repeated")
        identifiers.add(item["decision_id"])
        key = (
            item["surface_id"], item["principal_ref"],
            item["action_ref"], item["resource_ref"],
        )
        if key in surface_keys:
            raise CrossSurfaceAuthorizationError("One surface has duplicate decision keys")
        surface_keys.add(key)
        surfaces.add(item["surface_id"])
    if not 2 <= len(surfaces) <= MAX_SURFACES:
        raise CrossSurfaceAuthorizationError("Two to eight distinct surfaces are required")
    return model


def _derive(value: Any) -> dict:
    model = _model(value)
    grouped: dict[tuple[str, str, str], list[dict]] = {}
    for item in model["decisions"]:
        key = (item["principal_ref"], item["action_ref"], item["resource_ref"])
        grouped.setdefault(key, []).append(item)
    comparisons = []
    for (principal, action, resource), items in sorted(grouped.items()):
        if len(items) < 2:
            continue
        rows = [
            {
                "surface_id": item["surface_id"],
                "decision_id": item["decision_id"],
                "outcome": item["outcome"],
            }
            for item in sorted(items, key=lambda row: row["surface_id"])
        ]
        outcomes = {row["outcome"] for row in rows}
        if not model["identity_mapping_complete"]:
            disposition = "unresolved_identity_mapping"
        elif "unknown" in outcomes:
            disposition = "unresolved_decision"
        elif len(outcomes) > 1:
            disposition = "candidate_declared_decision_difference"
        else:
            disposition = "declared_decision_alignment"
        comparisons.append(
            {
                "principal_ref": principal,
                "action_ref": action,
                "resource_ref": resource,
                "surface_decisions": rows,
                "disposition": disposition,
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": model,
        "surface_count": len({item["surface_id"] for item in model["decisions"]}),
        "decision_count": len(model["decisions"]),
        "exact_shared_key_count": len(comparisons),
        "comparisons": comparisons,
        "flags": {
            "identity_mapping_verified": False,
            "target_authorization_verified": False,
            "authorization_bypass_verified": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Only exact caller-supplied opaque references are compared.",
            "Mapping completeness is an unverified operator assertion.",
            "Differing declared outcomes do not prove a bypass or policy defect.",
            "No file, credential, network, process, or target is accessed.",
        ],
    }
    digest = "sha256:" + hashlib.sha256(
        (DOMAIN + "\n" + _canonical(body)).encode("ascii")
    ).hexdigest()
    return json.loads(_canonical({
        **body, "analysis_id": "CSA-" + digest[7:39].upper(), "analysis_sha256": digest
    }))


@dataclass(frozen=True, slots=True, init=False)
class CrossSurfaceAuthorization:
    """Immutable report replayed from supplied authorization decisions."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise CrossSurfaceAuthorizationError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        if _canonical(document) != _canonical(expected):
            raise CrossSurfaceAuthorizationError("Report differs from embedded source replay")
        object.__setattr__(self, "_document_json", _canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_cross_surface_authorization(model: Any) -> CrossSurfaceAuthorization:
    """Compare exact supplied decision keys without target interaction."""
    return CrossSurfaceAuthorization(_derive(model))


def verify_supplied_cross_surface_authorization(
    report: Any, *, model: Any
) -> CrossSurfaceAuthorization:
    if type(report) is not CrossSurfaceAuthorization:
        raise CrossSurfaceAuthorizationError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != _canonical(expected):
        raise CrossSurfaceAuthorizationError("Report differs from supplied source replay")
    return CrossSurfaceAuthorization(expected)
