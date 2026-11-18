"""Inert comparison of supplied Electron renderer bridge-origin declarations."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "desktop_supplied_electron_bridge_origin_projection"
PROFILE_ID = "AOE-GB-D08-S18"
CAPABILITY_ID = "army.gb.d08.s18"
VECTOR_ID = "AV-GB-D08-S18-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D08-S18"
WAVE_ID = "IW2-004"
COMMANDER_ID = "AOE-GB-D08-CMD"
GROUP_OWNER_ID = "AOE-HQ-04"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:afdd18ec0a150bb9fcc9af3c066558e9b94947281e21456c3b86e9cd5274a448"
DOMAIN = "sunderkey.offline-electron-bridge-origin.v1"
MODEL_DOMAIN = "sunderkey.offline-electron-bridge-origin-model.v1"
SEMANTICS_PROFILE = "declared-remote-renderer-bridge-origin-projection.v1"
MAX_DOCUMENT_BYTES = 65_536
MAX_NATIVE_NODES = 8_192
MAX_NATIVE_DEPTH = 12
MAX_STRING_BYTES = 256
MAX_SURFACES = 32
MAX_ENTRIES = 128
MAX_ORIGINS = 32
MAX_WORK = 1_000_000
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_ORIGIN = re.compile(r"(https?)://([a-z0-9.-]+)(?::([0-9]{1,5}))?\Z")
_ENTRY_KINDS = frozenset(("remote_navigation", "packaged_content", "unknown"))
_TARGETS = frozenset(("renderer", "external_browser", "unknown"))
_FLAGS = dict.fromkeys(
    (
        "source_authenticated",
        "navigation_invoked",
        "renderer_loaded",
        "bridge_executed",
        "origin_policy_verified",
        "bridge_effect_verified",
        "exploit_verified",
        "positive_use_approved",
        "qualification_claimed",
    ),
    False,
)
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "browser",
        "credential",
        "execution",
        "network",
        "process",
        "provider",
        "qualification",
        "target",
    ),
    "none",
)
_BOUNDS = {
    "document_bytes": MAX_DOCUMENT_BYTES,
    "native_nodes": MAX_NATIVE_NODES,
    "scalar_inclusive_depth": MAX_NATIVE_DEPTH,
    "string_bytes": MAX_STRING_BYTES,
    "surfaces": MAX_SURFACES,
    "entries": MAX_ENTRIES,
    "origins_per_surface": MAX_ORIGINS,
    "work_steps": MAX_WORK,
}
_LIMITATIONS = (
    "Entry reachability, target, origin, bridge exposure and trust policy are caller declarations.",
    "Only canonical ASCII HTTP(S) tuple origins and exact allowlists are modeled.",
    "Wildcard, dynamic, version-dependent or incomplete bridge policy is unknown.",
    "A candidate is a contradiction within supplied policy, not observed bridge access.",
    "Renderer navigation, redirects, preload lifecycle and bridge method behavior are not modeled.",
    "No Electron runtime, URL open, target, network, process or credential is used.",
    "No authority, qualification, positive use or live finding is established.",
)


class ElectronBridgeOriginAnalysisError(ValueError):
    """A supplied model or report is outside the closed bounded contract."""


@dataclass(slots=True)
class _Work:
    count: int = 0

    def charge(self, amount: int) -> None:
        if self.count + amount > MAX_WORK:
            raise ElectronBridgeOriginAnalysisError("Software work bound exhausted")
        self.count += amount


def _measure(value: Any, work: _Work | None = None) -> None:
    size = nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal size, nodes
        nodes += 1
        if depth > MAX_NATIVE_DEPTH or nodes > MAX_NATIVE_NODES:
            raise ElectronBridgeOriginAnalysisError("Native node/depth bound exhausted")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_STRING_BYTES or not all(32 <= ord(char) <= 126 for char in item):
                raise ElectronBridgeOriginAnalysisError("Bounded printable ASCII string required")
            size += len(json.dumps(item, ensure_ascii=True))
        elif kind is bool:
            size += 4 if item else 5
        elif item is None:
            size += 4
        elif kind is int:
            if not -(2**63) <= item < 2**63:
                raise ElectronBridgeOriginAnalysisError("Signed 64-bit integer required")
            size += len(str(item))
        elif kind in (dict, list):
            if id(item) in active:
                raise ElectronBridgeOriginAnalysisError("Cyclic native document")
            active.add(id(item))
            size += 2 + len(item) * 2
            try:
                if kind is dict:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise ElectronBridgeOriginAnalysisError(
                                "Exact native string keys required"
                            )
                        visit(key, depth + 1)
                        visit(child, depth + 1)
                else:
                    for child in item:
                        visit(child, depth + 1)
            finally:
                active.remove(id(item))
        else:
            raise ElectronBridgeOriginAnalysisError("Exact native JSON primitives required")
        if size > MAX_DOCUMENT_BYTES:
            raise ElectronBridgeOriginAnalysisError("Document byte bound exhausted")

    visit(value, 1)
    if work is not None:
        work.charge(size + nodes)


def _serialize(value: Any, work: _Work | None = None) -> str:
    _measure(value, work)
    text = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    if len(text) > MAX_DOCUMENT_BYTES:
        raise ElectronBridgeOriginAnalysisError("Serialized byte bound exhausted")
    return text


def _decode(content: Any) -> Any:
    if (
        type(content) is not str
        or not content
        or len(content) > MAX_DOCUMENT_BYTES
        or not content.isascii()
    ):
        raise ElectronBridgeOriginAnalysisError("Bounded ASCII JSON required")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result: dict = {}
        for key, value in items:
            if key in result:
                raise ElectronBridgeOriginAnalysisError("Duplicate JSON member")
            result[key] = value
        return result

    def integer(token: str) -> int:
        if len(token) > 20 or re.fullmatch(r"-?(?:0|[1-9][0-9]{0,18})", token) is None:
            raise ElectronBridgeOriginAnalysisError("Raw integer bound failed")
        value = int(token)
        if not -(2**63) <= value < 2**63:
            raise ElectronBridgeOriginAnalysisError("Signed 64-bit integer required")
        return value

    def unsupported(_: str) -> None:
        raise ElectronBridgeOriginAnalysisError("Fractional or nonfinite number unsupported")

    try:
        value = json.loads(
            content,
            object_pairs_hook=pairs,
            parse_int=integer,
            parse_float=unsupported,
            parse_constant=unsupported,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, ElectronBridgeOriginAnalysisError):
            raise
        raise ElectronBridgeOriginAnalysisError("Malformed supplied JSON") from exc
    _measure(value)
    return value


def _capture(value: Any, work: _Work | None = None) -> tuple[Any, str]:
    text = _serialize(value, work)
    return _decode(text), text


def _identity(value: Any) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None or value == "unknown":
        raise ElectronBridgeOriginAnalysisError("Bounded concrete identity required")
    return value


def _origin(value: Any) -> str:
    if type(value) is not str:
        raise ElectronBridgeOriginAnalysisError("Tuple origin required")
    match = _ORIGIN.fullmatch(value)
    if match is None:
        raise ElectronBridgeOriginAnalysisError("Canonical ASCII HTTP(S) tuple origin required")
    scheme, host, raw_port = match.groups()
    if len(host) > 253 or any(
        not label or len(label) > 63 or label[0] == "-" or label[-1] == "-"
        for label in host.split(".")
    ):
        raise ElectronBridgeOriginAnalysisError("Canonical DNS host required")
    if raw_port is not None:
        port = int(raw_port)
        if not 1 <= port <= 65535 or str(port) != raw_port:
            raise ElectronBridgeOriginAnalysisError("Canonical port required")
        if (scheme, port) in (("https", 443), ("http", 80)):
            raise ElectronBridgeOriginAnalysisError("Default port must be omitted")
    return value


def _origin_list(value: Any) -> None:
    if type(value) is not list or len(value) > MAX_ORIGINS:
        raise ElectronBridgeOriginAnalysisError("Bounded exact origin list required")
    for origin in value:
        _origin(origin)
    if value != sorted(set(value)):
        raise ElectronBridgeOriginAnalysisError("Sorted unique origins required")


def _validate_model(model: Any, work: _Work) -> tuple[dict, str]:
    owned, source_text = _capture(model, work)
    if type(owned) is not dict or owned.keys() != {
        "schema_version",
        "surfaces_complete",
        "surfaces",
        "entries",
    }:
        raise ElectronBridgeOriginAnalysisError("Exact closed model fields required")
    if type(owned["schema_version"]) is not int or owned["schema_version"] != 1:
        raise ElectronBridgeOriginAnalysisError("Exact schema version 1 required")
    if type(owned["surfaces_complete"]) is not bool:
        raise ElectronBridgeOriginAnalysisError("Exact surface completeness boolean required")
    surfaces, entries = owned["surfaces"], owned["entries"]
    if type(surfaces) is not list or not 1 <= len(surfaces) <= MAX_SURFACES:
        raise ElectronBridgeOriginAnalysisError("Bounded nonempty surfaces required")
    if type(entries) is not list or not 1 <= len(entries) <= MAX_ENTRIES:
        raise ElectronBridgeOriginAnalysisError("Bounded nonempty entries required")
    surface_ids: set[str] = set()
    for surface in surfaces:
        work.charge(16)
        if type(surface) is not dict or surface.keys() != {
            "surface_id",
            "trusted_origins",
            "trusted_origins_complete",
            "bridge_origin_rule",
            "allowed_origins",
            "privileged_bridge_exposed",
            "policy_complete",
            "trusted_only_bridge_required",
        }:
            raise ElectronBridgeOriginAnalysisError("Exact closed surface fields required")
        surface_id = _identity(surface["surface_id"])
        if surface_id in surface_ids:
            raise ElectronBridgeOriginAnalysisError("Duplicate surface identity")
        surface_ids.add(surface_id)
        _origin_list(surface["trusted_origins"])
        _origin_list(surface["allowed_origins"])
        if type(surface["bridge_origin_rule"]) is not str or surface["bridge_origin_rule"] not in (
            "exact_allowlist",
            "none",
            "wildcard",
            "dynamic",
            "unknown",
        ):
            raise ElectronBridgeOriginAnalysisError("Supported bridge origin rule required")
        if surface["bridge_origin_rule"] != "exact_allowlist" and surface["allowed_origins"]:
            raise ElectronBridgeOriginAnalysisError("Only exact rule may list allowed origins")
        for field in (
            "trusted_origins_complete",
            "privileged_bridge_exposed",
            "policy_complete",
            "trusted_only_bridge_required",
        ):
            if type(surface[field]) is not bool:
                raise ElectronBridgeOriginAnalysisError("Exact surface booleans required")
    entry_ids: set[str] = set()
    surfaces_by_id = {surface["surface_id"]: surface for surface in surfaces}
    for entry in entries:
        work.charge(16)
        if type(entry) is not dict or entry.keys() != {
            "entry_id",
            "surface_id",
            "entry_kind",
            "target_surface",
            "entry_origin",
            "reachability",
            "reachability_complete",
            "context_complete",
            "bridge_exposed",
            "bridge_exposure_complete",
        }:
            raise ElectronBridgeOriginAnalysisError("Exact closed entry fields required")
        entry_id = _identity(entry["entry_id"])
        if entry_id in entry_ids:
            raise ElectronBridgeOriginAnalysisError("Duplicate entry identity")
        entry_ids.add(entry_id)
        if _identity(entry["surface_id"]) not in surface_ids:
            raise ElectronBridgeOriginAnalysisError("Unknown surface identity")
        if type(entry["entry_kind"]) is not str or entry["entry_kind"] not in _ENTRY_KINDS:
            raise ElectronBridgeOriginAnalysisError("Supported entry kind required")
        if type(entry["target_surface"]) is not str or entry["target_surface"] not in _TARGETS:
            raise ElectronBridgeOriginAnalysisError("Supported target surface required")
        if entry["entry_origin"] != "unknown":
            _origin(entry["entry_origin"])
        if type(entry["reachability"]) is not str or entry["reachability"] not in (
            "reachable",
            "unreachable",
            "unknown",
        ):
            raise ElectronBridgeOriginAnalysisError("Supported reachability required")
        for field in (
            "reachability_complete",
            "context_complete",
            "bridge_exposed",
            "bridge_exposure_complete",
        ):
            if type(entry[field]) is not bool:
                raise ElectronBridgeOriginAnalysisError("Exact entry booleans required")
        if (
            entry["bridge_exposure_complete"]
            and entry["bridge_exposed"]
            and not surfaces_by_id[entry["surface_id"]]["privileged_bridge_exposed"]
        ):
            raise ElectronBridgeOriginAnalysisError("Entry bridge contradicts surface declaration")
    if [row["surface_id"] for row in surfaces] != sorted(surface_ids) or [
        row["entry_id"] for row in entries
    ] != sorted(entry_ids):
        raise ElectronBridgeOriginAnalysisError("Sorted surfaces and entries required")
    return owned, source_text


def _observe(entry: dict, surface: dict, surfaces_complete: bool) -> dict:
    reasons: list[str] = []
    if not surfaces_complete:
        reasons.append("surfaces_incomplete")
    if not surface["trusted_origins_complete"]:
        reasons.append("trusted_origins_incomplete")
    if not surface["policy_complete"]:
        reasons.append("bridge_policy_incomplete")
    if surface["bridge_origin_rule"] in ("wildcard", "dynamic", "unknown"):
        reasons.append("bridge_rule_not_exactly_modeled")
    if not entry["reachability_complete"]:
        reasons.append("reachability_incomplete")
    if not entry["context_complete"]:
        reasons.append("entry_context_incomplete")
    if not entry["bridge_exposure_complete"]:
        reasons.append("entry_bridge_exposure_incomplete")
    if entry["reachability"] == "unknown":
        reasons.append("reachability_unknown")
    if entry["entry_kind"] == "unknown":
        reasons.append("entry_kind_unknown")
    if entry["target_surface"] == "unknown":
        reasons.append("target_surface_unknown")
    if entry["entry_origin"] == "unknown":
        reasons.append("entry_origin_unknown")
    origin = entry["entry_origin"]
    if reasons:
        outcome = "unknown"
    elif entry["reachability"] == "unreachable":
        outcome = "declared_unreachable"
    elif entry["target_surface"] != "renderer":
        outcome = "outside_declared_renderer_surface"
    elif entry["entry_kind"] != "remote_navigation":
        outcome = "not_remote_navigation_under_supplied_model"
    elif not surface["privileged_bridge_exposed"] or not entry["bridge_exposed"]:
        outcome = "no_declared_privileged_bridge"
    elif (
        surface["bridge_origin_rule"] == "exact_allowlist"
        and origin not in surface["allowed_origins"]
    ):
        outcome = "declared_bridge_origin_denied"
    elif origin in surface["trusted_origins"] or not surface["trusted_only_bridge_required"]:
        outcome = "consistent_with_declared_trust_policy"
    else:
        outcome = "candidate_supplied_bridge_trust_conflict"
    return {
        "entry_id": entry["entry_id"],
        "surface_id": entry["surface_id"],
        "entry_kind": entry["entry_kind"],
        "target_surface": entry["target_surface"],
        "entry_origin": origin,
        "outcome": outcome,
        "uncertainty": reasons,
    }


def _address(domain: str, text: str) -> str:
    return "sha256:" + hashlib.sha256((domain + "\n" + text).encode("ascii")).hexdigest()


def _derive(model: Any) -> dict:
    work = _Work()
    owned, source_text = _validate_model(model, work)
    surfaces = {item["surface_id"]: item for item in owned["surfaces"]}
    observations = [
        _observe(entry, surfaces[entry["surface_id"]], owned["surfaces_complete"])
        for entry in owned["entries"]
    ]
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "wave_id": WAVE_ID,
        "commander_id": COMMANDER_ID,
        "group_owner_id": GROUP_OWNER_ID,
        "independent_validator_id": INDEPENDENT_VALIDATOR_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "semantics_profile": SEMANTICS_PROFILE,
        "source_model": owned,
        "source_model_sha256": _address(MODEL_DOMAIN, source_text),
        "entry_count": len(observations),
        "candidate_count": sum(row["outcome"].startswith("candidate_") for row in observations),
        "unknown_count": sum(row["outcome"] == "unknown" for row in observations),
        "entry_observations": observations,
        "bounds": dict(_BOUNDS),
        "flags": dict(_FLAGS),
        "effects": dict(_EFFECTS),
        "limitations": list(_LIMITATIONS),
    }
    body_text = _serialize(body, work)
    work.charge(len(DOMAIN) + len(MODEL_DOMAIN) + len(source_text) + len(body_text))
    digest = _address(DOMAIN, body_text)
    body["analysis_id"] = "EBO-" + digest[7:39].upper()
    body["analysis_sha256"] = digest
    _serialize(body, work)
    return body


def _replay(document: Any) -> dict:
    owned, text = _capture(document)
    if type(owned) is not dict or "source_model" not in owned:
        raise ElectronBridgeOriginAnalysisError("Source-bearing report required")
    expected = _derive(owned["source_model"])
    if text != _serialize(expected):
        raise ElectronBridgeOriginAnalysisError("Report does not replay embedded source")
    return expected


@dataclass(frozen=True, slots=True, init=False)
class ElectronBridgeOriginAnalysis:
    """Detached supplied-data projection, never live Electron evidence."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        object.__setattr__(self, "_document_json", _serialize(_replay(document)))

    @classmethod
    def from_dict(cls, document: Any) -> ElectronBridgeOriginAnalysis:
        return cls(document)

    @classmethod
    def from_json(cls, content: Any) -> ElectronBridgeOriginAnalysis:
        return cls(_decode(content))

    def to_dict(self) -> dict:
        return _replay(_decode(getattr(self, "_document_json", None)))

    def to_json(self) -> str:
        return _serialize(self.to_dict())

    @property
    def analysis_id(self) -> str:
        return self.to_dict()["analysis_id"]

    @property
    def analysis_sha256(self) -> str:
        return self.to_dict()["analysis_sha256"]


def analyze_supplied_electron_bridge_origin(model: Any) -> ElectronBridgeOriginAnalysis:
    """Project only supplied renderer and bridge-origin declarations."""
    return ElectronBridgeOriginAnalysis(_derive(model))


def analyze_supplied_electron_bridge_origin_bytes(
    *, model_bytes: Any
) -> ElectronBridgeOriginAnalysis:
    """Accept bounded ASCII JSON bytes without reading a resource."""
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_DOCUMENT_BYTES:
        raise ElectronBridgeOriginAnalysisError("Bounded exact native model bytes required")
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ElectronBridgeOriginAnalysisError("ASCII model bytes required") from exc
    return analyze_supplied_electron_bridge_origin(_decode(text))


def verify_supplied_electron_bridge_origin_analysis(
    report: Any, *, model: Any
) -> ElectronBridgeOriginAnalysis:
    """Replay a report against separately supplied original premises."""
    if type(report) is not ElectronBridgeOriginAnalysis:
        raise ElectronBridgeOriginAnalysisError("Exact native report family required")
    expected = _derive(model)
    if _serialize(report.to_dict()) != _serialize(expected):
        raise ElectronBridgeOriginAnalysisError("Report differs from separately supplied originals")
    return ElectronBridgeOriginAnalysis(expected)


def component_fixture() -> dict:
    """Fresh synthetic candidate, trusted, denied and ambiguous entries."""
    return {
        "schema_version": 1,
        "surfaces_complete": True,
        "surfaces": [
            {
                "surface_id": "checkout",
                "trusted_origins": ["https://app.example"],
                "trusted_origins_complete": True,
                "bridge_origin_rule": "exact_allowlist",
                "allowed_origins": ["https://app.example", "https://untrusted.example"],
                "privileged_bridge_exposed": True,
                "policy_complete": True,
                "trusted_only_bridge_required": True,
            }
        ],
        "entries": [
            {
                "entry_id": "candidate",
                "surface_id": "checkout",
                "entry_kind": "remote_navigation",
                "target_surface": "renderer",
                "entry_origin": "https://untrusted.example",
                "reachability": "reachable",
                "reachability_complete": True,
                "context_complete": True,
                "bridge_exposed": True,
                "bridge_exposure_complete": True,
            },
            {
                "entry_id": "denied",
                "surface_id": "checkout",
                "entry_kind": "remote_navigation",
                "target_surface": "renderer",
                "entry_origin": "https://denied.example",
                "reachability": "reachable",
                "reachability_complete": True,
                "context_complete": True,
                "bridge_exposed": True,
                "bridge_exposure_complete": True,
            },
            {
                "entry_id": "external-browser",
                "surface_id": "checkout",
                "entry_kind": "remote_navigation",
                "target_surface": "external_browser",
                "entry_origin": "https://untrusted.example",
                "reachability": "reachable",
                "reachability_complete": True,
                "context_complete": True,
                "bridge_exposed": False,
                "bridge_exposure_complete": True,
            },
            {
                "entry_id": "trusted",
                "surface_id": "checkout",
                "entry_kind": "remote_navigation",
                "target_surface": "renderer",
                "entry_origin": "https://app.example",
                "reachability": "reachable",
                "reachability_complete": True,
                "context_complete": True,
                "bridge_exposed": True,
                "bridge_exposure_complete": True,
            },
            {
                "entry_id": "unknown-origin",
                "surface_id": "checkout",
                "entry_kind": "remote_navigation",
                "target_surface": "renderer",
                "entry_origin": "unknown",
                "reachability": "reachable",
                "reachability_complete": True,
                "context_complete": True,
                "bridge_exposed": True,
                "bridge_exposure_complete": True,
            },
        ],
    }


__all__ = [
    "ElectronBridgeOriginAnalysisError",
    "ElectronBridgeOriginAnalysis",
    "analyze_supplied_electron_bridge_origin",
    "analyze_supplied_electron_bridge_origin_bytes",
    "verify_supplied_electron_bridge_origin_analysis",
    "component_fixture",
]
