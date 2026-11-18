"""Offline projection of supplied service-worker scope and control facts."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

PROFILE_ID = "AOE-GB-D05-S16"
CAPABILITY_ID = "army.gb.d05.s16"
VECTOR_ID = "AV-GB-D05-S16-01"
WAVE_ID = "IW2-001"
DOMAIN = "sunderkey.offline-service-worker-scope.v1"
SCHEMA_VERSION = "v1"
MAX_SOURCE_BYTES = 262_144
MAX_REPORT_BYTES = 524_288
MAX_NODES = 40_000
MAX_DEPTH = 16
MAX_TEXT_BYTES = 512
MAX_REGISTRATIONS = 512
MAX_OBSERVATIONS = 2_048
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_PATH = re.compile(r"/(?:[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*)?/?\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_EFFECTS = {
    key: "none"
    for key in (
        "authority",
        "target",
        "execution",
        "routing",
        "qualification",
        "deployment",
        "network",
        "process",
        "credentials",
        "provider_requests",
    )
}
_FLAGS = {
    "offline_only": True,
    "facts_authenticated": False,
    "registration_state_authenticated": False,
    "controller_state_authenticated": False,
    "browser_semantics_verified": False,
    "service_worker_executed": False,
    "finding_claimed": False,
    "positive_use_approved": False,
    "qualification_claimed": False,
}
_LIMITATIONS = [
    "Origins, registrations, activation states and controller outcomes are supplied assertions.",
    "Scope matching is an inert exact ASCII path-prefix projection, not browser URL processing.",
    "Script-path scope allowance, headers, installation and lifecycle are not evaluated.",
    "A controller comparison requires an asserted applicable registration snapshot.",
    "A more specific unknown-state registration can make the expected controller unknown.",
    "A supplied contradiction is a candidate, not a verified service-worker flaw.",
    "No browser, extension, filesystem, network, process or credential action occurs.",
]
_ASSESSMENTS = {"candidate_control_contradiction", "declared_consistent", "unknown"}
_BASES = {
    "incomplete_facts",
    "incomplete_registration_set",
    "registration_snapshot_not_applicable",
    "unknown_registration_state",
    "most_specific_active_scope",
    "no_matching_active_scope",
}


class ServiceWorkerScopeError(ValueError):
    """Closed input, bounded resource or exact-source replay failed."""


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields or any(type(k) is not str for k in value):
        raise ServiceWorkerScopeError(f"{label} fields are invalid")
    return value


def _id(value: Any, label: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise ServiceWorkerScopeError(f"{label} must be bounded native ASCII text")
    return value


def _optional_id(value: Any, label: str) -> str | None:
    return None if value is None else _id(value, label)


def _path(value: Any, label: str) -> str:
    if type(value) is not str or _PATH.fullmatch(value) is None or len(value) > 256:
        raise ServiceWorkerScopeError(f"{label} must be an inert exact ASCII path")
    if "//" in value or any(segment in (".", "..") for segment in value.split("/")):
        raise ServiceWorkerScopeError(f"{label} has an ambiguous segment")
    return value


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ServiceWorkerScopeError("duplicate JSON key")
        result[key] = value
    return result


def _json_integer(token: str) -> int:
    if len(token) > 20 or len(token.lstrip("-")) > 19:
        raise ServiceWorkerScopeError("JSON integer exceeds signed64 bound")
    value = int(token)
    if not -(1 << 63) <= value < (1 << 63):
        raise ServiceWorkerScopeError("JSON integer exceeds signed64 bound")
    return value


def _unsupported_number(_token: str) -> None:
    raise ServiceWorkerScopeError("floating and nonfinite numbers are unsupported")


def _validate_tree(value: Any, *, maximum: int) -> None:
    stack = [(value, 1)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise ServiceWorkerScopeError("JSON node or depth bound exceeded")
        kind = type(item)
        if kind is dict:
            if nodes + len(stack) + 2 * len(item) > MAX_NODES:
                raise ServiceWorkerScopeError("JSON node bound exceeded")
            for key, child in item.items():
                if type(key) is not str:
                    raise ServiceWorkerScopeError("JSON keys must be native text")
                stack.append((child, depth + 1))
                stack.append((key, depth + 1))
        elif kind is list:
            if nodes + len(stack) + len(item) > MAX_NODES:
                raise ServiceWorkerScopeError("JSON node bound exceeded")
            stack.extend((child, depth + 1) for child in item)
        elif kind is str:
            if len(item.encode("utf-8", errors="surrogatepass")) > MAX_TEXT_BYTES or any(
                0xD800 <= ord(char) <= 0xDFFF for char in item
            ):
                raise ServiceWorkerScopeError("JSON string is unsupported or too long")
        elif kind is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise ServiceWorkerScopeError("JSON integer exceeds signed64 bound")
        elif kind not in (bool, type(None)):
            raise ServiceWorkerScopeError("unsupported JSON value family")
    if len(_canonical(value).encode("ascii")) > maximum:
        raise ServiceWorkerScopeError("canonical JSON byte bound exceeded")


def _decode(content: bytes, *, maximum: int) -> Any:
    if type(content) is not bytes or not content or len(content) > maximum:
        raise ServiceWorkerScopeError("source must be bounded nonempty native bytes")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ServiceWorkerScopeError("source must be UTF-8") from exc
    nesting = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            nesting += 1
            if nesting > MAX_DEPTH:
                raise ServiceWorkerScopeError("pre-decoder depth bound exceeded")
        elif char in "]}":
            nesting -= 1
            if nesting < 0:
                raise ServiceWorkerScopeError("malformed JSON nesting")
    if nesting or quoted:
        raise ServiceWorkerScopeError("malformed JSON nesting")
    try:
        result = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_json_integer,
            parse_float=_unsupported_number,
            parse_constant=_unsupported_number,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, ServiceWorkerScopeError):
            raise
        raise ServiceWorkerScopeError("malformed JSON source") from exc
    _validate_tree(result, maximum=maximum)
    return result


def _model(document: Any) -> tuple[bool, bool, dict, list]:
    model = _exact(
        document,
        {
            "schema_version",
            "facts_complete",
            "registration_set_complete",
            "registrations",
            "observations",
        },
        "model",
    )
    if type(model["schema_version"]) is not str or model["schema_version"] != SCHEMA_VERSION:
        raise ServiceWorkerScopeError("unsupported model version")
    if (
        type(model["facts_complete"]) is not bool
        or type(model["registration_set_complete"]) is not bool
    ):
        raise ServiceWorkerScopeError("completeness must be native Booleans")
    for name, maximum in (("registrations", MAX_REGISTRATIONS), ("observations", MAX_OBSERVATIONS)):
        values = model[name]
        if type(values) is not list or len(values) > maximum:
            raise ServiceWorkerScopeError(f"{name} must be a bounded native array")
    registrations = {}
    scopes = set()
    for raw in model["registrations"]:
        entry = _exact(
            raw,
            {"registration_id", "origin_id", "script_path", "scope_path", "state"},
            "registration",
        )
        registration_id = _id(entry["registration_id"], "registration ID")
        origin_id = _id(entry["origin_id"], "origin ID")
        script_path = _path(entry["script_path"], "script path")
        scope_path = _path(entry["scope_path"], "scope path")
        state = entry["state"]
        if type(state) is not str or state not in ("active", "inactive", "unknown"):
            raise ServiceWorkerScopeError("registration state is unsupported")
        if registration_id in registrations or (origin_id, scope_path) in scopes:
            raise ServiceWorkerScopeError("duplicate registration ID or origin/scope")
        scopes.add((origin_id, scope_path))
        registrations[registration_id] = {
            "origin_id": origin_id,
            "script_path": script_path,
            "scope_path": scope_path,
            "state": state,
        }
    observations = []
    seen = set()
    for raw in model["observations"]:
        entry = _exact(
            raw,
            {
                "observation_id",
                "page_origin_id",
                "page_path",
                "control_outcome",
                "observed_controller_id",
                "registration_snapshot_applies",
            },
            "observation",
        )
        observation_id = _id(entry["observation_id"], "observation ID")
        if observation_id in seen:
            raise ServiceWorkerScopeError("duplicate observation ID")
        seen.add(observation_id)
        outcome = entry["control_outcome"]
        if type(outcome) is not str or outcome not in ("controlled", "uncontrolled", "unknown"):
            raise ServiceWorkerScopeError("control outcome is unsupported")
        controller = _optional_id(entry["observed_controller_id"], "observed controller ID")
        if type(entry["registration_snapshot_applies"]) is not bool:
            raise ServiceWorkerScopeError("registration snapshot applicability must be Boolean")
        if (outcome == "controlled") != (controller is not None):
            raise ServiceWorkerScopeError("observed controller ID must match controlled outcome")
        observations.append(
            {
                "observation_id": observation_id,
                "page_origin_id": _id(entry["page_origin_id"], "page origin ID"),
                "page_path": _path(entry["page_path"], "page path"),
                "control_outcome": outcome,
                "observed_controller_id": controller,
                "registration_snapshot_applies": entry["registration_snapshot_applies"],
            }
        )
    return model["facts_complete"], model["registration_set_complete"], registrations, observations


def _project(
    facts_complete: bool, registration_set_complete: bool, registrations: dict, observations: list
) -> list:
    projections = []
    for observation in sorted(observations, key=lambda item: item["observation_id"]):
        matching = sorted(
            (
                (registration_id, registration)
                for registration_id, registration in registrations.items()
                if registration["origin_id"] == observation["page_origin_id"]
                and observation["page_path"].startswith(registration["scope_path"])
            ),
            key=lambda item: item[0],
        )
        active = [
            (identity, registration)
            for identity, registration in matching
            if registration["state"] == "active"
        ]
        unknown = [
            (identity, registration)
            for identity, registration in matching
            if registration["state"] == "unknown"
        ]
        strongest = max(active, key=lambda item: len(item[1]["scope_path"])) if active else None
        strongest_length = len(strongest[1]["scope_path"]) if strongest is not None else -1
        competing_unknown = any(len(item[1]["scope_path"]) >= strongest_length for item in unknown)
        expected_controller_id = None
        expected_control = "unknown"
        if not facts_complete:
            basis = "incomplete_facts"
        elif not registration_set_complete:
            basis = "incomplete_registration_set"
        elif not observation["registration_snapshot_applies"]:
            basis = "registration_snapshot_not_applicable"
        elif competing_unknown:
            basis = "unknown_registration_state"
        elif strongest is not None:
            expected_control = "controlled"
            expected_controller_id = strongest[0]
            basis = "most_specific_active_scope"
        else:
            expected_control = "uncontrolled"
            basis = "no_matching_active_scope"
        observed_control = observation["control_outcome"]
        observed_controller = observation["observed_controller_id"]
        if expected_control == "unknown" or observed_control == "unknown":
            assessment = "unknown"
        elif expected_control == observed_control and expected_controller_id == observed_controller:
            assessment = "declared_consistent"
        else:
            assessment = "candidate_control_contradiction"
        projections.append(
            {
                **observation,
                "matching_registration_ids": [identity for identity, _ in matching],
                "expected_control": expected_control,
                "expected_controller_id": expected_controller_id,
                "basis": basis,
                "assessment": assessment,
            }
        )
    return projections


@dataclass(frozen=True, slots=True)
class ServiceWorkerScopeReport:
    """Canonical report whose derivation requires original-source replay."""

    _json: str

    def __post_init__(self) -> None:
        if type(self) is not ServiceWorkerScopeReport or self._json != _checked_report_json(
            self._json
        ):
            raise ServiceWorkerScopeError("canonical exact report is required")

    def to_json(self) -> str:
        if type(self) is not ServiceWorkerScopeReport or self._json != _checked_report_json(
            self._json
        ):
            raise ServiceWorkerScopeError("canonical exact report is required")
        return self._json

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.to_json())

    @classmethod
    def from_json(cls, content: str) -> ServiceWorkerScopeReport:
        if cls is not ServiceWorkerScopeReport:
            raise ServiceWorkerScopeError("report must be the exact report family")
        return cls(_checked_report_json(content))


def _checked_report_json(content: Any) -> str:
    if type(content) is not str:
        raise ServiceWorkerScopeError("report must be native JSON text")
    try:
        raw = content.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ServiceWorkerScopeError("report must be UTF-8 JSON text") from exc
    document = _decode(raw, maximum=MAX_REPORT_BYTES)
    _validate_report(document)
    return _canonical(document)


def _validate_report(document: Any) -> None:
    item = _exact(
        document,
        {
            "schema_version",
            "profile_id",
            "capability_id",
            "vector_id",
            "wave_id",
            "domain",
            "source",
            "facts_complete",
            "registration_set_complete",
            "projections",
            "summary",
            "effects",
            "limitations",
            "report_id",
            "report_sha256",
            *_FLAGS,
        },
        "report",
    )
    for key, expected in {
        "schema_version": SCHEMA_VERSION,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "wave_id": WAVE_ID,
        "domain": DOMAIN,
        "effects": _EFFECTS,
        "limitations": _LIMITATIONS,
        **_FLAGS,
    }.items():
        if type(item[key]) is not type(expected) or item[key] != expected:
            raise ServiceWorkerScopeError(f"report {key} is invalid")
    source = _exact(item["source"], {"source_id", "sha256", "byte_count"}, "source")
    _id(source["source_id"], "source ID")
    if type(source["sha256"]) is not str or _DIGEST.fullmatch(source["sha256"]) is None:
        raise ServiceWorkerScopeError("source digest is invalid")
    if type(source["byte_count"]) is not int or not 1 <= source["byte_count"] <= MAX_SOURCE_BYTES:
        raise ServiceWorkerScopeError("source byte count is invalid")
    for key in ("facts_complete", "registration_set_complete"):
        if type(item[key]) is not bool:
            raise ServiceWorkerScopeError("report completeness is invalid")
    projections = item["projections"]
    if type(projections) is not list or len(projections) > MAX_OBSERVATIONS:
        raise ServiceWorkerScopeError("report projections are invalid")
    ids = []
    counts = {assessment: 0 for assessment in sorted(_ASSESSMENTS)}
    for raw in projections:
        projection = _exact(
            raw,
            {
                "observation_id",
                "page_origin_id",
                "page_path",
                "control_outcome",
                "observed_controller_id",
                "registration_snapshot_applies",
                "matching_registration_ids",
                "expected_control",
                "expected_controller_id",
                "basis",
                "assessment",
            },
            "projection",
        )
        ids.append(_id(projection["observation_id"], "observation ID"))
        _id(projection["page_origin_id"], "page origin ID")
        _path(projection["page_path"], "page path")
        observed_id = _optional_id(projection["observed_controller_id"], "observed controller ID")
        if type(projection["registration_snapshot_applies"]) is not bool:
            raise ServiceWorkerScopeError("report snapshot applicability is invalid")
        expected_id = _optional_id(projection["expected_controller_id"], "expected controller ID")
        observed = projection["control_outcome"]
        expected = projection["expected_control"]
        if type(observed) is not str or observed not in ("controlled", "uncontrolled", "unknown"):
            raise ServiceWorkerScopeError("report observed control is invalid")
        if type(expected) is not str or expected not in ("controlled", "uncontrolled", "unknown"):
            raise ServiceWorkerScopeError("report expected control is invalid")
        if (observed == "controlled") != (observed_id is not None):
            raise ServiceWorkerScopeError("report observed controller is invalid")
        if (expected == "controlled") != (expected_id is not None):
            raise ServiceWorkerScopeError("report expected controller is invalid")
        names = projection["matching_registration_ids"]
        if type(names) is not list or len(names) > MAX_REGISTRATIONS:
            raise ServiceWorkerScopeError("report registration references are invalid")
        checked = [_id(name, "registration ID") for name in names]
        if checked != sorted(set(checked)):
            raise ServiceWorkerScopeError("report registration references must be sorted unique")
        if type(projection["basis"]) is not str or projection["basis"] not in _BASES:
            raise ServiceWorkerScopeError("report basis is invalid")
        if (
            type(projection["assessment"]) is not str
            or projection["assessment"] not in _ASSESSMENTS
        ):
            raise ServiceWorkerScopeError("report assessment is invalid")
        counts[projection["assessment"]] += 1
    if ids != sorted(set(ids)):
        raise ServiceWorkerScopeError("report observation IDs must be sorted unique")
    summary = _exact(item["summary"], {"observation_count", *counts}, "summary")
    if summary != {"observation_count": len(projections), **counts} or any(
        type(value) is not int for value in summary.values()
    ):
        raise ServiceWorkerScopeError("report summary is invalid")
    body = {key: value for key, value in item.items() if key not in ("report_id", "report_sha256")}
    digest = _digest(_canonical({"domain": DOMAIN, "analysis": body}).encode("ascii"))
    if item["report_sha256"] != digest or item["report_id"] != "SWS-" + digest[7:39].upper():
        raise ServiceWorkerScopeError("report address is invalid")


def analyze_service_worker_scope(
    *, source_content: bytes, source_id: str
) -> ServiceWorkerScopeReport:
    """Compare supplied registrations with supplied page-control outcomes."""
    identity = _id(source_id, "source ID")
    source = _decode(source_content, maximum=MAX_SOURCE_BYTES)
    facts_complete, registration_set_complete, registrations, observations = _model(source)
    projections = _project(facts_complete, registration_set_complete, registrations, observations)
    counts = {
        assessment: sum(p["assessment"] == assessment for p in projections)
        for assessment in sorted(_ASSESSMENTS)
    }
    document = {
        "schema_version": SCHEMA_VERSION,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "wave_id": WAVE_ID,
        "domain": DOMAIN,
        "source": {
            "source_id": identity,
            "sha256": _digest(source_content),
            "byte_count": len(source_content),
        },
        "facts_complete": facts_complete,
        "registration_set_complete": registration_set_complete,
        "projections": projections,
        "summary": {"observation_count": len(projections), **counts},
        **_FLAGS,
        "effects": _EFFECTS,
        "limitations": _LIMITATIONS,
    }
    digest = _digest(_canonical({"domain": DOMAIN, "analysis": document}).encode("ascii"))
    document["report_id"] = "SWS-" + digest[7:39].upper()
    document["report_sha256"] = digest
    _validate_tree(document, maximum=MAX_REPORT_BYTES)
    _validate_report(document)
    return ServiceWorkerScopeReport(_canonical(document))


def analyze_supplied_service_worker_scope(model: dict[str, Any]) -> ServiceWorkerScopeReport:
    """Canonicalize an exact native source-backed component model."""
    _validate_tree(model, maximum=MAX_SOURCE_BYTES)
    item = _exact(model, {"source_id", "source"}, "component model")
    source_id = _id(item["source_id"], "source ID")
    _model(item["source"])
    return analyze_service_worker_scope(
        source_content=_canonical(item["source"]).encode("ascii"),
        source_id=source_id,
    )


def verify_service_worker_scope(
    report: ServiceWorkerScopeReport,
    *,
    source_content: bytes,
    source_id: str,
) -> ServiceWorkerScopeReport:
    """Rebuild a detached report from exact original supplied source bytes."""
    if type(report) is not ServiceWorkerScopeReport:
        raise ServiceWorkerScopeError("report must be the exact report family")
    loaded = ServiceWorkerScopeReport.from_json(report.to_json())
    expected = analyze_service_worker_scope(source_content=source_content, source_id=source_id)
    if loaded.to_json() != expected.to_json():
        raise ServiceWorkerScopeError("report does not replay from supplied source")
    return expected


def component_fixture() -> dict[str, Any]:
    """Return fresh inert registration and page-control assertions."""
    return {
        "schema_version": SCHEMA_VERSION,
        "facts_complete": True,
        "registration_set_complete": True,
        "registrations": [
            {
                "registration_id": "app-root",
                "origin_id": "app-origin",
                "script_path": "/sw.js",
                "scope_path": "/app/",
                "state": "active",
            },
            {
                "registration_id": "app-admin",
                "origin_id": "app-origin",
                "script_path": "/admin-sw.js",
                "scope_path": "/app/admin/",
                "state": "active",
            },
        ],
        "observations": [
            {
                "observation_id": "obs-admin",
                "page_origin_id": "app-origin",
                "page_path": "/app/admin/settings",
                "control_outcome": "controlled",
                "observed_controller_id": "app-admin",
                "registration_snapshot_applies": True,
            },
            {
                "observation_id": "obs-mismatch",
                "page_origin_id": "app-origin",
                "page_path": "/app/home",
                "control_outcome": "controlled",
                "observed_controller_id": "app-admin",
                "registration_snapshot_applies": True,
            },
            {
                "observation_id": "obs-outside",
                "page_origin_id": "app-origin",
                "page_path": "/help",
                "control_outcome": "uncontrolled",
                "observed_controller_id": None,
                "registration_snapshot_applies": True,
            },
        ],
    }


__all__ = [
    "ServiceWorkerScopeError",
    "ServiceWorkerScopeReport",
    "analyze_service_worker_scope",
    "analyze_supplied_service_worker_scope",
    "verify_service_worker_scope",
    "component_fixture",
]
