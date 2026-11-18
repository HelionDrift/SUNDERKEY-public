"""Offline web-route, UI visibility and tenant-policy projection."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

PROFILE_ID = "AOE-GB-D05-S12"
CAPABILITY_ID = "web.access-control.multitenancy"
VECTOR_ID = "AV-GB-D05-S12-01"
WAVE_ID = "IW2-001"
DOMAIN = "sunderkey.offline-web-route-authorization.v1"
SCHEMA_VERSION = "v1"
MAX_SOURCE_BYTES = 262_144
MAX_REPORT_BYTES = 524_288
MAX_NODES = 40_000
MAX_DEPTH = 16
MAX_TEXT_BYTES = 512
MAX_PRINCIPALS = 256
MAX_ROUTES = 512
MAX_OBSERVATIONS = 2_048
MAX_ROLES = 64
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_PATH = re.compile(r"/(?:[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*)?\Z")
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
    "policy_authenticated": False,
    "ui_observations_authenticated": False,
    "server_outcomes_authenticated": False,
    "server_enforcement_observed": False,
    "finding_claimed": False,
    "positive_use_approved": False,
    "qualification_claimed": False,
}
_LIMITATIONS = [
    "Principals, roles, routes, UI visibility and server outcomes are supplied assertions.",
    "Route paths are inert declarations; no URL, browser navigation or matching occurs.",
    "UI visibility does not establish server authorization or enforcement.",
    "UI visibility relative to access decisions is descriptive, not a UI policy claim.",
    "Unknown or incomplete premises cannot support a policy contradiction or alignment claim.",
    "A contradiction among supplied facts is a candidate, not a verified access-control flaw.",
    "No target access, network, process, credential, provider request or live exploit occurs.",
]
_ASSESSMENTS = {"candidate_policy_contradiction", "declared_consistent", "unknown"}
_UI_ASSESSMENTS = {
    "declared_ui_access_decision_differs",
    "declared_ui_access_decision_same",
    "unknown",
}
_BASES = {
    "incomplete_facts",
    "incomplete_policy",
    "missing_route",
    "missing_principal",
    "public_route",
    "anonymous_deny",
    "authenticated_route",
    "missing_role",
    "matched_role",
    "same_tenant",
    "different_tenant",
    "unknown_tenant",
}


class WebRouteAuthorizationError(ValueError):
    """Closed input, bounded resource or exact-source replay failed."""


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields or any(type(k) is not str for k in value):
        raise WebRouteAuthorizationError(f"{label} fields are invalid")
    return value


def _id(value: Any, label: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise WebRouteAuthorizationError(f"{label} must be bounded native ASCII text")
    return value


def _optional_id(value: Any, label: str) -> str | None:
    return None if value is None else _id(value, label)


def _route_path(value: Any) -> str:
    if type(value) is not str or _PATH.fullmatch(value) is None:
        raise WebRouteAuthorizationError("route path must be an inert exact ASCII path")
    if len(value) > 256 or any(segment in (".", "..") for segment in value.split("/")):
        raise WebRouteAuthorizationError("route path is ambiguous or too long")
    return value


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise WebRouteAuthorizationError("duplicate JSON key")
        result[key] = value
    return result


def _json_integer(token: str) -> int:
    if len(token) > 20 or len(token.lstrip("-")) > 19:
        raise WebRouteAuthorizationError("JSON integer exceeds signed64 bound")
    value = int(token)
    if not -(1 << 63) <= value < (1 << 63):
        raise WebRouteAuthorizationError("JSON integer exceeds signed64 bound")
    return value


def _unsupported_number(_token: str) -> None:
    raise WebRouteAuthorizationError("floating and nonfinite numbers are unsupported")


def _validate_tree(value: Any, *, maximum: int) -> None:
    stack = [(value, 1)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise WebRouteAuthorizationError("JSON node or depth bound exceeded")
        kind = type(item)
        if kind is dict:
            if nodes + len(stack) + 2 * len(item) > MAX_NODES:
                raise WebRouteAuthorizationError("JSON node bound exceeded")
            for key, child in item.items():
                if type(key) is not str:
                    raise WebRouteAuthorizationError("JSON keys must be native text")
                stack.append((child, depth + 1))
                stack.append((key, depth + 1))
        elif kind is list:
            if nodes + len(stack) + len(item) > MAX_NODES:
                raise WebRouteAuthorizationError("JSON node bound exceeded")
            stack.extend((child, depth + 1) for child in item)
        elif kind is str:
            if len(item.encode("utf-8", errors="surrogatepass")) > MAX_TEXT_BYTES or any(
                0xD800 <= ord(char) <= 0xDFFF for char in item
            ):
                raise WebRouteAuthorizationError("JSON string is unsupported or too long")
        elif kind is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise WebRouteAuthorizationError("JSON integer exceeds signed64 bound")
        elif kind not in (bool, type(None)):
            raise WebRouteAuthorizationError("unsupported JSON value family")
    if len(_canonical(value).encode("ascii")) > maximum:
        raise WebRouteAuthorizationError("canonical JSON byte bound exceeded")


def _decode(content: bytes, *, maximum: int) -> Any:
    if type(content) is not bytes or not content or len(content) > maximum:
        raise WebRouteAuthorizationError("source must be bounded nonempty native bytes")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WebRouteAuthorizationError("source must be UTF-8") from exc
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
                raise WebRouteAuthorizationError("pre-decoder depth bound exceeded")
        elif char in "]}":
            nesting -= 1
            if nesting < 0:
                raise WebRouteAuthorizationError("malformed JSON nesting")
    if nesting or quoted:
        raise WebRouteAuthorizationError("malformed JSON nesting")
    try:
        result = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_json_integer,
            parse_float=_unsupported_number,
            parse_constant=_unsupported_number,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, WebRouteAuthorizationError):
            raise
        raise WebRouteAuthorizationError("malformed JSON source") from exc
    _validate_tree(result, maximum=maximum)
    return result


def _model(document: Any) -> tuple[bool, bool, dict, dict, list]:
    model = _exact(
        document,
        {
            "schema_version",
            "facts_complete",
            "policy_complete",
            "principals",
            "routes",
            "observations",
        },
        "model",
    )
    if type(model["schema_version"]) is not str or model["schema_version"] != SCHEMA_VERSION:
        raise WebRouteAuthorizationError("unsupported model version")
    if type(model["facts_complete"]) is not bool or type(model["policy_complete"]) is not bool:
        raise WebRouteAuthorizationError("completeness must be native Booleans")
    for name, maximum in (
        ("principals", MAX_PRINCIPALS),
        ("routes", MAX_ROUTES),
        ("observations", MAX_OBSERVATIONS),
    ):
        values = model[name]
        if type(values) is not list or len(values) > maximum:
            raise WebRouteAuthorizationError(f"{name} must be a bounded native array")
    principals = {}
    for raw in model["principals"]:
        entry = _exact(raw, {"principal_id", "tenant_id", "roles"}, "principal")
        identity = _id(entry["principal_id"], "principal ID")
        if identity in principals:
            raise WebRouteAuthorizationError("duplicate principal ID")
        roles = entry["roles"]
        if type(roles) is not list or len(roles) > MAX_ROLES:
            raise WebRouteAuthorizationError("roles must be a bounded native array")
        checked = [_id(role, "role ID") for role in roles]
        if len(set(checked)) != len(checked):
            raise WebRouteAuthorizationError("duplicate role ID")
        principals[identity] = {
            "tenant_id": _optional_id(entry["tenant_id"], "tenant ID"),
            "roles": frozenset(checked),
        }
    routes = {}
    paths = set()
    for raw in model["routes"]:
        entry = _exact(
            raw, {"route_id", "route_path", "access", "required_role", "tenant_scope"}, "route"
        )
        identity = _id(entry["route_id"], "route ID")
        path = _route_path(entry["route_path"])
        if identity in routes or path in paths:
            raise WebRouteAuthorizationError("duplicate route ID or exact path")
        paths.add(path)
        access, scope = entry["access"], entry["tenant_scope"]
        if type(access) is not str or access not in ("public", "authenticated", "role"):
            raise WebRouteAuthorizationError("route access is unsupported")
        if type(scope) is not str or scope not in ("none", "same_tenant"):
            raise WebRouteAuthorizationError("route tenant scope is unsupported")
        required_role = _optional_id(entry["required_role"], "required role")
        if (access == "role") != (required_role is not None):
            raise WebRouteAuthorizationError("required role must match role access")
        if access == "public" and scope != "none":
            raise WebRouteAuthorizationError("public routes cannot require tenant membership")
        routes[identity] = {
            "route_path": path,
            "access": access,
            "required_role": required_role,
            "tenant_scope": scope,
        }
    observations = []
    seen = set()
    for raw in model["observations"]:
        entry = _exact(
            raw,
            {
                "observation_id",
                "principal_id",
                "route_id",
                "resource_tenant_id",
                "ui_visibility",
                "server_outcome",
            },
            "observation",
        )
        identity = _id(entry["observation_id"], "observation ID")
        if identity in seen:
            raise WebRouteAuthorizationError("duplicate observation ID")
        seen.add(identity)
        visibility, outcome = entry["ui_visibility"], entry["server_outcome"]
        if type(visibility) is not str or visibility not in ("visible", "hidden", "unknown"):
            raise WebRouteAuthorizationError("UI visibility is unsupported")
        if type(outcome) is not str or outcome not in ("allowed", "denied", "unknown"):
            raise WebRouteAuthorizationError("server outcome is unsupported")
        observations.append(
            {
                "observation_id": identity,
                "principal_id": _optional_id(entry["principal_id"], "principal ID"),
                "route_id": _id(entry["route_id"], "route ID"),
                "resource_tenant_id": _optional_id(
                    entry["resource_tenant_id"], "resource tenant ID"
                ),
                "ui_visibility": visibility,
                "server_outcome": outcome,
            }
        )
    return model["facts_complete"], model["policy_complete"], principals, routes, observations


def _project(
    facts_complete: bool, policy_complete: bool, principals: dict, routes: dict, observations: list
) -> list:
    projections = []
    for observation in sorted(observations, key=lambda item: item["observation_id"]):
        identity = observation["principal_id"]
        route = routes.get(observation["route_id"])
        principal = principals.get(identity) if identity is not None else None
        expected = "unknown"
        if not facts_complete:
            basis = "incomplete_facts"
        elif not policy_complete:
            basis = "incomplete_policy"
        elif route is None:
            basis = "missing_route"
        elif identity is not None and principal is None:
            basis = "missing_principal"
        elif route["access"] == "public":
            expected, basis = "allow", "public_route"
        elif identity is None:
            expected, basis = "deny", "anonymous_deny"
        elif route["access"] == "role" and route["required_role"] not in principal["roles"]:
            expected, basis = "deny", "missing_role"
        elif route["tenant_scope"] == "same_tenant":
            tenant = principal["tenant_id"]
            resource_tenant = observation["resource_tenant_id"]
            if tenant is None or resource_tenant is None:
                basis = "unknown_tenant"
            elif tenant == resource_tenant:
                expected, basis = "allow", "same_tenant"
            else:
                expected, basis = "deny", "different_tenant"
        else:
            expected, basis = (
                "allow",
                ("matched_role" if route["access"] == "role" else "authenticated_route"),
            )
        outcome = observation["server_outcome"]
        if expected == "unknown" or outcome == "unknown":
            server_assessment = "unknown"
        elif (expected == "allow") == (outcome == "allowed"):
            server_assessment = "declared_consistent"
        else:
            server_assessment = "candidate_policy_contradiction"
        visibility = observation["ui_visibility"]
        if expected == "unknown" or visibility == "unknown":
            ui_assessment = "unknown"
        elif (expected == "allow") == (visibility == "visible"):
            ui_assessment = "declared_ui_access_decision_same"
        else:
            ui_assessment = "declared_ui_access_decision_differs"
        projections.append(
            {
                **observation,
                "route_path": route["route_path"] if route is not None else None,
                "expected_decision": expected,
                "basis": basis,
                "server_assessment": server_assessment,
                "ui_assessment": ui_assessment,
            }
        )
    return projections


@dataclass(frozen=True, slots=True)
class WebRouteAuthorizationReport:
    """Canonical report; exact original-source replay proves derivation."""

    _json: str

    def __post_init__(self) -> None:
        if type(self) is not WebRouteAuthorizationReport or self._json != _checked_report_json(
            self._json
        ):
            raise WebRouteAuthorizationError("canonical exact report is required")

    def to_json(self) -> str:
        if type(self) is not WebRouteAuthorizationReport or self._json != _checked_report_json(
            self._json
        ):
            raise WebRouteAuthorizationError("canonical exact report is required")
        return self._json

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.to_json())

    @classmethod
    def from_json(cls, content: str) -> WebRouteAuthorizationReport:
        if cls is not WebRouteAuthorizationReport:
            raise WebRouteAuthorizationError("report must be the exact report family")
        return cls(_checked_report_json(content))


def _checked_report_json(content: Any) -> str:
    if type(content) is not str:
        raise WebRouteAuthorizationError("report must be native JSON text")
    try:
        raw = content.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise WebRouteAuthorizationError("report must be UTF-8 JSON text") from exc
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
            "policy_complete",
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
            raise WebRouteAuthorizationError(f"report {key} is invalid")
    source = _exact(item["source"], {"source_id", "sha256", "byte_count"}, "source")
    _id(source["source_id"], "source ID")
    if type(source["sha256"]) is not str or _DIGEST.fullmatch(source["sha256"]) is None:
        raise WebRouteAuthorizationError("source digest is invalid")
    if type(source["byte_count"]) is not int or not 1 <= source["byte_count"] <= MAX_SOURCE_BYTES:
        raise WebRouteAuthorizationError("source byte count is invalid")
    if type(item["facts_complete"]) is not bool or type(item["policy_complete"]) is not bool:
        raise WebRouteAuthorizationError("report completeness is invalid")
    projections = item["projections"]
    if type(projections) is not list or len(projections) > MAX_OBSERVATIONS:
        raise WebRouteAuthorizationError("report projections are invalid")
    ids = []
    server_counts = {assessment: 0 for assessment in sorted(_ASSESSMENTS)}
    ui_counts = {assessment: 0 for assessment in sorted(_UI_ASSESSMENTS)}
    for raw in projections:
        projection = _exact(
            raw,
            {
                "observation_id",
                "principal_id",
                "route_id",
                "resource_tenant_id",
                "ui_visibility",
                "server_outcome",
                "route_path",
                "expected_decision",
                "basis",
                "server_assessment",
                "ui_assessment",
            },
            "projection",
        )
        ids.append(_id(projection["observation_id"], "observation ID"))
        _optional_id(projection["principal_id"], "principal ID")
        _id(projection["route_id"], "route ID")
        _optional_id(projection["resource_tenant_id"], "resource tenant ID")
        if projection["route_path"] is not None:
            _route_path(projection["route_path"])
        for key, options in (
            ("ui_visibility", ("visible", "hidden", "unknown")),
            ("server_outcome", ("allowed", "denied", "unknown")),
            ("expected_decision", ("allow", "deny", "unknown")),
            ("basis", _BASES),
            ("server_assessment", _ASSESSMENTS),
            ("ui_assessment", _UI_ASSESSMENTS),
        ):
            if type(projection[key]) is not str or projection[key] not in options:
                raise WebRouteAuthorizationError(f"report {key} is invalid")
        server_counts[projection["server_assessment"]] += 1
        ui_counts[projection["ui_assessment"]] += 1
    if ids != sorted(set(ids)):
        raise WebRouteAuthorizationError("report observation IDs must be sorted unique")
    summary = _exact(item["summary"], {"observation_count", "server", "ui"}, "summary")
    if (
        summary
        != {
            "observation_count": len(projections),
            "server": server_counts,
            "ui": ui_counts,
        }
        or type(summary["observation_count"]) is not int
    ):
        raise WebRouteAuthorizationError("report summary is invalid")
    for key, counts in (("server", server_counts), ("ui", ui_counts)):
        reported = _exact(summary[key], set(counts), f"{key} summary")
        if any(type(value) is not int for value in reported.values()):
            raise WebRouteAuthorizationError("report summary counts are invalid")
    body = {key: value for key, value in item.items() if key not in ("report_id", "report_sha256")}
    digest = _digest(_canonical({"domain": DOMAIN, "analysis": body}).encode("ascii"))
    if item["report_sha256"] != digest or item["report_id"] != "WRA-" + digest[7:39].upper():
        raise WebRouteAuthorizationError("report address is invalid")


def analyze_web_route_authorization(
    *, source_content: bytes, source_id: str
) -> WebRouteAuthorizationReport:
    """Compare supplied route/UI/server observations to declared policy facts."""
    identity = _id(source_id, "source ID")
    source = _decode(source_content, maximum=MAX_SOURCE_BYTES)
    facts_complete, policy_complete, principals, routes, observations = _model(source)
    projections = _project(facts_complete, policy_complete, principals, routes, observations)
    server_counts = {
        assessment: sum(p["server_assessment"] == assessment for p in projections)
        for assessment in sorted(_ASSESSMENTS)
    }
    ui_counts = {
        assessment: sum(p["ui_assessment"] == assessment for p in projections)
        for assessment in sorted(_UI_ASSESSMENTS)
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
        "policy_complete": policy_complete,
        "projections": projections,
        "summary": {
            "observation_count": len(projections),
            "server": server_counts,
            "ui": ui_counts,
        },
        **_FLAGS,
        "effects": _EFFECTS,
        "limitations": _LIMITATIONS,
    }
    digest = _digest(_canonical({"domain": DOMAIN, "analysis": document}).encode("ascii"))
    document["report_id"] = "WRA-" + digest[7:39].upper()
    document["report_sha256"] = digest
    _validate_tree(document, maximum=MAX_REPORT_BYTES)
    _validate_report(document)
    return WebRouteAuthorizationReport(_canonical(document))


def analyze_supplied_web_route_authorization(model: dict[str, Any]) -> WebRouteAuthorizationReport:
    """Canonicalize an exact native source-backed component model."""
    _validate_tree(model, maximum=MAX_SOURCE_BYTES)
    item = _exact(model, {"source_id", "source"}, "component model")
    source_id = _id(item["source_id"], "source ID")
    _model(item["source"])
    return analyze_web_route_authorization(
        source_content=_canonical(item["source"]).encode("ascii"),
        source_id=source_id,
    )


def verify_web_route_authorization(
    report: WebRouteAuthorizationReport,
    *,
    source_content: bytes,
    source_id: str,
) -> WebRouteAuthorizationReport:
    """Rebuild a detached report from exact original supplied source bytes."""
    if type(report) is not WebRouteAuthorizationReport:
        raise WebRouteAuthorizationError("report must be the exact report family")
    loaded = WebRouteAuthorizationReport.from_json(report.to_json())
    expected = analyze_web_route_authorization(source_content=source_content, source_id=source_id)
    if loaded.to_json() != expected.to_json():
        raise WebRouteAuthorizationError("report does not replay from supplied source")
    return expected


def component_fixture() -> dict[str, Any]:
    """Return fresh inert route, principal and declared observation facts."""
    return {
        "schema_version": SCHEMA_VERSION,
        "facts_complete": True,
        "policy_complete": True,
        "principals": [
            {"principal_id": "alice", "tenant_id": "tenant-a", "roles": ["admin"]},
            {"principal_id": "bob", "tenant_id": "tenant-b", "roles": ["admin"]},
        ],
        "routes": [
            {
                "route_id": "tenant-admin",
                "route_path": "/workspace/settings",
                "access": "role",
                "required_role": "admin",
                "tenant_scope": "same_tenant",
            },
        ],
        "observations": [
            {
                "observation_id": "obs-owner",
                "principal_id": "alice",
                "route_id": "tenant-admin",
                "resource_tenant_id": "tenant-a",
                "ui_visibility": "visible",
                "server_outcome": "allowed",
            },
            {
                "observation_id": "obs-cross-tenant",
                "principal_id": "bob",
                "route_id": "tenant-admin",
                "resource_tenant_id": "tenant-a",
                "ui_visibility": "visible",
                "server_outcome": "allowed",
            },
            {
                "observation_id": "obs-anonymous",
                "principal_id": None,
                "route_id": "tenant-admin",
                "resource_tenant_id": "tenant-a",
                "ui_visibility": "hidden",
                "server_outcome": "denied",
            },
        ],
    }


__all__ = [
    "WebRouteAuthorizationError",
    "WebRouteAuthorizationReport",
    "analyze_web_route_authorization",
    "analyze_supplied_web_route_authorization",
    "verify_web_route_authorization",
    "component_fixture",
]
