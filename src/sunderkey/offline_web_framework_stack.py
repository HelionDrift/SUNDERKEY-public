"""Inert comparison of supplied web-stack middleware and route declarations."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "web_supplied_framework_stack_projection"
PROFILE_ID = "AOE-GB-D05-S08"
CAPABILITY_ID = "army.gb.d05.s08"
VECTOR_ID = "AV-GB-D05-S08-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D05-S08"
WAVE_ID = "IW2-008"
COMMANDER_ID = "AOE-GB-D05-CMD"
GROUP_OWNER_ID = "AOE-HQ-04"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-34"
BLUEPRINT_SHA256 = "sha256:0e02ec2292402bb99075e7e50309825408a9346685f899e44203f5f7a42dd3f0"
DOMAIN = "sunderkey.offline-web-framework-stack.v1"
MODEL_DOMAIN = "sunderkey.offline-web-framework-stack-model.v1"
SEMANTICS_PROFILE = "declared-exact-route-guard-order.v1"
MAX_DOCUMENT_BYTES = 131_072
MAX_NODES = 12_000
MAX_DEPTH = 14
MAX_STRING_BYTES = 256
MAX_APPLICATIONS = 32
MAX_ROUTES = 128
MAX_STEPS = 64
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z")
_FLAGS = dict.fromkeys(
    (
        "source_authenticated",
        "framework_runtime_verified",
        "route_reachability_verified",
        "middleware_execution_observed",
        "guard_enforcement_verified",
        "exploitability_verified",
        "positive_use_approved",
        "qualification_claimed",
    ),
    False,
)
_EFFECTS = dict.fromkeys(
    (
        "authority",
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
    "nodes": MAX_NODES,
    "depth": MAX_DEPTH,
    "string_bytes": MAX_STRING_BYTES,
    "applications": MAX_APPLICATIONS,
    "routes": MAX_ROUTES,
    "steps_per_route": MAX_STEPS,
}
_LIMITATIONS = [
    "Applications, routes, middleware steps and completeness assertions are supplied data.",
    "Stack language is a label; no JavaScript, Python, Ruby or PHP code is parsed or executed.",
    "Only exact required-guard presence and order before a declared handler are modeled.",
    "A guard-order gap is a supplied declaration candidate, not an observed authorization bypass.",
    "Ordered declarations do not prove runtime enforcement or absence of other vulnerabilities.",
    "Unknown reachability or incomplete policy, chain or controls yields unknown.",
    "No framework runtime, credential, network, process or target is contacted.",
    "No authority, qualification, positive use or live finding is established.",
]


class WebFrameworkStackAnalysisError(ValueError):
    """Invalid, unsupported or over-budget supplied declaration or report."""


def _measure(value: Any, depth: int = 1, active: set[int] | None = None) -> int:
    if active is None:
        active = set()
    if depth > MAX_DEPTH:
        raise WebFrameworkStackAnalysisError("Native depth bound exceeded")
    kind = type(value)
    if kind is str:
        if len(value.encode("utf-8", errors="surrogatepass")) > MAX_STRING_BYTES or not all(
            32 <= ord(char) <= 126 for char in value
        ):
            raise WebFrameworkStackAnalysisError("Bounded printable ASCII text required")
        return 1
    if kind is int:
        if not -(2**63) <= value < 2**63:
            raise WebFrameworkStackAnalysisError("Signed 64-bit integer required")
        return 1
    if kind in (bool, type(None)):
        return 1
    if kind not in (dict, list) or id(value) in active:
        raise WebFrameworkStackAnalysisError("Exact acyclic JSON primitives required")
    active.add(id(value))
    try:
        if kind is dict:
            if any(type(key) is not str for key in value):
                raise WebFrameworkStackAnalysisError("Native text keys required")
            count = 1 + sum(
                _measure(key, depth + 1, active) + _measure(child, depth + 1, active)
                for key, child in value.items()
            )
        else:
            count = 1 + sum(_measure(child, depth + 1, active) for child in value)
    finally:
        active.remove(id(value))
    if count > MAX_NODES:
        raise WebFrameworkStackAnalysisError("Native node bound exceeded")
    return count


def _serialize(value: Any) -> str:
    _measure(value)
    text = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    if len(text) > MAX_DOCUMENT_BYTES:
        raise WebFrameworkStackAnalysisError("Document byte bound exceeded")
    return text


def _decode(text: Any) -> Any:
    if type(text) is not str or not text or len(text) > MAX_DOCUMENT_BYTES or not text.isascii():
        raise WebFrameworkStackAnalysisError("Bounded ASCII JSON required")

    def pairs(rows: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, value in rows:
            if key in result:
                raise WebFrameworkStackAnalysisError("Duplicate JSON member")
            result[key] = value
        return result

    def integer(token: str) -> int:
        if len(token) > 20:
            raise WebFrameworkStackAnalysisError("Integer bound exceeded")
        value = int(token)
        if not -(2**63) <= value < 2**63:
            raise WebFrameworkStackAnalysisError("Signed 64-bit integer required")
        return value

    def unsupported(_token: str) -> None:
        raise WebFrameworkStackAnalysisError("Fractional or nonfinite number unsupported")

    try:
        value = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=integer,
            parse_float=unsupported,
            parse_constant=unsupported,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, WebFrameworkStackAnalysisError):
            raise
        raise WebFrameworkStackAnalysisError("Malformed supplied JSON") from exc
    _serialize(value)
    return value


def _exact(value: Any, fields: set[str], label: str) -> dict:
    if type(value) is not dict or set(value) != fields:
        raise WebFrameworkStackAnalysisError(f"Exact closed {label} fields required")
    return value


def _identity(value: Any) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None or value == "unknown":
        raise WebFrameworkStackAnalysisError("Bounded exact identity required")
    return value


def _rows(value: Any, field: str, limit: int, label: str) -> list:
    if type(value) is not list or not 1 <= len(value) <= limit:
        raise WebFrameworkStackAnalysisError(f"Bounded nonempty {label} list required")
    ids = [_identity(row[field]) for row in value if type(row) is dict and field in row]
    if len(ids) != len(value) or ids != sorted(set(ids)):
        raise WebFrameworkStackAnalysisError(f"Sorted unique {label} identities required")
    return value


def _boolean(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise WebFrameworkStackAnalysisError(f"Native {label} Boolean required")
    return value


def _validate_model(model: Any) -> dict:
    owned = _decode(_serialize(model))
    _exact(owned, {"schema_version", "applications", "routes"}, "model")
    if type(owned["schema_version"]) is not int or owned["schema_version"] != 1:
        raise WebFrameworkStackAnalysisError("Exact schema version 1 required")
    applications = _rows(owned["applications"], "application_id", MAX_APPLICATIONS, "application")
    routes = _rows(owned["routes"], "route_id", MAX_ROUTES, "route")
    app_ids = set()
    for app in applications:
        _exact(
            app,
            {
                "application_id",
                "language",
                "middleware_semantics_complete",
                "upstream_controls_complete",
            },
            "application",
        )
        if type(app["language"]) is not str or app["language"] not in (
            "javascript",
            "python",
            "ruby",
            "php",
        ):
            raise WebFrameworkStackAnalysisError("Supported stack label required")
        _boolean(app["middleware_semantics_complete"], "middleware semantics")
        _boolean(app["upstream_controls_complete"], "upstream controls")
        app_ids.add(app["application_id"])
    for route in routes:
        _exact(
            route,
            {
                "route_id",
                "application_id",
                "required_guard_id",
                "handler_id",
                "steps",
                "policy_complete",
                "chain_complete",
                "declared_reachable",
            },
            "route",
        )
        if _identity(route["application_id"]) not in app_ids:
            raise WebFrameworkStackAnalysisError("Unknown application reference")
        _identity(route["required_guard_id"])
        _identity(route["handler_id"])
        for field in ("policy_complete", "chain_complete", "declared_reachable"):
            _boolean(route[field], field)
        steps = route["steps"]
        if type(steps) is not list or not 1 <= len(steps) <= MAX_STEPS:
            raise WebFrameworkStackAnalysisError("Bounded route step list required")
        ids = set()
        handler_count = 0
        for step in steps:
            _exact(step, {"step_id", "kind"}, "middleware step")
            step_id = _identity(step["step_id"])
            if step_id in ids:
                raise WebFrameworkStackAnalysisError("Duplicate route step ID")
            ids.add(step_id)
            if type(step["kind"]) is not str or step["kind"] not in ("guard", "handler", "other"):
                raise WebFrameworkStackAnalysisError("Supported middleware kind required")
            handler_count += step["kind"] == "handler"
        if handler_count > 1:
            raise WebFrameworkStackAnalysisError("Only one declared handler is modeled")
    return owned


def _observe(route: dict, app: dict) -> dict:
    reasons = []
    if not app["middleware_semantics_complete"]:
        reasons.append("middleware_semantics_incomplete")
    if not app["upstream_controls_complete"]:
        reasons.append("upstream_controls_incomplete")
    if not route["policy_complete"]:
        reasons.append("route_policy_incomplete")
    if not route["chain_complete"]:
        reasons.append("route_chain_incomplete")
    if not route["declared_reachable"]:
        reasons.append("route_reachability_unknown")
    positions = {step["step_id"]: index for index, step in enumerate(route["steps"])}
    kinds = {step["step_id"]: step["kind"] for step in route["steps"]}
    handler_id = route["handler_id"]
    guard_id = route["required_guard_id"]
    if kinds.get(handler_id) != "handler":
        reasons.append("declared_handler_missing_or_mistyped")
    if guard_id in positions and kinds[guard_id] != "guard":
        reasons.append("required_guard_kind_mismatch")
    if reasons:
        outcome = "unknown"
        gap = None
    elif guard_id not in positions:
        outcome, gap = "candidate_declared_guard_order_gap", "required_guard_absent"
    elif positions[guard_id] > positions[handler_id]:
        outcome, gap = "candidate_declared_guard_order_gap", "required_guard_after_handler"
    else:
        outcome, gap = "declared_guard_precedes_handler", None
    return {
        "route_id": route["route_id"],
        "application_id": route["application_id"],
        "language": app["language"],
        "outcome": outcome,
        "gap": gap,
        "uncertainty": reasons,
    }


def _address(domain: str, text: str) -> str:
    return "sha256:" + hashlib.sha256((domain + "\n" + text).encode("ascii")).hexdigest()


def _derive(model: Any) -> dict:
    owned = _validate_model(model)
    apps = {row["application_id"]: row for row in owned["applications"]}
    observations = [_observe(row, apps[row["application_id"]]) for row in owned["routes"]]
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
        "source_model_sha256": _address(MODEL_DOMAIN, _serialize(owned)),
        "route_count": len(observations),
        "candidate_count": sum(
            row["outcome"] == "candidate_declared_guard_order_gap" for row in observations
        ),
        "unknown_count": sum(row["outcome"] == "unknown" for row in observations),
        "route_observations": observations,
        "bounds": dict(_BOUNDS),
        "flags": dict(_FLAGS),
        "effects": dict(_EFFECTS),
        "limitations": list(_LIMITATIONS),
    }
    digest = _address(DOMAIN, _serialize(body))
    body["analysis_id"] = "WFS-" + digest[7:39].upper()
    body["analysis_sha256"] = digest
    _serialize(body)
    return body


def _replay(document: Any) -> dict:
    owned = _decode(_serialize(document))
    if type(owned) is not dict or "source_model" not in owned:
        raise WebFrameworkStackAnalysisError("Source-bearing report required")
    expected = _derive(owned["source_model"])
    if _serialize(owned) != _serialize(expected):
        raise WebFrameworkStackAnalysisError("Report does not replay embedded source")
    return expected


@dataclass(frozen=True, slots=True, init=False)
class WebFrameworkStackAnalysis:
    """Detached declaration comparison, not framework-runtime evidence."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        object.__setattr__(self, "_document_json", _serialize(_replay(document)))

    @classmethod
    def from_dict(cls, document: Any) -> WebFrameworkStackAnalysis:
        return cls(document)

    @classmethod
    def from_json(cls, content: Any) -> WebFrameworkStackAnalysis:
        return cls(_decode(content))

    def to_dict(self) -> dict:
        return _replay(_decode(getattr(self, "_document_json", None)))

    def to_json(self) -> str:
        return _serialize(self.to_dict())


def analyze_supplied_web_framework_stack(model: Any) -> WebFrameworkStackAnalysis:
    """Project only supplied route-local guard and handler declarations."""
    return WebFrameworkStackAnalysis(_derive(model))


def analyze_supplied_web_framework_stack_bytes(*, model_bytes: Any) -> WebFrameworkStackAnalysis:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_DOCUMENT_BYTES:
        raise WebFrameworkStackAnalysisError("Bounded exact native model bytes required")
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise WebFrameworkStackAnalysisError("ASCII model bytes required") from exc
    return analyze_supplied_web_framework_stack(_decode(text))


def verify_supplied_web_framework_stack_analysis(
    report: Any, *, model: Any
) -> WebFrameworkStackAnalysis:
    if type(report) is not WebFrameworkStackAnalysis:
        raise WebFrameworkStackAnalysisError("Exact native report family required")
    expected = _derive(model)
    if report.to_json() != _serialize(expected):
        raise WebFrameworkStackAnalysisError("Report differs from separately supplied originals")
    return WebFrameworkStackAnalysis(expected)


def component_fixture() -> dict:
    """Fresh synthetic gap, ordered guard and unknown middleware declarations."""
    return {
        "schema_version": 1,
        "applications": [
            {
                "application_id": "portal",
                "language": "python",
                "middleware_semantics_complete": True,
                "upstream_controls_complete": True,
            }
        ],
        "routes": [
            {
                "route_id": "account-gap",
                "application_id": "portal",
                "required_guard_id": "session-guard",
                "handler_id": "account-handler",
                "steps": [
                    {"step_id": "account-handler", "kind": "handler"},
                    {"step_id": "session-guard", "kind": "guard"},
                ],
                "policy_complete": True,
                "chain_complete": True,
                "declared_reachable": True,
            },
            {
                "route_id": "account-ordered",
                "application_id": "portal",
                "required_guard_id": "session-guard",
                "handler_id": "account-handler",
                "steps": [
                    {"step_id": "session-guard", "kind": "guard"},
                    {"step_id": "account-handler", "kind": "handler"},
                ],
                "policy_complete": True,
                "chain_complete": True,
                "declared_reachable": True,
            },
            {
                "route_id": "account-unknown",
                "application_id": "portal",
                "required_guard_id": "session-guard",
                "handler_id": "account-handler",
                "steps": [{"step_id": "account-handler", "kind": "handler"}],
                "policy_complete": True,
                "chain_complete": False,
                "declared_reachable": True,
            },
        ],
    }


__all__ = [
    "WebFrameworkStackAnalysisError",
    "WebFrameworkStackAnalysis",
    "analyze_supplied_web_framework_stack",
    "analyze_supplied_web_framework_stack_bytes",
    "verify_supplied_web_framework_stack_analysis",
    "component_fixture",
]
