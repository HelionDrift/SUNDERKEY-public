"""Offline fixed-window projection over supplied API admission records."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

PROFILE_ID = "AOE-GB-D06-S13"
CAPABILITY_ID = "army.gb.d06.s13"
VECTOR_ID = "AV-GB-D06-S13-01"
WAVE_ID = "IW2-004"
DOMAIN = "sunderkey.offline-api-rate-limit.v1"
SCHEMA_VERSION = "v1"
MAX_SOURCE_BYTES = 262_144
MAX_REPORT_BYTES = 524_288
MAX_NODES = 100_000
MAX_DEPTH = 16
MAX_STRING_BYTES = 512
MAX_RECORDS = 4_096
MAX_ROUTES = 128
MAX_WINDOWS = 4_096
MAX_TIMESTAMP_MS = 1_000_000_000_000_000
MAX_WINDOW_MS = 86_400_000
MAX_REQUESTS = 1_000_000
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
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
    "traffic_authenticated": False,
    "policy_authenticated": False,
    "server_enforcement_observed": False,
    "abuse_finding_claimed": False,
    "positive_use_approved": False,
    "qualification_claimed": False,
}
_LIMITATIONS = [
    "Policy, route mapping, event outcomes and traffic completeness are caller declarations.",
    "Fixed windows use the declared origin and duration, not a discovered server algorithm.",
    "Admitted counts above a declared limit are supplied-data candidates, not verified abuse.",
    "Incomplete traffic yields unknown assessment even when a supplied count exceeds a limit.",
    "Retries, distributed counters, exemptions, clock skew and dynamic policy are not modeled.",
    "No request, response, target state, authority, live use or qualification is established.",
]
_ASSESSMENTS = {
    "candidate_admitted_over_limit",
    "within_supplied_limit",
    "unknown_incomplete_traffic",
}


class ApiRateLimitError(ValueError):
    """Closed input, resource bound or replay validation failed."""


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields or any(type(k) is not str for k in value):
        raise ApiRateLimitError(f"{label} fields are invalid")
    return value


def _id(value: Any, label: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise ApiRateLimitError(f"{label} must be bounded native ASCII text")
    return value


def _integer(value: Any, minimum: int, maximum: int, label: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ApiRateLimitError(f"{label} must be a bounded native integer")
    return value


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ApiRateLimitError("duplicate JSON key")
        result[key] = value
    return result


def _json_integer(token: str) -> int:
    if len(token) > 20 or len(token.lstrip("-")) > 19:
        raise ApiRateLimitError("JSON integer exceeds signed64 bound")
    value = int(token)
    if not -(1 << 63) <= value < (1 << 63):
        raise ApiRateLimitError("JSON integer exceeds signed64 bound")
    return value


def _unsupported_number(_token: str) -> None:
    raise ApiRateLimitError("floating and nonfinite numbers are unsupported")


def _validate_tree(value: Any, *, maximum: int) -> None:
    stack = [(value, 1)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise ApiRateLimitError("JSON node or depth bound exceeded")
        kind = type(item)
        if kind is dict:
            if nodes + len(stack) + 2 * len(item) > MAX_NODES:
                raise ApiRateLimitError("JSON node bound exceeded")
            for key, child in item.items():
                if type(key) is not str:
                    raise ApiRateLimitError("JSON keys must be native text")
                stack.append((child, depth + 1))
                stack.append((key, depth + 1))
        elif kind is list:
            if nodes + len(stack) + len(item) > MAX_NODES:
                raise ApiRateLimitError("JSON node bound exceeded")
            stack.extend((child, depth + 1) for child in item)
        elif kind is str:
            if len(item.encode("utf-8", errors="surrogatepass")) > MAX_STRING_BYTES or any(
                0xD800 <= ord(char) <= 0xDFFF for char in item
            ):
                raise ApiRateLimitError("JSON string is unsupported or too long")
        elif kind is int:
            _integer(item, -(1 << 63), (1 << 63) - 1, "JSON integer")
        elif kind not in (bool, type(None)):
            raise ApiRateLimitError("unsupported JSON value family")
    if len(_canonical(value).encode("ascii")) > maximum:
        raise ApiRateLimitError("canonical JSON byte bound exceeded")


def _decode(content: bytes, *, maximum: int) -> Any:
    if type(content) is not bytes or not content or len(content) > maximum:
        raise ApiRateLimitError("source must be bounded nonempty native bytes")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ApiRateLimitError("source must be UTF-8") from exc
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
                raise ApiRateLimitError("pre-decoder depth bound exceeded")
        elif char in "]}":
            nesting -= 1
            if nesting < 0:
                raise ApiRateLimitError("malformed JSON nesting")
    if nesting or quoted:
        raise ApiRateLimitError("malformed JSON nesting")
    try:
        result = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_json_integer,
            parse_float=_unsupported_number,
            parse_constant=_unsupported_number,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, ApiRateLimitError):
            raise
        raise ApiRateLimitError("malformed JSON source") from exc
    _validate_tree(result, maximum=maximum)
    return result


def _model(document: Any) -> tuple[bool, int, int, dict[str, int], list[dict[str, Any]]]:
    model = _exact(
        document,
        {"schema_version", "traffic_complete", "policy", "records"},
        "model",
    )
    if type(model["schema_version"]) is not str or model["schema_version"] != SCHEMA_VERSION:
        raise ApiRateLimitError("unsupported model version")
    if type(model["traffic_complete"]) is not bool:
        raise ApiRateLimitError("traffic completeness must be a native Boolean")
    policy = _exact(model["policy"], {"window_ms", "window_origin_ms", "route_limits"}, "policy")
    duration = _integer(policy["window_ms"], 1, MAX_WINDOW_MS, "window duration")
    origin = _integer(policy["window_origin_ms"], 0, MAX_TIMESTAMP_MS, "window origin")
    declared = policy["route_limits"]
    if type(declared) is not list or not 1 <= len(declared) <= MAX_ROUTES:
        raise ApiRateLimitError("route limits must be a bounded nonempty array")
    routes: dict[str, int] = {}
    for raw in declared:
        entry = _exact(raw, {"route_id", "max_admitted_requests"}, "route limit")
        route = _id(entry["route_id"], "route ID")
        limit = _integer(entry["max_admitted_requests"], 0, MAX_REQUESTS, "route limit")
        if route in routes:
            raise ApiRateLimitError("duplicate route limit")
        routes[route] = limit
    records = model["records"]
    if type(records) is not list or len(records) > MAX_RECORDS:
        raise ApiRateLimitError("records must be a bounded native array")
    seen = set()
    validated = []
    for raw in records:
        entry = _exact(
            raw, {"event_id", "timestamp_ms", "subject_id", "route_id", "outcome"}, "record"
        )
        event = _id(entry["event_id"], "event ID")
        if event in seen:
            raise ApiRateLimitError("duplicate event ID")
        seen.add(event)
        timestamp = _integer(entry["timestamp_ms"], origin, MAX_TIMESTAMP_MS, "timestamp")
        subject = _id(entry["subject_id"], "subject ID")
        route = _id(entry["route_id"], "route ID")
        if route not in routes:
            raise ApiRateLimitError("record route has no declared limit")
        outcome = entry["outcome"]
        if type(outcome) is not str or outcome not in ("admitted", "rate_limited"):
            raise ApiRateLimitError("record outcome is unsupported")
        validated.append(
            {
                "event_id": event,
                "timestamp_ms": timestamp,
                "subject_id": subject,
                "route_id": route,
                "outcome": outcome,
            }
        )
    return model["traffic_complete"], duration, origin, routes, validated


def _projection(
    complete: bool,
    duration: int,
    origin: int,
    routes: dict[str, int],
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, int], dict[str, Any]] = {}
    for record in records:
        ordinal = (record["timestamp_ms"] - origin) // duration
        start = origin + ordinal * duration
        key = (record["subject_id"], record["route_id"], start)
        if key not in groups:
            if len(groups) >= MAX_WINDOWS:
                raise ApiRateLimitError("window count bound exceeded")
            groups[key] = {"admitted": [], "rate_limited": []}
        groups[key][record["outcome"]].append((record["timestamp_ms"], record["event_id"]))
    windows = []
    for (subject, route, start), events in sorted(groups.items()):
        admitted = [event for _, event in sorted(events["admitted"])]
        limited = [event for _, event in sorted(events["rate_limited"])]
        limit = routes[route]
        crossed = len(admitted) > limit
        if not complete:
            assessment = "unknown_incomplete_traffic"
        elif crossed:
            assessment = "candidate_admitted_over_limit"
        else:
            assessment = "within_supplied_limit"
        windows.append(
            {
                "subject_id": subject,
                "route_id": route,
                "window_start_ms": start,
                "window_end_ms_exclusive": start + duration,
                "max_admitted_requests": limit,
                "observed_admitted": len(admitted),
                "observed_rate_limited": len(limited),
                "admitted_event_ids": admitted,
                "rate_limited_event_ids": limited,
                "threshold_exceeded_in_supplied_records": crossed,
                "assessment": assessment,
            }
        )
    return windows


@dataclass(frozen=True, slots=True)
class ApiRateLimitReport:
    """Canonical locally valid report; derivation requires exact-source replay."""

    _json: str

    def __post_init__(self) -> None:
        if type(self) is not ApiRateLimitReport:
            raise ApiRateLimitError("report must be the exact report family")
        _validated_report_text(self._json, canonical_required=True)

    def to_json(self) -> str:
        if type(self) is not ApiRateLimitReport:
            raise ApiRateLimitError("report must be the exact report family")
        text = getattr(self, "_json", None)
        _validated_report_text(text, canonical_required=True)
        return text

    def to_dict(self) -> dict[str, Any]:
        if type(self) is not ApiRateLimitReport:
            raise ApiRateLimitError("report must be the exact report family")
        document, _ = _validated_report_text(getattr(self, "_json", None), canonical_required=True)
        return document

    @classmethod
    def from_json(cls, content: str) -> ApiRateLimitReport:
        if cls is not ApiRateLimitReport:
            raise ApiRateLimitError("report must be the exact report family")
        _, canonical = _validated_report_text(content, canonical_required=False)
        return cls(canonical)


def _validated_report_text(content: Any, *, canonical_required: bool) -> tuple[dict[str, Any], str]:
    if type(content) is not str:
        raise ApiRateLimitError("report must be native JSON text")
    try:
        raw = content.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ApiRateLimitError("report must be UTF-8 JSON text") from exc
    document = _decode(raw, maximum=MAX_REPORT_BYTES)
    canonical = _canonical(document)
    if canonical_required and content != canonical:
        raise ApiRateLimitError("report must be exact canonical JSON")
    _validate_report(document)
    return document, canonical


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
            "traffic_complete",
            "window_ms",
            "window_origin_ms",
            "windows",
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
            raise ApiRateLimitError(f"report {key} is invalid")
    source = _exact(item["source"], {"source_id", "sha256", "byte_count"}, "source")
    _id(source["source_id"], "source ID")
    if type(source["sha256"]) is not str or _SHA.fullmatch(source["sha256"]) is None:
        raise ApiRateLimitError("source digest is invalid")
    _integer(source["byte_count"], 1, MAX_SOURCE_BYTES, "source byte count")
    if type(item["traffic_complete"]) is not bool:
        raise ApiRateLimitError("report completeness is invalid")
    duration = _integer(item["window_ms"], 1, MAX_WINDOW_MS, "window duration")
    origin = _integer(item["window_origin_ms"], 0, MAX_TIMESTAMP_MS, "window origin")
    windows = item["windows"]
    if type(windows) is not list or len(windows) > MAX_WINDOWS:
        raise ApiRateLimitError("report windows are invalid")
    seen_windows = set()
    seen_events = set()
    counts = {assessment: 0 for assessment in sorted(_ASSESSMENTS)}
    admitted_count = limited_count = 0
    for raw in windows:
        window = _exact(
            raw,
            {
                "subject_id",
                "route_id",
                "window_start_ms",
                "window_end_ms_exclusive",
                "max_admitted_requests",
                "observed_admitted",
                "observed_rate_limited",
                "admitted_event_ids",
                "rate_limited_event_ids",
                "threshold_exceeded_in_supplied_records",
                "assessment",
            },
            "window",
        )
        subject = _id(window["subject_id"], "subject ID")
        route = _id(window["route_id"], "route ID")
        start = _integer(window["window_start_ms"], origin, MAX_TIMESTAMP_MS, "window start")
        _integer(
            window["window_end_ms_exclusive"],
            start + 1,
            MAX_TIMESTAMP_MS + MAX_WINDOW_MS,
            "window end",
        )
        if window["window_end_ms_exclusive"] != start + duration or (start - origin) % duration:
            raise ApiRateLimitError("window boundaries contradict declared policy")
        key = (subject, route, start)
        if key in seen_windows:
            raise ApiRateLimitError("duplicate window")
        seen_windows.add(key)
        limit = _integer(window["max_admitted_requests"], 0, MAX_REQUESTS, "limit")
        admitted = window["admitted_event_ids"]
        limited = window["rate_limited_event_ids"]
        if (
            type(admitted) is not list
            or type(limited) is not list
            or (len(admitted) + len(limited) > MAX_RECORDS)
        ):
            raise ApiRateLimitError("event IDs are invalid")
        for event in [*admitted, *limited]:
            event = _id(event, "event ID")
            if event in seen_events:
                raise ApiRateLimitError("duplicate report event ID")
            seen_events.add(event)
        if (
            window["observed_admitted"] != len(admitted)
            or (type(window["observed_admitted"]) is not int)
            or window["observed_rate_limited"] != len(limited)
            or (type(window["observed_rate_limited"]) is not int)
        ):
            raise ApiRateLimitError("event counts are invalid")
        crossed = len(admitted) > limit
        if type(window["threshold_exceeded_in_supplied_records"]) is not bool or (
            window["threshold_exceeded_in_supplied_records"] != crossed
        ):
            raise ApiRateLimitError("threshold flag is invalid")
        assessment = window["assessment"]
        expected = (
            "unknown_incomplete_traffic"
            if not item["traffic_complete"]
            else "candidate_admitted_over_limit"
            if crossed
            else "within_supplied_limit"
        )
        if type(assessment) is not str or assessment != expected:
            raise ApiRateLimitError("window assessment is invalid")
        counts[assessment] += 1
        admitted_count += len(admitted)
        limited_count += len(limited)
    summary = _exact(
        item["summary"],
        {
            "window_count",
            "record_count",
            "admitted_count",
            "rate_limited_count",
            *counts,
        },
        "summary",
    )
    expected_summary = {
        "window_count": len(windows),
        "record_count": len(seen_events),
        "admitted_count": admitted_count,
        "rate_limited_count": limited_count,
        **counts,
    }
    if any(type(value) is not int for value in summary.values()) or summary != expected_summary:
        raise ApiRateLimitError("report summary is invalid")
    body = {key: value for key, value in item.items() if key not in ("report_id", "report_sha256")}
    digest = _digest(_canonical({"domain": DOMAIN, "analysis": body}).encode("ascii"))
    if item["report_sha256"] != digest or item["report_id"] != "ARL-" + digest[7:39].upper():
        raise ApiRateLimitError("report address is invalid")


def analyze_api_rate_limit(*, source_content: bytes, source_id: str) -> ApiRateLimitReport:
    """Project supplied admission outcomes into declared per-subject route windows."""
    identity = _id(source_id, "source ID")
    model = _decode(source_content, maximum=MAX_SOURCE_BYTES)
    complete, duration, origin, routes, records = _model(model)
    windows = _projection(complete, duration, origin, routes, records)
    counts = {
        assessment: sum(w["assessment"] == assessment for w in windows)
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
        "traffic_complete": complete,
        "window_ms": duration,
        "window_origin_ms": origin,
        "windows": windows,
        "summary": {
            "window_count": len(windows),
            "record_count": len(records),
            "admitted_count": sum(w["observed_admitted"] for w in windows),
            "rate_limited_count": sum(w["observed_rate_limited"] for w in windows),
            **counts,
        },
        **_FLAGS,
        "effects": _EFFECTS,
        "limitations": _LIMITATIONS,
    }
    digest = _digest(_canonical({"domain": DOMAIN, "analysis": document}).encode("ascii"))
    document["report_id"] = "ARL-" + digest[7:39].upper()
    document["report_sha256"] = digest
    _validate_tree(document, maximum=MAX_REPORT_BYTES)
    _validate_report(document)
    return ApiRateLimitReport(_canonical(document))


def analyze_supplied_api_rate_limit(model: Any) -> ApiRateLimitReport:
    """Analyze one exact native source envelope for inert catalog dispatch."""
    item = _exact(model, {"source_id", "source"}, "supplied rate-limit model")
    _validate_tree(item, maximum=MAX_SOURCE_BYTES)
    return analyze_api_rate_limit(
        source_content=_canonical(item["source"]).encode("ascii"),
        source_id=item["source_id"],
    )


def verify_api_rate_limit(
    report: ApiRateLimitReport,
    *,
    source_content: bytes,
    source_id: str,
) -> ApiRateLimitReport:
    """Rebuild the report from exact source bytes and compare canonically."""
    if type(report) is not ApiRateLimitReport:
        raise ApiRateLimitError("report must be the exact report family")
    loaded = ApiRateLimitReport.from_json(report.to_json())
    expected = analyze_api_rate_limit(source_content=source_content, source_id=source_id)
    if loaded.to_json() != expected.to_json():
        raise ApiRateLimitError("report does not replay from supplied source")
    return expected


def component_fixture() -> dict[str, Any]:
    """Return one fresh, inert fixed-window model."""
    return {
        "schema_version": SCHEMA_VERSION,
        "traffic_complete": True,
        "policy": {
            "window_ms": 1_000,
            "window_origin_ms": 0,
            "route_limits": [{"route_id": "lookup", "max_admitted_requests": 2}],
        },
        "records": [
            {
                "event_id": "e1",
                "timestamp_ms": 100,
                "subject_id": "test-user",
                "route_id": "lookup",
                "outcome": "admitted",
            },
            {
                "event_id": "e2",
                "timestamp_ms": 200,
                "subject_id": "test-user",
                "route_id": "lookup",
                "outcome": "admitted",
            },
            {
                "event_id": "e3",
                "timestamp_ms": 300,
                "subject_id": "test-user",
                "route_id": "lookup",
                "outcome": "admitted",
            },
            {
                "event_id": "e4",
                "timestamp_ms": 400,
                "subject_id": "test-user",
                "route_id": "lookup",
                "outcome": "rate_limited",
            },
        ],
    }


__all__ = [
    "ApiRateLimitError",
    "ApiRateLimitReport",
    "analyze_api_rate_limit",
    "analyze_supplied_api_rate_limit",
    "verify_api_rate_limit",
    "component_fixture",
]
