"""Inert projection of supplied browser message origin and listener decisions."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "browser_supplied_message_boundary_projection"
PROFILE_ID = "AOE-GB-D05-S15"
CAPABILITY_ID = "army.gb.d05.s15"
VECTOR_ID = "AV-GB-D05-S15-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D05-S15"
WAVE_ID = "IW2-015"
COMMANDER_ID = "AOE-GB-D05-CMD"
GROUP_OWNER_ID = "AOE-HQ-04"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-34"
BLUEPRINT_SHA256 = "sha256:ccb3eeabd1ad0f809e6ccc1f29f50509ac860e4b9bf2fbdbc9e25d8908e7c842"
DOMAIN = "sunderkey.offline-browser-message-boundary.v1"
MODEL_DOMAIN = "sunderkey.offline-browser-message-boundary-model.v1"
SEMANTICS_PROFILE = "declared-exact-origin-listener-projection.v1"
MAX_DOCUMENT_BYTES = 65_536
MAX_NATIVE_NODES = 8_192
MAX_NATIVE_DEPTH = 12
MAX_STRING_BYTES = 256
MAX_LISTENERS = 32
MAX_MESSAGES = 128
MAX_ACCEPTED_ORIGINS = 32
MAX_WORK = 1_000_000
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_ORIGIN = re.compile(r"(https?)://([a-z0-9.-]+)(?::([0-9]{1,5}))?\Z")
_PLACEHOLDER = "sha256:" + "0" * 64
_FLAGS = dict.fromkeys(
    (
        "source_authenticated",
        "browser_executed",
        "message_delivered",
        "listener_code_verified",
        "handler_effect_verified",
        "csrf_verified",
        "clickjacking_verified",
        "postmessage_exploit_verified",
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
    "listeners": MAX_LISTENERS,
    "messages": MAX_MESSAGES,
    "accepted_origins_per_listener": MAX_ACCEPTED_ORIGINS,
    "work_steps": MAX_WORK,
}
_LIMITATIONS = (
    "Origins, listener rules, sensitivity, payload trust and completeness are caller declarations.",
    "Only canonical ASCII HTTP(S) tuple origins and exact allowlists are modeled.",
    "Opaque origins, uncertain target origins and incomplete rules cannot yield a candidate.",
    "A candidate denotes a supplied cross-origin message path without a declared origin check.",
    "A candidate is not an observed delivery or exploit.",
    "Data validation, handler side effects, windows and frames are not modeled.",
    "CSRF and clickjacking are not modeled.",
    "No browser, JavaScript, payload, URL request, target, network, process or credential is used.",
    "No authority, qualification, positive use or live finding is established.",
)


class BrowserMessageBoundaryAnalysisError(ValueError):
    """A supplied model or report is outside the closed bounded contract."""


@dataclass(slots=True)
class _Work:
    count: int = 0

    def charge(self, amount: int) -> None:
        if self.count + amount > MAX_WORK:
            raise BrowserMessageBoundaryAnalysisError("Software work bound exhausted")
        self.count += amount


def _measure(value: Any, work: _Work | None = None) -> tuple[int, int]:
    size = nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal size, nodes
        nodes += 1
        if depth > MAX_NATIVE_DEPTH or nodes > MAX_NATIVE_NODES:
            raise BrowserMessageBoundaryAnalysisError("Native node/depth bound exhausted")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_STRING_BYTES or not all(32 <= ord(c) <= 126 for c in item):
                raise BrowserMessageBoundaryAnalysisError("Bounded printable ASCII string required")
            size += len(json.dumps(item, ensure_ascii=True))
        elif kind is bool:
            size += 4 if item else 5
        elif item is None:
            size += 4
        elif kind is int:
            if not -(2**63) <= item < 2**63:
                raise BrowserMessageBoundaryAnalysisError("Signed 64-bit integer required")
            size += len(str(item))
        elif kind in (dict, list):
            if id(item) in active:
                raise BrowserMessageBoundaryAnalysisError("Cyclic native document")
            active.add(id(item))
            size += 2 + len(item) * 2
            try:
                if kind is dict:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise BrowserMessageBoundaryAnalysisError(
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
            raise BrowserMessageBoundaryAnalysisError("Exact native JSON primitives required")
        if size > MAX_DOCUMENT_BYTES:
            raise BrowserMessageBoundaryAnalysisError("Document byte bound exhausted")

    visit(value, 1)
    if work is not None:
        work.charge(size + nodes)
    return size, nodes


def _serialize(value: Any, work: _Work | None = None) -> str:
    _measure(value, work)
    text = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    if len(text) > MAX_DOCUMENT_BYTES:
        raise BrowserMessageBoundaryAnalysisError("Serialized document byte bound exhausted")
    return text


def _decode(text: Any) -> Any:
    if type(text) is not str or not text or len(text) > MAX_DOCUMENT_BYTES or not text.isascii():
        raise BrowserMessageBoundaryAnalysisError("Bounded ASCII JSON required")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result: dict = {}
        for key, value in items:
            if key in result:
                raise BrowserMessageBoundaryAnalysisError("Duplicate JSON member")
            result[key] = value
        return result

    def integer(token: str) -> int:
        if len(token) > 20 or not re.fullmatch(r"-?(?:0|[1-9][0-9]{0,18})", token):
            raise BrowserMessageBoundaryAnalysisError("Raw integer bound failed")
        value = int(token)
        if not -(2**63) <= value < 2**63:
            raise BrowserMessageBoundaryAnalysisError("Signed 64-bit integer required")
        return value

    def unsupported(_: str) -> None:
        raise BrowserMessageBoundaryAnalysisError("Fractional or nonfinite number unsupported")

    try:
        value = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=integer,
            parse_float=unsupported,
            parse_constant=unsupported,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, BrowserMessageBoundaryAnalysisError):
            raise
        raise BrowserMessageBoundaryAnalysisError("Malformed supplied JSON") from exc
    _measure(value)
    return value


def _capture(value: Any, work: _Work | None = None) -> tuple[Any, str]:
    text = _serialize(value, work)
    return _decode(text), text


def _identity(value: Any) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise BrowserMessageBoundaryAnalysisError("Bounded identity required")
    return value


def _origin(value: Any) -> str:
    if type(value) is not str:
        raise BrowserMessageBoundaryAnalysisError("Tuple origin string required")
    match = _ORIGIN.fullmatch(value)
    if match is None:
        raise BrowserMessageBoundaryAnalysisError("Canonical ASCII HTTP(S) tuple origin required")
    scheme, host, raw_port = match.groups()
    if len(host) > 253 or any(
        not label or len(label) > 63 or label[0] == "-" or label[-1] == "-"
        for label in host.split(".")
    ):
        raise BrowserMessageBoundaryAnalysisError("Canonical DNS host required")
    if raw_port is not None:
        port = int(raw_port)
        if not 1 <= port <= 65535 or str(port) != raw_port:
            raise BrowserMessageBoundaryAnalysisError("Canonical port required")
        if (scheme, port) in (("https", 443), ("http", 80)):
            raise BrowserMessageBoundaryAnalysisError("Default port must be omitted")
    return value


def _validate_model(model: Any, work: _Work) -> tuple[dict, str]:
    owned, source_text = _capture(model, work)
    if type(owned) is not dict or owned.keys() != {
        "schema_version",
        "origins_complete",
        "listeners",
        "messages",
    }:
        raise BrowserMessageBoundaryAnalysisError("Exact closed model fields required")
    if type(owned["schema_version"]) is not int or owned["schema_version"] != 1:
        raise BrowserMessageBoundaryAnalysisError("Exact schema version 1 required")
    if type(owned["origins_complete"]) is not bool:
        raise BrowserMessageBoundaryAnalysisError("Exact origin completeness boolean required")
    listeners = owned["listeners"]
    messages = owned["messages"]
    if type(listeners) is not list or not 1 <= len(listeners) <= MAX_LISTENERS:
        raise BrowserMessageBoundaryAnalysisError("Bounded nonempty listeners required")
    if type(messages) is not list or not 1 <= len(messages) <= MAX_MESSAGES:
        raise BrowserMessageBoundaryAnalysisError("Bounded nonempty messages required")
    listener_ids: set[str] = set()
    for listener in listeners:
        work.charge(16)
        if type(listener) is not dict or listener.keys() != {
            "listener_id",
            "receiver_origin",
            "origin_rule",
            "accepted_origins",
            "handler_sensitive",
            "semantics_complete",
        }:
            raise BrowserMessageBoundaryAnalysisError("Exact closed listener fields required")
        listener_id = _identity(listener["listener_id"])
        if listener_id in listener_ids:
            raise BrowserMessageBoundaryAnalysisError("Duplicate listener identity")
        listener_ids.add(listener_id)
        _origin(listener["receiver_origin"])
        if listener["origin_rule"] not in ("exact_allowlist", "none", "unknown"):
            raise BrowserMessageBoundaryAnalysisError("Supported exact origin rule required")
        accepted = listener["accepted_origins"]
        if type(accepted) is not list or len(accepted) > MAX_ACCEPTED_ORIGINS:
            raise BrowserMessageBoundaryAnalysisError("Bounded accepted origins required")
        for item in accepted:
            _origin(item)
        if accepted != sorted(set(accepted)):
            raise BrowserMessageBoundaryAnalysisError("Sorted unique accepted origins required")
        if listener["origin_rule"] != "exact_allowlist" and accepted:
            raise BrowserMessageBoundaryAnalysisError("Only an exact rule may list origins")
        if (
            type(listener["handler_sensitive"]) is not bool
            or type(listener["semantics_complete"]) is not bool
        ):
            raise BrowserMessageBoundaryAnalysisError("Exact listener booleans required")
    message_ids: set[str] = set()
    for message in messages:
        work.charge(16)
        if type(message) is not dict or message.keys() != {
            "message_id",
            "listener_id",
            "sender_origin",
            "target_origin",
            "payload_trust",
            "context_complete",
        }:
            raise BrowserMessageBoundaryAnalysisError("Exact closed message fields required")
        message_id = _identity(message["message_id"])
        if message_id in message_ids:
            raise BrowserMessageBoundaryAnalysisError("Duplicate message identity")
        message_ids.add(message_id)
        if _identity(message["listener_id"]) not in listener_ids:
            raise BrowserMessageBoundaryAnalysisError("Unknown listener identity")
        if message["sender_origin"] != "null":
            _origin(message["sender_origin"])
        if message["target_origin"] not in ("*", "unknown"):
            _origin(message["target_origin"])
        if message["payload_trust"] not in ("untrusted", "trusted", "unknown"):
            raise BrowserMessageBoundaryAnalysisError("Supported payload trust required")
        if type(message["context_complete"]) is not bool:
            raise BrowserMessageBoundaryAnalysisError("Exact message completeness boolean required")
    if [row["listener_id"] for row in listeners] != sorted(listener_ids):
        raise BrowserMessageBoundaryAnalysisError("Sorted listeners required")
    if [row["message_id"] for row in messages] != sorted(message_ids):
        raise BrowserMessageBoundaryAnalysisError("Sorted messages required")
    return owned, source_text


def _observe(message: dict, listener: dict, origins_complete: bool) -> dict:
    reasons: list[str] = []
    if not origins_complete:
        reasons.append("origins_incomplete")
    if not listener["semantics_complete"]:
        reasons.append("listener_semantics_incomplete")
    if not message["context_complete"]:
        reasons.append("message_context_incomplete")
    if message["sender_origin"] == "null":
        reasons.append("opaque_sender_origin")
    if message["target_origin"] == "unknown":
        reasons.append("target_origin_unknown")
    if message["payload_trust"] == "unknown":
        reasons.append("payload_trust_unknown")
    if listener["origin_rule"] == "unknown":
        reasons.append("listener_origin_rule_unknown")
    sender = message["sender_origin"]
    receiver = listener["receiver_origin"]
    target = message["target_origin"]
    if reasons:
        outcome = "unknown"
    elif target != "*" and target != receiver:
        outcome = "not_delivered_under_supplied_model"
    elif listener["origin_rule"] == "exact_allowlist":
        outcome = (
            "accepted_by_declared_policy"
            if sender in listener["accepted_origins"]
            else "rejected_by_declared_policy"
        )
    elif sender == receiver:
        outcome = "accepted_same_origin_under_supplied_model"
    elif listener["handler_sensitive"] and message["payload_trust"] == "untrusted":
        outcome = "candidate_cross_origin_message_without_check"
    else:
        outcome = "accepted_under_supplied_model"
    return {
        "message_id": message["message_id"],
        "listener_id": message["listener_id"],
        "sender_origin": sender,
        "receiver_origin": receiver,
        "target_origin": target,
        "outcome": outcome,
        "uncertainty": reasons,
    }


def _address(domain: str, text: str) -> str:
    return "sha256:" + hashlib.sha256((domain + "\n" + text).encode("ascii")).hexdigest()


def _derive(model: Any) -> dict:
    work = _Work()
    owned, source_text = _validate_model(model, work)
    listeners = {item["listener_id"]: item for item in owned["listeners"]}
    observations = [
        _observe(message, listeners[message["listener_id"]], owned["origins_complete"])
        for message in owned["messages"]
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
        "message_count": len(observations),
        "candidate_count": sum(
            row["outcome"] == "candidate_cross_origin_message_without_check" for row in observations
        ),
        "unknown_count": sum(row["outcome"] == "unknown" for row in observations),
        "message_observations": observations,
        "bounds": dict(_BOUNDS),
        "flags": dict(_FLAGS),
        "effects": dict(_EFFECTS),
        "limitations": list(_LIMITATIONS),
    }
    body_text = _serialize(body, work)
    work.charge(len(DOMAIN) + len(MODEL_DOMAIN) + len(source_text) + len(body_text))
    digest = _address(DOMAIN, body_text)
    body["analysis_id"] = "BMB-" + digest[7:39].upper()
    body["analysis_sha256"] = digest
    _serialize(body, work)
    return body


def _replay(document: Any) -> dict:
    owned, text = _capture(document)
    if type(owned) is not dict or "source_model" not in owned:
        raise BrowserMessageBoundaryAnalysisError("Source-bearing report required")
    expected = _derive(owned["source_model"])
    if text != _serialize(expected):
        raise BrowserMessageBoundaryAnalysisError("Report does not replay embedded source")
    return expected


@dataclass(frozen=True, slots=True, init=False)
class BrowserMessageBoundaryAnalysis:
    """Detached supplied-data projection, never live browser evidence."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        object.__setattr__(self, "_document_json", _serialize(_replay(document)))

    @classmethod
    def from_dict(cls, document: Any) -> BrowserMessageBoundaryAnalysis:
        return cls(document)

    @classmethod
    def from_json(cls, content: Any) -> BrowserMessageBoundaryAnalysis:
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


def analyze_supplied_browser_message_boundary(model: Any) -> BrowserMessageBoundaryAnalysis:
    """Project only supplied listener and message declarations."""
    return BrowserMessageBoundaryAnalysis(_derive(model))


def analyze_supplied_browser_message_boundary_bytes(
    *, model_bytes: Any
) -> BrowserMessageBoundaryAnalysis:
    """Accept bounded ASCII JSON bytes without reading a resource."""
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_DOCUMENT_BYTES:
        raise BrowserMessageBoundaryAnalysisError("Bounded exact native model bytes required")
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise BrowserMessageBoundaryAnalysisError("ASCII model bytes required") from exc
    return analyze_supplied_browser_message_boundary(_decode(text))


def verify_supplied_browser_message_boundary_analysis(
    report: Any, *, model: Any
) -> BrowserMessageBoundaryAnalysis:
    """Replay a report against separately supplied original premises."""
    if type(report) is not BrowserMessageBoundaryAnalysis:
        raise BrowserMessageBoundaryAnalysisError("Exact native report family required")
    expected = _derive(model)
    if _serialize(report.to_dict()) != _serialize(expected):
        raise BrowserMessageBoundaryAnalysisError(
            "Report differs from separately supplied originals"
        )
    return BrowserMessageBoundaryAnalysis(expected)


def component_fixture() -> dict:
    """Fresh synthetic unchecked, exact-policy, target-mismatch and opaque cases."""
    return {
        "schema_version": 1,
        "origins_complete": True,
        "listeners": [
            {
                "listener_id": "checked",
                "receiver_origin": "https://app.example",
                "origin_rule": "exact_allowlist",
                "accepted_origins": ["https://partner.example"],
                "handler_sensitive": True,
                "semantics_complete": True,
            },
            {
                "listener_id": "unchecked",
                "receiver_origin": "https://app.example",
                "origin_rule": "none",
                "accepted_origins": [],
                "handler_sensitive": True,
                "semantics_complete": True,
            },
        ],
        "messages": [
            {
                "message_id": "candidate",
                "listener_id": "unchecked",
                "sender_origin": "https://other.example",
                "target_origin": "https://app.example",
                "payload_trust": "untrusted",
                "context_complete": True,
            },
            {
                "message_id": "checked-partner",
                "listener_id": "checked",
                "sender_origin": "https://partner.example",
                "target_origin": "*",
                "payload_trust": "untrusted",
                "context_complete": True,
            },
            {
                "message_id": "mismatched-target",
                "listener_id": "unchecked",
                "sender_origin": "https://other.example",
                "target_origin": "https://wrong.example",
                "payload_trust": "untrusted",
                "context_complete": True,
            },
            {
                "message_id": "opaque-sender",
                "listener_id": "unchecked",
                "sender_origin": "null",
                "target_origin": "https://app.example",
                "payload_trust": "untrusted",
                "context_complete": True,
            },
        ],
    }


__all__ = [
    "BrowserMessageBoundaryAnalysisError",
    "BrowserMessageBoundaryAnalysis",
    "analyze_supplied_browser_message_boundary",
    "analyze_supplied_browser_message_boundary_bytes",
    "verify_supplied_browser_message_boundary_analysis",
    "component_fixture",
]
