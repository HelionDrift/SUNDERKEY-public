"""Offline comparison of supplied JSON bodies against a declared property write policy.

This leaf neither observes a request nor proves that a server accepted a change.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

PROFILE_ID = "AOE-GB-D06-S11"
CAPABILITY_ID = "army.gb.d06.s11"
VECTOR_ID = "AV-GB-D06-S11-01"
DOMAIN = "sunderkey.offline-property-authorization.v1"
SCHEMA_VERSION = "v1"
MAX_SOURCE_BYTES = 262_144
MAX_REPORT_BYTES = 524_288
MAX_NODES = 8_192
MAX_DEPTH = 32
MAX_STRING_BYTES = 16_384
MAX_PROPERTIES = 512
MAX_CHANGES = 2_048
_SOURCE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_ROLE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
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
    "body_provenance_authenticated": False,
    "policy_authenticated": False,
    "server_enforcement_observed": False,
    "finding_claimed": False,
    "positive_use_approved": False,
    "qualification_claimed": False,
}
_LIMITATIONS = [
    "Before and after JSON bodies, actor role and policy completeness are caller declarations.",
    "A changed prohibited property is a supplied-data conflict, not a verified server flaw.",
    "No request, response, target state, identity, policy source or enforcement is authenticated.",
    "Only exact JSON Pointer paths and property writes in the declared role are modeled.",
    "Unlisted paths are uncertain unless the caller declares the property policy complete.",
    "No target access, finding, authority, qualification or live use is established.",
]


class PropertyAuthorizationError(ValueError):
    """Closed input, resource bound or replay validation failed."""


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys or any(type(k) is not str for k in value):
        raise PropertyAuthorizationError(f"{label} fields are invalid")
    return value


def _source_id(value: Any) -> str:
    if type(value) is not str or _SOURCE_ID.fullmatch(value) is None:
        raise PropertyAuthorizationError("source ID must be bounded native ASCII text")
    return value


def _role(value: Any) -> str:
    if type(value) is not str or _ROLE.fullmatch(value) is None:
        raise PropertyAuthorizationError("role must be bounded native ASCII text")
    return value


def _sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PropertyAuthorizationError("duplicate JSON key")
        result[key] = value
    return result


def _integer(token: str) -> int:
    if len(token) > 20 or len(token.lstrip("-")) > 19:
        raise PropertyAuthorizationError("JSON integer exceeds signed64 bound")
    value = int(token)
    if not -(1 << 63) <= value < (1 << 63):
        raise PropertyAuthorizationError("JSON integer exceeds signed64 bound")
    return value


def _unsupported_number(_token: str) -> None:
    raise PropertyAuthorizationError("floating and nonfinite numbers are unsupported")


def _validate_tree(value: Any, *, byte_limit: int) -> None:
    stack = [(value, 1)]
    count = 0
    while stack:
        item, depth = stack.pop()
        count += 1
        if count > MAX_NODES or depth > MAX_DEPTH:
            raise PropertyAuthorizationError("JSON node or depth bound exceeded")
        kind = type(item)
        if kind is dict:
            if count + len(stack) + 2 * len(item) > MAX_NODES:
                raise PropertyAuthorizationError("JSON node bound exceeded")
            for key, child in item.items():
                if type(key) is not str:
                    raise PropertyAuthorizationError("JSON keys must be native text")
                stack.append((child, depth + 1))
                stack.append((key, depth + 1))
        elif kind is list:
            if count + len(stack) + len(item) > MAX_NODES:
                raise PropertyAuthorizationError("JSON node bound exceeded")
            stack.extend((child, depth + 1) for child in item)
        elif kind is str:
            if len(item.encode("utf-8", errors="surrogatepass")) > MAX_STRING_BYTES or any(
                0xD800 <= ord(char) <= 0xDFFF for char in item
            ):
                raise PropertyAuthorizationError("JSON string is unsupported or too long")
        elif kind is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise PropertyAuthorizationError("JSON integer exceeds signed64 bound")
        elif kind not in (bool, type(None)):
            raise PropertyAuthorizationError("unsupported JSON value family")
    if len(_canonical(value).encode("ascii")) > byte_limit:
        raise PropertyAuthorizationError("canonical JSON byte bound exceeded")


def _decode(content: bytes, *, maximum: int) -> Any:
    if type(content) is not bytes or not content or len(content) > maximum:
        raise PropertyAuthorizationError("source must be bounded nonempty native bytes")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PropertyAuthorizationError("source must be UTF-8") from exc
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
                raise PropertyAuthorizationError("pre-decoder depth bound exceeded")
        elif char in "]}":
            nesting -= 1
            if nesting < 0:
                raise PropertyAuthorizationError("malformed JSON nesting")
    if nesting != 0 or quoted:
        raise PropertyAuthorizationError("malformed JSON nesting")
    try:
        result = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_integer,
            parse_float=_unsupported_number,
            parse_constant=_unsupported_number,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, PropertyAuthorizationError):
            raise
        raise PropertyAuthorizationError("malformed JSON source") from exc
    _validate_tree(result, byte_limit=maximum)
    return result


def _pointer(path: Any) -> str:
    if type(path) is not str or not path.startswith("/") or len(path) > 1024:
        raise PropertyAuthorizationError("property path must be a bounded JSON Pointer")
    for segment in path[1:].split("/"):
        index = 0
        while index < len(segment):
            if segment[index] == "~":
                if index + 1 >= len(segment) or segment[index + 1] not in "01":
                    raise PropertyAuthorizationError("invalid JSON Pointer escape")
                index += 1
            index += 1
    return path


def _join(parent: str, key: str) -> str:
    return parent + "/" + key.replace("~", "~0").replace("/", "~1")


def _policy(document: Any) -> tuple[str, bool, dict[str, tuple[str, ...]]]:
    model = _exact(document, {"schema_version", "role", "complete", "properties"}, "policy")
    if model["schema_version"] != SCHEMA_VERSION or type(model["complete"]) is not bool:
        raise PropertyAuthorizationError("policy version or completeness is invalid")
    role = _role(model["role"])
    properties = model["properties"]
    if type(properties) is not list or len(properties) > MAX_PROPERTIES:
        raise PropertyAuthorizationError("policy properties are invalid or unbounded")
    mapping: dict[str, tuple[str, ...]] = {}
    for entry in properties:
        item = _exact(entry, {"path", "write_roles"}, "property rule")
        path = _pointer(item["path"])
        roles = item["write_roles"]
        if type(roles) is not list or len(roles) > 64:
            raise PropertyAuthorizationError("write roles are invalid or unbounded")
        named = tuple(_role(value) for value in roles)
        if len(set(named)) != len(named) or path in mapping:
            raise PropertyAuthorizationError("duplicate role or property rule")
        mapping[path] = named
    return role, model["complete"], mapping


_ABSENT = object()


def _change_paths(before: dict[str, Any], after: dict[str, Any]) -> list[tuple[str, str]]:
    changes: list[tuple[str, str]] = []
    stack: list[tuple[str, Any, Any, int]] = [("", before, after, 0)]
    while stack:
        path, old, new, depth = stack.pop()
        if depth > MAX_DEPTH:
            raise PropertyAuthorizationError("comparison depth bound exceeded")
        if type(old) is dict and type(new) is dict:
            for key in sorted(set(old) | set(new), reverse=True):
                stack.append(
                    (
                        _join(path, key),
                        old.get(key, _ABSENT),
                        new.get(key, _ABSENT),
                        depth + 1,
                    )
                )
            continue
        if old is _ABSENT or new is _ABSENT:
            kind = "added" if old is _ABSENT else "removed"
        elif type(old) is not type(new) or _canonical(old) != _canonical(new):
            kind = "replaced"
        else:
            continue
        changes.append((path, kind))
        if len(changes) > MAX_CHANGES:
            raise PropertyAuthorizationError("change count bound exceeded")
        if type(old) is dict:
            for key in sorted(old, reverse=True):
                stack.append((_join(path, key), old[key], _ABSENT, depth + 1))
        if type(new) is dict:
            for key in sorted(new, reverse=True):
                stack.append((_join(path, key), _ABSENT, new[key], depth + 1))
    return changes


@dataclass(frozen=True, slots=True)
class PropertyAuthorizationReport:
    """Immutable canonical report; replay is required to establish its derivation."""

    _json: str

    def __post_init__(self) -> None:
        if type(self) is not PropertyAuthorizationReport:
            raise PropertyAuthorizationError("report must be the exact report family")
        if self._json != _checked_report_json(self._json):
            raise PropertyAuthorizationError("canonical report JSON is required")

    def to_json(self) -> str:
        if type(self) is not PropertyAuthorizationReport or self._json != (
            _checked_report_json(self._json)
        ):
            raise PropertyAuthorizationError("canonical exact report is required")
        return self._json

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.to_json())

    @classmethod
    def from_json(cls, content: str) -> PropertyAuthorizationReport:
        if cls is not PropertyAuthorizationReport:
            raise PropertyAuthorizationError("report must be the exact report family")
        return cls(_checked_report_json(content))


def _checked_report_json(content: Any) -> str:
    if type(content) is not str:
        raise PropertyAuthorizationError("report must be native JSON text")
    try:
        encoded = content.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise PropertyAuthorizationError("report must be UTF-8 JSON text") from exc
    document = _decode(encoded, maximum=MAX_REPORT_BYTES)
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
            "domain",
            "before_source",
            "after_source",
            "policy_source",
            "role",
            "policy_complete",
            "changes",
            "summary",
            "offline_only",
            "body_provenance_authenticated",
            "policy_authenticated",
            "server_enforcement_observed",
            "finding_claimed",
            "positive_use_approved",
            "qualification_claimed",
            "effects",
            "limitations",
            "report_id",
            "report_sha256",
        },
        "report",
    )
    for key, expected in {
        "schema_version": SCHEMA_VERSION,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "domain": DOMAIN,
        "effects": _EFFECTS,
        "limitations": _LIMITATIONS,
        **_FLAGS,
    }.items():
        if type(item[key]) is not type(expected) or item[key] != expected:
            raise PropertyAuthorizationError(f"report {key} is invalid")
    _role(item["role"])
    if type(item["policy_complete"]) is not bool:
        raise PropertyAuthorizationError("report policy completeness is invalid")
    for key in ("before_source", "after_source", "policy_source"):
        source = _exact(item[key], {"source_id", "sha256", "byte_count"}, key)
        _source_id(source["source_id"])
        if type(source["sha256"]) is not str or _SHA.fullmatch(source["sha256"]) is None:
            raise PropertyAuthorizationError("report source digest is invalid")
        if type(source["byte_count"]) is not int or not (
            1 <= source["byte_count"] <= MAX_SOURCE_BYTES
        ):
            raise PropertyAuthorizationError("report source byte count is invalid")
    if type(item["changes"]) is not list or len(item["changes"]) > MAX_CHANGES:
        raise PropertyAuthorizationError("report changes are invalid")
    seen = set()
    counts = {"declared_permitted": 0, "declared_prohibited": 0, "uncertain": 0}
    for change in item["changes"]:
        entry = _exact(change, {"path", "change", "assessment", "policy_basis"}, "change")
        path = _pointer(entry["path"])
        if (
            path in seen
            or type(entry["change"]) is not str
            or entry["change"] not in ("added", "removed", "replaced")
        ):
            raise PropertyAuthorizationError("duplicate or invalid change")
        seen.add(path)
        if (
            type(entry["assessment"]) is not str
            or entry["assessment"] not in counts
            or (
                type(entry["policy_basis"]) is not str
                or entry["policy_basis"]
                not in ("explicit_rule", "complete_default_deny", "incomplete_unlisted")
            )
        ):
            raise PropertyAuthorizationError("change assessment is invalid")
        counts[entry["assessment"]] += 1
    summary = _exact(item["summary"], {"changed_path_count", *counts}, "summary")
    if any(type(value) is not int for value in summary.values()) or summary != {
        "changed_path_count": len(seen),
        **counts,
    }:
        raise PropertyAuthorizationError("report summary is invalid")
    body = {key: value for key, value in item.items() if key not in ("report_id", "report_sha256")}
    digest = _sha(_canonical({"domain": DOMAIN, "analysis": body}).encode("ascii"))
    if item["report_sha256"] != digest or item["report_id"] != "PA-" + digest[7:39].upper():
        raise PropertyAuthorizationError("report address is invalid")


def analyze_property_authorization(
    *,
    before_content: bytes,
    after_content: bytes,
    policy_content: bytes,
    before_source_id: str,
    after_source_id: str,
    policy_source_id: str,
) -> PropertyAuthorizationReport:
    """Classify supplied body differences under one explicit role/property write policy."""
    identifiers = tuple(
        _source_id(v)
        for v in (
            before_source_id,
            after_source_id,
            policy_source_id,
        )
    )
    if len(set(identifiers)) != 3:
        raise PropertyAuthorizationError("source IDs must be distinct")
    before = _decode(before_content, maximum=MAX_SOURCE_BYTES)
    after = _decode(after_content, maximum=MAX_SOURCE_BYTES)
    policy = _decode(policy_content, maximum=MAX_SOURCE_BYTES)
    if type(before) is not dict or type(after) is not dict:
        raise PropertyAuthorizationError("before and after bodies must be JSON objects")
    role, complete, rules = _policy(policy)
    changes = []
    for path, kind in _change_paths(before, after):
        if path in rules:
            assessment = "declared_permitted" if role in rules[path] else "declared_prohibited"
            basis = "explicit_rule"
        elif complete:
            assessment, basis = "declared_prohibited", "complete_default_deny"
        else:
            assessment, basis = "uncertain", "incomplete_unlisted"
        changes.append(
            {
                "path": path,
                "change": kind,
                "assessment": assessment,
                "policy_basis": basis,
            }
        )
    counts = {
        key: sum(c["assessment"] == key for c in changes)
        for key in (
            "declared_permitted",
            "declared_prohibited",
            "uncertain",
        )
    }
    document = {
        "schema_version": SCHEMA_VERSION,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "domain": DOMAIN,
        "before_source": {
            "source_id": identifiers[0],
            "sha256": _sha(before_content),
            "byte_count": len(before_content),
        },
        "after_source": {
            "source_id": identifiers[1],
            "sha256": _sha(after_content),
            "byte_count": len(after_content),
        },
        "policy_source": {
            "source_id": identifiers[2],
            "sha256": _sha(policy_content),
            "byte_count": len(policy_content),
        },
        "role": role,
        "policy_complete": complete,
        "changes": changes,
        "summary": {"changed_path_count": len(changes), **counts},
        **_FLAGS,
        "effects": _EFFECTS,
        "limitations": _LIMITATIONS,
    }
    digest = _sha(_canonical({"domain": DOMAIN, "analysis": document}).encode("ascii"))
    document["report_id"] = "PA-" + digest[7:39].upper()
    document["report_sha256"] = digest
    _validate_tree(document, byte_limit=MAX_REPORT_BYTES)
    _validate_report(document)
    return PropertyAuthorizationReport(_canonical(document))


def analyze_supplied_property_authorization(model: Any) -> PropertyAuthorizationReport:
    """Run the byte-bound analysis over one exact native inert model."""
    item = _exact(
        model,
        {
            "before",
            "after",
            "policy",
            "before_source_id",
            "after_source_id",
            "policy_source_id",
        },
        "supplied property model",
    )
    _validate_tree(item, byte_limit=3 * MAX_SOURCE_BYTES)
    return analyze_property_authorization(
        before_content=_canonical(item["before"]).encode("ascii"),
        after_content=_canonical(item["after"]).encode("ascii"),
        policy_content=_canonical(item["policy"]).encode("ascii"),
        before_source_id=item["before_source_id"],
        after_source_id=item["after_source_id"],
        policy_source_id=item["policy_source_id"],
    )


def verify_property_authorization(
    report: PropertyAuthorizationReport,
    *,
    before_content: bytes,
    after_content: bytes,
    policy_content: bytes,
    before_source_id: str,
    after_source_id: str,
    policy_source_id: str,
) -> PropertyAuthorizationReport:
    """Rebuild a detached report from exact supplied source bytes and compare canonically."""
    if type(report) is not PropertyAuthorizationReport:
        raise PropertyAuthorizationError("report must be the exact report family")
    loaded = PropertyAuthorizationReport.from_json(report.to_json())
    expected = analyze_property_authorization(
        before_content=before_content,
        after_content=after_content,
        policy_content=policy_content,
        before_source_id=before_source_id,
        after_source_id=after_source_id,
        policy_source_id=policy_source_id,
    )
    if loaded.to_json() != expected.to_json():
        raise PropertyAuthorizationError("report does not replay from supplied sources")
    return expected


def component_fixture() -> dict[str, Any]:
    """Return fresh inert source models and IDs for a local demonstration."""
    return {
        "before": {"profile": {"display_name": "Ada", "role": "member"}},
        "after": {"profile": {"display_name": "Ada L", "role": "admin"}},
        "policy": {
            "schema_version": SCHEMA_VERSION,
            "role": "member",
            "complete": True,
            "properties": [
                {"path": "/profile/display_name", "write_roles": ["member", "admin"]},
                {"path": "/profile/role", "write_roles": ["admin"]},
            ],
        },
        "before_source_id": "synthetic:before",
        "after_source_id": "synthetic:after",
        "policy_source_id": "synthetic:policy",
    }


__all__ = [
    "PropertyAuthorizationError",
    "PropertyAuthorizationReport",
    "analyze_property_authorization",
    "analyze_supplied_property_authorization",
    "verify_property_authorization",
    "component_fixture",
]
