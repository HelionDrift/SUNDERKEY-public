"""Bounded Android component declaration arithmetic over supplied merged metadata.

This is not a manifest/APK parser, installation test or component access check.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "android_supplied_component_declarations"
PROFILE_ID = "AOE-GB-D08-S03"
CAPABILITY_ID = "army.gb.d08.s03"
VECTOR_ID = "AV-GB-D08-S03-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D08-S03"
WAVE_ID = "IW2-007"
COMMANDER_ID = "AOE-GB-D08-CMD"
GROUP_OWNER_ID = "AOE-HQ-04"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:85aad60ac63ea5f31466de3fcbc888d6ce67b9ec1358e231de7ee8a34709031b"
MODEL_DOMAIN = "sunderkey.offline-android-component-model.v1"
DOMAIN = "sunderkey.offline-android-component-analysis.v1"
SEMANTICS_PROFILE = "aosp-s-exported-enabled-declarations.v1"
MAX_DOCUMENT_BYTES = 1_048_576
MAX_NATIVE_NODES = 32_768
MAX_NATIVE_DEPTH = 16
MAX_STRING_BYTES = 512
MAX_COMPONENTS = 1_024
MAX_WORK = 8_388_608
MIN_INTEGER = -(2**63)
MAX_INTEGER = 2**63 - 1
MAX_TARGET_SDK = 2**31 - 1
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_PLACEHOLDER = "sha256:" + "0" * 64
_MODEL_FIELDS = {
    "schema_version",
    "source_id",
    "projection_complete",
    "target_sdk",
    "application_enabled",
    "components",
}
_COMPONENT_FIELDS = {"component_id", "kind", "enabled", "exported", "has_intent_filters"}
_FLAGS = {
    name: False
    for name in (
        "source_authenticated",
        "merged_projection_verified",
        "target_sdk_verified",
        "installability_verified",
        "runtime_enabled_state_verified",
        "ipc_access_verified",
        "permission_analysis_performed",
        "vulnerability_claimed",
        "positive_use_approved",
        "qualification_claimed",
    )
}
_EFFECTS = {
    name: "none"
    for name in (
        "apk_read",
        "xml_parsing",
        "manifest_merge",
        "installation",
        "component_toggle",
        "ipc",
        "network",
        "credential",
        "provider",
        "execution",
        "authority",
        "qualification",
    )
}
_BOUNDS = {
    "maximum_document_bytes": MAX_DOCUMENT_BYTES,
    "maximum_native_nodes": MAX_NATIVE_NODES,
    "maximum_native_depth": MAX_NATIVE_DEPTH,
    "maximum_string_bytes": MAX_STRING_BYTES,
    "maximum_components": MAX_COMPONENTS,
    "maximum_work_units_per_reconstruction": MAX_WORK,
}
_SOURCE_PROFILE = {
    "exported_rule_commit": "c4e90ac06ad3e0fd2af9e3864742e2d1199a8cdd",
    "activity_receiver_parser_commit": "ff4060f5a59b787139570d733712fae34283ed6c",
    "service_parser_commit": "380f9be2ee11a8caa2f5eb053cdcd3ea88c93545",
    "enabled_parser_tag": "android-12.0.0_r1",
    "explicit_exported_target_sdk_threshold": 31,
}
_LIMITATIONS = (
    "Inputs are declared merged metadata, not authenticated APK or manifest evidence.",
    "Null enabled/exported attributes mean declared absence, not unavailable projection.",
    "Null target SDK means unavailable target premise; absent SDK is not defaulted.",
    "Intent-filter presence means retained formed filters, not arbitrary raw XML elements.",
    "Only activities, services and static receivers are modeled; aliases/providers are excluded.",
    "Enabled/exported values are declarations, not runtime state, installation or IPC permission.",
    "The pinned parser subset excludes platform compatibility overrides "
    "and all other manifest checks.",
    "No intent resolution, permissions, merging, toggles, signature, "
    "vulnerability or qualification proof.",
    "Metadata exports replay content; source verification needs the separate original model.",
)


class AndroidComponentAnalysisError(ValueError):
    """Invalid or out-of-budget supplied component metadata."""


@dataclass(slots=True)
class _Work:
    count: int = 0

    def charge(self, amount: int) -> None:
        self.count += amount
        if self.count > MAX_WORK:
            raise AndroidComponentAnalysisError("Cumulative software work bound")


def _measure(value: Any, work: _Work | None = None) -> tuple[int, int]:
    """Charge repeated trees, exact printable ASCII JSON costs and keys before copying."""
    nodes = 0
    size = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes, size
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise AndroidComponentAnalysisError("Native node/depth bound")
        kind = type(item)
        if item is None:
            size += 4
        elif kind is bool:
            size += 4 if item else 5
        elif kind is int:
            if not MIN_INTEGER <= item <= MAX_INTEGER:
                raise AndroidComponentAnalysisError("Native signed64 integer bound")
            size += len(str(item))
        elif kind is str:
            if len(item) > MAX_STRING_BYTES:
                raise AndroidComponentAnalysisError("Native string byte bound")
            size += 2
            for character in item:
                code = ord(character)
                if not 32 <= code <= 126:
                    raise AndroidComponentAnalysisError("Printable ASCII metadata required")
                size += 2 if character in {'"', "\\"} else 1
        elif kind in (dict, list):
            identity = id(item)
            if identity in active:
                raise AndroidComponentAnalysisError("Cyclic native metadata")
            children = 2 * len(item) if kind is dict else len(item)
            if children + nodes > MAX_NATIVE_NODES:
                raise AndroidComponentAnalysisError("Queued native node bound")
            size += 2 + max(0, len(item) - 1)
            active.add(identity)
            if kind is dict:
                size += len(item)
                for key, child in item.items():
                    if type(key) is not str:
                        raise AndroidComponentAnalysisError("Exact native string keys required")
                    visit(key, depth + 1)
                    visit(child, depth + 1)
            else:
                for child in item:
                    visit(child, depth + 1)
            active.remove(identity)
        else:
            raise AndroidComponentAnalysisError("Exact native JSON metadata required")
        if size > MAX_DOCUMENT_BYTES:
            raise AndroidComponentAnalysisError("Native document byte bound")

    visit(value, 1)
    if work is not None:
        work.charge(size + nodes)
    return size, nodes


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _serialize(value: Any, work: _Work | None = None) -> str:
    _measure(value, work)
    return _canonical(value)


def _capture(value: Any, work: _Work | None = None) -> tuple[Any, str]:
    text = _serialize(value, work)
    return json.loads(text), text


def _integer(text: str) -> int:
    if len(text) > 20 or _INTEGER.fullmatch(text) is None:
        raise AndroidComponentAnalysisError("Raw integer lexical bound")
    number = int(text)
    if not MIN_INTEGER <= number <= MAX_INTEGER:
        raise AndroidComponentAnalysisError("Raw signed64 integer bound")
    return number


def _decode(text: Any) -> Any:
    if type(text) is not str or not text or len(text) > MAX_DOCUMENT_BYTES:
        raise AndroidComponentAnalysisError("Bounded native raw JSON string required")
    if not text.isascii():
        raise AndroidComponentAnalysisError("ASCII raw JSON required")
    index = 0
    depth = 0
    nodes = 0
    while index < len(text):
        character = text[index]
        if character in " \t\r\n,:]}":
            if character in "]}":
                depth -= 1
                if depth < 0:
                    raise AndroidComponentAnalysisError("Malformed raw JSON depth")
            index += 1
            continue
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth + 1 > MAX_NATIVE_DEPTH:
            raise AndroidComponentAnalysisError("Raw node/depth bound before decoding")
        if character in "[{":
            depth += 1
            index += 1
        elif character == '"':
            index += 1
            length = 0
            while index < len(text) and text[index] != '"':
                code = ord(text[index])
                if text[index] == "\\":
                    index += 1
                    if index >= len(text):
                        raise AndroidComponentAnalysisError("Incomplete raw string escape")
                    if text[index] == "u":
                        digits = text[index + 1 : index + 5]
                        if len(digits) != 4 or any(
                            digit not in "0123456789abcdefABCDEF" for digit in digits
                        ):
                            raise AndroidComponentAnalysisError("Malformed raw Unicode escape")
                        code = int(digits, 16)
                        if not 32 <= code <= 126:
                            raise AndroidComponentAnalysisError("Printable ASCII escapes required")
                        index += 4
                    elif text[index] not in '\\"/':
                        raise AndroidComponentAnalysisError("Unsupported raw string escape")
                elif not 32 <= code <= 126:
                    raise AndroidComponentAnalysisError("Printable ASCII raw strings required")
                length += 1
                if length > MAX_STRING_BYTES:
                    raise AndroidComponentAnalysisError("Raw string byte bound before decoding")
                index += 1
            if index >= len(text):
                raise AndroidComponentAnalysisError("Incomplete raw JSON string")
            index += 1
        else:
            start = index
            while index < len(text) and text[index] not in ' \t\r\n,:]}[{"':
                index += 1
            token = text[start:index]
            if token not in ("true", "false", "null"):
                _integer(token)
            if start == index:
                raise AndroidComponentAnalysisError("Malformed raw JSON token")
    if depth != 0:
        raise AndroidComponentAnalysisError("Incomplete raw JSON containers")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        document = {}
        for key, value in items:
            if key in document:
                raise AndroidComponentAnalysisError("Duplicate raw JSON key")
            document[key] = value
        return document

    def unsupported(_: str) -> None:
        raise AndroidComponentAnalysisError("Native signed64 JSON integers only")

    try:
        result = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=_integer,
            parse_float=unsupported,
            parse_constant=unsupported,
        )
    except (json.JSONDecodeError, RecursionError) as error:
        raise AndroidComponentAnalysisError("Malformed bounded raw JSON") from error
    _measure(result)
    return result


def _identifier(value: Any) -> None:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise AndroidComponentAnalysisError("Bounded native declared identity required")


def _nullable_boolean(value: Any) -> None:
    if value is not None and type(value) is not bool:
        raise AndroidComponentAnalysisError("Exact native boolean or declared absence required")


def _validate_model(model: Any, work: _Work) -> tuple[dict, str]:
    owned, text = _capture(model, work)
    if type(owned) is not dict or owned.keys() != _MODEL_FIELDS:
        raise AndroidComponentAnalysisError("Exact closed merged projection fields required")
    if type(owned["schema_version"]) is not int or owned["schema_version"] != 1:
        raise AndroidComponentAnalysisError("Exact native schema version 1 required")
    _identifier(owned["source_id"])
    if type(owned["projection_complete"]) is not bool:
        raise AndroidComponentAnalysisError("Exact native projection completeness required")
    _nullable_boolean(owned["application_enabled"])
    sdk = owned["target_sdk"]
    if sdk is not None and (type(sdk) is not int or not 1 <= sdk <= MAX_TARGET_SDK):
        raise AndroidComponentAnalysisError(
            "Positive native target SDK or unavailable null required"
        )
    components = owned["components"]
    if type(components) is not list or len(components) > MAX_COMPONENTS:
        raise AndroidComponentAnalysisError("Bounded native component array required")
    identities: set[str] = set()
    for component in components:
        work.charge(1 + len(_COMPONENT_FIELDS))
        if type(component) is not dict or component.keys() != _COMPONENT_FIELDS:
            raise AndroidComponentAnalysisError("Exact closed component fields required")
        _identifier(component["component_id"])
        if component["component_id"] in identities:
            raise AndroidComponentAnalysisError("Duplicate declared component identity")
        identities.add(component["component_id"])
        kind = component["kind"]
        if type(kind) is not str or kind not in {"activity", "service", "receiver"}:
            raise AndroidComponentAnalysisError("Supported native component kind required")
        _nullable_boolean(component["enabled"])
        _nullable_boolean(component["exported"])
        if type(component["has_intent_filters"]) is not bool:
            raise AndroidComponentAnalysisError("Exact native retained-filter presence required")
    return owned, text


def _observation(model: dict, component: dict, work: _Work) -> dict:
    work.charge(40)
    row = {
        "component_id": component["component_id"],
        "kind": component["kind"],
        "application_enabled_attribute": model["application_enabled"],
        "component_enabled_attribute": component["enabled"],
        "exported_attribute": component["exported"],
        "has_intent_filters": component["has_intent_filters"],
        "application_enabled_defaulted": model["application_enabled"] is None,
        "component_enabled_defaulted": component["enabled"] is None,
        "declared_enabled": None,
        "declared_exported": None,
        "requires_explicit_exported": None,
        "explicit_exported_requirement_satisfied": None,
        "declared_enabled_and_exported": None,
        "exported_resolution": "projection_unavailable",
        "outcome": "unassessed",
        "reasons": [],
    }
    if not model["projection_complete"]:
        row["reasons"].append("merged_projection_incomplete")
        return row
    row["declared_enabled"] = (
        model["application_enabled"] is not False and component["enabled"] is not False
    )
    sdk = model["target_sdk"]
    filters = component["has_intent_filters"]
    exported = component["exported"]
    required = (sdk >= 31 if sdk is not None else None) if filters else False
    row["requires_explicit_exported"] = required
    if exported is not None:
        row["declared_exported"] = exported
        row["exported_resolution"] = "explicit_attribute"
        row["explicit_exported_requirement_satisfied"] = True
    elif not filters:
        row["declared_exported"] = False
        row["exported_resolution"] = "default_false_no_retained_filters"
        row["explicit_exported_requirement_satisfied"] = True
    elif required is False:
        row["declared_exported"] = True
        row["exported_resolution"] = "pre31_retained_filter_default_true"
        row["explicit_exported_requirement_satisfied"] = True
    elif required is True:
        row["exported_resolution"] = "sdk31_explicit_attribute_required"
        row["explicit_exported_requirement_satisfied"] = False
        row["outcome"] = "missing_required_exported_declaration"
        row["reasons"].append("sdk31_filter_requires_explicit_exported")
        return row
    else:
        row["exported_resolution"] = "target_sdk_unavailable"
        row["reasons"].append("target_sdk_unavailable_for_filter_default")
        return row
    row["declared_enabled_and_exported"] = row["declared_enabled"] and row["declared_exported"]
    row["outcome"] = "declaration_subset_resolved"
    return row


def _address(domain: str, text: str) -> str:
    return "sha256:" + hashlib.sha256((domain + "\n" + text).encode("ascii")).hexdigest()


def _derive(model: Any) -> dict:
    work = _Work()
    owned, source_text = _validate_model(model, work)
    rows: list[dict] = []
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
        "parser_source_profile": dict(_SOURCE_PROFILE),
        "source_model": owned,
        "source_model_sha256": _PLACEHOLDER,
        "component_count": len(owned["components"]),
        "component_observations": rows,
        "bounds": dict(_BOUNDS),
        "flags": dict(_FLAGS),
        "effects": dict(_EFFECTS),
        "limitations": list(_LIMITATIONS),
        "analysis_id": "ACD-" + "0" * 32,
        "analysis_sha256": _PLACEHOLDER,
    }
    size, nodes = _measure(body, work)
    for component in owned["components"]:
        row = _observation(owned, component, work)
        row_size, row_nodes = _measure(row, work)
        row_size += 1 if rows else 0
        if size + row_size > MAX_DOCUMENT_BYTES or nodes + row_nodes > MAX_NATIVE_NODES:
            raise AndroidComponentAnalysisError("Cumulative report bound before retention")
        size += row_size
        nodes += row_nodes
        rows.append(row)
    report_size, report_nodes = _measure(body, work)
    # Reserve complete result serialization, equality and bounded replay/export passes
    # before hashing either source or result. Fixed-width addresses were retained above.
    work.charge(12 * (report_size + report_nodes))
    del body["analysis_id"]
    del body["analysis_sha256"]
    hash_size, _ = _measure(body, work)
    work.charge(len(MODEL_DOMAIN) + 1 + len(source_text) + len(DOMAIN) + 1 + hash_size)
    body["source_model_sha256"] = _address(MODEL_DOMAIN, source_text)
    digest = _address(DOMAIN, _canonical(body))
    body["analysis_id"] = "ACD-" + digest[7:39].upper()
    body["analysis_sha256"] = digest
    return body


def _replay(document: Any) -> dict:
    owned, text = _capture(document)
    if type(owned) is not dict or "source_model" not in owned:
        raise AndroidComponentAnalysisError("Source-bearing native analysis required")
    expected = _derive(owned["source_model"])
    if text != _serialize(expected):
        raise AndroidComponentAnalysisError("Analysis does not exactly replay its embedded source")
    return expected


@dataclass(frozen=True, slots=True, init=False)
class AndroidComponentAnalysis:
    """Detached unsigned declarations; exports are not current device or access proof."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        object.__setattr__(self, "_document_json", _serialize(_replay(document)))

    @classmethod
    def from_dict(cls, document: Any) -> AndroidComponentAnalysis:
        return cls(document)

    @classmethod
    def from_json(cls, content: Any) -> AndroidComponentAnalysis:
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


def analyze_supplied_android_components(model: Any) -> AndroidComponentAnalysis:
    """Analyze only declared exported/enabled metadata without runtime effects."""
    return AndroidComponentAnalysis(_derive(model))


def analyze_supplied_android_components_bytes(*, model_bytes: Any) -> AndroidComponentAnalysis:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_DOCUMENT_BYTES:
        raise AndroidComponentAnalysisError("Bounded exact native model bytes required")
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as error:
        raise AndroidComponentAnalysisError("ASCII model bytes required") from error
    return analyze_supplied_android_components(_decode(text))


def verify_supplied_android_component_analysis(
    report: Any, *, model: Any
) -> AndroidComponentAnalysis:
    if type(report) is not AndroidComponentAnalysis:
        raise AndroidComponentAnalysisError("Exact native analysis family required")
    expected = _derive(model)
    if _serialize(expected) != _serialize(report.to_dict()):
        raise AndroidComponentAnalysisError("Analysis does not replay the separate original source")
    return AndroidComponentAnalysis(expected)


def component_fixture() -> dict:
    """Fresh wholly synthetic merged metadata, without a file or device source."""
    return {
        "schema_version": 1,
        "source_id": "synthetic-merged-declarations",
        "projection_complete": True,
        "target_sdk": 31,
        "application_enabled": None,
        "components": [
            {
                "component_id": "activity-explicit",
                "kind": "activity",
                "enabled": None,
                "exported": False,
                "has_intent_filters": True,
            },
            {
                "component_id": "disabled-service-missing",
                "kind": "service",
                "enabled": False,
                "exported": None,
                "has_intent_filters": True,
            },
            {
                "component_id": "receiver-no-filter",
                "kind": "receiver",
                "enabled": None,
                "exported": None,
                "has_intent_filters": False,
            },
        ],
    }


__all__ = [
    "AndroidComponentAnalysis",
    "AndroidComponentAnalysisError",
    "analyze_supplied_android_components",
    "analyze_supplied_android_components_bytes",
    "component_fixture",
    "verify_supplied_android_component_analysis",
]
