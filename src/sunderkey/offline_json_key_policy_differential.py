"""Compare finite duplicate-key policies on supplied flat JSON text."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "supplied_json_key_policy_differential"
PROFILE_ID = "AOE-GE-D23-S04"
CAPABILITY_ID = "army.ge.d23.s04"
VECTOR_ID = "AV-GE-D23-S04-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D23-S04"
WAVE_ID = "IW2-018"
COMMANDER_ID = "AOE-GE-D23-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:334503ac5d6320cc6a4fd1cf5069bcdb8b8289bb03c2f2e4a2ceb72e3a3662ef"
SEMANTICS_PROFILE = "supplied-flat-json-key-policies-v1"
DOMAIN = "sunderkey.offline-json-key-policy-differential.v1"
MAX_SOURCE_BYTES = 8_192
MAX_DOCUMENT_BYTES = 32_768
MAX_FIELDS = 256
MAX_FIELD_LENGTH = 128
MAX_VALUE_LENGTH = 256
MAX_NATIVE_NODES = 2_048
MAX_NATIVE_DEPTH = 10
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_EFFECTS = dict.fromkeys(
    (
        "authority", "credential", "execution", "filesystem", "network",
        "publication", "qualification", "target",
    ),
    "none",
)


class JsonKeyPolicyDifferentialError(ValueError):
    """A supplied JSON source or replay report was refused."""


class _Pairs(list):
    """Preserve decoded object pair order before any key policy is applied."""


def _canonical(value: Any) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise JsonKeyPolicyDifferentialError("Native structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_SOURCE_BYTES:
                raise JsonKeyPolicyDifferentialError("Native string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise JsonKeyPolicyDifferentialError("Native integer bound exceeded")
            return
        if family not in (dict, list):
            raise JsonKeyPolicyDifferentialError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise JsonKeyPolicyDifferentialError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise JsonKeyPolicyDifferentialError("Native JSON text keys are required")
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
        raise JsonKeyPolicyDifferentialError("Document byte bound exceeded")
    return encoded


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise JsonKeyPolicyDifferentialError(f"{label} fields are invalid")


def _integer(text: str) -> int:
    if len(text.lstrip("-")) > 19:
        raise JsonKeyPolicyDifferentialError("JSON integer exceeds bound")
    value = int(text)
    if not -(1 << 63) <= value < (1 << 63):
        raise JsonKeyPolicyDifferentialError("JSON integer exceeds bound")
    return value


def _unsupported_number(_text: str) -> None:
    raise JsonKeyPolicyDifferentialError("Only bounded JSON integers are supported")


def _parse_source(text: str) -> _Pairs:
    if type(text) is not str:
        raise JsonKeyPolicyDifferentialError("Source text must be native text")
    try:
        size = len(text.encode("utf-8"))
    except UnicodeError as exc:
        raise JsonKeyPolicyDifferentialError("Source text has invalid Unicode") from exc
    if not 1 <= size <= MAX_SOURCE_BYTES:
        raise JsonKeyPolicyDifferentialError("Source text byte bound exceeded")
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_Pairs,
            parse_int=_integer,
            parse_float=_unsupported_number,
            parse_constant=_unsupported_number,
        )
    except (ValueError, RecursionError) as exc:
        raise JsonKeyPolicyDifferentialError("Source is not supported flat JSON") from exc
    if type(parsed) is not _Pairs or not 1 <= len(parsed) <= MAX_FIELDS:
        raise JsonKeyPolicyDifferentialError("Only a bounded flat JSON object is supported")
    for key, value in parsed:
        if type(key) is not str or not 1 <= len(key) <= MAX_FIELD_LENGTH:
            raise JsonKeyPolicyDifferentialError("JSON field name is invalid")
        if any(
            ord(character) < 32 or ord(character) == 127 or 0xD800 <= ord(character) <= 0xDFFF
            for character in key
        ):
            raise JsonKeyPolicyDifferentialError("Control or surrogate field names are refused")
        if type(value) is str:
            if len(value) > MAX_VALUE_LENGTH:
                raise JsonKeyPolicyDifferentialError("JSON string value exceeds bound")
            if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
                raise JsonKeyPolicyDifferentialError("Surrogate string values are refused")
        elif type(value) not in (int, bool) and value is not None:
            raise JsonKeyPolicyDifferentialError("Nested or unsupported values are refused")
    return parsed


def _model(value: Any) -> tuple[dict, _Pairs]:
    model = json.loads(_canonical(value))
    _fields(model, {"schema_version", "semantics_profile", "source_id", "document_text"}, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise JsonKeyPolicyDifferentialError("Schema version is invalid")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise JsonKeyPolicyDifferentialError("Semantics profile is invalid")
    source_id = model["source_id"]
    if type(source_id) is not str or _ID.fullmatch(source_id) is None:
        raise JsonKeyPolicyDifferentialError("Source identifier is invalid")
    return model, _parse_source(model["document_text"])


def _derive(value: Any) -> dict:
    model, pairs = _model(value)
    occurrences: dict[str, list[Any]] = {}
    for key, item in pairs:
        occurrences.setdefault(key, []).append(item)
    fields = []
    for key, values in sorted(occurrences.items()):
        first, last = values[0], values[-1]
        if len(values) == 1:
            disposition = "single_occurrence"
        elif first == last and type(first) is type(last):
            disposition = "duplicate_same_endpoint_value"
        else:
            disposition = "candidate_first_last_difference"
        fields.append(
            {
                "field_name": key,
                "occurrence_count": len(values),
                "first_value": first,
                "last_value": last,
                "disposition": disposition,
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": model,
        "field_interpretations": fields,
        "flags": {
            "target_parser_behavior_verified": False,
            "polyglot_execution_verified": False,
            "parser_differential_exploitable": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Only flat JSON objects with scalar values and bounded integers are modeled.",
            "First and last occurrence policies are local finite interpretations.",
            "A differing key does not prove a target parser choice or a security impact.",
            "No file, parser service, credential, network, or target is accessed.",
        ],
    }
    digest = (
        "sha256:" + hashlib.sha256((DOMAIN + "\n" + _canonical(body)).encode("ascii")).hexdigest()
    )
    return json.loads(
        _canonical(
            {**body, "analysis_id": "JKD-" + digest[7:39].upper(), "analysis_sha256": digest}
        )
    )


@dataclass(frozen=True, slots=True, init=False)
class JsonKeyPolicyDifferential:
    """Immutable report replayed from supplied JSON text."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise JsonKeyPolicyDifferentialError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        if _canonical(document) != _canonical(expected):
            raise JsonKeyPolicyDifferentialError("Report differs from embedded source replay")
        object.__setattr__(self, "_document_json", _canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_json_key_policies(model: Any) -> JsonKeyPolicyDifferential:
    """Compare only local first and last occurrence interpretations."""
    return JsonKeyPolicyDifferential(_derive(model))


def verify_supplied_json_key_policies(
    report: Any, *, model: Any
) -> JsonKeyPolicyDifferential:
    if type(report) is not JsonKeyPolicyDifferential:
        raise JsonKeyPolicyDifferentialError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != _canonical(expected):
        raise JsonKeyPolicyDifferentialError("Report differs from supplied source replay")
    return JsonKeyPolicyDifferential(expected)
