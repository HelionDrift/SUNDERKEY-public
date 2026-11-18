"""Bounded offline field-shape comparison of supplied JSON and form sources."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

PROFILE_ID = "AOE-GB-D06-S12"
CAPABILITY_ID = "army.gb.d06.s12"
VECTOR_ID = "AV-GB-D06-S12-01"
DOMAIN = "sunderkey.offline-content-type-differential.v1"
ANALYSIS_PROFILE = "supplied-json-form-field-shapes.v1"
MAX_MODEL_BYTES = 131_072
MAX_BODY_BYTES = 32_768
MAX_DEPTH = 16
MAX_NODES = 8_192
MAX_FIELDS = 256
MAX_FORM_PAIRS = 512
MAX_DIFFERENCES = 1_024
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_FIELD = re.compile(r"[A-Za-z_][A-Za-z0-9_.\[\]-]{0,127}\Z")
_TYPES = frozenset(("string", "integer", "number", "boolean", "object", "array", "null"))
_EFFECTS = {
    "authority": "none",
    "credential_resolution": "none",
    "execution": "none",
    "network": "none",
    "target_interaction": "none",
    "finding_publication": "none",
    "qualification": "none",
}


class ContentTypeDifferentialError(ValueError):
    """Invalid, unsupported, or over-budget supplied source or report."""


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys or any(type(key) is not str for key in value):
        raise ContentTypeDifferentialError(f"{label} must have exact native fields")
    return value


def _identifier(value: Any, label: str, pattern: re.Pattern[str] = _ID) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise ContentTypeDifferentialError(f"{label} must be a bounded source name")
    return value


def _bounded_text(value: Any, label: str, maximum: int) -> str:
    if type(value) is not str:
        raise ContentTypeDifferentialError(f"{label} must be native text")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError as exc:
        raise ContentTypeDifferentialError(f"{label} has invalid Unicode") from exc
    if size > maximum:
        raise ContentTypeDifferentialError(f"{label} exceeds byte limit")
    return value


def _canonical(value: Any) -> str:
    stack = [(value, 1)]
    nodes = 0
    size = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise ContentTypeDifferentialError("Native node or depth limit exceeded")
        kind = type(item)
        if kind is dict:
            if nodes + len(stack) + 2 * len(item) > MAX_NODES:
                raise ContentTypeDifferentialError("Native node limit exceeded")
            size += 2 + len(item)
            for key, child in item.items():
                if type(key) is not str:
                    raise ContentTypeDifferentialError("Native mapping keys must be strings")
                stack.append((child, depth + 1))
                stack.append((key, depth + 1))
        elif kind is list:
            if nodes + len(stack) + len(item) > MAX_NODES:
                raise ContentTypeDifferentialError("Native node limit exceeded")
            size += 2 + len(item)
            stack.extend((child, depth + 1) for child in item)
        elif kind is str:
            _bounded_text(item, "native string", MAX_BODY_BYTES)
            size += 2 + 12 * len(item)
        elif kind is int:
            if item.bit_length() > 63:
                raise ContentTypeDifferentialError("Native integer exceeds 64 bits")
            size += len(str(item))
        elif kind is bool:
            size += 5
        elif item is None:
            size += 4
        else:
            raise ContentTypeDifferentialError("Unsupported native primitive")
        if size > 12 * MAX_MODEL_BYTES:
            raise ContentTypeDifferentialError("Native serialized size limit exceeded")
    result = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if len(result) > MAX_MODEL_BYTES:
        raise ContentTypeDifferentialError("Canonical model byte limit exceeded")
    return result


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise ContentTypeDifferentialError("JSON duplicate key rejected")
        result[key] = value
    return result


def _integer(text: str) -> int:
    if len(text.lstrip("-")) > 19:
        raise ContentTypeDifferentialError("JSON integer exceeds bound")
    result = int(text)
    if result.bit_length() > 63:
        raise ContentTypeDifferentialError("JSON integer exceeds bound")
    return result


def _decimal(text: str) -> Decimal:
    if len(text) > 128 or len(text.split("e")[-1].split("E")[-1]) > 10:
        raise ContentTypeDifferentialError("JSON number exceeds bound")
    result = Decimal(text)
    if not result.is_finite() or abs(result.adjusted()) > 10_000:
        raise ContentTypeDifferentialError("JSON number exceeds bound")
    return result


def _nonfinite(_text: str) -> None:
    raise ContentTypeDifferentialError("Nonfinite JSON number rejected")


def _json(text: Any, label: str, maximum: int = MAX_BODY_BYTES) -> Any:
    _bounded_text(text, label, maximum)
    if not text:
        raise ContentTypeDifferentialError(f"{label} must not be empty")
    depth = 0
    quoted = escaped = False
    for character in text:
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise ContentTypeDifferentialError("JSON depth limit exceeded")
        elif character in "]}":
            depth -= 1
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_integer,
            parse_float=_decimal,
            parse_constant=_nonfinite,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, ContentTypeDifferentialError):
            raise
        raise ContentTypeDifferentialError(f"{label} is malformed JSON") from exc
    stack = [(value, 1)]
    nodes = 0
    while stack:
        item, level = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or level > MAX_DEPTH:
            raise ContentTypeDifferentialError("JSON node or depth limit exceeded")
        if type(item) is dict:
            for key in item:
                _bounded_text(key, "JSON key", MAX_BODY_BYTES)
            stack.extend((child, level + 1) for child in item.values())
        elif type(item) is list:
            stack.extend((child, level + 1) for child in item)
        elif type(item) is str:
            _bounded_text(item, "JSON string", MAX_BODY_BYTES)
    return value


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _decode_form_part(value: str) -> str:
    if not value.isascii():
        raise ContentTypeDifferentialError("Form source must use ASCII or percent-encoded UTF-8")
    raw = bytearray()
    index = 0
    while index < len(value):
        char = value[index]
        if char == "%":
            if (
                index + 2 >= len(value)
                or re.fullmatch(r"[0-9A-Fa-f]{2}", value[index + 1 : index + 3]) is None
            ):
                raise ContentTypeDifferentialError("Malformed form percent escape")
            raw.append(int(value[index + 1 : index + 3], 16))
            index += 3
        else:
            raw.append(32 if char == "+" else ord(char))
            index += 1
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContentTypeDifferentialError("Form field is not UTF-8") from exc


def _form(text: Any) -> dict[str, int]:
    _bounded_text(text, "form body", MAX_BODY_BYTES)
    if not text:
        return {}
    pairs = text.split("&")
    if len(pairs) > MAX_FORM_PAIRS:
        raise ContentTypeDifferentialError("Form pair limit exceeded")
    result: dict[str, int] = {}
    for pair in pairs:
        if "=" not in pair:
            raise ContentTypeDifferentialError("Form pair requires equals delimiter")
        key, value = pair.split("=", 1)
        name = _identifier(_decode_form_part(key), "form key", _FIELD)
        _bounded_text(_decode_form_part(value), "form value", MAX_BODY_BYTES)
        result[name] = result.get(name, 0) + 1
        if len(result) > MAX_FIELDS:
            raise ContentTypeDifferentialError("Form field limit exceeded")
    return result


def _type(value: Any) -> str:
    kind = type(value)
    if kind is str:
        return "string"
    if kind is bool:
        return "boolean"
    if kind is int:
        return "integer"
    if kind is Decimal:
        return "number"
    if kind is dict:
        return "object"
    if kind is list:
        return "array"
    if value is None:
        return "null"
    raise ContentTypeDifferentialError("Unsupported JSON field type")


def _json_fields(text: Any) -> dict[str, dict[str, Any]]:
    body = _json(text, "JSON body")
    if type(body) is not dict or len(body) > MAX_FIELDS:
        raise ContentTypeDifferentialError("JSON body must be a bounded object")
    result: dict[str, dict[str, Any]] = {}
    for key, value in body.items():
        name = _identifier(key, "JSON field", _FIELD)
        shape: dict[str, Any] = {"type": _type(value)}
        if type(value) is list:
            shape["element_types"] = sorted({_type(item) for item in value})
        result[name] = shape
    return result


def _representation(value: Any, expected: str, label: str) -> tuple[str, dict[str, Any], str]:
    _exact(value, {"source_id", "content_type", "body"}, label)
    source_id = _identifier(value["source_id"], f"{label} source_id")
    if value["content_type"] != expected or type(value["content_type"]) is not str:
        raise ContentTypeDifferentialError(f"{label} has unsupported content type")
    body = value["body"]
    fields = (
        _json_fields(body)
        if expected == "application/json"
        else {name: {"type": "string", "occurrences": count} for name, count in _form(body).items()}
    )
    return source_id, fields, _digest(body)


def _schema(value: Any) -> tuple[str, dict[str, dict[str, Any]], str]:
    _exact(value, {"source_id", "fields"}, "declared_schema")
    source_id = _identifier(value["source_id"], "schema source_id")
    fields = value["fields"]
    if type(fields) is not list or len(fields) > MAX_FIELDS:
        raise ContentTypeDifferentialError("Schema fields must be a bounded list")
    result: dict[str, dict[str, Any]] = {}
    for field in fields:
        _exact(field, {"name", "type", "required"}, "schema field")
        name = _identifier(field["name"], "schema field name", _FIELD)
        if (
            name in result
            or type(field["type"]) is not str
            or field["type"] not in _TYPES
            or type(field["required"]) is not bool
        ):
            raise ContentTypeDifferentialError("Schema field has duplicate or invalid declaration")
        result[name] = {"type": field["type"], "required": field["required"]}
    return source_id, result, _digest(_canonical(value))


def _differences(
    json_fields: dict[str, dict[str, Any]],
    form_fields: dict[str, dict[str, Any]],
    schema: dict[str, dict[str, Any]] | None,
    phase: str,
) -> list[dict[str, Any]]:
    rows = []
    names = set(json_fields) | set(form_fields) | (set(schema) if schema is not None else set())
    for name in sorted(names):
        left = json_fields.get(name)
        right = form_fields.get(name)
        declared = schema.get(name) if schema is not None else None
        reasons = []
        if (left is None) != (right is None):
            reasons.append("representation_presence")
        elif left is not None and right is not None and left["type"] != right["type"]:
            reasons.append("representation_type")
        if right is not None and right["occurrences"] > 1:
            reasons.append("form_repeated_key")
        if declared is not None:
            if declared["required"] and (left is None or right is None):
                reasons.append("declared_required_absent")
            if (
                left is not None
                and left["type"] != declared["type"]
                and not (declared["type"] == "number" and left["type"] == "integer")
            ):
                reasons.append("json_declared_type")
            if right is not None and declared["type"] != "string":
                reasons.append("form_wire_type_vs_declaration")
        elif schema is not None:
            reasons.append("undeclared_field")
        if reasons:
            rows.append(
                {
                    "phase": phase,
                    "field": name,
                    "reasons": reasons,
                    "json_shape": left,
                    "form_shape": right,
                    "declared": declared,
                }
            )
        if len(rows) > MAX_DIFFERENCES:
            raise ContentTypeDifferentialError("Difference limit exceeded")
    return rows


def _build(model: Any) -> dict[str, Any]:
    source_text = _canonical(model)
    _exact(
        model,
        {
            "schema_version",
            "source_id",
            "json_request",
            "form_request",
            "declared_schema",
            "responses",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise ContentTypeDifferentialError("Unsupported schema version")
    source_id = _identifier(model["source_id"], "model source_id")
    json_id, json_fields, json_sha = _representation(
        model["json_request"], "application/json", "json_request"
    )
    form_id, form_fields, form_sha = _representation(
        model["form_request"], "application/x-www-form-urlencoded", "form_request"
    )
    schema_id, schema, schema_sha = _schema(model["declared_schema"])
    response = model["responses"]
    response_fields = None
    response_sources = None
    identifiers = [source_id, json_id, form_id, schema_id]
    if response is not None:
        _exact(response, {"json", "form"}, "responses")
        response_json_id, response_json, response_json_sha = _representation(
            response["json"], "application/json", "json response"
        )
        response_form_id, response_form, response_form_sha = _representation(
            response["form"], "application/x-www-form-urlencoded", "form response"
        )
        identifiers.extend((response_json_id, response_form_id))
        response_fields = {"json": response_json, "form": response_form}
        response_sources = {
            "json": {"source_id": response_json_id, "body_sha256": response_json_sha},
            "form": {"source_id": response_form_id, "body_sha256": response_form_sha},
        }
    if len(set(identifiers)) != len(identifiers):
        raise ContentTypeDifferentialError("Source identifiers must be distinct")
    source = {
        "source_id": source_id,
        "model_sha256": _digest(source_text),
        "json_request": {"source_id": json_id, "body_sha256": json_sha},
        "form_request": {"source_id": form_id, "body_sha256": form_sha},
        "declared_schema": {"source_id": schema_id, "schema_sha256": schema_sha},
        "responses": response_sources,
    }
    return _render(source, schema, {"json": json_fields, "form": form_fields}, response_fields)


def _shape_fields(value: Any, *, form: bool) -> dict[str, dict[str, Any]]:
    if type(value) is not dict or len(value) > MAX_FIELDS:
        raise ContentTypeDifferentialError("Shape fields must be a bounded native mapping")
    occurrences = 0
    for name, shape in value.items():
        _identifier(name, "shape field", _FIELD)
        if type(shape) is not dict:
            raise ContentTypeDifferentialError("Shape field must be a native mapping")
        if form:
            _exact(shape, {"type", "occurrences"}, "form shape")
            if (
                shape["type"] != "string"
                or type(shape["occurrences"]) is not int
                or not 1 <= shape["occurrences"] <= MAX_FORM_PAIRS
            ):
                raise ContentTypeDifferentialError("Invalid form shape")
            occurrences += shape["occurrences"]
        else:
            if shape.get("type") == "array":
                _exact(shape, {"type", "element_types"}, "JSON array shape")
                elements = shape["element_types"]
                if type(elements) is not list or any(
                    type(item) is not str or item not in _TYPES for item in elements
                ):
                    raise ContentTypeDifferentialError("Invalid JSON array element types")
                if elements != sorted(set(elements)):
                    raise ContentTypeDifferentialError("Invalid JSON array element types")
            else:
                _exact(shape, {"type"}, "JSON shape")
                if type(shape["type"]) is not str or shape["type"] not in _TYPES:
                    raise ContentTypeDifferentialError("Invalid JSON shape type")
    if form and occurrences > MAX_FORM_PAIRS:
        raise ContentTypeDifferentialError("Form pair shape limit exceeded")
    return value


def _render(
    source: Any,
    schema: Any,
    request_fields: Any,
    response_fields: Any,
) -> dict[str, Any]:
    _exact(
        source,
        {
            "source_id",
            "model_sha256",
            "json_request",
            "form_request",
            "declared_schema",
            "responses",
        },
        "source",
    )
    _identifier(source["source_id"], "source_id")
    addresses = [source["model_sha256"]]
    ids = [source["source_id"]]
    for key, digest_key in (
        ("json_request", "body_sha256"),
        ("form_request", "body_sha256"),
        ("declared_schema", "schema_sha256"),
    ):
        _exact(source[key], {"source_id", digest_key}, key)
        ids.append(_identifier(source[key]["source_id"], f"{key} source_id"))
        addresses.append(source[key][digest_key])
    if source["responses"] is not None:
        _exact(source["responses"], {"json", "form"}, "response source")
        for key in ("json", "form"):
            _exact(source["responses"][key], {"source_id", "body_sha256"}, "response address")
            ids.append(_identifier(source["responses"][key]["source_id"], "response source_id"))
            addresses.append(source["responses"][key]["body_sha256"])
    if len(set(ids)) != len(ids) or any(
        type(item) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", item) is None
        for item in addresses
    ):
        raise ContentTypeDifferentialError("Source addresses are invalid")
    if type(schema) is not dict or len(schema) > MAX_FIELDS:
        raise ContentTypeDifferentialError("Declared field mapping is invalid")
    for name, declaration in schema.items():
        _identifier(name, "declared field", _FIELD)
        _exact(declaration, {"type", "required"}, "declared field")
        if (
            type(declaration["type"]) is not str
            or declaration["type"] not in _TYPES
            or type(declaration["required"]) is not bool
        ):
            raise ContentTypeDifferentialError("Declared field type is invalid")
    _exact(request_fields, {"json", "form"}, "request fields")
    json_fields = _shape_fields(request_fields["json"], form=False)
    form_fields = _shape_fields(request_fields["form"], form=True)
    if response_fields is None:
        if source["responses"] is not None:
            raise ContentTypeDifferentialError("Response source and shape presence differ")
        response_differences: list[dict[str, Any]] = []
    else:
        if source["responses"] is None:
            raise ContentTypeDifferentialError("Response source and shape presence differ")
        _exact(response_fields, {"json", "form"}, "response fields")
        response_json = _shape_fields(response_fields["json"], form=False)
        response_form = _shape_fields(response_fields["form"], form=True)
        response_differences = _differences(response_json, response_form, None, "response")
    differences = _differences(json_fields, form_fields, schema, "request") + response_differences
    if len(differences) > MAX_DIFFERENCES:
        raise ContentTypeDifferentialError("Difference limit exceeded")
    report = {
        "schema_version": 1,
        "analysis_profile": ANALYSIS_PROFILE,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "source": source,
        "declared_schema": schema,
        "request_fields": request_fields,
        "response_fields": response_fields,
        "differences": differences,
        "uncertainty": [
            "Form keys are literal and repeated keys are not assumed to be arrays.",
            "Form strings are not assumed to be coerced to declared JSON types.",
            "Supplied representations and schema are not authenticated or asserted "
            "to be processed by a target.",
            "No target behavior, acceptance, validation, vulnerability, or impact is inferred.",
        ],
        "offline_only": True,
        "target_behavior_verified": False,
        "effects": dict(_EFFECTS),
    }
    address = hashlib.sha256(
        _canonical({"domain": DOMAIN, "report": report}).encode("ascii")
    ).hexdigest()
    report["report_id"] = "CTD-" + address[:32].upper()
    report["report_sha256"] = "sha256:" + address
    _canonical(report)
    return report


def _replay(document: Any) -> str:
    _exact(
        document,
        {
            "schema_version",
            "analysis_profile",
            "profile_id",
            "capability_id",
            "vector_id",
            "source",
            "declared_schema",
            "request_fields",
            "response_fields",
            "differences",
            "uncertainty",
            "offline_only",
            "target_behavior_verified",
            "effects",
            "report_id",
            "report_sha256",
        },
        "report",
    )
    expected = _render(
        document["source"],
        document["declared_schema"],
        document["request_fields"],
        document["response_fields"],
    )
    if document != expected:
        raise ContentTypeDifferentialError("Report does not replay supplied model")
    return _canonical(expected)


def _owned(text: str) -> ContentTypeDifferentialReport:
    result = object.__new__(ContentTypeDifferentialReport)
    object.__setattr__(result, "document_json", text)
    return result


@dataclass(frozen=True, slots=True)
class ContentTypeDifferentialReport:
    """Detached local report retaining original supplied sources for replay."""

    document_json: str

    def __post_init__(self) -> None:
        if type(self) is not ContentTypeDifferentialReport:
            raise ContentTypeDifferentialError("Exact report family required")
        self.to_dict()

    @classmethod
    def from_dict(cls, value: Any) -> ContentTypeDifferentialReport:
        if cls is not ContentTypeDifferentialReport:
            raise ContentTypeDifferentialError("Exact report family required")
        return _owned(_replay(value))

    @classmethod
    def from_json(cls, value: Any) -> ContentTypeDifferentialReport:
        if cls is not ContentTypeDifferentialReport or type(value) is not str:
            raise ContentTypeDifferentialError("Exact native report JSON required")
        document = _json(value, "report", MAX_MODEL_BYTES)
        canonical = _replay(document)
        if value != canonical:
            raise ContentTypeDifferentialError("Canonical report JSON required")
        return _owned(canonical)

    def to_dict(self) -> dict[str, Any]:
        if type(self) is not ContentTypeDifferentialReport or type(self.document_json) is not str:
            raise ContentTypeDifferentialError("Exact native report wrapper required")
        return ContentTypeDifferentialReport.from_json(self.document_json)._document()

    def _document(self) -> dict[str, Any]:
        return _json(self.document_json, "report", MAX_MODEL_BYTES)

    def to_json(self) -> str:
        self.to_dict()
        return self.document_json


def analyze_supplied_content_type_differential(model: Any) -> ContentTypeDifferentialReport:
    """Compare only supplied JSON/form field shapes and a caller declaration."""
    return _owned(_canonical(_build(model)))


def analyze_supplied_content_type_differential_bytes(
    *, model_bytes: Any
) -> ContentTypeDifferentialReport:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise ContentTypeDifferentialError("Bounded native model bytes required")
    try:
        text = model_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContentTypeDifferentialError("Model bytes must be UTF-8") from exc
    return analyze_supplied_content_type_differential(_json(text, "model", MAX_MODEL_BYTES))


def verify_supplied_content_type_differential(
    report: Any, *, model: Any
) -> ContentTypeDifferentialReport:
    if type(report) is not ContentTypeDifferentialReport:
        raise ContentTypeDifferentialError("Exact native report wrapper required")
    retained = report.to_json()
    expected = _canonical(_build(model))
    if retained != expected:
        raise ContentTypeDifferentialError("Report differs from separately supplied source")
    return _owned(expected)


def component_fixture() -> dict[str, Any]:
    """Return a fresh synthetic pair with no destination or executable effect."""
    return {
        "schema_version": 1,
        "source_id": "synthetic-pair",
        "json_request": {
            "source_id": "request-json",
            "content_type": "application/json",
            "body": '{"active":true,"roles":["reader"]}',
        },
        "form_request": {
            "source_id": "request-form",
            "content_type": "application/x-www-form-urlencoded",
            "body": "active=true&roles=reader&roles=writer",
        },
        "declared_schema": {
            "source_id": "declared-schema",
            "fields": [
                {"name": "active", "type": "boolean", "required": True},
                {"name": "roles", "type": "array", "required": True},
            ],
        },
        "responses": None,
    }


__all__ = [
    "ContentTypeDifferentialError",
    "ContentTypeDifferentialReport",
    "analyze_supplied_content_type_differential",
    "analyze_supplied_content_type_differential_bytes",
    "verify_supplied_content_type_differential",
    "component_fixture",
]
