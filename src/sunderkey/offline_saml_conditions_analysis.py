"""Unsigned arithmetic over supplied SAML 2.0 assertion conditions."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from xml.parsers import expat

COMPONENT_ID = "saml_supplied_conditions_audience_restrictions"
PROFILE_ID = "AOE-GA-D03-S03"
CAPABILITY_ID = "army.ga.d03.s03"
VECTOR_ID = "AV-GA-D03-S03-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D03-S03"
WAVE_ID = "IW2-004"
COMMANDER_ID = "AOE-GA-D03-CMD"
GROUP_OWNER_ID = "AOE-HQ-03"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:604c5aaf9d3a4cabccc1e0ff194a70a383af1ec16ce44bd0f0eb739911041352"
SEMANTICS_PROFILE = "supplied-saml2-conditions-audience-subset.v1"
DOMAIN = "sunderkey.offline-saml-conditions-analysis.v1"
MODEL_DOMAIN = "sunderkey.offline-saml-conditions-model.v1"
_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
_CONDITIONS = "{" + _SAML + "}Conditions"
_AUDIENCE_RESTRICTION = "{" + _SAML + "}AudienceRestriction"
_AUDIENCE = "{" + _SAML + "}Audience"
MAX_XML_BYTES = 131_072
MAX_MODEL_BYTES = 262_144
MAX_REPORT_BYTES = 524_288
MAX_MODEL_NODES = 4_096
MAX_REPORT_NODES = 8_192
MAX_XML_NODES = 4_096
MAX_XML_DEPTH = 32
MAX_NATIVE_DEPTH = 16
MAX_AUDIENCES = 256
MAX_TEXT = 4 * ((MAX_XML_BYTES + 2) // 3)
MAX_WORK = 33_554_432
_BOUNDS = {
    "xml_bytes": MAX_XML_BYTES,
    "model_bytes": MAX_MODEL_BYTES,
    "report_bytes": MAX_REPORT_BYTES,
    "model_nodes": MAX_MODEL_NODES,
    "report_nodes": MAX_REPORT_NODES,
    "xml_nodes": MAX_XML_NODES,
    "xml_depth": MAX_XML_DEPTH,
    "native_depth": MAX_NATIVE_DEPTH,
    "audiences": MAX_AUDIENCES,
    "cumulative_work": MAX_WORK,
}
_FLAGS = {
    "offline_only": True,
    "signature_authenticated": False,
    "issuer_trusted": False,
    "subject_confirmed": False,
    "login_authorized": False,
    "positive_use_approved": False,
    "qualification_claimed": False,
}
_EFFECTS = {
    "authority": "none",
    "target": "none",
    "execution": "none",
    "routing": "none",
    "qualification": "none",
    "deployment": "none",
    "provider_requests": "none",
}
_LIMITATIONS = [
    "The XML and evaluation context are supplied and unauthenticated.",
    "Only Conditions time and AudienceRestriction declarations are evaluated.",
    "Unsupported conditions or time lexicals are indeterminate, not accepted.",
    "Audience membership is an exact supplied URI comparison without normalization.",
    "No signature, issuer, subject, recipient, confirmation or protocol is verified.",
    "Condition arithmetic is not a SAML login, trust or schema-validity decision.",
]
_SOURCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]*)\Z")
_TIME = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z\Z")
_URI = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+\Z")
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_PLACEHOLDER = "sha256:" + "0" * 64
_ID_PLACEHOLDER = "SCA-" + "0" * 32


class SamlConditionsAnalysisError(ValueError):
    """Closed-input, unsupported-cost, or replay refusal."""


@dataclass(slots=True)
class _Budget:
    used: int = 0

    def charge(self, amount: int) -> None:
        if amount < 0 or amount > MAX_WORK - self.used:
            raise SamlConditionsAnalysisError("Cumulative software work ceiling exhausted")
        self.used += amount


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _text_size(value: str) -> int:
    size = 2
    for character in value:
        code = ord(character)
        if not 32 <= code <= 126:
            raise SamlConditionsAnalysisError("Printable ASCII metadata required")
        size += 2 if character in '\\"' else 1
    return size


def _measure(value: Any, budget: _Budget, *, report: bool = False) -> tuple[int, int]:
    byte_limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    size = nodes = 0
    active: set[int] = set()

    def add(amount: int) -> None:
        nonlocal size
        if amount > byte_limit - size:
            raise SamlConditionsAnalysisError("Canonical document byte ceiling exhausted")
        budget.charge(amount)
        size += amount

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        budget.charge(1)
        nodes += 1
        if depth > MAX_NATIVE_DEPTH or nodes > node_limit:
            raise SamlConditionsAnalysisError("Native node/depth ceiling exhausted")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_TEXT:
                raise SamlConditionsAnalysisError("Native string ceiling exhausted")
            budget.charge(len(item))
            add(_text_size(item))
        elif kind is bool:
            add(4 if item else 5)
        elif item is None:
            add(4)
        elif kind is int:
            if not -(1 << 63) <= item < 1 << 63:
                raise SamlConditionsAnalysisError("Exact signed64 integer required")
            add(len(str(item)))
        elif kind in (dict, list):
            if id(item) in active:
                raise SamlConditionsAnalysisError("Cyclic native document")
            if len(item) * (2 if kind is dict else 1) > node_limit - nodes:
                raise SamlConditionsAnalysisError("Queued native node ceiling exhausted")
            add(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
            active.add(id(item))
            try:
                if kind is dict:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise SamlConditionsAnalysisError("Exact native text keys required")
                        visit(key, depth + 1)
                        budget.charge(len(key) * (len(item).bit_length() + 1))
                        visit(child, depth + 1)
                else:
                    for child in item:
                        visit(child, depth + 1)
            finally:
                active.remove(id(item))
        else:
            raise SamlConditionsAnalysisError("Exact native JSON families required")

    visit(value, 1)
    return size, nodes


def _clone(value: Any) -> Any:
    if type(value) is dict:
        return {key: _clone(child) for key, child in value.items()}
    if type(value) is list:
        return [_clone(child) for child in value]
    return value


def _capture(value: Any, budget: _Budget, *, report: bool = False) -> tuple[Any, int, int]:
    size, nodes = _measure(value, budget, report=report)
    budget.charge(4 * (size + nodes))
    return _clone(value), size, nodes


def _integer(text: str) -> int:
    if len(text) > 20 or _INTEGER.fullmatch(text) is None:
        raise SamlConditionsAnalysisError("Bounded raw integer grammar required")
    negative = text.startswith("-")
    digits = text[1:] if negative else text
    limit = "9223372036854775808" if negative else "9223372036854775807"
    if len(digits) > 19 or (len(digits) == 19 and digits > limit):
        raise SamlConditionsAnalysisError("Raw signed64 integer ceiling exhausted")
    return int(text)


def _decode(text: Any, budget: _Budget, *, report: bool = False) -> Any:
    byte_limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    if type(text) is not str or not text or len(text) > byte_limit:
        raise SamlConditionsAnalysisError("Bounded native JSON text required")
    budget.charge(2 * len(text))
    if not text.isascii():
        raise SamlConditionsAnalysisError("ASCII raw JSON metadata required")
    index = nodes = 0
    stack: list[str] = []
    while index < len(text):
        char = text[index]
        if char in " \t\r\n,:":
            index += 1
            continue
        if char in "]}":
            if not stack or stack.pop() != ("[" if char == "]" else "{"):
                raise SamlConditionsAnalysisError("Malformed raw JSON containers")
            index += 1
            continue
        nodes += 1
        if nodes > node_limit or len(stack) + 1 > MAX_NATIVE_DEPTH:
            raise SamlConditionsAnalysisError("Pre-decoder node/depth ceiling exhausted")
        if char in "[{":
            stack.append(char)
            index += 1
        elif char == '"':
            index += 1
            length = 0
            while index < len(text) and text[index] != '"':
                budget.charge(1)
                code = ord(text[index])
                if text[index] == "\\":
                    index += 1
                    if index >= len(text):
                        raise SamlConditionsAnalysisError("Incomplete JSON escape")
                    if text[index] == "u":
                        digits = text[index + 1 : index + 5]
                        if len(digits) != 4 or any(
                            c not in "0123456789abcdefABCDEF" for c in digits
                        ):
                            raise SamlConditionsAnalysisError("Malformed JSON Unicode escape")
                        code = int(digits, 16)
                        index += 4
                    elif text[index] in '\\"/':
                        code = ord(text[index])
                    else:
                        raise SamlConditionsAnalysisError("Unsupported JSON string escape")
                if not 32 <= code <= 126:
                    raise SamlConditionsAnalysisError("Printable ASCII JSON strings required")
                length += 1
                if length > MAX_TEXT:
                    raise SamlConditionsAnalysisError("Pre-decoder string ceiling exhausted")
                index += 1
            if index >= len(text):
                raise SamlConditionsAnalysisError("Unterminated JSON string")
            index += 1
        else:
            start = index
            while index < len(text) and text[index] not in ' \t\r\n,:]}[{"':
                index += 1
                if index - start > 20:
                    raise SamlConditionsAnalysisError("Pre-decoder scalar ceiling exhausted")
            token = text[start:index]
            if token not in ("true", "false", "null"):
                _integer(token)
    if stack:
        raise SamlConditionsAnalysisError("Unterminated JSON containers")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, value in items:
            if key in result:
                raise SamlConditionsAnalysisError("Duplicate raw JSON key")
            result[key] = value
        return result

    def unsupported(_: str) -> None:
        raise SamlConditionsAnalysisError("Integer-only raw JSON required")

    budget.charge(4 * len(text) + 32 * nodes)
    try:
        document = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=_integer,
            parse_float=unsupported,
            parse_constant=unsupported,
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise SamlConditionsAnalysisError("Malformed bounded JSON document") from exc
    _measure(document, budget, report=report)
    return document


def _time(value: Any) -> tuple[int, ...] | None:
    if type(value) is not str or len(value) > 40:
        return None
    matched = _TIME.fullmatch(value)
    if matched is None:
        return None
    fields = tuple(int(part) for part in matched.groups()[:6])
    try:
        datetime(*fields)
    except ValueError:
        return None
    fraction = matched.group(7) or ""
    return (*fields, int(fraction.ljust(9, "0")) if fraction else 0)


def _uri(value: Any) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 2_048
        and _URI.fullmatch(value) is not None
        and all(
            value[index + 1 : index + 3].isalnum()
            and len(value[index + 1 : index + 3]) == 2
            and all(char in "0123456789abcdefABCDEF" for char in value[index + 1 : index + 3])
            for index, character in enumerate(value)
            if character == "%"
        )
    )


def _xml(encoded: Any, budget: _Budget) -> tuple[ET.Element, bytes, int]:
    if type(encoded) is not str or len(encoded) > 4 * ((MAX_XML_BYTES + 2) // 3):
        raise SamlConditionsAnalysisError("Bounded canonical XML base64 required")
    budget.charge(5 * len(encoded) + MAX_XML_BYTES)
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise SamlConditionsAnalysisError("Invalid XML base64") from exc
    if not raw or len(raw) > MAX_XML_BYTES or base64.b64encode(raw).decode("ascii") != encoded:
        raise SamlConditionsAnalysisError("XML byte bound or base64 is invalid")
    if b"\x00" in raw:
        raise SamlConditionsAnalysisError("NUL and UTF-16 XML are unsupported")
    if b"<!" in raw:
        raise SamlConditionsAnalysisError("DTD, entities, comments and CDATA are unsupported")
    if b"<?" in raw:
        stripped = raw.lstrip()
        end = stripped.find(b"?>")
        declaration = stripped[: end + 2]
        if (
            not stripped.startswith(b"<?xml ")
            or end < 0
            or end > 128
            or b"<?" in stripped[end + 2 :]
            or re.fullmatch(
                rb'<\?xml version=([\'"])1\.0\1(?: encoding=([\'"])UTF-8\2)?\?>',
                declaration,
                flags=re.IGNORECASE,
            )
            is None
        ):
            raise SamlConditionsAnalysisError("Unsupported XML declaration or instruction")
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SamlConditionsAnalysisError("Exact UTF-8 XML bytes required") from exc
    nodes = depth = 0
    parser = expat.ParserCreate(namespace_separator="}")

    def start(_name: str, _attributes: dict) -> None:
        nonlocal nodes, depth
        nodes += 1
        depth += 1
        if nodes > MAX_XML_NODES or depth > MAX_XML_DEPTH:
            raise SamlConditionsAnalysisError("XML node/depth ceiling exhausted")

    def end(_name: str) -> None:
        nonlocal depth
        depth -= 1

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    budget.charge(16 * len(raw) + 128 * min(len(raw), MAX_XML_NODES))
    try:
        parser.Parse(raw, True)
        root = ET.fromstring(raw)
    except (expat.ExpatError, ET.ParseError) as exc:
        raise SamlConditionsAnalysisError("Malformed bounded XML document") from exc
    return root, raw, nodes


def _restriction(element: ET.Element, audience: str, budget: _Budget) -> dict:
    values: list[str] = []
    unknown = bool(element.attrib or (element.text and element.text.strip()))
    for child in element:
        budget.charge(32)
        if len(values) >= MAX_AUDIENCES:
            raise SamlConditionsAnalysisError("Audience count ceiling exhausted")
        if (
            child.tag != _AUDIENCE
            or child.attrib
            or len(child)
            or (child.tail and child.tail.strip())
            or not _uri(child.text)
        ):
            unknown = True
            continue
        values.append(child.text)
    if not values:
        unknown = True
    matched = audience in values
    status = "indeterminate" if unknown else "matched" if matched else "unmatched"
    return {"audiences": values, "result": status}


def _evaluate(root: ET.Element, context: dict, budget: _Budget) -> dict:
    if root.tag != "{" + _SAML + "}Assertion" or root.attrib.get("Version") != "2.0":
        raise SamlConditionsAnalysisError("SAML 2.0 Assertion root required")
    conditions = [child for child in root if child.tag == _CONDITIONS]
    if len(conditions) > 1:
        raise SamlConditionsAnalysisError("Multiple direct Conditions are unsupported")
    now = _time(context["evaluated_at_utc"])
    if now is None:
        raise SamlConditionsAnalysisError("Supported supplied UTC evaluation instant required")
    if not _uri(context["audience"]):
        raise SamlConditionsAnalysisError("Bounded absolute supplied audience URI required")
    if not conditions:
        return {
            "not_before": None,
            "not_on_or_after": None,
            "time_result": "conditions_absent",
            "audience_restrictions": [],
            "unsupported_conditions": 0,
            "analysis_status": "conditions_absent_unassessed",
        }
    condition = conditions[0]
    before = condition.attrib.get("NotBefore")
    after = condition.attrib.get("NotOnOrAfter")
    start = _time(before) if before is not None else None
    end = _time(after) if after is not None else None
    unknown = int(bool(set(condition.attrib) - {"NotBefore", "NotOnOrAfter"}))
    unknown += int(bool(condition.text and condition.text.strip()))
    if start is not None and end is not None and start >= end:
        time_result = "invalid_interval"
    elif (start is not None and now < start) or (end is not None and now >= end):
        time_result = "outside_window"
    elif (before is not None and start is None) or (after is not None and end is None):
        time_result = "indeterminate"
    else:
        time_result = "within_window"
    rows: list[dict] = []
    audience_count = 0
    for child in condition:
        budget.charge(32)
        if child.tag == _AUDIENCE_RESTRICTION:
            if len(rows) >= MAX_AUDIENCES:
                raise SamlConditionsAnalysisError("Restriction count ceiling exhausted")
            row = _restriction(child, context["audience"], budget)
            audience_count += len(row["audiences"])
            if audience_count > MAX_AUDIENCES:
                raise SamlConditionsAnalysisError("Aggregate audience ceiling exhausted")
            rows.append(row)
        else:
            unknown += 1
        if child.tail and child.tail.strip():
            unknown += 1
    if time_result in {"invalid_interval", "outside_window"} or any(
        row["result"] == "unmatched" for row in rows
    ):
        status = "known_condition_false"
    elif (
        time_result == "indeterminate"
        or unknown
        or any(row["result"] == "indeterminate" for row in rows)
    ):
        status = "indeterminate"
    else:
        status = "supported_conditions_satisfied"
    return {
        "not_before": before,
        "not_on_or_after": after,
        "time_result": time_result,
        "audience_restrictions": rows,
        "unsupported_conditions": unknown,
        "analysis_status": status,
    }


@dataclass(slots=True)
class _Plan:
    document: dict
    size: int
    xml_bytes: bytes


def _plan(model: Any, budget: _Budget) -> _Plan:
    if type(model) is not dict:
        raise SamlConditionsAnalysisError("Exact native source model required")
    source, source_size, _ = _capture(model, budget)
    if set(source) != {"schema_version", "source_id", "assertion_xml_base64", "evaluation_context"}:
        raise SamlConditionsAnalysisError("Closed source model fields required")
    if type(source["schema_version"]) is not int or source["schema_version"] != 1:
        raise SamlConditionsAnalysisError("Exact native schema version one required")
    if type(source["source_id"]) is not str or _SOURCE.fullmatch(source["source_id"]) is None:
        raise SamlConditionsAnalysisError("Bounded source identifier required")
    context = source["evaluation_context"]
    if type(context) is not dict or set(context) != {"evaluated_at_utc", "audience"}:
        raise SamlConditionsAnalysisError("Closed evaluation context required")
    if type(context["evaluated_at_utc"]) is not str or type(context["audience"]) is not str:
        raise SamlConditionsAnalysisError("Exact native evaluation strings required")
    root, raw, xml_nodes = _xml(source["assertion_xml_base64"], budget)
    result = _evaluate(root, context, budget)
    document = {
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
        "roadmap_package_ids": ["A7.4"],
        "source_model": source,
        "source_model_sha256": _PLACEHOLDER,
        "assertion_xml_sha256": _PLACEHOLDER,
        "evaluation_context": _clone(context),
        "not_before": result["not_before"],
        "not_on_or_after": result["not_on_or_after"],
        "time_result": result["time_result"],
        "audience_restrictions": result["audience_restrictions"],
        "unsupported_conditions": result["unsupported_conditions"],
        "analysis_status": result["analysis_status"],
        "xml_node_count": xml_nodes,
        "flags": dict(_FLAGS),
        "effects": dict(_EFFECTS),
        "bounds": dict(_BOUNDS),
        "limitations": list(_LIMITATIONS),
        "analysis_id": _ID_PLACEHOLDER,
        "analysis_sha256": _PLACEHOLDER,
    }
    document, size, nodes = _capture(document, budget, report=True)
    budget.charge(
        18 * size
        + 8 * source_size
        + 8 * len(raw)
        + 8 * nodes
        + 256 * xml_nodes
        + len(DOMAIN)
        + len(MODEL_DOMAIN)
        + 2
    )
    return _Plan(document, size, raw)


def _digest(domain: str, value: dict) -> str:
    return (
        "sha256:" + hashlib.sha256((domain + "\n" + _canonical(value)).encode("ascii")).hexdigest()
    )


def _materialize(plan: _Plan) -> str:
    document = plan.document
    document["assertion_xml_sha256"] = "sha256:" + hashlib.sha256(plan.xml_bytes).hexdigest()
    document["source_model_sha256"] = _digest(MODEL_DOMAIN, document["source_model"])
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = _digest(DOMAIN, body)
    document["analysis_id"] = "SCA-" + digest[7:39].upper()
    document["analysis_sha256"] = digest
    return _canonical(document)


def _report_plan(document: Any, budget: _Budget) -> tuple[dict, str, _Plan]:
    if type(document) is not dict:
        raise SamlConditionsAnalysisError("Exact native report object required")
    owned, size, nodes = _capture(document, budget, report=True)
    if "source_model" not in owned:
        raise SamlConditionsAnalysisError("Report requires complete original source model")
    expected = _plan(owned["source_model"], budget)
    for field in ("source_model_sha256", "assertion_xml_sha256", "analysis_sha256"):
        if type(owned.get(field)) is not str or _SHA.fullmatch(owned[field]) is None:
            raise SamlConditionsAnalysisError("Exact SHA256 report address required")
    if (
        type(owned.get("analysis_id")) is not str
        or owned["analysis_id"] != "SCA-" + owned["analysis_sha256"][7:39].upper()
    ):
        raise SamlConditionsAnalysisError("Exact report ID/address join required")
    budget.charge(12 * size + 4 * expected.size + 8 * nodes)
    return owned, _canonical(owned), expected


def _replay_text(text: Any, budget: _Budget) -> dict:
    document, canonical, plan = _report_plan(_decode(text, budget, report=True), budget)
    if text != canonical:
        raise SamlConditionsAnalysisError("Exact canonical retained report JSON required")
    if _materialize(plan) != canonical:
        raise SamlConditionsAnalysisError("Report does not replay original model")
    return document


def _stored(report: Any) -> str:
    if type(report) is not SamlConditionsAnalysis:
        raise SamlConditionsAnalysisError("Exact native report wrapper required")
    text = getattr(report, "document_json", None)
    if type(text) is not str:
        raise SamlConditionsAnalysisError("Exact native retained report text required")
    return text


def _owned(text: str) -> SamlConditionsAnalysis:
    report = object.__new__(SamlConditionsAnalysis)
    object.__setattr__(report, "document_json", text)
    return report


@dataclass(frozen=True, slots=True)
class SamlConditionsAnalysis:
    """Detached unsigned result retaining the complete original source model."""

    document_json: str

    def __post_init__(self) -> None:
        if type(self) is not SamlConditionsAnalysis:
            raise SamlConditionsAnalysisError("Exact native report family required")
        _replay_text(self.document_json, _Budget())

    @classmethod
    def from_dict(cls, document: Any) -> SamlConditionsAnalysis:
        if cls is not SamlConditionsAnalysis:
            raise SamlConditionsAnalysisError("Exact native report family required")
        budget = _Budget()
        _owned_document, text, plan = _report_plan(document, budget)
        if _materialize(plan) != text:
            raise SamlConditionsAnalysisError("Report does not replay original model")
        return _owned(text)

    @classmethod
    def from_json(cls, document_json: Any) -> SamlConditionsAnalysis:
        if cls is not SamlConditionsAnalysis:
            raise SamlConditionsAnalysisError("Exact native report family required")
        _replay_text(document_json, _Budget())
        return _owned(document_json)

    def to_dict(self) -> dict:
        return _replay_text(_stored(self), _Budget())

    def to_json(self) -> str:
        text = _stored(self)
        _replay_text(text, _Budget())
        return text

    @property
    def analysis_id(self) -> str:
        return self.to_dict()["analysis_id"]

    @property
    def analysis_sha256(self) -> str:
        return self.to_dict()["analysis_sha256"]


def analyze_supplied_saml_conditions(model: Any) -> SamlConditionsAnalysis:
    """Analyze only declared SAML Conditions against a supplied context."""
    return _owned(_materialize(_plan(model, _Budget())))


def analyze_supplied_saml_conditions_bytes(*, model_bytes: Any) -> SamlConditionsAnalysis:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise SamlConditionsAnalysisError("Bounded exact native model JSON bytes required")
    budget = _Budget()
    budget.charge(2 * len(model_bytes))
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SamlConditionsAnalysisError("ASCII source JSON bytes required") from exc
    return _owned(_materialize(_plan(_decode(text, budget), budget)))


def verify_supplied_saml_conditions_analysis(report: Any, *, model: Any) -> SamlConditionsAnalysis:
    """Replay embedded and separately supplied source under one work budget."""
    budget = _Budget()
    text = _stored(report)
    _document, canonical, embedded = _report_plan(_decode(text, budget, report=True), budget)
    original = _plan(model, budget)
    budget.charge(4 * (embedded.size + original.size))
    if text != canonical:
        raise SamlConditionsAnalysisError("Exact canonical retained report JSON required")
    expected = _materialize(embedded)
    separate = _materialize(original)
    if expected != text or expected != separate:
        raise SamlConditionsAnalysisError(
            "Report differs from embedded or separately original source"
        )
    return _owned(separate)


def component_fixture() -> dict:
    """Return a fresh unsigned synthetic assertion and evaluation context."""
    raw = (
        '<s:Assertion xmlns:s="urn:oasis:names:tc:SAML:2.0:assertion" '
        'Version="2.0" ID="_synthetic" IssueInstant="2026-09-29T00:00:00Z">'
        '<s:Conditions NotBefore="2026-09-29T00:00:00Z" '
        'NotOnOrAfter="2026-09-30T00:00:00Z">'
        "<s:AudienceRestriction><s:Audience>https://service.invalid/sp</s:Audience>"
        "</s:AudienceRestriction></s:Conditions></s:Assertion>"
    ).encode("ascii")
    return {
        "schema_version": 1,
        "source_id": "synthetic-saml-conditions",
        "assertion_xml_base64": base64.b64encode(raw).decode("ascii"),
        "evaluation_context": {
            "evaluated_at_utc": "2026-09-29T12:00:00Z",
            "audience": "https://service.invalid/sp",
        },
    }


__all__ = [
    "SamlConditionsAnalysis",
    "SamlConditionsAnalysisError",
    "analyze_supplied_saml_conditions",
    "analyze_supplied_saml_conditions_bytes",
    "verify_supplied_saml_conditions_analysis",
    "component_fixture",
]
