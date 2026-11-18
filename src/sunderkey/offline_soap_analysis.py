"""Pure supplied WSDL 1.1 / SOAP 1.1 document-literal instance analysis."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any
from xml.parsers import expat

PROFILE_ID = "AOE-GB-D06-S04"
CAPABILITY_ID = "army.gb.d06.s04"
VECTOR_ID = "AV-GB-D06-S04-01"
DOMAIN = "sunderkey.offline-soap-analysis.v1"
SYNTAX_PROFILE = "wsdl11-soap11-document-literal-subset.v1"
MAX_DOCUMENT_BYTES = 1_048_576
MAX_ITEMS = 50_000
MAX_NATIVE_DEPTH = 32
MAX_XML_DEPTH = 64
MAX_TEXT = 8_192
MAX_OBSERVATIONS = 2_048
WSDL = "http://schemas.xmlsoap.org/wsdl/"
SOAP_BINDING = "http://schemas.xmlsoap.org/wsdl/soap/"
SOAP = "http://schemas.xmlsoap.org/soap/envelope/"
SOAP12 = "http://www.w3.org/2003/05/soap-envelope"
XSD = "http://www.w3.org/2001/XMLSchema"
XSI = "http://www.w3.org/2001/XMLSchema-instance"
XML = "http://www.w3.org/XML/1998/namespace"
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}\Z")
_SOURCE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_INTEGER = re.compile(r"[+-]?[0-9]+\Z")
_DECIMAL = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)\Z")
_XML_SPACE = " \t\r\n"
_SCALARS = {"string", "boolean", "int", "decimal"}
_LIMITS = {
    "max_wsdl_bytes": MAX_DOCUMENT_BYTES,
    "max_envelope_bytes": MAX_DOCUMENT_BYTES,
    "max_xml_tokens": MAX_ITEMS,
    "max_xml_nodes": MAX_ITEMS,
    "max_xml_depth": MAX_XML_DEPTH,
    "max_observations": MAX_OBSERVATIONS,
}
_SELECTION_FIELDS = {
    "binding_qname",
    "operation_name",
    "message_kind",
    "fault_name",
    "observed_action",
}
_EFFECTS = {
    key: "none"
    for key in ("authority", "target", "execution", "routing", "qualification", "deployment")
}
_FLAGS = {
    "positive_use_approved",
    "qualification_claimed",
    "full_xsd_validation_claimed",
    "receiver_processing_verified",
    "transport_metadata_authenticated",
    "security_findings_verified",
    "server_safety_verified",
}


class SoapAnalysisError(ValueError):
    """Invalid, inconsistent, unsafe or over-budget supplied inputs."""


class _Unsupported(Exception):
    def __init__(self, code: str, path: str = "/contract") -> None:
        self.code = code
        self.path = path


def _integer(value: Any, label: str, maximum: int, minimum: int = 1) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise SoapAnalysisError(f"{label} must be a bounded native integer")
    return value


def _text(value: Any, label: str, maximum: int = MAX_TEXT, *, empty: bool = False) -> str:
    if type(value) is not str or (not value and not empty) or len(value) > maximum:
        raise SoapAnalysisError(f"{label} must be bounded native text")
    try:
        if len(value.encode("utf-8")) > maximum:
            raise SoapAnalysisError(f"{label} exceeds its byte limit")
    except UnicodeError as exc:
        raise SoapAnalysisError(f"{label} must be valid UTF-8 text") from exc
    return value


def _name(value: Any) -> str:
    if type(value) is not str or _NAME.fullmatch(value) is None:
        raise SoapAnalysisError("Name is outside the supported ASCII XML name subset")
    return value


def _q(namespace: str, name: str) -> str:
    return f"{{{namespace}}}{name}" if namespace else name


def _expanded(value: Any) -> str:
    value = _text(value, "Expanded QName", 768)
    if value.startswith("{"):
        namespace, separator, local = value[1:].partition("}")
        if not separator or not namespace or "{" in namespace or "}" in local:
            raise SoapAnalysisError("Expanded QName is invalid")
        _text(namespace, "Namespace", 512)
        _name(local)
    else:
        _name(value)
    return value


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or any(type(key) is not str for key in value) or set(value) != keys:
        raise SoapAnalysisError(f"{label} fields are invalid")
    return value


def _native(value: Any) -> str:
    """Charge repeated subtrees and exact ASCII JSON escape costs before serialization."""
    stack = [(value, 0)]
    nodes = 0
    size = 0

    def quoted(text: str) -> int:
        _text(text, "Native string", MAX_TEXT, empty=True)
        cost = 2
        for char in text:
            number = ord(char)
            cost += (
                2
                if char in {'"', "\\", "\b", "\f", "\n", "\r", "\t"}
                else 6
                if number < 32 or number > 126 and number <= 65535
                else 12
                if number > 65535
                else 1
            )
            if cost > MAX_DOCUMENT_BYTES:
                raise SoapAnalysisError("Native document exceeds its byte budget")
        return cost

    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_ITEMS or depth > MAX_NATIVE_DEPTH:
            raise SoapAnalysisError("Native document exceeds node/depth limits")
        if type(item) is dict:
            if len(item) > MAX_ITEMS or len(stack) + len(item) > MAX_ITEMS:
                raise SoapAnalysisError("Native object exceeds its node budget")
            if any(type(key) is not str for key in item):
                raise SoapAnalysisError("Native object keys must be exact strings")
            size += 2 + max(0, len(item) - 1)
            for key, child in item.items():
                size += quoted(key) + 1
                stack.append((child, depth + 1))
        elif type(item) is list:
            if len(item) > MAX_ITEMS or len(stack) + len(item) > MAX_ITEMS:
                raise SoapAnalysisError("Native array exceeds its node budget")
            size += 2 + max(0, len(item) - 1)
            stack.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            size += quoted(item)
        elif type(item) is bool:
            size += 4 if item else 5
        elif item is None:
            size += 4
        elif type(item) is int and item.bit_length() <= 63:
            size += len(str(item))
        else:
            raise SoapAnalysisError("Native document contains unsupported scalar/container types")
        if size > MAX_DOCUMENT_BYTES:
            raise SoapAnalysisError("Native document exceeds its byte budget")
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def _json_preflight(text: str) -> None:
    """Bound raw JSON depth and value tokens before the decoder allocates a graph."""
    index = nodes = depth = 0
    while index < len(text):
        char = text[index]
        if char in " \t\r\n,:":
            index += 1
            continue
        if char in "[{":
            if depth > MAX_NATIVE_DEPTH:
                raise SoapAnalysisError("Report JSON exceeds its depth budget")
            depth += 1
            nodes += 1
            index += 1
        elif char in "]}":
            depth -= 1
            if depth < 0:
                raise SoapAnalysisError("Report JSON structure is invalid")
            index += 1
        elif char == '"':
            index += 1
            while index < len(text):
                if text[index] == "\\":
                    index += 2
                elif text[index] == '"':
                    index += 1
                    break
                else:
                    index += 1
            else:
                raise SoapAnalysisError("Report JSON string is incomplete")
            after = index
            while after < len(text) and text[after] in " \t\r\n":
                after += 1
            if after >= len(text) or text[after] != ":":
                nodes += 1
                if depth > MAX_NATIVE_DEPTH:
                    raise SoapAnalysisError("Report JSON exceeds its depth budget")
        else:
            end = index
            while end < len(text) and text[end] not in ' \t\r\n,:]}[{"':
                end += 1
            if end == index:
                raise SoapAnalysisError("Report JSON token is invalid")
            token = text[index:end]
            if re.fullmatch(r"-?[0-9]+", token) is not None:
                _json_integer(token)
            nodes += 1
            if depth > MAX_NATIVE_DEPTH:
                raise SoapAnalysisError("Report JSON exceeds its depth budget")
            index = end
        if nodes > MAX_ITEMS:
            raise SoapAnalysisError("Report JSON exceeds its node budget")
    if depth:
        raise SoapAnalysisError("Report JSON structure is incomplete")


def _json_integer(lexical: str) -> int:
    digits = lexical[1:] if lexical.startswith("-") else lexical
    if len(digits) > 19 or re.fullmatch(r"[0-9]+", digits) is None:
        raise SoapAnalysisError("JSON integer exceeds its native magnitude budget")
    value = int(lexical)
    if value.bit_length() > 63:
        raise SoapAnalysisError("JSON integer exceeds its native magnitude budget")
    return value


def _decode(text: Any) -> Any:
    if type(text) is not str or not text or len(text) > MAX_DOCUMENT_BYTES:
        raise SoapAnalysisError("Report JSON must be bounded native text")
    try:
        if len(text.encode("utf-8")) > MAX_DOCUMENT_BYTES:
            raise SoapAnalysisError("Report JSON exceeds its byte budget")
        _json_preflight(text)

        def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in items:
                if key in result:
                    raise SoapAnalysisError("Duplicate JSON key")
                result[key] = value
            return result

        def number(_: str) -> None:
            raise SoapAnalysisError("Floats and nonfinite JSON numbers are unsupported")

        value = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=_json_integer,
            parse_float=number,
            parse_constant=number,
        )
        _native(value)
        return value
    except (ValueError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, SoapAnalysisError):
            raise
        raise SoapAnalysisError("Report JSON is invalid") from exc


@dataclass(frozen=True, slots=True)
class SoapAnalysisLimits:
    """Required per-source software-cost ceilings, not target or operational budgets."""

    max_wsdl_bytes: int
    max_envelope_bytes: int
    max_xml_tokens: int
    max_xml_nodes: int
    max_xml_depth: int
    max_observations: int

    def __post_init__(self) -> None:
        for key, maximum in _LIMITS.items():
            _integer(getattr(self, key), key, maximum)

    def to_dict(self) -> dict[str, int]:
        return _capture_limits(self)


def _capture_limits(value: Any) -> dict[str, int]:
    if type(value) is not SoapAnalysisLimits:
        raise SoapAnalysisError("Limits require the exact native SoapAnalysisLimits family")
    try:
        return {
            key: _integer(getattr(value, key), key, maximum) for key, maximum in _LIMITS.items()
        }
    except AttributeError as exc:
        raise SoapAnalysisError("Limits are incomplete") from exc


def _selection(value: Any) -> dict[str, Any]:
    _native(value)
    raw = json.loads(_native(_exact(value, _SELECTION_FIELDS, "Selection")))
    _expanded(raw["binding_qname"])
    if not raw["binding_qname"].startswith("{"):
        raise SoapAnalysisError("Binding selection must include its namespace")
    _name(raw["operation_name"])
    if type(raw["message_kind"]) is not str or raw["message_kind"] not in {
        "request",
        "response",
        "fault",
    }:
        raise SoapAnalysisError("Message kind is invalid")
    if raw["message_kind"] == "fault":
        _name(raw["fault_name"])
    elif raw["fault_name"] is not None:
        raise SoapAnalysisError("Only a fault selection can specify fault_name")
    if raw["observed_action"] is not None:
        _text(raw["observed_action"], "Declared observed action", empty=True)
    return raw


@dataclass(frozen=True, slots=True)
class _NamespaceFrame:
    bindings: MappingProxyType
    parent: _NamespaceFrame | None = None

    def get(self, prefix: str, default: str | None = None) -> str | None:
        frame: _NamespaceFrame | None = self
        while frame is not None:
            value = frame.bindings.get(prefix)
            if value is not None:
                return value
            frame = frame.parent
        return default


@dataclass(slots=True)
class _Node:
    tag: str
    attrs: dict[str, str]
    namespaces: _NamespaceFrame
    children: list[_Node] = field(default_factory=list)
    text: str = ""


@dataclass(slots=True)
class _Parsed:
    root: _Node
    tokens: int
    nodes: int
    depth: int


def _preflight(content: Any, maximum: int, limits: dict[str, int]) -> tuple[str, int, int, int]:
    if type(content) is not bytes or not content or len(content) > maximum:
        raise SoapAnalysisError("XML source must be nonempty bounded native bytes")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeError as exc:
        raise SoapAnalysisError("XML source must be UTF-8") from exc
    index = 0
    tokens = nodes = depth = highest = 0
    while index < len(text):
        if text[index] != "<":
            end = text.find("<", index)
            end = len(text) if end < 0 else end
            if end > index:
                tokens += 1
            index = end
        elif text.startswith("<!--", index):
            end = text.find("-->", index + 4)
            if end < 0:
                raise SoapAnalysisError("XML comment is incomplete")
            tokens += 1
            index = end + 3
        elif text.startswith("<?xml", index) and index == 0:
            end = text.find("?>", index + 5)
            if (
                end < 0
                or re.fullmatch(
                    r"""<\?xml\s+version\s*=\s*(["'])1\.0\1(?:\s+encoding\s*=\s*(["'])(?i:utf-8)\2)?(?:\s+standalone\s*=\s*(["'])(?:yes|no)\3)?\s*\?>""",
                    text[index : end + 2],
                )
                is None
            ):
                raise SoapAnalysisError("Only a UTF-8 XML 1.0 declaration is supported")
            tokens += 1
            index = end + 2
        elif text.startswith(("<!", "<?"), index):
            raise SoapAnalysisError(
                "XML declarations, DTD, entities, CDATA and processing instructions are unsupported"
            )
        else:
            end = index + 1
            quote = ""
            attributes = 0
            while end < len(text):
                char = text[end]
                if quote:
                    if char == quote:
                        quote = ""
                elif char in {'"', "'"}:
                    quote = char
                elif char == "=":
                    attributes += 1
                elif char == ">":
                    break
                end += 1
            if end == len(text):
                raise SoapAnalysisError("XML markup is incomplete")
            closing = text.startswith("</", index)
            empty = text[index:end].rstrip().endswith("/")
            tokens += 1 + attributes * 2
            if closing:
                depth -= 1
                if depth < 0:
                    raise SoapAnalysisError("XML closing structure is invalid")
            else:
                nodes += 1 + attributes
                highest = max(highest, depth + 1)
                if not empty:
                    depth += 1
            index = end + 1
        if (
            tokens > limits["max_xml_tokens"]
            or nodes > limits["max_xml_nodes"]
            or highest > limits["max_xml_depth"]
        ):
            raise SoapAnalysisError("XML source exceeds token/node/depth limits before parsing")
    if depth != 0 or nodes == 0:
        raise SoapAnalysisError("XML element structure is incomplete")
    return text, tokens, nodes, highest


def _parse(preflight: tuple[str, int, int, int], limits: dict[str, int]) -> _Parsed:
    text, tokens, nodes, highest = preflight
    parser = expat.ParserCreate(namespace_separator="}")
    parser.buffer_text = True
    stack: list[_Node] = []
    pending: list[tuple[str, str]] = []
    roots: list[_Node] = []
    visited = 0

    def expanded(name: str) -> str:
        if "}" in name:
            namespace, local = name.rsplit("}", 1)
            return _expanded(_q(namespace, local))
        return _expanded(name)

    def namespace(prefix: str | None, uri: str | None) -> None:
        prefix = prefix or ""
        if prefix:
            _name(prefix)
        if uri:
            _text(uri, "XML namespace", 512)
            if "{" in uri or "}" in uri:
                raise SoapAnalysisError("XML namespace is outside the supported URI subset")
        pending.append((prefix, uri or ""))

    def start(name: str, attrs: dict[str, str]) -> None:
        nonlocal visited
        visited += 1 + len(attrs) + len(pending)
        if visited > limits["max_xml_nodes"] or len(stack) >= limits["max_xml_depth"]:
            raise SoapAnalysisError("XML parser exceeds node/depth limits")
        if not stack:
            namespaces = _NamespaceFrame(MappingProxyType({"xml": XML, **dict(pending)}))
        elif pending:
            namespaces = _NamespaceFrame(MappingProxyType(dict(pending)), stack[-1].namespaces)
        else:
            namespaces = stack[-1].namespaces
        pending.clear()
        captured = {
            expanded(key): _text(value, "XML attribute", empty=True) for key, value in attrs.items()
        }
        node = _Node(expanded(name), captured, namespaces)
        if stack:
            stack[-1].children.append(node)
        else:
            roots.append(node)
        stack.append(node)

    def data(value: str) -> None:
        if stack:
            node = stack[-1]
            if len(node.text) + len(value) > MAX_TEXT:
                raise SoapAnalysisError("XML character content exceeds its scalar bound")
            node.text += value
            _text(node.text, "XML character content", empty=True)
        elif value.strip(_XML_SPACE):
            raise SoapAnalysisError("XML has character content outside its root")

    def deny(*_: Any) -> None:
        raise SoapAnalysisError("XML external/declaration processing is forbidden")

    parser.StartNamespaceDeclHandler = namespace
    parser.StartElementHandler = start
    parser.EndElementHandler = lambda _: stack.pop()
    parser.CharacterDataHandler = data
    parser.StartDoctypeDeclHandler = deny
    parser.EntityDeclHandler = deny
    parser.ExternalEntityRefHandler = deny
    parser.ProcessingInstructionHandler = deny
    try:
        parser.Parse(text, True)
    except (expat.ExpatError, UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, SoapAnalysisError):
            raise
        raise SoapAnalysisError("XML source is malformed") from exc
    if len(roots) != 1 or stack:
        raise SoapAnalysisError("XML requires exactly one complete root")
    todo = [roots[0]]
    while todo:
        node = todo.pop()
        if node.tag.startswith("{http://www.w3.org/2001/XInclude}") or node.tag in {
            _q(WSDL, "import"),
            _q(XSD, "import"),
            _q(XSD, "include"),
            _q(XSD, "redefine"),
            _q(XSD, "override"),
        }:
            raise SoapAnalysisError("XML includes/imports and external schemas are forbidden")
        todo.extend(node.children)
    return _Parsed(roots[0], tokens, nodes, highest)


def _resolve(value: str | None, node: _Node) -> str:
    if value is None or value != value.strip(_XML_SPACE):
        raise SoapAnalysisError("Contract QName reference is missing or malformed")
    if ":" in value:
        parts = value.split(":")
        if len(parts) != 2:
            raise SoapAnalysisError("Contract QName reference is malformed")
        prefix, local = map(_name, parts)
        namespace = node.namespaces.get(prefix)
        if not namespace:
            raise SoapAnalysisError("Contract QName prefix is undefined")
        return _q(namespace, local)
    return _q(node.namespaces.get("", ""), _name(value))


def _attrs(node: _Node, allowed: set[str], required: set[str] | None = None) -> None:
    if set(node.attrs) - allowed:
        raise _Unsupported("contract_attribute_not_supported")
    if required and not required <= set(node.attrs):
        raise SoapAnalysisError("Contract required attributes are missing")


def _children(node: _Node, allowed: set[str]) -> list[_Node]:
    if node.text.strip(_XML_SPACE):
        raise SoapAnalysisError("Contract contains unexpected character content")
    result = [
        child
        for child in node.children
        if not (node.tag.startswith(f"{{{WSDL}}}") and child.tag == _q(WSDL, "documentation"))
    ]
    if any(child.tag not in allowed for child in result):
        raise _Unsupported("contract_construct_not_supported")
    return result


def _one(nodes: list[_Node], tag: str, *, optional: bool = False) -> _Node | None:
    matches = [node for node in nodes if node.tag == tag]
    if len(matches) != 1 and not (optional and not matches):
        raise SoapAnalysisError("Contract element is missing or duplicated")
    return matches[0] if matches else None


@dataclass(frozen=True, slots=True)
class _Field:
    qname: str
    scalar: str
    minimum: int
    maximum: int | None


@dataclass(frozen=True, slots=True)
class _Element:
    qname: str
    scalar: str | None
    fields: tuple[_Field, ...]


@dataclass(frozen=True, slots=True)
class _Contract:
    action: str
    payload: _Element
    headers: tuple[_Element, ...]


def _scalar_type(node: _Node) -> str:
    name = _resolve(node.attrs.get("type"), node)
    if not name.startswith(f"{{{XSD}}}") or name.split("}", 1)[1] not in _SCALARS:
        raise _Unsupported("xsd_type_not_supported")
    return name.split("}", 1)[1]


def _occurs(value: str | None, default: int = 1) -> int:
    if value is None:
        return default
    if re.fullmatch(r"[0-9]{1,5}", value) is None or int(value) > MAX_ITEMS:
        raise _Unsupported("xsd_occurrence_bound_not_supported")
    return int(value)


def _elements(schema: _Node) -> dict[str, _Element]:
    _attrs(schema, {"targetNamespace", "elementFormDefault"}, {"targetNamespace"})
    namespace = _text(schema.attrs["targetNamespace"], "Schema namespace", 512)
    qualified = schema.attrs.get("elementFormDefault", "unqualified")
    if qualified not in {"qualified", "unqualified"}:
        raise SoapAnalysisError("Schema elementFormDefault is invalid")
    elements: dict[str, _Element] = {}
    for node in _children(schema, {_q(XSD, "element")}):
        _attrs(node, {"name", "type"}, {"name"})
        name = _q(namespace, _name(node.attrs["name"]))
        if name in elements:
            raise SoapAnalysisError("Duplicate schema element definition")
        if "type" in node.attrs:
            _children(node, set())
            elements[name] = _Element(name, _scalar_type(node), ())
            continue
        complex_type = _one(_children(node, {_q(XSD, "complexType")}), _q(XSD, "complexType"))
        assert complex_type is not None
        _attrs(complex_type, set())
        sequence = _one(_children(complex_type, {_q(XSD, "sequence")}), _q(XSD, "sequence"))
        assert sequence is not None
        _attrs(sequence, set())
        fields: list[_Field] = []
        seen: set[str] = set()
        for child in _children(sequence, {_q(XSD, "element")}):
            _attrs(child, {"name", "type", "minOccurs", "maxOccurs", "form"}, {"name", "type"})
            _children(child, set())
            form = child.attrs.get("form", qualified)
            if form not in {"qualified", "unqualified"}:
                raise SoapAnalysisError("Schema local element form is invalid")
            qname = _q(namespace if form == "qualified" else "", _name(child.attrs["name"]))
            if qname in seen:
                raise _Unsupported("ambiguous_xsd_sequence")
            seen.add(qname)
            minimum = _occurs(child.attrs.get("minOccurs"))
            maximum = (
                None
                if child.attrs.get("maxOccurs") == "unbounded"
                else _occurs(child.attrs.get("maxOccurs"))
            )
            if maximum is not None and minimum > maximum:
                raise SoapAnalysisError("Schema occurrence range is invalid")
            fields.append(_Field(qname, _scalar_type(child), minimum, maximum))
        elements[name] = _Element(name, None, tuple(fields))
    return elements


def _compile(root: _Node, selection: dict[str, Any]) -> _Contract:
    if root.tag != _q(WSDL, "definitions"):
        raise _Unsupported("wsdl_version_not_supported")
    _attrs(root, {"targetNamespace", "name"}, {"targetNamespace"})
    namespace = _text(root.attrs["targetNamespace"], "WSDL namespace", 512)
    nodes = _children(
        root, {_q(WSDL, item) for item in ("types", "message", "portType", "binding", "service")}
    )
    types = _one(nodes, _q(WSDL, "types"))
    assert types is not None
    _attrs(types, set())
    schema = _one(_children(types, {_q(XSD, "schema")}), _q(XSD, "schema"))
    assert schema is not None
    elements = _elements(schema)
    messages: dict[str, dict[str, _Element]] = {}
    port_types: dict[str, dict[str, _Node]] = {}
    bindings: dict[str, _Node] = {}
    for node in nodes:
        if node.tag == _q(WSDL, "message"):
            _attrs(node, {"name"}, {"name"})
            qname = _q(namespace, _name(node.attrs["name"]))
            if qname in messages:
                raise SoapAnalysisError("Duplicate WSDL message definition")
            parts: dict[str, _Element] = {}
            for part in _children(node, {_q(WSDL, "part")}):
                _attrs(part, {"name", "element"}, {"name", "element"})
                part_name = _name(part.attrs["name"])
                reference = _resolve(part.attrs["element"], part)
                _children(part, set())
                if part_name in parts or reference not in elements:
                    raise SoapAnalysisError(
                        "WSDL part is duplicated or references an undefined inline element"
                    )
                parts[part_name] = elements[reference]
            messages[qname] = parts
        elif node.tag == _q(WSDL, "portType"):
            _attrs(node, {"name"}, {"name"})
            qname = _q(namespace, _name(node.attrs["name"]))
            if qname in port_types:
                raise SoapAnalysisError("Duplicate WSDL portType definition")
            operations: dict[str, _Node] = {}
            for operation in _children(node, {_q(WSDL, "operation")}):
                _attrs(operation, {"name"}, {"name"})
                name = _name(operation.attrs["name"])
                if name in operations:
                    raise _Unsupported("overloaded_wsdl_operation_not_supported")
                operations[name] = operation
            port_types[qname] = operations
        elif node.tag == _q(WSDL, "binding"):
            _attrs(node, {"name", "type"}, {"name", "type"})
            qname = _q(namespace, _name(node.attrs["name"]))
            if qname in bindings:
                raise SoapAnalysisError("Duplicate WSDL binding definition")
            bindings[qname] = node
    if selection["binding_qname"] not in bindings:
        raise SoapAnalysisError("Selected WSDL binding is absent")
    binding = bindings[selection["binding_qname"]]
    port_type = _resolve(binding.attrs["type"], binding)
    if port_type not in port_types:
        raise SoapAnalysisError("WSDL binding references an undefined portType")
    binding_nodes = _children(binding, {_q(SOAP_BINDING, "binding"), _q(WSDL, "operation")})
    soap_binding = _one(binding_nodes, _q(SOAP_BINDING, "binding"))
    assert soap_binding is not None
    _attrs(soap_binding, {"style", "transport"}, {"transport"})
    _children(soap_binding, set())
    if (
        soap_binding.attrs.get("style", "document") != "document"
        or soap_binding.attrs["transport"] != "http://schemas.xmlsoap.org/soap/http"
    ):
        raise _Unsupported("soap_binding_not_supported")
    selected: _Node | None = None
    operation_names: set[str] = set()
    for node in binding_nodes:
        if node.tag != _q(WSDL, "operation"):
            continue
        _attrs(node, {"name"}, {"name"})
        name = _name(node.attrs["name"])
        if name in operation_names:
            raise SoapAnalysisError("Duplicate WSDL binding operation")
        operation_names.add(name)
        if name not in port_types[port_type]:
            raise SoapAnalysisError("Binding operation references an undefined portType operation")
        if name == selection["operation_name"]:
            selected = node
    if selected is None:
        raise SoapAnalysisError("Selected WSDL operation is absent")
    abstract = port_types[port_type][selection["operation_name"]]
    abstract_nodes = _children(abstract, {_q(WSDL, item) for item in ("input", "output", "fault")})
    _one(abstract_nodes, _q(WSDL, "input"))
    _one(abstract_nodes, _q(WSDL, "output"), optional=True)
    operation_nodes = _children(
        selected,
        {_q(SOAP_BINDING, "operation"), *(_q(WSDL, item) for item in ("input", "output", "fault"))},
    )
    soap_operation = _one(operation_nodes, _q(SOAP_BINDING, "operation"))
    assert soap_operation is not None
    _attrs(soap_operation, {"soapAction", "style"}, {"soapAction"})
    _children(soap_operation, set())
    if soap_operation.attrs.get("style", "document") != "document":
        raise _Unsupported("soap_operation_not_supported")
    kind = selection["message_kind"]
    node_tag = _q(WSDL, "fault" if kind == "fault" else "input" if kind == "request" else "output")

    def selected_message(items: list[_Node], *, bound: bool) -> _Node:
        matches = [
            item
            for item in items
            if item.tag == node_tag
            and (kind != "fault" or item.attrs.get("name") == selection["fault_name"])
        ]
        if len(matches) != 1:
            raise SoapAnalysisError("Selected WSDL message direction/fault is absent or duplicated")
        result = matches[0]
        _attrs(result, {"name"} if bound else {"name", "message"}, set() if bound else {"message"})
        return result

    abstract_message = selected_message(abstract_nodes, bound=False)
    _children(abstract_message, set())
    reference = _resolve(abstract_message.attrs["message"], abstract_message)
    if reference not in messages:
        raise SoapAnalysisError("WSDL operation references an undefined message")
    parts = messages[reference]
    bound_message = selected_message(operation_nodes, bound=True)
    if kind == "fault":
        fault = _one(
            _children(bound_message, {_q(SOAP_BINDING, "fault")}), _q(SOAP_BINDING, "fault")
        )
        assert fault is not None
        _attrs(fault, {"name", "use"}, {"name", "use"})
        if fault.attrs["name"] != selection["fault_name"]:
            raise SoapAnalysisError("SOAP fault name contradicts its WSDL fault")
        body = fault
    else:
        body_nodes = _children(
            bound_message, {_q(SOAP_BINDING, "body"), _q(SOAP_BINDING, "header")}
        )
        body = _one(body_nodes, _q(SOAP_BINDING, "body"))
        assert body is not None
        _attrs(body, {"parts", "use"}, {"use"})
    if body.attrs["use"] != "literal":
        raise _Unsupported("encoded_soap_not_supported")
    _children(body, set())
    selected_parts = body.attrs.get("parts")
    if selected_parts is None:
        names = list(parts)
    else:
        selected_parts = selected_parts.strip(_XML_SPACE)
        if not selected_parts:
            raise SoapAnalysisError("SOAP body part selection is empty")
        names = [_name(name) for name in re.split(r"[ \t\r\n]+", selected_parts)]
    if len(names) != 1:
        raise _Unsupported("multipart_body_not_supported")
    if names[0] not in parts:
        raise SoapAnalysisError("SOAP body references an undefined message part")
    headers: list[_Element] = []
    if kind != "fault":
        for header in body_nodes:
            if header.tag != _q(SOAP_BINDING, "header"):
                continue
            _attrs(header, {"message", "part", "use"}, {"message", "part", "use"})
            _children(header, set())
            if header.attrs["use"] != "literal":
                raise _Unsupported("soap_header_not_supported")
            message = _resolve(header.attrs["message"], header)
            part = _name(header.attrs["part"])
            if message not in messages or part not in messages[message]:
                raise SoapAnalysisError("SOAP header references an undefined message part")
            element = messages[message][part]
            if any(item.qname == element.qname for item in headers):
                raise _Unsupported("ambiguous_header_declaration")
            headers.append(element)
    return _Contract(
        soap_operation.attrs["soapAction"],
        parts[names[0]],
        tuple(sorted(headers, key=lambda item: item.qname)),
    )


_CODES = {
    "contract_attribute_not_supported",
    "contract_construct_not_supported",
    "xsd_type_not_supported",
    "xsd_occurrence_bound_not_supported",
    "nested_xsd_definition_not_supported",
    "ambiguous_xsd_sequence",
    "wsdl_version_not_supported",
    "overloaded_wsdl_operation_not_supported",
    "soap_binding_not_supported",
    "soap_operation_not_supported",
    "encoded_soap_not_supported",
    "multipart_body_not_supported",
    "soap_header_not_supported",
    "ambiguous_header_declaration",
    "soap_version_not_supported",
    "soap_encoding_not_supported",
    "soap_extension_not_supported",
    "xsi_override_not_supported",
    "fault_extension_not_supported",
    "fault_body_subset_not_supported",
    "envelope_name_mismatch",
    "envelope_structure_mismatch",
    "soap_character_content",
    "header_namespace_missing",
    "must_understand_lexical_mismatch",
    "unknown_header_semantics",
    "must_understand_processing_unassessed",
    "header_actor_processing_unassessed",
    "declared_header_not_observed",
    "repeated_header_semantics_unassessed",
    "body_element_mismatch",
    "body_cardinality_mismatch",
    "field_not_declared",
    "sequence_order_mismatch",
    "field_cardinality_mismatch",
    "unexpected_attribute",
    "scalar_structure_mismatch",
    "scalar_lexical_mismatch",
    "action_mismatch",
    "response_action_semantics_unassessed",
    "unexpected_fault_for_message_kind",
    "selected_fault_not_observed",
    "fault_structure_mismatch",
    "fault_code_mismatch",
    "fault_detail_missing",
}


@dataclass(slots=True)
class _Analysis:
    maximum: int
    observations: list[dict[str, Any]] = field(default_factory=list)
    scalar_checks: int = 0
    sequence_checks: int = 0
    observed_headers: int = 0
    declared_headers: int = 0
    soap_version: str | None = None
    declared_payload: str | None = None
    fault_present: bool | None = None
    body_elements: list[str] = field(default_factory=list)

    def add(
        self,
        kind: str,
        code: str,
        path: str,
        expected: str | None = None,
        actual: str | None = None,
    ) -> None:
        if len(self.observations) >= self.maximum:
            raise SoapAnalysisError("Analysis exceeds its observation limit")
        self.observations.append(
            {"kind": kind, "code": code, "path": path, "expected": expected, "actual": actual}
        )


def _scalar(node: _Node, scalar: str, path: str, analysis: _Analysis) -> None:
    analysis.scalar_checks += 1
    if node.children:
        analysis.add(
            "violation", "scalar_structure_mismatch", path, "scalar text", "nested elements"
        )
        return
    value = node.text.strip(_XML_SPACE)
    valid = True
    if scalar == "boolean":
        valid = value in {"true", "false", "1", "0"}
    elif scalar == "int":
        valid = _INTEGER.fullmatch(value) is not None
        if valid:
            unsigned = value.lstrip("+-").lstrip("0") or "0"
            valid = len(unsigned) <= 10
            if valid:
                integer = int(("-" if value.startswith("-") else "") + unsigned)
                valid = -(2**31) <= integer <= 2**31 - 1
    elif scalar == "decimal":
        valid = _DECIMAL.fullmatch(value) is not None
    if not valid:
        analysis.add(
            "violation",
            "scalar_lexical_mismatch",
            path,
            f"xsd:{scalar} lexical form",
            "outside lexical subset",
        )


def _instance_attributes(node: _Node, path: str, analysis: _Analysis, allowed: set[str]) -> None:
    for name in node.attrs:
        if name.startswith(f"{{{XSI}}}"):
            raise _Unsupported("xsi_override_not_supported", path)
        if name == _q(SOAP, "encodingStyle"):
            raise _Unsupported("soap_encoding_not_supported", path)
        if name not in allowed:
            analysis.add(
                "violation", "unexpected_attribute", path, "declared attribute subset", name
            )


def _payload(
    node: _Node, declaration: _Element, path: str, analysis: _Analysis, *, header: bool = False
) -> None:
    if node.tag != declaration.qname:
        analysis.add("violation", "body_element_mismatch", path, declaration.qname, node.tag)
        return
    allowed = {_q(SOAP, "mustUnderstand"), _q(SOAP, "actor")} if header else set()
    _instance_attributes(node, path, analysis, allowed)
    if declaration.scalar is not None:
        _scalar(node, declaration.scalar, path, analysis)
        return
    analysis.sequence_checks += 1
    if node.text.strip(_XML_SPACE):
        analysis.add(
            "violation",
            "soap_character_content",
            path,
            "element-only sequence",
            "character content",
        )
    indexes = {item.qname: index for index, item in enumerate(declaration.fields)}
    counts = {item.qname: 0 for item in declaration.fields}
    previous = -1
    for number, child in enumerate(node.children):
        child_path = f"{path}/field[{number}]"
        if child.tag not in indexes:
            analysis.add(
                "violation",
                "field_not_declared",
                child_path,
                "declared sequence element",
                child.tag,
            )
            continue
        index = indexes[child.tag]
        if index < previous:
            analysis.add(
                "violation",
                "sequence_order_mismatch",
                child_path,
                "declared sequence order",
                child.tag,
            )
        previous = max(previous, index)
        counts[child.tag] += 1
        _instance_attributes(child, child_path, analysis, set())
        _scalar(child, declaration.fields[index].scalar, child_path, analysis)
    for item in declaration.fields:
        count = counts[item.qname]
        if count < item.minimum or item.maximum is not None and count > item.maximum:
            ceiling = "unbounded" if item.maximum is None else str(item.maximum)
            analysis.add(
                "violation",
                "field_cardinality_mismatch",
                path,
                f"{item.qname} [{item.minimum},{ceiling}]",
                str(count),
            )


def _fault(node: _Node, contract: _Contract | None, analysis: _Analysis) -> None:
    _instance_attributes(node, "/Envelope/Body/Fault", analysis, set())
    if node.text.strip(_XML_SPACE):
        analysis.add(
            "violation",
            "soap_character_content",
            "/Envelope/Body/Fault",
            "element-only content",
            "character content",
        )
    allowed = {"faultcode", "faultstring", "faultactor", "detail"}
    if any(child.tag not in allowed for child in node.children):
        raise _Unsupported("fault_extension_not_supported", "/Envelope/Body/Fault")
    selected: dict[str, _Node] = {}
    for name in allowed:
        matches = [child for child in node.children if child.tag == name]
        if len(matches) > 1 or name in {"faultcode", "faultstring"} and not matches:
            analysis.add(
                "violation",
                "fault_structure_mismatch",
                "/Envelope/Body/Fault",
                f"one {name}",
                str(len(matches)),
            )
        elif matches:
            selected[name] = matches[0]
    for name in ("faultcode", "faultstring", "faultactor"):
        if name not in selected:
            continue
        child = selected[name]
        path = f"/Envelope/Body/Fault/{name}"
        _instance_attributes(
            child, path, analysis, {_q(XML, "lang")} if name == "faultstring" else set()
        )
        if child.children:
            analysis.add(
                "violation", "scalar_structure_mismatch", path, "simple text", "nested elements"
            )
        if name == "faultcode":
            try:
                _resolve(child.text.strip(_XML_SPACE), child)
            except SoapAnalysisError:
                analysis.add(
                    "violation",
                    "fault_code_mismatch",
                    path,
                    "namespace-resolved QName",
                    "invalid QName",
                )
    if contract is not None:
        detail = selected.get("detail")
        if detail is None:
            analysis.add(
                "violation",
                "fault_detail_missing",
                "/Envelope/Body/Fault",
                contract.payload.qname,
                None,
            )
        else:
            _instance_attributes(detail, "/Envelope/Body/Fault/detail", analysis, set())
            if detail.text.strip(_XML_SPACE):
                analysis.add(
                    "violation",
                    "soap_character_content",
                    "/Envelope/Body/Fault/detail",
                    "element-only content",
                    "character content",
                )
            if len(detail.children) != 1:
                analysis.add(
                    "violation",
                    "body_cardinality_mismatch",
                    "/Envelope/Body/Fault/detail",
                    "one selected fault part",
                    str(len(detail.children)),
                )
            else:
                _payload(
                    detail.children[0],
                    contract.payload,
                    "/Envelope/Body/Fault/detail/part",
                    analysis,
                )


def _inspect(
    root: _Node, contract: _Contract, selection: dict[str, Any], analysis: _Analysis
) -> None:
    if root.tag == _q(SOAP12, "Envelope"):
        raise _Unsupported("soap_version_not_supported", "/Envelope")
    if root.tag != _q(SOAP, "Envelope"):
        analysis.add("violation", "envelope_name_mismatch", "/", _q(SOAP, "Envelope"), root.tag)
        return
    analysis.soap_version = "1.1"
    analysis.declared_headers = len(contract.headers)
    analysis.declared_payload = contract.payload.qname
    _instance_attributes(root, "/Envelope", analysis, set())
    if root.text.strip(_XML_SPACE):
        analysis.add(
            "violation",
            "soap_character_content",
            "/Envelope",
            "element-only content",
            "character content",
        )
    tags = [child.tag for child in root.children]
    if any(tag not in {_q(SOAP, "Header"), _q(SOAP, "Body")} for tag in tags):
        raise _Unsupported("soap_extension_not_supported", "/Envelope")
    if tags not in [[_q(SOAP, "Body")], [_q(SOAP, "Header"), _q(SOAP, "Body")]]:
        analysis.add(
            "violation",
            "envelope_structure_mismatch",
            "/Envelope",
            "optional Header then one Body",
            "different ordering/cardinality",
        )
    headers = [node for node in root.children if node.tag == _q(SOAP, "Header")]
    declarations = {item.qname: item for item in contract.headers}
    header_counts: dict[str, int] = {}
    for header in headers:
        _instance_attributes(header, "/Envelope/Header", analysis, set())
        if header.text.strip(_XML_SPACE):
            analysis.add(
                "violation",
                "soap_character_content",
                "/Envelope/Header",
                "header elements",
                "character content",
            )
        for number, block in enumerate(header.children):
            path = f"/Envelope/Header/block[{analysis.observed_headers}]"
            analysis.observed_headers += 1
            header_counts[block.tag] = header_counts.get(block.tag, 0) + 1
            if not block.tag.startswith("{"):
                analysis.add(
                    "violation",
                    "header_namespace_missing",
                    path,
                    "qualified header",
                    "unqualified header",
                )
            must = block.attrs.get(_q(SOAP, "mustUnderstand"), "0")
            if must not in {"0", "1"}:
                analysis.add(
                    "violation",
                    "must_understand_lexical_mismatch",
                    path,
                    "SOAP 1.1 0 or 1",
                    "other lexical form",
                )
            elif must == "1":
                analysis.add(
                    "unassessed", "must_understand_processing_unassessed", path, None, block.tag
                )
            if _q(SOAP, "actor") in block.attrs:
                analysis.add(
                    "unassessed", "header_actor_processing_unassessed", path, None, block.tag
                )
            if block.tag in declarations:
                _payload(block, declarations[block.tag], path, analysis, header=True)
            else:
                if _q(SOAP, "encodingStyle") in block.attrs:
                    raise _Unsupported("soap_encoding_not_supported", path)
                analysis.add("unassessed", "unknown_header_semantics", path, None, block.tag)
    for declaration in contract.headers:
        count = header_counts.get(declaration.qname, 0)
        if not count:
            analysis.add(
                "unassessed",
                "declared_header_not_observed",
                "/Envelope/Header",
                declaration.qname,
                None,
            )
        elif count > 1:
            analysis.add(
                "unassessed",
                "repeated_header_semantics_unassessed",
                "/Envelope/Header",
                declaration.qname,
                str(count),
            )
    bodies = [node for node in root.children if node.tag == _q(SOAP, "Body")]
    if len(bodies) != 1:
        return
    body = bodies[0]
    _instance_attributes(body, "/Envelope/Body", analysis, set())
    if body.text.strip(_XML_SPACE):
        analysis.add(
            "violation",
            "soap_character_content",
            "/Envelope/Body",
            "body elements",
            "character content",
        )
    analysis.body_elements = [child.tag for child in body.children]
    faults = [child for child in body.children if child.tag == _q(SOAP, "Fault")]
    analysis.fault_present = bool(faults)
    if faults:
        if len(faults) > 1:
            analysis.add(
                "violation",
                "fault_structure_mismatch",
                "/Envelope/Body",
                "at most one Fault",
                str(len(faults)),
            )
        if len(body.children) != 1:
            raise _Unsupported("fault_body_subset_not_supported", "/Envelope/Body")
        if selection["message_kind"] != "fault":
            analysis.add(
                "violation",
                "unexpected_fault_for_message_kind",
                "/Envelope/Body",
                selection["message_kind"],
                "fault",
            )
        _fault(faults[0], contract if selection["message_kind"] == "fault" else None, analysis)
    elif selection["message_kind"] == "fault":
        analysis.add(
            "violation", "selected_fault_not_observed", "/Envelope/Body", "Fault", "non-fault body"
        )
    elif len(body.children) != 1:
        analysis.add(
            "violation",
            "body_cardinality_mismatch",
            "/Envelope/Body",
            "one selected message part",
            str(len(body.children)),
        )
    else:
        _payload(body.children[0], contract.payload, "/Envelope/Body/part", analysis)
    if selection["message_kind"] == "request":
        if selection["observed_action"] != contract.action:
            analysis.add(
                "violation",
                "action_mismatch",
                "/declared_transport/action",
                "exact WSDL action",
                "absent or different action",
            )
    elif selection["observed_action"] is not None:
        analysis.add(
            "unassessed", "response_action_semantics_unassessed", "/declared_transport/action"
        )


_STATISTICS = {
    f"{side}_{item}"
    for side in ("wsdl", "envelope")
    for item in ("xml_tokens", "xml_nodes", "xml_depth")
} | {"declared_header_count", "observed_header_count", "scalar_checks", "sequence_checks"}
_SUMMARY_FIELDS = {
    "soap_version",
    "declared_payload_qname",
    "observed_body_qnames",
    "fault_present",
}
_BODY_FIELDS = {
    "schema_version",
    "profile_id",
    "capability_id",
    "vector_id",
    "syntax_profile",
    "analysis_status",
    "wsdl_source",
    "envelope_source",
    "selection",
    "limits",
    "statistics",
    "structural_summary",
    "observation_count",
    "observations",
    "offline_only",
    "operational_effects",
    *_FLAGS,
}


def _hash(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _address(body: dict[str, Any]) -> tuple[str, str]:
    document = _native({"domain": DOMAIN, "analysis": body})
    digest = _hash(document.encode("ascii"))
    return "SOA-" + digest[7:39].upper(), digest


def _validate_report(raw: Any) -> dict[str, Any]:
    _native(raw)
    raw = _exact(raw, _BODY_FIELDS | {"report_id", "report_sha256"}, "Report")
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
        raise SoapAnalysisError("Report schema version is unsupported")
    for key, value in {
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "syntax_profile": SYNTAX_PROFILE,
    }.items():
        if type(raw[key]) is not str or raw[key] != value:
            raise SoapAnalysisError("Report profile/syntax bindings are invalid")
    for side in ("wsdl", "envelope"):
        source = _exact(
            raw[f"{side}_source"], {"source_id", "byte_count", "sha256"}, "Report source"
        )
        if (
            type(source["source_id"]) is not str
            or _SOURCE_ID.fullmatch(source["source_id"]) is None
        ):
            raise SoapAnalysisError("Report source ID is invalid")
        _integer(source["byte_count"], "Source bytes", MAX_DOCUMENT_BYTES)
        if type(source["sha256"]) is not str or _DIGEST.fullmatch(source["sha256"]) is None:
            raise SoapAnalysisError("Report source hash is invalid")
    _selection(raw["selection"])
    limits = _exact(raw["limits"], set(_LIMITS), "Report limits")
    for key, maximum in _LIMITS.items():
        _integer(limits[key], key, maximum)
    for side in ("wsdl", "envelope"):
        if raw[f"{side}_source"]["byte_count"] > limits[f"max_{side}_bytes"]:
            raise SoapAnalysisError("Report source exceeds its declared byte limit")
    statistics = _exact(raw["statistics"], _STATISTICS, "Report statistics")
    for key, value in statistics.items():
        _integer(value, key, MAX_ITEMS, minimum=0)
    for side in ("wsdl", "envelope"):
        for item in ("tokens", "nodes", "depth"):
            _integer(statistics[f"{side}_xml_{item}"], item, limits[f"max_xml_{item}"])
    summary = _exact(raw["structural_summary"], _SUMMARY_FIELDS, "Structural summary")
    if summary["soap_version"] is not None and (
        type(summary["soap_version"]) is not str or summary["soap_version"] != "1.1"
    ):
        raise SoapAnalysisError("Report SOAP version is invalid")
    if summary["declared_payload_qname"] is not None:
        _expanded(summary["declared_payload_qname"])
    if type(summary["observed_body_qnames"]) is not list:
        raise SoapAnalysisError("Report body names are invalid")
    for name in summary["observed_body_qnames"]:
        _expanded(name)
    if summary["fault_present"] is not None and type(summary["fault_present"]) is not bool:
        raise SoapAnalysisError("Report fault indicator must be a native boolean or null")
    if raw["offline_only"] is not True or any(raw[key] is not False for key in _FLAGS):
        raise SoapAnalysisError("Report cannot grant authority or claim full validation")
    if _native(raw["operational_effects"]) != _native(_EFFECTS):
        raise SoapAnalysisError("Report effects must remain none")
    observations = raw["observations"]
    if type(observations) is not list:
        raise SoapAnalysisError("Report observations must be a native array")
    _integer(raw["observation_count"], "Observation count", limits["max_observations"], minimum=0)
    if raw["observation_count"] != len(observations):
        raise SoapAnalysisError("Report observation count is inconsistent")
    kinds: set[str] = set()
    for observation in observations:
        _exact(observation, {"kind", "code", "path", "expected", "actual"}, "Observation")
        if type(observation["kind"]) is not str or observation["kind"] not in {
            "violation",
            "unassessed",
            "unsupported",
        }:
            raise SoapAnalysisError("Observation kind is invalid")
        if type(observation["code"]) is not str or observation["code"] not in _CODES:
            raise SoapAnalysisError("Observation code is invalid")
        _text(observation["path"], "Observation path", 1024)
        for key in ("expected", "actual"):
            if observation[key] is not None:
                _text(observation[key], "Observation metadata", empty=True)
        kinds.add(observation["kind"])
    if observations != sorted(observations, key=_native):
        raise SoapAnalysisError("Report observations are not canonically ordered")
    status = (
        "unsupported"
        if "unsupported" in kinds
        else "mismatch"
        if "violation" in kinds
        else "partially_assessed"
        if "unassessed" in kinds
        else "consistent_with_supported_subset"
    )
    if type(raw["analysis_status"]) is not str or raw["analysis_status"] != status:
        raise SoapAnalysisError("Report analysis status is inconsistent")
    body = {key: value for key, value in raw.items() if key not in {"report_id", "report_sha256"}}
    identifier, digest = _address(body)
    if (
        type(raw["report_id"]) is not str
        or type(raw["report_sha256"]) is not str
        or raw["report_id"] != identifier
        or raw["report_sha256"] != digest
    ):
        raise SoapAnalysisError("Report identity does not match canonical content")
    return raw


@dataclass(frozen=True, slots=True)
class SoapAnalysisReport:
    """Detached unsigned content integrity; full conclusions require source replay."""

    document_json: str

    def __post_init__(self) -> None:
        raw = _validate_report(_decode(self.document_json))
        if _native(raw) != self.document_json:
            raise SoapAnalysisError("Report document must be canonical JSON")

    def to_dict(self) -> dict[str, Any]:
        try:
            text = self.document_json
        except AttributeError as exc:
            raise SoapAnalysisError("Report wrapper is incomplete") from exc
        raw = _validate_report(_decode(text))
        if _native(raw) != text:
            raise SoapAnalysisError("Report document must be canonical JSON")
        return raw

    def to_json(self) -> str:
        return _native(self.to_dict())

    @classmethod
    def from_dict(cls, raw: Any) -> SoapAnalysisReport:
        return cls(_native(_validate_report(raw)))

    @classmethod
    def from_json(cls, text: str) -> SoapAnalysisReport:
        return cls.from_dict(_decode(text))


def analyze_soap_contract_instance(
    *,
    wsdl_content: bytes,
    envelope_content: bytes,
    wsdl_source_id: str,
    envelope_source_id: str,
    selection: dict[str, Any],
    limits: SoapAnalysisLimits,
) -> SoapAnalysisReport:
    """Analyze supplied source structure without external resolution or runtime access."""
    captured_limits = _capture_limits(limits)
    captured_selection = _selection(selection)
    for source_id in (wsdl_source_id, envelope_source_id):
        if type(source_id) is not str or _SOURCE_ID.fullmatch(source_id) is None:
            raise SoapAnalysisError("Source ID must be a bounded native identifier")
    wsdl_preflight = _preflight(wsdl_content, captured_limits["max_wsdl_bytes"], captured_limits)
    envelope_preflight = _preflight(
        envelope_content, captured_limits["max_envelope_bytes"], captured_limits
    )
    wsdl = _parse(wsdl_preflight, captured_limits)
    envelope = _parse(envelope_preflight, captured_limits)
    analysis = _Analysis(captured_limits["max_observations"])
    try:
        contract = _compile(wsdl.root, captured_selection)
        _inspect(envelope.root, contract, captured_selection, analysis)
    except _Unsupported as exc:
        analysis.add("unsupported", exc.code, exc.path)
    observations = sorted(analysis.observations, key=_native)
    kinds = {item["kind"] for item in observations}
    status = (
        "unsupported"
        if "unsupported" in kinds
        else "mismatch"
        if "violation" in kinds
        else "partially_assessed"
        if "unassessed" in kinds
        else "consistent_with_supported_subset"
    )
    body = {
        "schema_version": 1,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "syntax_profile": SYNTAX_PROFILE,
        "analysis_status": status,
        "wsdl_source": {
            "source_id": wsdl_source_id,
            "byte_count": len(wsdl_content),
            "sha256": _hash(wsdl_content),
        },
        "envelope_source": {
            "source_id": envelope_source_id,
            "byte_count": len(envelope_content),
            "sha256": _hash(envelope_content),
        },
        "selection": captured_selection,
        "limits": captured_limits,
        "statistics": {
            "wsdl_xml_tokens": wsdl.tokens,
            "wsdl_xml_nodes": wsdl.nodes,
            "wsdl_xml_depth": wsdl.depth,
            "envelope_xml_tokens": envelope.tokens,
            "envelope_xml_nodes": envelope.nodes,
            "envelope_xml_depth": envelope.depth,
            "declared_header_count": analysis.declared_headers,
            "observed_header_count": analysis.observed_headers,
            "scalar_checks": analysis.scalar_checks,
            "sequence_checks": analysis.sequence_checks,
        },
        "structural_summary": {
            "soap_version": analysis.soap_version,
            "declared_payload_qname": analysis.declared_payload,
            "observed_body_qnames": analysis.body_elements,
            "fault_present": analysis.fault_present,
        },
        "observation_count": len(observations),
        "observations": observations,
        "offline_only": True,
        "operational_effects": dict(_EFFECTS),
        **{key: False for key in _FLAGS},
    }
    identifier, digest = _address(body)
    return SoapAnalysisReport.from_dict({**body, "report_id": identifier, "report_sha256": digest})


def verify_soap_contract_instance(
    *,
    report: SoapAnalysisReport,
    wsdl_content: bytes,
    envelope_content: bytes,
    wsdl_source_id: str,
    envelope_source_id: str,
    selection: dict[str, Any],
    limits: SoapAnalysisLimits,
) -> SoapAnalysisReport:
    """Reproduce exact source/config bytes, not merely self-consistent unsigned hashes."""
    if type(report) is not SoapAnalysisReport:
        raise SoapAnalysisError("Report must use the exact native report family")
    captured = report.to_dict()
    expected = analyze_soap_contract_instance(
        wsdl_content=wsdl_content,
        envelope_content=envelope_content,
        wsdl_source_id=wsdl_source_id,
        envelope_source_id=envelope_source_id,
        selection=selection,
        limits=limits,
    )
    if _native(captured) != expected.to_json():
        raise SoapAnalysisError("Report does not reproduce exact sources and configuration")
    return SoapAnalysisReport.from_dict(expected.to_dict())


__all__ = [
    "SoapAnalysisError",
    "SoapAnalysisLimits",
    "SoapAnalysisReport",
    "analyze_soap_contract_instance",
    "verify_soap_contract_instance",
]
