"""Bounded symbolic comparison of supplied OpenAPI 3.0 security declarations."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

PROFILE_ID = "AOE-GB-D06-S01"
CAPABILITY_ID = "army.gb.d06.s01"
VECTOR_ID = "AV-GB-D06-S01-01"
DOMAIN = "sunderkey.offline-openapi-security-evolution.v1"
ANALYSIS_PROFILE = "openapi30-local-security-dnf.v1"
MAX_DOCUMENT_BYTES = 1_048_576
MAX_DEPTH = 32
MAX_NODES = 50_000
MAX_STRING_BYTES = 8_192
MAX_OPERATIONS = 512
MAX_ALTERNATIVES = 64
MAX_ATOMS_PER_TERM = 128
MAX_ATOM_OCCURRENCES = 16_384
MAX_SCHEMES = 256
MAX_WORK = 1_000_000
MAX_ISSUES = 2_048
MIN_INTEGER = -(2**63)
MAX_INTEGER = 2**63 - 1
_METHODS = frozenset(("get", "put", "post", "delete", "options", "head", "patch", "trace"))
_VERSIONS = frozenset(f"3.0.{patch}" for patch in range(5))
_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ID = re.compile(r"OAE-[0-9A-F]{32}\Z")
_LIMITS = {
    "max_document_bytes": MAX_DOCUMENT_BYTES,
    "max_depth": MAX_DEPTH,
    "max_nodes": MAX_NODES,
    "max_string_bytes": MAX_STRING_BYTES,
    "max_operations": MAX_OPERATIONS,
    "max_alternatives": MAX_ALTERNATIVES,
    "max_atoms_per_term": MAX_ATOMS_PER_TERM,
    "max_atom_occurrences": MAX_ATOM_OCCURRENCES,
    "max_schemes": MAX_SCHEMES,
    "max_work": MAX_WORK,
    "max_issues": MAX_ISSUES,
}
_RELATIONS = (
    "equivalent",
    "weakened",
    "strengthened",
    "incomparable",
    "unassessed",
    "added",
    "removed",
)
_EFFECTS = {
    key: "none"
    for key in (
        "authority",
        "credential_resolution",
        "execution",
        "finding_publication",
        "network",
        "qualification",
        "target_interaction",
    )
}
_FLAGS = {
    "positive_use_approved",
    "target_authorization_verified",
    "credential_rights_verified",
    "server_behavior_verified",
    "full_openapi_validation_claimed",
    "qualification_claimed",
}
_ISSUES = {
    "no_security_declaration",
    "opaque_path_reference",
    "operation_reference",
    "unsupported_root_field",
    "unsupported_path_field",
    "unsupported_operation_field",
    "unsupported_root_extension",
    "unsupported_path_extension",
    "unsupported_operation_extension",
    "unsupported_components_extension",
    "undefined_scheme",
    "scheme_reference",
    "unsupported_scheme_type",
    "unsupported_scheme_field",
    "unsupported_scheme_extension",
    "incomplete_scheme",
    "unsupported_http_scheme",
    "external_oidc",
    "unsupported_oauth_flow",
    "unsupported_oauth_field",
    "unsupported_oauth_extension",
    "incomplete_oauth_flow",
    "undefined_scope",
    "scopes_on_non_oauth_scheme",
    "definition_not_shared",
}
_SIDE_FIELDS = {
    "present",
    "declaration_origin",
    "declaration_form",
    "declared_alternative_count",
    "resolved",
    "formula",
    "issues",
}
_ROW_FIELDS = {
    "method",
    "path",
    "previous",
    "current",
    "relationship",
    "previous_implies_current",
    "current_implies_previous",
    "previous_not_current_witness",
    "current_not_previous_witness",
}
_REPORT_FIELDS = {
    "schema_version",
    "analysis_profile",
    "profile_id",
    "capability_id",
    "vector_id",
    "source",
    "limits",
    "operation_count",
    "operations",
    "opaque_paths",
    "document_issues",
    "summary",
    "work_units",
    "analysis_status",
    "offline_only",
    "declaration_only",
    "effects",
    "report_id",
    "report_sha256",
    *_FLAGS,
}


class OpenAPISecurityEvolutionError(ValueError):
    """Invalid, unsupported or over-budget supplied analysis input."""


def _integer(value: Any, maximum: int, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise OpenAPISecurityEvolutionError("A bounded native integer is required")
    return value


def _text(value: Any, maximum: int = MAX_STRING_BYTES, *, empty: bool = False) -> str:
    if type(value) is not str or len(value) > maximum or (not value and not empty):
        raise OpenAPISecurityEvolutionError("Bounded native text is required")
    try:
        if len(value.encode("utf-8")) > maximum:
            raise OpenAPISecurityEvolutionError("Text exceeds its byte limit")
    except UnicodeError as exc:
        raise OpenAPISecurityEvolutionError("Text must contain valid Unicode scalars") from exc
    return value


def _string_cost(value: str) -> int:
    return 2 + sum(_character_cost(ord(char)) for char in value)


def _character_cost(code: int) -> int:
    if code in {34, 92, 8, 9, 10, 12, 13}:
        return 2
    if code < 32 or 126 < code <= 65535:
        return 6
    return 12 if code > 65535 else 1


def _canonical(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def _native(value: Any) -> str:
    """Charge queued children, repeated subtrees and escaped bytes before dumps."""
    stack = [(value, 1)]
    nodes = size = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise OpenAPISecurityEvolutionError("Native document exceeds node/depth limits")
        kind = type(item)
        if kind is dict:
            children = 2 * len(item)
            if nodes + len(stack) + children > MAX_NODES:
                raise OpenAPISecurityEvolutionError("Native queued-node limit exceeded")
            size += 2 + max(0, len(item) - 1) + len(item)
            for key, child in item.items():
                if type(key) is not str:
                    raise OpenAPISecurityEvolutionError("Native string mapping keys are required")
                stack.append((child, depth + 1))
                stack.append((key, depth + 1))
        elif kind is list:
            if nodes + len(stack) + len(item) > MAX_NODES:
                raise OpenAPISecurityEvolutionError("Native queued-node limit exceeded")
            size += 2 + max(0, len(item) - 1)
            stack.extend((child, depth + 1) for child in item)
        elif kind is str:
            size += _string_cost(_text(item, empty=True))
        elif kind is int:
            if not MIN_INTEGER <= item <= MAX_INTEGER:
                raise OpenAPISecurityEvolutionError("Integer exceeds the signed 64-bit subset")
            size += len(str(item))
        elif kind is bool:
            size += 4 if item else 5
        elif item is None:
            size += 4
        else:
            raise OpenAPISecurityEvolutionError(
                "Only exact native JSON subset values are supported"
            )
        if size > MAX_DOCUMENT_BYTES:
            raise OpenAPISecurityEvolutionError("Native escaped-byte document limit exceeded")
    return _canonical(value)


def _detach(value: Any) -> dict[str, Any]:
    encoded = _native(value)
    if type(value) is not dict:
        raise OpenAPISecurityEvolutionError("A native document object is required")
    return json.loads(encoded)


def _raw_string(text: str, index: int) -> tuple[int, int]:
    index += 1
    decoded_bytes, cost = 0, 2
    escapes = {'"': 34, "\\": 92, "/": 47, "b": 8, "f": 12, "n": 10, "r": 13, "t": 9}
    while index < len(text):
        char = text[index]
        if char == '"':
            return index + 1, cost
        code = ord(char)
        if char == "\\":
            index += 1
            if index >= len(text):
                break
            if text[index] in escapes:
                code = escapes[text[index]]
            elif text[index] == "u":
                lexical = text[index + 1 : index + 5]
                if len(lexical) != 4 or any(
                    char not in "0123456789abcdefABCDEF" for char in lexical
                ):
                    raise OpenAPISecurityEvolutionError("Raw JSON Unicode escape is malformed")
                code = int(lexical, 16)
                index += 4
                if 0xD800 <= code <= 0xDBFF:
                    lexical = text[index + 3 : index + 7]
                    if (
                        text[index + 1 : index + 3] != "\\u"
                        or len(lexical) != 4
                        or any(char not in "0123456789abcdefABCDEF" for char in lexical)
                    ):
                        raise OpenAPISecurityEvolutionError("Raw JSON surrogate pair is malformed")
                    low = int(lexical, 16)
                    if not 0xDC00 <= low <= 0xDFFF:
                        raise OpenAPISecurityEvolutionError("Raw JSON surrogate pair is malformed")
                    code = 0x10000 + ((code - 0xD800) << 10) + low - 0xDC00
                    index += 6
                elif 0xDC00 <= code <= 0xDFFF:
                    raise OpenAPISecurityEvolutionError("Raw JSON has an unpaired surrogate")
            else:
                raise OpenAPISecurityEvolutionError("Raw JSON escape is malformed")
        elif code < 32:
            raise OpenAPISecurityEvolutionError("Raw JSON contains an unescaped control")
        decoded_bytes += 1 if code < 128 else 2 if code < 2048 else 3 if code < 65536 else 4
        cost += _character_cost(code)
        if decoded_bytes > MAX_STRING_BYTES or cost > MAX_DOCUMENT_BYTES:
            raise OpenAPISecurityEvolutionError("Raw JSON string exceeds its predecode limit")
        index += 1
    raise OpenAPISecurityEvolutionError("Raw JSON string is incomplete")


def _integer_lexical(text: str) -> None:
    digits = text[1:] if text.startswith("-") else text
    ceiling = "9223372036854775808" if text.startswith("-") else "9223372036854775807"
    if not digits or len(digits) > 19 or any(char not in "0123456789" for char in digits):
        raise OpenAPISecurityEvolutionError("JSON integer lexical limit exceeded")
    if len(digits) == 19 and digits > ceiling:
        raise OpenAPISecurityEvolutionError("JSON integer exceeds the signed 64-bit subset")


def _raw_preflight(text: Any) -> str:
    if type(text) is not str or not text or len(text) > MAX_DOCUMENT_BYTES:
        raise OpenAPISecurityEvolutionError("A bounded native JSON string is required")
    size = 0
    for char in text:
        code = ord(char)
        if 0xD800 <= code <= 0xDFFF:
            raise OpenAPISecurityEvolutionError("Raw JSON contains invalid Unicode scalars")
        size += 1 if code < 128 else 2 if code < 2048 else 3 if code < 65536 else 4
        if size > MAX_DOCUMENT_BYTES:
            raise OpenAPISecurityEvolutionError("Raw JSON byte limit exceeded")
    index = nodes = depth = canonical_size = 0
    while index < len(text):
        char = text[index]
        scalar = False
        if char in "[{":
            depth += 1
            nodes += 1
            canonical_size += 1
            index += 1
        elif char in "]}":
            depth -= 1
            if depth < 0:
                raise OpenAPISecurityEvolutionError("Raw JSON nesting is malformed")
            canonical_size += 1
            index += 1
        elif char == '"':
            nodes += 1
            scalar = True
            index, cost = _raw_string(text, index)
            canonical_size += cost
        elif char == "-" or char in "0123456789":
            end = index + 1
            while end < len(text) and text[end] in "0123456789.eE+-":
                end += 1
            if end - index > 20:
                raise OpenAPISecurityEvolutionError("Raw JSON numeric lexical limit exceeded")
            _integer_lexical(text[index:end])
            canonical_size += end - index
            nodes += 1
            scalar = True
            index = end
        elif char in "tfn":
            lexical = next(
                (
                    literal
                    for literal in ("true", "false", "null")
                    if text.startswith(literal, index)
                ),
                None,
            )
            if lexical is None:
                raise OpenAPISecurityEvolutionError("Raw JSON literal is malformed")
            index += len(lexical)
            canonical_size += len(lexical)
            nodes += 1
            scalar = True
        else:
            if char in ",:":
                canonical_size += 1
            index += 1
        if nodes > MAX_NODES or depth + int(scalar) > MAX_DEPTH:
            raise OpenAPISecurityEvolutionError("Raw JSON exceeds node/depth limits before decode")
        if canonical_size > MAX_DOCUMENT_BYTES:
            raise OpenAPISecurityEvolutionError(
                "Raw JSON escaped-byte limit exceeded before decode"
            )
    if depth:
        raise OpenAPISecurityEvolutionError("Raw JSON nesting is incomplete")
    return text


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise OpenAPISecurityEvolutionError("Duplicate JSON key")
        result[key] = value
    return result


def _json_integer(text: str) -> int:
    _integer_lexical(text)
    value = int(text)
    if not MIN_INTEGER <= value <= MAX_INTEGER:
        raise OpenAPISecurityEvolutionError("JSON integer exceeds the signed 64-bit subset")
    return value


def _no_number(_: str) -> None:
    raise OpenAPISecurityEvolutionError("JSON floats and nonfinite numbers are unsupported")


def _decode(text: Any) -> dict[str, Any]:
    checked = _raw_preflight(text)
    try:
        raw = json.loads(
            checked,
            object_pairs_hook=_pairs,
            parse_int=_json_integer,
            parse_float=_no_number,
            parse_constant=_no_number,
        )
    except (ValueError, TypeError, RecursionError) as exc:
        if isinstance(exc, OpenAPISecurityEvolutionError):
            raise
        raise OpenAPISecurityEvolutionError("Report JSON is malformed") from exc
    return _detach(raw)


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _name(value: Any) -> str:
    if type(value) is not str or _NAME.fullmatch(value) is None:
        raise OpenAPISecurityEvolutionError("Scheme name is outside the supported component subset")
    return value


def _scope(value: Any) -> str:
    checked = _text(value, 256)
    if any(ord(char) < 32 or ord(char) == 127 for char in checked):
        raise OpenAPISecurityEvolutionError("Scope symbol contains control characters")
    return checked


def _path(value: Any) -> str:
    checked = _text(value, 1024)
    if not checked.startswith("/") or any(ord(char) < 32 or ord(char) == 127 for char in checked):
        raise OpenAPISecurityEvolutionError("A literal bounded OpenAPI path is required")
    return checked


def _fields(value: dict[str, Any], expected: set[str]) -> None:
    if set(value) != expected:
        raise OpenAPISecurityEvolutionError("Document fields are not the exact supported shape")


@dataclass(slots=True)
class _Work:
    units: int = 0
    atoms: int = 0
    issues: int = 0

    def charge(self, units: int = 1) -> None:
        if self.units + units > MAX_WORK:
            raise OpenAPISecurityEvolutionError("Symbolic comparison work limit exceeded")
        self.units += units

    def add_atoms(self, count: int) -> None:
        if self.atoms + count > MAX_ATOM_OCCURRENCES:
            raise OpenAPISecurityEvolutionError("Raw atom occurrence limit exceeded")
        self.atoms += count

    def add_issues(self, count: int) -> None:
        if self.issues + count > MAX_ISSUES:
            raise OpenAPISecurityEvolutionError("Issue count limit exceeded")
        self.issues += count


@dataclass(slots=True)
class _Output:
    size: int = 8192
    nodes: int = 256

    def reserve(self, size: int, nodes: int) -> None:
        if self.size + size > MAX_DOCUMENT_BYTES or self.nodes + nodes > MAX_NODES:
            raise OpenAPISecurityEvolutionError("Conservative output reservation limit exceeded")
        self.size += size
        self.nodes += nodes


def _subset(smaller: frozenset, larger: frozenset, work: _Work) -> bool:
    work.charge(1 + len(smaller))
    return smaller <= larger


def _minimal(terms: list[frozenset], work: _Work) -> list[frozenset]:
    kept = []
    for term in sorted(set(terms), key=lambda item: (len(item), tuple(sorted(item)))):
        if not any(_subset(prior, term, work) for prior in kept):
            kept.append(term)
    return sorted(kept, key=lambda item: tuple(sorted(item)))


def _implies(left: list[frozenset], right: list[frozenset], work: _Work) -> tuple[bool, Any]:
    for term in left:
        if not any(_subset(other, term, work) for other in right):
            return False, term
    return True, None


def _term_document(term: frozenset, output: _Output | None = None) -> list[dict[str, Any]]:
    ordered = sorted(term)
    names = {name for name, scope in ordered if not scope}
    if output is not None:
        output.reserve(
            16
            + sum(64 + _string_cost(name) for name in names)
            + sum(_string_cost(scope) + 1 for _, scope in ordered if scope),
            1 + 5 * len(names) + sum(bool(scope) for _, scope in ordered),
        )
    groups = []
    for name, scope in ordered:
        if not scope:
            groups.append({"scheme": name, "scopes": []})
        else:
            groups[-1]["scopes"].append(scope)
    return groups


def _issue(code: str, subject: str = "") -> tuple[str, str]:
    return code, subject


def _issues_document(issues: set[tuple[str, str]], output: _Output) -> list[dict[str, str]]:
    output.reserve(
        sum(48 + _string_cost(code) + _string_cost(subject) for code, subject in issues),
        1 + 5 * len(issues),
    )
    return [{"code": code, "subject": subject} for code, subject in sorted(issues)]


def _container_issues(value: dict, allowed: set[str], context: str) -> set[tuple[str, str]]:
    issues = set()
    for key in value:
        if key.startswith("x-"):
            issues.add(_issue(f"unsupported_{context}_extension"))
        elif key not in allowed:
            issues.add(_issue(f"unsupported_{context}_field"))
    return issues


def _url(value: Any) -> bool:
    if type(value) is not str or not value or any(char.isspace() for char in value):
        return False
    try:
        parsed = urlsplit(value)
        port = parsed.port
        return (
            parsed.scheme == "https"
            and bool(parsed.hostname)
            and parsed.username is None
            and parsed.password is None
            and (port is None or 0 < port <= 65535)
        )
    except (ValueError, UnicodeError):
        return False


@dataclass(frozen=True, slots=True)
class _Scheme:
    identity: str | None
    oauth: bool
    scopes: frozenset[str]
    issues: frozenset[tuple[str, str]]


def _scheme_structure(name: str, definition: Any) -> _Scheme:
    identity = _canonical(definition) if definition is not None else None

    def result(issues, *, oauth=False, scopes=frozenset()):
        return _Scheme(identity, oauth, frozenset(scopes), frozenset(issues))

    if definition is None:
        return result({_issue("undefined_scheme", name)})
    if type(definition) is not dict:
        return result({_issue("incomplete_scheme", name)})
    if "$ref" in definition:
        return result({_issue("scheme_reference", name)})
    kind = definition.get("type")
    if type(kind) is not str or kind not in {"apiKey", "http", "oauth2", "openIdConnect"}:
        return result({_issue("unsupported_scheme_type", name)})
    if kind == "openIdConnect":
        return result({_issue("external_oidc", name)})
    allowed = {
        "apiKey": {"type", "description", "name", "in"},
        "http": {"type", "description", "scheme", "bearerFormat"},
        "oauth2": {"type", "description", "flows"},
    }[kind]
    issues = {
        _issue(
            "unsupported_scheme_extension" if key.startswith("x-") else "unsupported_scheme_field",
            name,
        )
        for key in definition
        if key not in allowed
    }
    if "description" in definition and type(definition["description"]) is not str:
        issues.add(_issue("incomplete_scheme", name))
    if kind == "apiKey":
        if (
            type(definition.get("name")) is not str
            or not definition["name"]
            or type(definition.get("in")) is not str
            or definition["in"] not in {"header", "query", "cookie"}
        ):
            issues.add(_issue("incomplete_scheme", name))
    elif kind == "http":
        scheme = definition.get("scheme")
        if type(scheme) is not str or scheme.lower() not in {"basic", "bearer"}:
            issues.add(_issue("unsupported_http_scheme", name))
        if "bearerFormat" in definition and (
            type(definition["bearerFormat"]) is not str
            or type(scheme) is not str
            or scheme.lower() != "bearer"
        ):
            issues.add(_issue("incomplete_scheme", name))
    else:
        flows = definition.get("flows")
        if type(flows) is not dict or not flows:
            return result(issues | {_issue("incomplete_oauth_flow", name)}, oauth=True)
        required = {
            "implicit": {"authorizationUrl"},
            "password": {"tokenUrl"},
            "clientCredentials": {"tokenUrl"},
            "authorizationCode": {"authorizationUrl", "tokenUrl"},
        }
        declared = set()
        for flow_name, flow in flows.items():
            if flow_name not in required or type(flow) is not dict:
                issues.add(_issue("unsupported_oauth_flow", name))
                continue
            for key in flow:
                if key.startswith("x-"):
                    issues.add(_issue("unsupported_oauth_extension", name))
                elif key not in required[flow_name] | {"refreshUrl", "scopes"}:
                    issues.add(_issue("unsupported_oauth_field", name))
            scope_map = flow.get("scopes")
            if (
                type(scope_map) is not dict
                or any(
                    type(key) is not str or type(value) is not str
                    for key, value in scope_map.items()
                )
                or any(not _url(flow.get(key)) for key in required[flow_name])
                or ("refreshUrl" in flow and not _url(flow["refreshUrl"]))
            ):
                issues.add(_issue("incomplete_oauth_flow", name))
                continue
            declared.update(scope_map)
        return result(issues, oauth=True, scopes=declared)
    return result(issues)


@dataclass(slots=True)
class _Document:
    document: dict
    operations: dict[tuple[str, str], dict]
    opaque: set[str]
    definitions: dict
    issues: set[tuple[str, str]]
    scheme_cache: dict[str, _Scheme]

    def scheme(self, name: str) -> _Scheme:
        if name not in self.scheme_cache:
            self.scheme_cache[name] = _scheme_structure(name, self.definitions.get(name))
        return self.scheme_cache[name]


def _document(value: dict) -> _Document:
    if type(value.get("openapi")) is not str or value["openapi"] not in _VERSIONS:
        raise OpenAPISecurityEvolutionError("Only exact OpenAPI 3.0.0 through 3.0.4 is supported")
    paths = value.get("paths")
    if type(paths) is not dict or len(paths) > MAX_OPERATIONS:
        raise OpenAPISecurityEvolutionError("Bounded native OpenAPI paths are required")
    components = value.get("components", {})
    if type(components) is not dict:
        raise OpenAPISecurityEvolutionError("OpenAPI components must be a native object")
    definitions = components.get("securitySchemes", {})
    if type(definitions) is not dict or len(definitions) > MAX_SCHEMES:
        raise OpenAPISecurityEvolutionError("Local security scheme definition count is invalid")
    issues = _container_issues(
        value,
        {
            "openapi",
            "info",
            "servers",
            "paths",
            "components",
            "security",
            "tags",
            "externalDocs",
        },
        "root",
    )
    if any(key.startswith("x-") for key in components):
        issues.add(_issue("unsupported_components_extension"))
    operations = {}
    opaque = set()
    for path, item in paths.items():
        _path(path)
        if type(item) is not dict:
            raise OpenAPISecurityEvolutionError("Path items must be native objects")
        if "$ref" in item:
            opaque.add(path)
        methods = _METHODS & item.keys()
        if len(operations) + len(methods) > MAX_OPERATIONS:
            raise OpenAPISecurityEvolutionError("Operation count limit exceeded")
        for method in methods:
            if type(item[method]) is not dict:
                raise OpenAPISecurityEvolutionError("Operations must be native objects")
            operations[(path, method.upper())] = item[method]
    return _Document(value, operations, opaque, definitions, issues, {})


def _security(value: Any, work: _Work) -> tuple[list[frozenset], set[str], str, int]:
    if type(value) is not list or len(value) > MAX_ALTERNATIVES:
        raise OpenAPISecurityEvolutionError("Bounded security alternative arrays are required")
    if not value:
        return [frozenset()], set(), "explicit_empty", 0
    terms = []
    names = set()
    anonymous = False
    for requirement in value:
        if type(requirement) is not dict or len(requirement) > MAX_ATOMS_PER_TERM:
            raise OpenAPISecurityEvolutionError(
                "Security alternatives must be bounded native objects"
            )
        count = len(requirement)
        for name, scopes in requirement.items():
            _name(name)
            if type(scopes) is not list or len(scopes) > MAX_ATOMS_PER_TERM:
                raise OpenAPISecurityEvolutionError("Scope lists are outside the supported bounds")
            count += len(scopes)
        if count > MAX_ATOMS_PER_TERM:
            raise OpenAPISecurityEvolutionError("Per-term raw atom limit exceeded")
        work.add_atoms(count)
        term = set()
        for name, scopes in requirement.items():
            names.add(name)
            term.add((name, ""))
            for scope in scopes:
                term.add((name, _scope(scope)))
        anonymous |= not requirement
        terms.append(frozenset(term))
    return terms, names, "anonymous_alternative" if anonymous else "requirements", len(value)


@dataclass(slots=True)
class _Side:
    present: bool
    origin: str
    form: str
    alternatives: int
    terms: list[frozenset]
    names: set[str]
    issues: set[tuple[str, str]]

    @property
    def resolved(self) -> bool:
        return self.present and self.form not in {"absent", "unavailable"} and not self.issues

    def document(self, output: _Output) -> dict:
        output.reserve(256, 24)
        return {
            "present": self.present,
            "declaration_origin": self.origin,
            "declaration_form": self.form,
            "declared_alternative_count": self.alternatives,
            "resolved": self.resolved,
            "formula": [_term_document(term, output) for term in self.terms],
            "issues": _issues_document(self.issues, output),
        }


def _side(document: _Document, path: str, method: str, work: _Work) -> _Side:
    operation = document.operations.get((path, method))
    if path in document.opaque:
        return _Side(
            operation is not None,
            "opaque_path",
            "unavailable",
            0,
            [],
            set(),
            {_issue("opaque_path_reference")},
        )
    if operation is None:
        return _Side(False, "operation_missing", "unavailable", 0, [], set(), set())
    issues = set(document.issues)
    item = document.document["paths"][path]
    issues.update(
        _container_issues(
            item,
            {
                *_METHODS,
                "summary",
                "description",
                "servers",
                "parameters",
            },
            "path",
        )
    )
    issues.update(
        _container_issues(
            operation,
            {
                "tags",
                "summary",
                "description",
                "externalDocs",
                "operationId",
                "parameters",
                "requestBody",
                "responses",
                "callbacks",
                "deprecated",
                "security",
                "servers",
                "$ref",
            },
            "operation",
        )
    )
    if "$ref" in operation:
        issues.add(_issue("operation_reference"))
    if "security" in operation:
        origin, raw = "operation", operation["security"]
    elif "security" in document.document:
        origin, raw = "root", document.document["security"]
    else:
        return _Side(
            True, "absent", "absent", 0, [], set(), issues | {_issue("no_security_declaration")}
        )
    raw_terms, names, form, alternatives = _security(raw, work)
    # All original alternatives are resolved before absorption can hide any scheme.
    requested_scopes = {name: set() for name in names}
    for term in raw_terms:
        for name, scope in term:
            if scope:
                requested_scopes[name].add(scope)
    for name in names:
        scheme = document.scheme(name)
        scopes = requested_scopes[name]
        issues.update(scheme.issues)
        if not scheme.oauth and scopes:
            issues.add(_issue("scopes_on_non_oauth_scheme", name))
        elif scheme.oauth and not scopes <= scheme.scopes:
            issues.add(_issue("undefined_scope", name))
    terms = _minimal(raw_terms, work)
    return _Side(True, origin, form, alternatives, terms, names, issues)


def _relationship(previous: _Side, current: _Side, work: _Work) -> tuple[str, Any, Any, Any, Any]:
    if (
        previous.origin == "opaque_path"
        or current.origin == "opaque_path"
        or any(code == "operation_reference" for code, _ in previous.issues | current.issues)
    ):
        return "unassessed", None, None, None, None
    if not previous.present:
        return "added", None, None, None, None
    if not current.present:
        return "removed", None, None, None, None
    if not previous.resolved or not current.resolved:
        return "unassessed", None, None, None, None
    forward, forward_witness = _implies(previous.terms, current.terms, work)
    backward, backward_witness = _implies(current.terms, previous.terms, work)
    relationship = (
        "equivalent"
        if forward and backward
        else "weakened"
        if forward
        else "strengthened"
        if backward
        else "incomparable"
    )
    return relationship, forward, backward, forward_witness, backward_witness


def _row(
    previous: _Side, current: _Side, path: str, method: str, work: _Work, output: _Output
) -> dict:
    relationship, forward, backward, forward_witness, backward_witness = _relationship(
        previous,
        current,
        work,
    )
    output.reserve(320 + _string_cost(path), 24)
    return {
        "method": method,
        "path": path,
        "previous": previous.document(output),
        "current": current.document(output),
        "relationship": relationship,
        "previous_implies_current": forward,
        "current_implies_previous": backward,
        "previous_not_current_witness": (
            _term_document(forward_witness, output) if forward_witness is not None else None
        ),
        "current_not_previous_witness": (
            _term_document(backward_witness, output) if backward_witness is not None else None
        ),
    }


def _build(model: dict) -> dict:
    _fields(model, {"schema_version", "previous_document", "current_document"})
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise OpenAPISecurityEvolutionError("Model schema_version must be native integer 1")
    if type(model["previous_document"]) is not dict or type(model["current_document"]) is not dict:
        raise OpenAPISecurityEvolutionError("Both original documents must be native objects")
    previous = _document(model["previous_document"])
    current = _document(model["current_document"])
    keys = previous.operations.keys() | current.operations.keys()
    if len(keys) > MAX_OPERATIONS:
        raise OpenAPISecurityEvolutionError("Union operation count limit exceeded")
    work, output = _Work(), _Output()
    shared_definitions = {}
    rows = []
    for path, method in sorted(keys):
        old = _side(previous, path, method, work)
        new = _side(current, path, method, work)
        if old.present and new.present:
            for name in old.names | new.names:
                if name not in shared_definitions:
                    before = previous.scheme(name).identity
                    after = current.scheme(name).identity
                    shared_definitions[name] = before is not None and before == after
                if not shared_definitions[name]:
                    old.issues.add(_issue("definition_not_shared", name))
                    new.issues.add(_issue("definition_not_shared", name))
        work.add_issues(len(old.issues) + len(new.issues))
        rows.append(_row(old, new, path, method, work, output))
    opaque_paths = []
    for path in sorted(previous.opaque | current.opaque):
        output.reserve(96 + _string_cost(path), 7)
        opaque_paths.append(
            {
                "path": path,
                "previous_opaque": path in previous.opaque,
                "current_opaque": path in current.opaque,
            }
        )
    document_issues = []
    for side, document in (("previous", previous), ("current", current)):
        work.add_issues(len(document.issues))
        for code, subject in sorted(document.issues):
            output.reserve(80 + _string_cost(code) + _string_cost(subject), 7)
            document_issues.append({"side": side, "code": code, "subject": subject})
    summary = {kind: sum(row["relationship"] == kind for row in rows) for kind in _RELATIONS}
    body = {
        "schema_version": 1,
        "analysis_profile": ANALYSIS_PROFILE,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "source": {
            "model_sha256": _digest(model),
            "previous_document_sha256": _digest(model["previous_document"]),
            "current_document_sha256": _digest(model["current_document"]),
        },
        "limits": dict(_LIMITS),
        "operation_count": len(rows),
        "operations": rows,
        "opaque_paths": opaque_paths,
        "document_issues": document_issues,
        "summary": summary,
        "work_units": work.units,
        "analysis_status": (
            "partially_assessed"
            if summary["unassessed"] or opaque_paths or document_issues
            else "complete"
        ),
        "offline_only": True,
        "declaration_only": True,
        "effects": dict(_EFFECTS),
        **{key: False for key in _FLAGS},
    }
    _native(body)
    digest = _digest({"domain": DOMAIN, "analysis": body})
    return {**body, "report_id": "OAE-" + digest[7:39].upper(), "report_sha256": digest}


def _term_from_document(value: Any) -> frozenset:
    if type(value) is not list or len(value) > MAX_ATOMS_PER_TERM:
        raise OpenAPISecurityEvolutionError("Symbolic witness/term shape is invalid")
    atoms = set()
    names = []
    count = 0
    for group in value:
        if type(group) is not dict:
            raise OpenAPISecurityEvolutionError("Symbolic scheme group is invalid")
        _fields(group, {"scheme", "scopes"})
        name = _name(group["scheme"])
        names.append(name)
        scopes = group["scopes"]
        if type(scopes) is not list or len(scopes) > MAX_ATOMS_PER_TERM:
            raise OpenAPISecurityEvolutionError("Symbolic scopes are invalid")
        checked = [_scope(scope) for scope in scopes]
        if checked != sorted(set(checked)):
            raise OpenAPISecurityEvolutionError("Symbolic scopes are not sorted and unique")
        count += 1 + len(scopes)
        if count > MAX_ATOMS_PER_TERM:
            raise OpenAPISecurityEvolutionError("Symbolic atom count exceeds limit")
        atoms.add((name, ""))
        atoms.update((name, scope) for scope in checked)
    if names != sorted(set(names)):
        raise OpenAPISecurityEvolutionError("Symbolic scheme groups are not sorted and unique")
    return frozenset(atoms)


def _side_from_document(value: Any, work: _Work) -> _Side:
    if type(value) is not dict:
        raise OpenAPISecurityEvolutionError("Report declaration side is invalid")
    _fields(value, _SIDE_FIELDS)
    if type(value["present"]) is not bool or type(value["resolved"]) is not bool:
        raise OpenAPISecurityEvolutionError("Report declaration flags must be native booleans")
    origin, form = value["declaration_origin"], value["declaration_form"]
    if (
        type(origin) is not str
        or origin
        not in {
            "root",
            "operation",
            "absent",
            "operation_missing",
            "opaque_path",
        }
        or type(form) is not str
        or form
        not in {
            "requirements",
            "explicit_empty",
            "anonymous_alternative",
            "absent",
            "unavailable",
        }
    ):
        raise OpenAPISecurityEvolutionError("Report declaration origin/form is invalid")
    alternatives = _integer(value["declared_alternative_count"], MAX_ALTERNATIVES)
    formula, issues = value["formula"], value["issues"]
    if type(formula) is not list or len(formula) > MAX_ALTERNATIVES:
        raise OpenAPISecurityEvolutionError("Report symbolic formula is invalid")
    terms = [_term_from_document(term) for term in formula]
    if _canonical([_term_document(term) for term in _minimal(terms, work)]) != _canonical(formula):
        raise OpenAPISecurityEvolutionError("Report symbolic formula is not minimal/canonical")
    if type(issues) is not list or len(issues) > MAX_ISSUES:
        raise OpenAPISecurityEvolutionError("Report declaration issues are invalid")
    checked_issues = set()
    for issue in issues:
        if type(issue) is not dict:
            raise OpenAPISecurityEvolutionError("Report issue shape is invalid")
        _fields(issue, {"code", "subject"})
        if type(issue["code"]) is not str or issue["code"] not in _ISSUES:
            raise OpenAPISecurityEvolutionError("Report issue code is invalid")
        checked_issues.add((issue["code"], _text(issue["subject"], 128, empty=True)))
    if _canonical(
        [{"code": code, "subject": subject} for code, subject in sorted(checked_issues)]
    ) != _canonical(issues):
        raise OpenAPISecurityEvolutionError("Report issues are not sorted and unique")
    work.add_atoms(sum(len(term) for term in terms))
    work.add_issues(len(issues))
    side = _Side(value["present"], origin, form, alternatives, terms, set(), checked_issues)
    if value["resolved"] is not side.resolved:
        raise OpenAPISecurityEvolutionError("Report resolved flag contradicts its shape")
    if origin in {"root", "operation"}:
        if not side.present or form not in {
            "requirements",
            "explicit_empty",
            "anonymous_alternative",
        }:
            raise OpenAPISecurityEvolutionError("Report declared side shape is inconsistent")
        if form == "explicit_empty" and (alternatives != 0 or terms != [frozenset()]):
            raise OpenAPISecurityEvolutionError("Report explicit-empty declaration is inconsistent")
        if form != "explicit_empty" and (alternatives < 1 or not terms):
            raise OpenAPISecurityEvolutionError("Report nonempty declaration is inconsistent")
        if (form == "anonymous_alternative") != (
            terms == [frozenset()]
        ) and form != "explicit_empty":
            raise OpenAPISecurityEvolutionError("Report anonymous declaration is inconsistent")
    elif alternatives or terms or form != ("absent" if origin == "absent" else "unavailable"):
        raise OpenAPISecurityEvolutionError("Report unavailable side shape is inconsistent")
    if origin == "operation_missing" and (side.present or issues):
        raise OpenAPISecurityEvolutionError("Missing operation cannot claim a declaration")
    if origin == "absent" and (
        not side.present or ("no_security_declaration", "") not in checked_issues
    ):
        raise OpenAPISecurityEvolutionError("Absent security declaration is inconsistent")
    if origin == "opaque_path" and ("opaque_path_reference", "") not in checked_issues:
        raise OpenAPISecurityEvolutionError("Opaque path lacks its uncertainty")
    return side


def _validate_report(raw: Any) -> dict:
    value = _detach(raw)
    _fields(value, _REPORT_FIELDS)
    constants = {
        "schema_version": 1,
        "analysis_profile": ANALYSIS_PROFILE,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "limits": _LIMITS,
        "offline_only": True,
        "declaration_only": True,
        "effects": _EFFECTS,
        **{key: False for key in _FLAGS},
    }
    if any(_canonical(value[key]) != _canonical(expected) for key, expected in constants.items()):
        raise OpenAPISecurityEvolutionError("Report profile, limits or non-authority fields differ")
    source = value["source"]
    if type(source) is not dict:
        raise OpenAPISecurityEvolutionError("Report source shape is invalid")
    _fields(source, {"model_sha256", "previous_document_sha256", "current_document_sha256"})
    if any(type(digest) is not str or _SHA.fullmatch(digest) is None for digest in source.values()):
        raise OpenAPISecurityEvolutionError("Report source digest is invalid")
    rows = value["operations"]
    if type(rows) is not list or len(rows) > MAX_OPERATIONS:
        raise OpenAPISecurityEvolutionError("Report operation rows are invalid")
    if _integer(value["operation_count"], MAX_OPERATIONS) != len(rows):
        raise OpenAPISecurityEvolutionError("Report operation count is inconsistent")
    work = _Work()
    keys = []
    for row in rows:
        if type(row) is not dict:
            raise OpenAPISecurityEvolutionError("Report row is invalid")
        _fields(row, _ROW_FIELDS)
        path, method = _path(row["path"]), row["method"]
        if type(method) is not str or method.lower() not in _METHODS or method != method.upper():
            raise OpenAPISecurityEvolutionError("Report method is invalid")
        keys.append((path, method))
        before = _side_from_document(row["previous"], work)
        after = _side_from_document(row["current"], work)
        if not before.present and not after.present:
            raise OpenAPISecurityEvolutionError("Report row has no declared operation")
        relation = _relationship(before, after, work)
        expected = {
            "relationship": relation[0],
            "previous_implies_current": relation[1],
            "current_implies_previous": relation[2],
            "previous_not_current_witness": (
                _term_document(relation[3]) if relation[3] is not None else None
            ),
            "current_not_previous_witness": (
                _term_document(relation[4]) if relation[4] is not None else None
            ),
        }
        if any(_canonical(row[key]) != _canonical(item) for key, item in expected.items()):
            raise OpenAPISecurityEvolutionError(
                "Report relationship/witness does not reproduce formula"
            )
    if keys != sorted(set(keys)):
        raise OpenAPISecurityEvolutionError("Report operation rows are not sorted and unique")
    opaque = value["opaque_paths"]
    if type(opaque) is not list or len(opaque) > 2 * MAX_OPERATIONS:
        raise OpenAPISecurityEvolutionError("Report opaque paths are invalid")
    opaque_keys = []
    for entry in opaque:
        if type(entry) is not dict:
            raise OpenAPISecurityEvolutionError("Report opaque path shape is invalid")
        _fields(entry, {"path", "previous_opaque", "current_opaque"})
        opaque_keys.append(_path(entry["path"]))
        if any(
            type(entry[key]) is not bool for key in ("previous_opaque", "current_opaque")
        ) or not (entry["previous_opaque"] or entry["current_opaque"]):
            raise OpenAPISecurityEvolutionError("Report opaque path flags are invalid")
    if opaque_keys != sorted(set(opaque_keys)):
        raise OpenAPISecurityEvolutionError("Report opaque paths are not sorted and unique")
    document_issues = value["document_issues"]
    if type(document_issues) is not list or len(document_issues) > MAX_ISSUES:
        raise OpenAPISecurityEvolutionError("Report document issues are invalid")
    issue_keys = []
    for issue in document_issues:
        if type(issue) is not dict:
            raise OpenAPISecurityEvolutionError("Report document issue shape is invalid")
        _fields(issue, {"side", "code", "subject"})
        if (
            type(issue["side"]) is not str
            or issue["side"] not in {"previous", "current"}
            or (type(issue["code"]) is not str or issue["code"] not in _ISSUES)
        ):
            raise OpenAPISecurityEvolutionError("Report document issue is invalid")
        issue_keys.append((issue["side"], issue["code"], _text(issue["subject"], 128, empty=True)))
    # Producer order is previous then current, each internally sorted.
    if issue_keys != sorted(set(issue_keys), key=lambda item: (item[0] != "previous", item[1:])):
        raise OpenAPISecurityEvolutionError("Report document issues are not sorted and unique")
    work.add_issues(len(document_issues))
    expected_summary = {
        kind: sum(row["relationship"] == kind for row in rows) for kind in _RELATIONS
    }
    if _canonical(value["summary"]) != _canonical(expected_summary):
        raise OpenAPISecurityEvolutionError("Report summary is inconsistent")
    expected_status = (
        "partially_assessed"
        if expected_summary["unassessed"] or opaque or document_issues
        else "complete"
    )
    if type(value["analysis_status"]) is not str or value["analysis_status"] != expected_status:
        raise OpenAPISecurityEvolutionError("Report analysis status is inconsistent")
    _integer(value["work_units"], MAX_WORK)
    identifier, digest = value["report_id"], value["report_sha256"]
    if (
        type(identifier) is not str
        or _ID.fullmatch(identifier) is None
        or type(digest) is not str
        or _SHA.fullmatch(digest) is None
    ):
        raise OpenAPISecurityEvolutionError("Report address is invalid")
    body = {key: item for key, item in value.items() if key not in {"report_id", "report_sha256"}}
    expected_digest = _digest({"domain": DOMAIN, "analysis": body})
    if digest != expected_digest or identifier != "OAE-" + digest[7:39].upper():
        raise OpenAPISecurityEvolutionError("Report content address does not reproduce")
    return value


@dataclass(frozen=True, slots=True)
class OpenAPISecurityEvolutionReport:
    """Unsigned metadata integrity; original-model replay is a separate operation."""

    document_json: str

    def __post_init__(self) -> None:
        document = _validate_report(_decode(self.document_json))
        if _canonical(document) != self.document_json:
            raise OpenAPISecurityEvolutionError(
                "Direct report construction requires canonical JSON"
            )

    def to_dict(self) -> dict:
        try:
            encoded = object.__getattribute__(self, "document_json")
        except AttributeError as exc:
            raise OpenAPISecurityEvolutionError("Report wrapper is incomplete") from exc
        document = _validate_report(_decode(encoded))
        if _canonical(document) != encoded:
            raise OpenAPISecurityEvolutionError("Report wrapper is not canonical")
        return document

    def to_json(self) -> str:
        return _canonical(self.to_dict())

    @classmethod
    def from_dict(cls, value: Any) -> OpenAPISecurityEvolutionReport:
        return cls(_canonical(_validate_report(value)))

    @classmethod
    def from_json(cls, text: Any) -> OpenAPISecurityEvolutionReport:
        return cls.from_dict(_decode(text))


def analyze_openapi_security_evolution(model: dict) -> OpenAPISecurityEvolutionReport:
    """Analyze owned native source declarations, without target or principal effects."""
    owned = _detach(model)
    return OpenAPISecurityEvolutionReport.from_dict(_build(owned))


def verify_openapi_security_evolution(
    report: OpenAPISecurityEvolutionReport,
    *,
    model: dict,
) -> OpenAPISecurityEvolutionReport:
    """Reconstruct using the separately supplied complete original canonical model."""
    if type(report) is not OpenAPISecurityEvolutionReport:
        raise OpenAPISecurityEvolutionError("The exact report wrapper is required")
    original = report.to_dict()
    expected = analyze_openapi_security_evolution(model)
    if _canonical(original) != expected.to_json():
        raise OpenAPISecurityEvolutionError("Report does not reproduce the original model")
    return expected


def component_fixture() -> dict:
    """Return a detached wholly synthetic weakening example, not a target request."""
    previous = {
        "openapi": "3.0.4",
        "info": {"title": "Synthetic declarations", "version": "1"},
        "components": {
            "securitySchemes": {
                "bearer": {"type": "http", "scheme": "bearer"},
                "key": {"type": "apiKey", "in": "header", "name": "X-Synthetic-Key"},
            }
        },
        "security": [{"bearer": [], "key": []}],
        "paths": {"/synthetic": {"get": {"responses": {"200": {"description": "synthetic"}}}}},
    }
    current = json.loads(_canonical(previous))
    current["security"] = [{"bearer": []}]
    return {"schema_version": 1, "previous_document": previous, "current_document": current}


__all__ = [
    "OpenAPISecurityEvolutionError",
    "OpenAPISecurityEvolutionReport",
    "analyze_openapi_security_evolution",
    "verify_openapi_security_evolution",
    "component_fixture",
]
