"""Bounded offline comparison of declared function grants and invocations."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "api_supplied_function_authorization_differential"
PROFILE_ID = "AOE-GB-D06-S10"
CAPABILITY_ID = "api.authorization.function-level"
VECTOR_ID = "AV-GB-D06-S10-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D06-S10"
WAVE_ID = "IW2-002"
COMMANDER_ID = "AOE-GB-D06-CMD"
GROUP_OWNER_ID = "AOE-HQ-04"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-34"
BLUEPRINT_SHA256 = "sha256:a3682a899d6c4d56015e87e18250f2af492061bab828338b995478b1a11c085b"
DOMAIN = "sunderkey.offline-api-function-authorization.v1"
MODEL_DOMAIN = "sunderkey.offline-api-function-authorization-model.v1"
SEMANTICS_PROFILE = "declared-any-role-allow-function-matrix.v1"
MAX_DOCUMENT_BYTES = 1_048_576
MAX_NATIVE_NODES = 32_768
MAX_NATIVE_DEPTH = 16
MAX_STRING_BYTES = 256
MAX_ROLES = 32
MAX_SUBJECTS = 32
MAX_FUNCTIONS = 32
MAX_INVOCATIONS = 128
MAX_WORK = 4_000_000
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_PLACEHOLDER = "sha256:" + "0" * 64
_FLAGS = dict.fromkeys(
    (
        "source_authenticated",
        "subject_identity_verified",
        "role_membership_verified",
        "policy_source_verified",
        "invocation_observed",
        "server_enforcement_verified",
        "bypass_verified",
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
    "native_nodes": MAX_NATIVE_NODES,
    "scalar_inclusive_depth": MAX_NATIVE_DEPTH,
    "string_bytes": MAX_STRING_BYTES,
    "roles": MAX_ROLES,
    "subjects": MAX_SUBJECTS,
    "functions": MAX_FUNCTIONS,
    "invocations": MAX_INVOCATIONS,
    "work_steps": MAX_WORK,
}
_LIMITATIONS = (
    "Subjects, roles, function grants, completeness and invocation outcomes are supplied premises.",
    "Any declared allow among complete held-role rules grants the function in this model.",
    "Incomplete roles, matrix or invocation observations make a comparison unknown.",
    "A candidate contradiction is a declared-data mismatch, not a verified bypass.",
    "Object identity, property writes, URLs, route matching and provider policy are not modeled.",
    "No request, server enforcement, credentials, target state or authority is observed.",
    "No network, process, execution, qualification or positive use is established.",
)


class ApiFunctionAuthorizationAnalysisError(ValueError):
    """A supplied model or report is outside the exact bounded contract."""


@dataclass(slots=True)
class _Work:
    count: int = 0

    def charge(self, amount: int) -> None:
        if self.count + amount > MAX_WORK:
            raise ApiFunctionAuthorizationAnalysisError("Software work bound exhausted")
        self.count += amount


def _measure(value: Any, work: _Work | None = None) -> tuple[int, int]:
    size = nodes = 0
    active: set[int] = set()

    def charge(amount: int) -> None:
        nonlocal size
        size += amount
        if size > MAX_DOCUMENT_BYTES:
            raise ApiFunctionAuthorizationAnalysisError("Document byte bound exhausted")

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if depth > MAX_NATIVE_DEPTH or nodes > MAX_NATIVE_NODES:
            raise ApiFunctionAuthorizationAnalysisError("Native node/depth bound exhausted")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_STRING_BYTES:
                raise ApiFunctionAuthorizationAnalysisError("Native string bound exhausted")
            charge(2 + len(item))
            for char in item:
                if not 32 <= ord(char) <= 126:
                    raise ApiFunctionAuthorizationAnalysisError(
                        "Printable native ASCII strings required"
                    )
                if char in '\\"':
                    charge(1)
        elif kind is bool:
            charge(4 if item else 5)
        elif item is None:
            charge(4)
        elif kind is int:
            if item.bit_length() > 64 or not -(2**63) <= item < 2**63:
                raise ApiFunctionAuthorizationAnalysisError("Native integer exceeds signed 64-bit")
            charge(len(str(item)))
        elif kind in (dict, list):
            if id(item) in active:
                raise ApiFunctionAuthorizationAnalysisError("Cyclic native document")
            children = len(item) * (2 if kind is dict else 1)
            if children > MAX_NATIVE_NODES - nodes:
                raise ApiFunctionAuthorizationAnalysisError(
                    "Native collection node bound exhausted"
                )
            charge(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
            active.add(id(item))
            try:
                if kind is dict:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise ApiFunctionAuthorizationAnalysisError(
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
            raise ApiFunctionAuthorizationAnalysisError(
                "Only exact native JSON primitives are supported"
            )

    visit(value, 1)
    if work is not None:
        work.charge(size + nodes)
    return size, nodes


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _serialize(value: Any, work: _Work | None = None) -> str:
    _measure(value, work)
    return _canonical(value)


def _capture(value: Any, work: _Work | None = None) -> tuple[Any, str]:
    text = _serialize(value, work)
    return json.loads(text), text


def _integer(text: str) -> int:
    if len(text) > 20 or _INTEGER.fullmatch(text) is None:
        raise ApiFunctionAuthorizationAnalysisError("Raw integer grammar or lexical bound failed")
    number = int(text)
    if not -(2**63) <= number < 2**63:
        raise ApiFunctionAuthorizationAnalysisError("Raw integer exceeds signed 64-bit")
    return number


def _decode(text: Any) -> Any:
    """Bound raw tokens, escapes and duplicate members before decoding."""
    if type(text) is not str or not text or len(text) > MAX_DOCUMENT_BYTES or not text.isascii():
        raise ApiFunctionAuthorizationAnalysisError("Bounded native ASCII JSON required")
    index = depth = nodes = 0
    while index < len(text):
        char = text[index]
        if char == '"':
            if depth + 1 > MAX_NATIVE_DEPTH:
                raise ApiFunctionAuthorizationAnalysisError("Raw scalar depth bound exhausted")
            nodes += 1
            index += 1
            length = 0
            while True:
                if index >= len(text):
                    raise ApiFunctionAuthorizationAnalysisError("Unterminated raw JSON string")
                char = text[index]
                if char == '"':
                    index += 1
                    break
                if char == "\\":
                    index += 1
                    if index >= len(text):
                        raise ApiFunctionAuthorizationAnalysisError("Unterminated raw escape")
                    escape = text[index]
                    if escape == "u":
                        digits = text[index + 1 : index + 5]
                        if len(digits) != 4 or any(
                            d not in "0123456789abcdefABCDEF" for d in digits
                        ):
                            raise ApiFunctionAuthorizationAnalysisError(
                                "Malformed raw Unicode escape"
                            )
                        if not 32 <= int(digits, 16) <= 126:
                            raise ApiFunctionAuthorizationAnalysisError(
                                "Printable ASCII escapes required"
                            )
                        index += 5
                    elif escape in '\\"/':
                        index += 1
                    else:
                        raise ApiFunctionAuthorizationAnalysisError("Unsupported raw string escape")
                else:
                    if not 32 <= ord(char) <= 126:
                        raise ApiFunctionAuthorizationAnalysisError(
                            "Printable ASCII strings required"
                        )
                    index += 1
                length += 1
                if length > MAX_STRING_BYTES:
                    raise ApiFunctionAuthorizationAnalysisError("Raw string bound exhausted")
        elif char in "[{":
            depth += 1
            nodes += 1
            index += 1
        elif char in "]}":
            depth -= 1
            index += 1
        elif char in " \t\r\n,:":
            index += 1
        else:
            if depth + 1 > MAX_NATIVE_DEPTH:
                raise ApiFunctionAuthorizationAnalysisError("Raw scalar depth bound exhausted")
            start = index
            while index < len(text) and text[index] not in ' \t\r\n,:]}{["':
                index += 1
                if index - start > 20:
                    raise ApiFunctionAuthorizationAnalysisError(
                        "Raw scalar lexical bound exhausted"
                    )
            nodes += 1
            token = text[start:index]
            if token not in {"true", "false", "null"}:
                _integer(token)
        if depth < 0 or depth > MAX_NATIVE_DEPTH or nodes > MAX_NATIVE_NODES:
            raise ApiFunctionAuthorizationAnalysisError("Raw node/depth bound exhausted")
    if depth:
        raise ApiFunctionAuthorizationAnalysisError("Unterminated raw structure")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, value in items:
            if key in result:
                raise ApiFunctionAuthorizationAnalysisError("Duplicate JSON object member")
            result[key] = value
        return result

    def unsupported(_: str) -> None:
        raise ApiFunctionAuthorizationAnalysisError("Fractional/nonfinite JSON numbers unsupported")

    try:
        document = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=_integer,
            parse_float=unsupported,
            parse_constant=unsupported,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, ApiFunctionAuthorizationAnalysisError):
            raise
        raise ApiFunctionAuthorizationAnalysisError("Malformed supplied JSON") from exc
    _measure(document)
    return document


def _identity(value: Any) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise ApiFunctionAuthorizationAnalysisError("Bounded exact identity required")
    return value


def _id_list(value: Any, limit: int, *, nonempty: bool) -> list[str]:
    if type(value) is not list or len(value) > limit or (nonempty and not value):
        raise ApiFunctionAuthorizationAnalysisError("Bounded exact identity list required")
    for item in value:
        _identity(item)
    if len(set(value)) != len(value) or value != sorted(value):
        raise ApiFunctionAuthorizationAnalysisError("Sorted unique identity list required")
    return value


def _validate_model(value: Any, work: _Work) -> tuple[dict, str]:
    owned, text = _capture(value, work)
    if type(owned) is not dict or owned.keys() != {
        "schema_version",
        "roles",
        "subjects",
        "functions",
        "invocations",
    }:
        raise ApiFunctionAuthorizationAnalysisError("Exact closed model fields required")
    if type(owned["schema_version"]) is not int or owned["schema_version"] != 1:
        raise ApiFunctionAuthorizationAnalysisError("Exact native schema version 1 required")
    roles = _id_list(owned["roles"], MAX_ROLES, nonempty=True)
    subjects, functions, invocations = (owned["subjects"], owned["functions"], owned["invocations"])
    if type(subjects) is not list or not 1 <= len(subjects) <= MAX_SUBJECTS:
        raise ApiFunctionAuthorizationAnalysisError("Bounded nonempty subjects required")
    if type(functions) is not list or not 1 <= len(functions) <= MAX_FUNCTIONS:
        raise ApiFunctionAuthorizationAnalysisError("Bounded nonempty functions required")
    if type(invocations) is not list or not 1 <= len(invocations) <= MAX_INVOCATIONS:
        raise ApiFunctionAuthorizationAnalysisError("Bounded nonempty invocations required")
    subject_ids: set[str] = set()
    function_ids: set[str] = set()
    invocation_ids: set[str] = set()
    role_set = set(roles)
    for subject in subjects:
        work.charge(8)
        if type(subject) is not dict or subject.keys() != {
            "subject_id",
            "role_ids",
            "roles_complete",
        }:
            raise ApiFunctionAuthorizationAnalysisError("Exact closed subject fields required")
        identity = _identity(subject["subject_id"])
        if identity in subject_ids:
            raise ApiFunctionAuthorizationAnalysisError("Duplicate subject identity")
        subject_ids.add(identity)
        held = _id_list(subject["role_ids"], MAX_ROLES, nonempty=False)
        if any(role not in role_set for role in held):
            raise ApiFunctionAuthorizationAnalysisError("Unknown held role identity")
        if type(subject["roles_complete"]) is not bool:
            raise ApiFunctionAuthorizationAnalysisError("Exact role completeness boolean required")
    for function in functions:
        work.charge(8)
        if type(function) is not dict or function.keys() != {
            "function_id",
            "role_permissions",
            "matrix_complete",
        }:
            raise ApiFunctionAuthorizationAnalysisError("Exact closed function fields required")
        identity = _identity(function["function_id"])
        if identity in function_ids:
            raise ApiFunctionAuthorizationAnalysisError("Duplicate function identity")
        function_ids.add(identity)
        matrix = function["role_permissions"]
        if type(matrix) is not dict or len(matrix) > MAX_ROLES:
            raise ApiFunctionAuthorizationAnalysisError("Bounded role permission matrix required")
        for role, permission in matrix.items():
            if (
                role not in role_set
                or type(permission) is not str
                or permission not in {"allow", "deny", "unknown"}
            ):
                raise ApiFunctionAuthorizationAnalysisError(
                    "Exact declared role permission required"
                )
        if type(function["matrix_complete"]) is not bool:
            raise ApiFunctionAuthorizationAnalysisError(
                "Exact matrix completeness boolean required"
            )
        if function["matrix_complete"] and set(matrix) != role_set:
            raise ApiFunctionAuthorizationAnalysisError("Complete matrix must enumerate all roles")
    for invocation in invocations:
        work.charge(8)
        if type(invocation) is not dict or invocation.keys() != {
            "invocation_id",
            "subject_id",
            "function_id",
            "outcome",
            "observation_complete",
        }:
            raise ApiFunctionAuthorizationAnalysisError("Exact closed invocation fields required")
        identity = _identity(invocation["invocation_id"])
        if identity in invocation_ids:
            raise ApiFunctionAuthorizationAnalysisError("Duplicate invocation identity")
        invocation_ids.add(identity)
        if type(invocation["subject_id"]) is not str or invocation["subject_id"] not in subject_ids:
            raise ApiFunctionAuthorizationAnalysisError("Exact known invocation subject required")
        if (
            type(invocation["function_id"]) is not str
            or invocation["function_id"] not in function_ids
        ):
            raise ApiFunctionAuthorizationAnalysisError("Exact known invocation function required")
        if type(invocation["outcome"]) is not str or invocation["outcome"] not in {
            "allowed",
            "denied",
            "unknown",
        }:
            raise ApiFunctionAuthorizationAnalysisError("Declared invocation outcome required")
        if type(invocation["observation_complete"]) is not bool:
            raise ApiFunctionAuthorizationAnalysisError(
                "Exact observation completeness boolean required"
            )
    return owned, text


def _observe(invocation: dict, subjects: dict, functions: dict, work: _Work) -> dict:
    subject = subjects[invocation["subject_id"]]
    function = functions[invocation["function_id"]]
    work.charge(24 + len(subject["role_ids"]))
    reasons: list[str] = []
    if not subject["roles_complete"]:
        reasons.append("subject_roles_incomplete")
    if not function["matrix_complete"]:
        reasons.append("function_matrix_incomplete")
    grants = [function["role_permissions"].get(role) for role in subject["role_ids"]]
    if any(grant is None for grant in grants):
        reasons.append("held_role_rule_missing")
    if any(grant == "unknown" for grant in grants):
        reasons.append("held_role_permission_unknown")
    if not invocation["observation_complete"]:
        reasons.append("invocation_observation_incomplete")
    if invocation["outcome"] == "unknown":
        reasons.append("invocation_outcome_unknown")
    expected = None
    if not reasons:
        expected = "allow" if "allow" in grants else "deny"
    direction = None
    if reasons:
        outcome = "unknown"
    elif (expected == "allow") == (invocation["outcome"] == "allowed"):
        outcome = "matches_declared_policy"
    else:
        outcome = "candidate_contradiction"
        direction = (
            "declared_allow_supplied_denied"
            if expected == "allow"
            else "declared_deny_supplied_allowed"
        )
    return {
        "invocation_id": invocation["invocation_id"],
        "subject_id": invocation["subject_id"],
        "function_id": invocation["function_id"],
        "held_role_ids": list(subject["role_ids"]),
        "declared_role_permissions": {
            role: function["role_permissions"].get(role) for role in subject["role_ids"]
        },
        "expected_permission": expected,
        "supplied_outcome": invocation["outcome"],
        "outcome": outcome,
        "contradiction_direction": direction,
        "uncertainty": reasons,
    }


def _address(domain: str, text: str) -> str:
    return "sha256:" + hashlib.sha256((domain + "\n" + text).encode("ascii")).hexdigest()


def _derive(model: Any) -> dict:
    work = _Work()
    owned, source_text = _validate_model(model, work)
    subjects = {subject["subject_id"]: subject for subject in owned["subjects"]}
    functions = {function["function_id"]: function for function in owned["functions"]}
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
        "source_model": owned,
        "source_model_sha256": _PLACEHOLDER,
        "invocation_count": len(owned["invocations"]),
        "candidate_contradiction_count": 0,
        "unknown_count": 0,
        "invocation_observations": rows,
        "bounds": dict(_BOUNDS),
        "flags": dict(_FLAGS),
        "effects": dict(_EFFECTS),
        "limitations": list(_LIMITATIONS),
        "analysis_id": "AFA-" + "0" * 32,
        "analysis_sha256": _PLACEHOLDER,
    }
    size, nodes = _measure(body, work)
    for invocation in owned["invocations"]:
        row = _observe(invocation, subjects, functions, work)
        row_size, row_nodes = _measure(row, work)
        if size + row_size + 1 > MAX_DOCUMENT_BYTES or nodes + row_nodes > MAX_NATIVE_NODES:
            raise ApiFunctionAuthorizationAnalysisError("Cumulative report bound before retention")
        size += row_size + 1
        nodes += row_nodes
        rows.append(row)
        body["candidate_contradiction_count"] += int(row["outcome"] == "candidate_contradiction")
        body["unknown_count"] += int(row["outcome"] == "unknown")
    report_size, report_nodes = _measure(body, work)
    work.charge(4 * (report_size + report_nodes))
    del body["analysis_id"]
    del body["analysis_sha256"]
    hash_size, _ = _measure(body, work)
    work.charge(len(MODEL_DOMAIN) + len(DOMAIN) + len(source_text) + hash_size + 2)
    body["source_model_sha256"] = _address(MODEL_DOMAIN, source_text)
    digest = _address(DOMAIN, _canonical(body))
    body["analysis_id"] = "AFA-" + digest[7:39].upper()
    body["analysis_sha256"] = digest
    return body


def _replay(document: Any) -> dict:
    owned, text = _capture(document)
    if type(owned) is not dict or "source_model" not in owned:
        raise ApiFunctionAuthorizationAnalysisError("Source-bearing native analysis required")
    expected = _derive(owned["source_model"])
    if text != _serialize(expected):
        raise ApiFunctionAuthorizationAnalysisError(
            "Report does not exactly replay its embedded source"
        )
    return expected


@dataclass(frozen=True, slots=True, init=False)
class ApiFunctionAuthorizationAnalysis:
    """Detached supplied-data comparison, never live authorization evidence."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        object.__setattr__(self, "_document_json", _serialize(_replay(document)))

    @classmethod
    def from_dict(cls, document: Any) -> ApiFunctionAuthorizationAnalysis:
        return cls(document)

    @classmethod
    def from_json(cls, content: Any) -> ApiFunctionAuthorizationAnalysis:
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


def analyze_supplied_api_function_authorization(model: Any) -> ApiFunctionAuthorizationAnalysis:
    """Compare only supplied function permissions and invocation outcomes."""
    return ApiFunctionAuthorizationAnalysis(_derive(model))


def analyze_supplied_api_function_authorization_bytes(
    *, model_bytes: Any
) -> ApiFunctionAuthorizationAnalysis:
    """Accept exact bounded ASCII JSON bytes without reading a resource."""
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_DOCUMENT_BYTES:
        raise ApiFunctionAuthorizationAnalysisError("Bounded exact native model bytes required")
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ApiFunctionAuthorizationAnalysisError("ASCII model bytes required") from exc
    return analyze_supplied_api_function_authorization(_decode(text))


def verify_supplied_api_function_authorization_analysis(
    report: Any, *, model: Any
) -> ApiFunctionAuthorizationAnalysis:
    """Check a report against separately supplied original premises."""
    if type(report) is not ApiFunctionAuthorizationAnalysis:
        raise ApiFunctionAuthorizationAnalysisError(
            "Exact native function analysis family required"
        )
    expected = _derive(model)
    if _serialize(report.to_dict()) != _serialize(expected):
        raise ApiFunctionAuthorizationAnalysisError(
            "Report differs from separately supplied originals"
        )
    return ApiFunctionAuthorizationAnalysis(expected)


def component_fixture() -> dict:
    """Return a fresh synthetic denial mismatch, match and incomplete case."""
    return {
        "schema_version": 1,
        "roles": ["reader", "writer"],
        "subjects": [
            {"subject_id": "guest", "role_ids": ["reader"], "roles_complete": True},
            {"subject_id": "editor", "role_ids": ["writer"], "roles_complete": True},
        ],
        "functions": [
            {
                "function_id": "publish",
                "role_permissions": {"reader": "deny", "writer": "allow"},
                "matrix_complete": True,
            },
        ],
        "invocations": [
            {
                "invocation_id": "synthetic-deny-mismatch",
                "subject_id": "guest",
                "function_id": "publish",
                "outcome": "allowed",
                "observation_complete": True,
            },
            {
                "invocation_id": "synthetic-allow-match",
                "subject_id": "editor",
                "function_id": "publish",
                "outcome": "allowed",
                "observation_complete": True,
            },
            {
                "invocation_id": "synthetic-unknown",
                "subject_id": "guest",
                "function_id": "publish",
                "outcome": "unknown",
                "observation_complete": False,
            },
        ],
    }


__all__ = [
    "ApiFunctionAuthorizationAnalysisError",
    "ApiFunctionAuthorizationAnalysis",
    "analyze_supplied_api_function_authorization",
    "analyze_supplied_api_function_authorization_bytes",
    "verify_supplied_api_function_authorization_analysis",
    "component_fixture",
]
