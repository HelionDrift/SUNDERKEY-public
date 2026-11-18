"""Supplied identity-policy union and complements, never effective AWS access."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "aws-identity-policy-set-v1"
DOMAIN = "sunderkey.offline-aws-identity-policy-analysis.v1"
PROFILE_ID = "AOE-GC-D14-S01"
CAPABILITY_ID = "army.gc.d14.s01"
VECTOR_ID = "AV-GC-D14-S01-01"
WAVE_ID = "IW2-004"
MAX_DOCUMENT_BYTES = 2_097_152
MAX_NATIVE_NODES = 25_000
MAX_NATIVE_DEPTH = 16
MAX_STRING_BYTES = 512
MAX_POLICIES = 64
MAX_STATEMENTS = 512
MAX_QUERIES = 64
MAX_VALUES = 32
MAX_CONDITION_OPERATORS = 8
MAX_MATCHING_STEPS = 1_000_000
MAX_WITNESSES = 1024
_JSON_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_ACTION = re.compile(r"[A-Za-z0-9_-]+:[A-Za-z0-9_-]+\Z")
_ACTION_PATTERN = re.compile(r"[A-Za-z0-9_-]+:[A-Za-z0-9*?_-]+\Z")
_CONTEXT_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9:/_.-]*\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_DECISIONS = (
    "allowed_by_supplied_identity_policies",
    "explicit_denial_by_supplied_identity_policies",
    "implicit_denial_by_supplied_identity_policies",
    "inconclusive",
    "not_applicable",
)
_OPERATORS = {
    "StringEquals",
    "StringEqualsIgnoreCase",
    "StringLike",
    "StringNotEquals",
    "StringNotLike",
    "Bool",
    "Null",
}
_FLAGS = {
    "offline_only": True,
    "principal_authenticated": False,
    "attachments_authenticated": False,
    "applicability_authenticated": False,
    "effective_access_proven": False,
    "live_use_approved": False,
    "qualification_claimed": False,
}
_EFFECTS = {
    name: "none"
    for name in (
        "authority",
        "target",
        "execution",
        "routing",
        "qualification",
        "deployment",
        "network",
        "provider_requests",
        "credentials",
        "process",
    )
}
_BOUNDS = {
    "maximum_document_bytes": MAX_DOCUMENT_BYTES,
    "maximum_native_nodes": MAX_NATIVE_NODES,
    "maximum_native_depth": MAX_NATIVE_DEPTH,
    "maximum_string_bytes": MAX_STRING_BYTES,
    "maximum_policies": MAX_POLICIES,
    "maximum_statements": MAX_STATEMENTS,
    "maximum_queries": MAX_QUERIES,
    "maximum_selector_values": MAX_VALUES,
    "maximum_context_keys": MAX_VALUES,
    "maximum_condition_operators": MAX_CONDITION_OPERATORS,
    "maximum_matching_steps": MAX_MATCHING_STEPS,
    "maximum_witnesses": MAX_WITNESSES,
}
_LIMITATIONS = [
    "Principal, attachment completeness, applicability and context are caller assertions.",
    "The identity-policy union is not a full or authenticated AWS authorization decision.",
    "Action/resource applicability is never inferred from an ARN or a service catalog.",
    "Resource wildcards and scalar conditions are a finite conservative software subset.",
    "Unsupported source features remain uncertainty and contribute no definite witness.",
    "Resource, session, boundary, SCP, RCP and cross-account policies are not composed.",
    "No currentness, policy acquisition, source authenticity, live use or qualification is proved.",
]
_MODEL_FIELDS = {"schema_version", "principal_ref", "attachments_complete", "policies", "queries"}
_QUERY_FIELDS = {"query_id", "action", "resource", "action_resource_applicability", "context"}
_WITNESS_FIELDS = {
    "policy_id",
    "policy_sha256",
    "statement_index",
    "statement_sid",
    "statement_sha256",
}
_RESULT_FIELDS = {
    "query_id",
    "query_sha256",
    "decision",
    "allow_witnesses",
    "deny_witnesses",
    "unresolved_witnesses",
    "reasons",
}
_REPORT_FIELDS = {
    "analysis_id",
    "analysis_sha256",
    "schema_version",
    "component_id",
    "profile_id",
    "capability_id",
    "vector_id",
    "wave_id",
    "source_model",
    "source_model_sha256",
    "results",
    "source_issues",
    "summary",
    "bounds",
    "effects",
    "limitations",
    *_FLAGS,
}


class AwsIdentityPolicyAnalysisError(ValueError):
    """Native shape, finite software costs or original-model replay failed."""


def _capture(value: Any) -> Any:
    nodes = size = 0
    active: set[int] = set()

    def charge(amount: int) -> None:
        nonlocal size
        size += amount
        if size > MAX_DOCUMENT_BYTES:
            raise AwsIdentityPolicyAnalysisError("Document exceeds its canonical byte budget")

    def visit(item: Any, depth: int) -> Any:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise AwsIdentityPolicyAnalysisError("Document exceeds its node or depth budget")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_STRING_BYTES or any(not 32 <= ord(c) <= 126 for c in item):
                raise AwsIdentityPolicyAnalysisError("Text exceeds the printable ASCII subset")
            charge(2 + len(item) + item.count('"') + item.count("\\"))
            return item
        if kind is int:
            if item.bit_length() > 63:
                raise AwsIdentityPolicyAnalysisError("Integer exceeds its finite magnitude")
            charge(len(str(item)))
            return item
        if kind is bool:
            charge(4 if item else 5)
            return item
        if item is None:
            charge(4)
            return None
        if kind not in (dict, list):
            raise AwsIdentityPolicyAnalysisError("Only exact native JSON families are supported")
        if id(item) in active:
            raise AwsIdentityPolicyAnalysisError("Cyclic input is unsupported")
        active.add(id(item))
        charge(2)
        try:
            if kind is list:
                result = []
                for index, child in enumerate(item):
                    if index:
                        charge(1)
                    result.append(visit(child, depth + 1))
                return result
            result = {}
            for index, (key, child) in enumerate(item.items()):
                if type(key) is not str:
                    raise AwsIdentityPolicyAnalysisError("Object keys require native strings")
                if index:
                    charge(1)
                owned_key = visit(key, depth + 1)
                charge(1)
                result[owned_key] = visit(child, depth + 1)
            return result
        finally:
            active.remove(id(item))

    return visit(value, 1)


def _canonical(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def _sha(domain: str, value: Any) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            domain.encode("ascii") + b"\n" + _canonical(value).encode("ascii")
        ).hexdigest()
    )


def _json(text: Any) -> Any:
    if type(text) is not str or not text or len(text) > MAX_DOCUMENT_BYTES or not text.isascii():
        raise AwsIdentityPolicyAnalysisError("JSON requires bounded exact native ASCII text")
    depth = nodes = index = 0
    while index < len(text):
        char = text[index]
        if char == '"':
            nodes += 1
            if depth + 1 > MAX_NATIVE_DEPTH:
                raise AwsIdentityPolicyAnalysisError("JSON scalar exceeds its depth budget")
            index += 1
            length = 0
            closed = False
            while index < len(text):
                char = text[index]
                if char == '"':
                    index += 1
                    closed = True
                    break
                if char == "\\":
                    index += 1
                    if index >= len(text):
                        raise AwsIdentityPolicyAnalysisError("JSON escape is incomplete")
                    escape = text[index]
                    if escape == "u":
                        digits = text[index + 1 : index + 5]
                        if len(digits) != 4 or any(
                            c not in "0123456789abcdefABCDEF" for c in digits
                        ):
                            raise AwsIdentityPolicyAnalysisError("JSON Unicode escape is invalid")
                        if not 32 <= int(digits, 16) <= 126:
                            raise AwsIdentityPolicyAnalysisError(
                                "JSON text is outside printable ASCII"
                            )
                        index += 5
                    elif escape in '"\\/':
                        index += 1
                    else:
                        raise AwsIdentityPolicyAnalysisError(
                            "JSON escape is outside printable ASCII"
                        )
                else:
                    if not 32 <= ord(char) <= 126:
                        raise AwsIdentityPolicyAnalysisError("JSON text is outside printable ASCII")
                    index += 1
                length += 1
                if length > MAX_STRING_BYTES:
                    raise AwsIdentityPolicyAnalysisError("JSON scalar exceeds its text budget")
            if not closed:
                raise AwsIdentityPolicyAnalysisError("JSON string is incomplete")
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
            start = index
            while index < len(text) and text[index] not in ' \t\r\n,:]}{["':
                index += 1
            if index == start:
                raise AwsIdentityPolicyAnalysisError("JSON token is invalid")
            lexical = text[start:index]
            nodes += 1
            if depth + 1 > MAX_NATIVE_DEPTH:
                raise AwsIdentityPolicyAnalysisError("JSON scalar exceeds its depth budget")
            if lexical not in {"true", "false", "null"}:
                if _JSON_INTEGER.fullmatch(lexical) is None:
                    raise AwsIdentityPolicyAnalysisError(
                        "JSON number is outside the integer subset"
                    )
                if int(lexical).bit_length() > 63:
                    raise AwsIdentityPolicyAnalysisError(
                        "JSON integer exceeds its finite magnitude"
                    )
        if depth < 0 or depth > MAX_NATIVE_DEPTH or nodes > MAX_NATIVE_NODES:
            raise AwsIdentityPolicyAnalysisError("JSON exceeds its pre-decoder cost budgets")
    if depth:
        raise AwsIdentityPolicyAnalysisError("JSON structure is incomplete")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in items:
            if key in result:
                raise AwsIdentityPolicyAnalysisError("JSON contains a duplicate field")
            result[key] = value
        return result

    def unsupported(_: str) -> None:
        raise AwsIdentityPolicyAnalysisError(
            "Fractional and nonfinite JSON numbers are unsupported"
        )

    try:
        parsed = json.loads(
            text, object_pairs_hook=pairs, parse_float=unsupported, parse_constant=unsupported
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, AwsIdentityPolicyAnalysisError):
            raise
        raise AwsIdentityPolicyAnalysisError("JSON is malformed") from exc
    return _capture(parsed)


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise AwsIdentityPolicyAnalysisError(f"{label} has missing or unsupported fields")
    return value


def _text(value: Any, label: str) -> str:
    if type(value) is not str or not value or len(value) > MAX_STRING_BYTES:
        raise AwsIdentityPolicyAnalysisError(f"{label} requires a nonempty bounded native string")
    return value


def _integer(value: Any, maximum: int, label: str) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise AwsIdentityPolicyAnalysisError(f"{label} requires a bounded native integer")
    return value


def _list(value: Any, maximum: int, label: str, *, nonempty: bool = False) -> list[Any]:
    if type(value) is not list or len(value) > maximum or (nonempty and not value):
        raise AwsIdentityPolicyAnalysisError(f"{label} exceeds its native list subset")
    return value


def _values(value: Any, label: str) -> list[str]:
    if type(value) is str:
        return [_text(value, label)]
    return [_text(item, label) for item in _list(value, MAX_VALUES, label, nonempty=True)]


def _context_key(value: Any) -> str:
    text = _text(value, "Context key")
    if _CONTEXT_KEY.fullmatch(text) is None:
        raise AwsIdentityPolicyAnalysisError("Context key is outside the scalar vocabulary")
    return text.lower()


def _arn(value: str) -> list[str] | None:
    parts = value.split(":", 5)
    if len(parts) != 6 or parts[0] != "arn" or not parts[1] or not parts[2] or not parts[5]:
        return None
    return parts


def _resource_supported(value: str) -> bool:
    if value == "*":
        return True
    parts = _arn(value)
    return (
        parts is not None
        and "${" not in value
        and not any("*" in part or "?" in part for part in parts[:5])
        and not (":" in parts[5] and ("*" in parts[5] or "?" in parts[5]))
    )


def _statement(statement: Any) -> tuple[str, ...]:
    if type(statement) is not dict or type(statement.get("Effect")) is not str:
        raise AwsIdentityPolicyAnalysisError("Statement requires a native object and Effect")
    if statement["Effect"] not in {"Allow", "Deny"}:
        raise AwsIdentityPolicyAnalysisError("Statement Effect requires Allow or Deny")
    if ("Action" in statement) == ("NotAction" in statement):
        raise AwsIdentityPolicyAnalysisError("Statement requires exactly one action selector")
    if ("Resource" in statement) == ("NotResource" in statement):
        raise AwsIdentityPolicyAnalysisError("Statement requires exactly one resource selector")
    if "Sid" in statement:
        _text(statement["Sid"], "Statement Sid")
    reasons = set()
    if statement.keys() - {
        "Sid",
        "Effect",
        "Action",
        "NotAction",
        "Resource",
        "NotResource",
        "Condition",
    }:
        reasons.add("unsupported_statement_fields")
    for name in ("Action", "NotAction", "Resource", "NotResource"):
        if name not in statement:
            continue
        values = _values(statement[name], name)
        if any("${" in item for item in values):
            reasons.add("unsupported_policy_variable")
        if name in {"Action", "NotAction"}:
            if any(item != "*" and _ACTION_PATTERN.fullmatch(item) is None for item in values):
                reasons.add("unsupported_action_pattern")
        elif any(not _resource_supported(item) for item in values):
            reasons.add("unsupported_resource_pattern")
    if "Condition" in statement:
        operators = statement["Condition"]
        if type(operators) is not dict or not 1 <= len(operators) <= MAX_CONDITION_OPERATORS:
            raise AwsIdentityPolicyAnalysisError("Condition requires bounded operator objects")
        for operator, keys in operators.items():
            _text(operator, "Condition operator")
            if type(keys) is not dict or not 1 <= len(keys) <= MAX_VALUES:
                raise AwsIdentityPolicyAnalysisError(
                    "Condition requires bounded scalar-key objects"
                )
            seen = set()
            for key, value in keys.items():
                lowered = _context_key(key)
                if lowered in seen:
                    raise AwsIdentityPolicyAnalysisError(
                        "Case-colliding condition keys are ambiguous"
                    )
                seen.add(lowered)
                values = _values(value, "Condition candidates")
                if any("${" in item for item in values):
                    reasons.add("unsupported_policy_variable")
                if operator not in _OPERATORS:
                    reasons.add("unsupported_condition_operator")
                if operator in {"Bool", "Null"} and any(
                    item not in {"true", "false"} for item in values
                ):
                    raise AwsIdentityPolicyAnalysisError("Bool and Null require true or false text")
    return tuple(sorted(reasons))


def _model(
    value: Any,
) -> tuple[dict[str, Any], list[tuple[dict, int, dict, tuple[str, ...]]], list[dict]]:
    model = _exact(_capture(value), _MODEL_FIELDS, "Identity-policy model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise AwsIdentityPolicyAnalysisError("Model schema version requires native integer one")
    _text(model["principal_ref"], "Principal reference")
    if type(model["attachments_complete"]) is not bool:
        raise AwsIdentityPolicyAnalysisError("Attachment completeness requires native bool")
    statements = []
    issues = []
    policy_ids = set()
    for policy in _list(model["policies"], MAX_POLICIES, "Policy attachments"):
        _exact(policy, {"policy_id", "document"}, "Policy attachment")
        policy_id = _text(policy["policy_id"], "Policy ID")
        if policy_id in policy_ids:
            raise AwsIdentityPolicyAnalysisError("Policy attachment IDs cannot repeat")
        policy_ids.add(policy_id)
        document = policy["document"]
        if type(document) is not dict or "Statement" not in document:
            raise AwsIdentityPolicyAnalysisError("Policy document requires Statement")
        source_reasons = set()
        if document.keys() - {"Version", "Id", "Statement"}:
            source_reasons.add("unsupported_policy_fields")
        if "Id" in document:
            _text(document["Id"], "Policy document Id")
        if "Version" not in document or document["Version"] is None:
            source_reasons.add("unavailable_policy_version")
        else:
            _text(document["Version"], "Policy version")
            if document["Version"] != "2012-10-17":
                source_reasons.add("unsupported_policy_version")
        declared = _list(document["Statement"], MAX_STATEMENTS, "Statements", nonempty=True)
        if len(statements) + len(declared) > MAX_STATEMENTS:
            raise AwsIdentityPolicyAnalysisError("Total statement count exceeds its finite bound")
        seen_sids = set()
        for index, statement in enumerate(declared):
            reasons = tuple(sorted(source_reasons | set(_statement(statement))))
            sid = statement.get("Sid")
            if sid is not None:
                if sid in seen_sids:
                    raise AwsIdentityPolicyAnalysisError(
                        "Statement Sids cannot repeat within a policy"
                    )
                seen_sids.add(sid)
            statements.append((policy, index, statement, reasons))
            for reason in reasons:
                issues.append({"policy_id": policy_id, "statement_index": index, "reason": reason})
    query_ids = set()
    for query in _list(model["queries"], MAX_QUERIES, "Queries", nonempty=True):
        _exact(query, _QUERY_FIELDS, "Query")
        query_id = _text(query["query_id"], "Query ID")
        if query_id in query_ids:
            raise AwsIdentityPolicyAnalysisError("Query IDs cannot repeat")
        query_ids.add(query_id)
        if _ACTION.fullmatch(_text(query["action"], "Query action")) is None:
            raise AwsIdentityPolicyAnalysisError("Query action must be one concrete service/action")
        resource = _text(query["resource"], "Query resource")
        if _arn(resource) is None or any(char in resource for char in "*?") or "${" in resource:
            raise AwsIdentityPolicyAnalysisError(
                "Query resource must be one concrete non-variable ARN"
            )
        if (
            query["action_resource_applicability"] is not None
            and type(query["action_resource_applicability"]) is not bool
        ):
            raise AwsIdentityPolicyAnalysisError("Query applicability requires native bool or null")
        context = _exact(query["context"], {"values", "absent_keys"}, "Context")
        values = context["values"]
        if type(values) is not dict or len(values) > MAX_VALUES:
            raise AwsIdentityPolicyAnalysisError("Context values require a bounded scalar map")
        absent = _list(context["absent_keys"], MAX_VALUES, "Known absent context keys")
        if len(values) + len(absent) > MAX_VALUES:
            raise AwsIdentityPolicyAnalysisError("Combined context keys exceed their finite bound")
        keys = set()
        for key, item in values.items():
            lowered = _context_key(key)
            if lowered in keys:
                raise AwsIdentityPolicyAnalysisError("Case-colliding context keys are ambiguous")
            keys.add(lowered)
            _text(item, "Scalar context value")
        for key in absent:
            lowered = _context_key(key)
            if lowered in keys:
                raise AwsIdentityPolicyAnalysisError(
                    "Context presence and absence conflict or repeat"
                )
            keys.add(lowered)
    return model, statements, issues


class _Work:
    def __init__(self) -> None:
        self.steps = 0

    def charge(self, amount: int = 1) -> None:
        self.steps += amount
        if self.steps > MAX_MATCHING_STEPS:
            raise AwsIdentityPolicyAnalysisError("Matching work exceeds its finite budget")


def _literal(pattern: str, value: str, work: _Work) -> bool:
    work.charge(len(pattern) + len(value) + 1)
    return pattern == value


def _glob(pattern: str, value: str, work: _Work) -> bool:
    position = index = 0
    star = retry = -1
    while index < len(value):
        work.charge()
        if position < len(pattern) and pattern[position] == "*":
            star = position
            retry = index
            position += 1
        elif position < len(pattern) and (
            pattern[position] == "?" or pattern[position] == value[index]
        ):
            position += 1
            index += 1
        elif star >= 0:
            retry += 1
            index = retry
            position = star + 1
        else:
            return False
    while position < len(pattern) and pattern[position] == "*":
        work.charge()
        position += 1
    return position == len(pattern)


def _and(values: list[bool | None]) -> bool | None:
    if False in values:
        return False
    return None if None in values else True


def _or(values: list[bool | None]) -> bool | None:
    if True in values:
        return True
    return None if None in values else False


def _resource_match(pattern: str, value: str, work: _Work) -> bool | None:
    if pattern == "*":
        work.charge()
        return True
    if _literal(pattern, value, work):
        return True
    if "*" not in pattern and "?" not in pattern:
        return False
    left, right = _arn(pattern), _arn(value)
    if left is None or right is None:
        return None
    if not _literal(":".join(left[:5]), ":".join(right[:5]), work):
        return False
    if ":" in right[5] and not (
        left[5].endswith("*") and left[5].count("*") == 1 and "?" not in left[5]
    ):
        return None
    return _glob(left[5], right[5], work)


def _conditions(statement: dict, query: dict, work: _Work) -> bool | None:
    context = query["context"]
    present = {key.lower(): value for key, value in context["values"].items()}
    absent = {key.lower() for key in context["absent_keys"]}
    outcomes = []
    for operator, keys in sorted(statement.get("Condition", {}).items()):
        for key, raw in sorted(keys.items()):
            candidates = _values(raw, "Condition candidates")
            lowered = key.lower()
            negated = operator in {"StringNotEquals", "StringNotLike"}
            if lowered not in present and lowered not in absent:
                outcomes.append(None)
            elif operator == "Null":
                actual = "true" if lowered in absent else "false"
                outcomes.append(any(_literal(item, actual, work) for item in candidates))
            elif lowered in absent:
                outcomes.append(negated)
            elif operator == "Bool" and present[lowered] not in {"true", "false"}:
                outcomes.append(None)
            else:
                value = present[lowered]
                if operator in {"StringLike", "StringNotLike"}:
                    matches = [_glob(item, value, work) for item in candidates]
                elif operator == "StringEqualsIgnoreCase":
                    matches = [_literal(item.lower(), value.lower(), work) for item in candidates]
                else:
                    matches = [_literal(item, value, work) for item in candidates]
                matched = any(matches)
                outcomes.append(not matched if negated else matched)
    return _and(outcomes)


def _matches(statement: dict, query: dict, work: _Work) -> tuple[bool | None, list[str]]:
    action_key = "Action" if "Action" in statement else "NotAction"
    action = _or(
        [
            _glob(item.lower(), query["action"].lower(), work)
            for item in _values(statement[action_key], action_key)
        ]
    )
    if action_key == "NotAction" and action is not None:
        action = not action
    resource_key = "Resource" if "Resource" in statement else "NotResource"
    resource = _or(
        [
            _resource_match(item, query["resource"], work)
            for item in _values(statement[resource_key], resource_key)
        ]
    )
    if resource_key == "NotResource" and resource is not None:
        resource = not resource
    condition = _conditions(statement, query, work)
    matched = _and([action, resource, condition])
    reasons = []
    if matched is None:
        if resource is None:
            reasons.append("unsupported_query_resource_tail_boundary")
        if condition is None:
            reasons.append("unavailable_scalar_context")
    return matched, reasons


def _derive(value: Any) -> dict[str, Any]:
    model, statements, issues = _model(value)
    work = _Work()
    witness_count = 0
    results = []
    # Bind each captured source once, not once for every matching query.
    policy_digests = {
        policy["policy_id"]: _sha("sunderkey.offline-aws-identity-policy.v1", policy)
        for policy in model["policies"]
    }
    bound_statements = [
        (
            statement,
            unsupported,
            {
                "policy_id": policy["policy_id"],
                "policy_sha256": policy_digests[policy["policy_id"]],
                "statement_index": index,
                "statement_sid": statement.get("Sid"),
                "statement_sha256": _sha("sunderkey.offline-aws-identity-statement.v1", statement),
            },
        )
        for policy, index, statement, unsupported in statements
    ]
    for query in sorted(model["queries"], key=lambda item: item["query_id"]):
        allows, denies, unresolved = [], [], []
        reasons = set()
        applicability = query["action_resource_applicability"]
        if applicability is False:
            decision = "not_applicable"
            reasons.add("caller_declared_action_resource_not_applicable")
        elif applicability is None:
            decision = "inconclusive"
            reasons.add("unavailable_action_resource_applicability")
        else:
            if not model["attachments_complete"]:
                reasons.add("incomplete_policy_attachments")
            if issues:
                reasons.add("unsupported_policy_source_features")
            for statement, unsupported, binding in bound_statements:
                if unsupported:
                    matched, missing = None, list(unsupported)
                else:
                    matched, missing = _matches(statement, query, work)
                if matched is False:
                    continue
                witness_count += 1
                if witness_count > MAX_WITNESSES:
                    raise AwsIdentityPolicyAnalysisError(
                        "Total witnesses exceed their finite bound"
                    )
                witness = dict(binding)
                if matched is None:
                    witness["reasons"] = missing
                    unresolved.append(witness)
                    reasons.update(missing)
                elif statement["Effect"] == "Deny":
                    denies.append(witness)
                else:
                    allows.append(witness)
            if denies:
                decision = "explicit_denial_by_supplied_identity_policies"
                reasons.add("matching_explicit_identity_deny")
            elif unresolved or issues or not model["attachments_complete"]:
                decision = "inconclusive"
            elif allows:
                decision = "allowed_by_supplied_identity_policies"
            else:
                decision = "implicit_denial_by_supplied_identity_policies"
                reasons.add("no_matching_identity_allow")
        results.append(
            {
                "query_id": query["query_id"],
                "query_sha256": _sha("sunderkey.offline-aws-identity-query.v1", query),
                "decision": decision,
                "allow_witnesses": sorted(allows, key=_canonical),
                "deny_witnesses": sorted(denies, key=_canonical),
                "unresolved_witnesses": sorted(unresolved, key=_canonical),
                "reasons": sorted(reasons),
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "wave_id": WAVE_ID,
        "source_model": model,
        "source_model_sha256": _sha("sunderkey.offline-aws-identity-policy-model.v1", model),
        "results": results,
        "source_issues": sorted(issues, key=_canonical),
        "summary": {
            "query_count": len(results),
            "policy_count": len(model["policies"]),
            "statement_count": len(statements),
            "matching_steps": work.steps,
            **{
                decision: sum(item["decision"] == decision for item in results)
                for decision in _DECISIONS
            },
        },
        "bounds": _BOUNDS,
        "effects": _EFFECTS,
        "limitations": _LIMITATIONS,
        **_FLAGS,
    }
    # Include final identity overhead in the pre-address canonical cost budget.
    _capture({"analysis_id": "AIP-" + "0" * 32, "analysis_sha256": "sha256:" + "0" * 64, **body})
    digest = _sha(DOMAIN, body)
    return _capture(
        {"analysis_id": "AIP-" + digest[7:39].upper(), "analysis_sha256": digest, **body}
    )


def _digest(value: Any) -> None:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise AwsIdentityPolicyAnalysisError("Content digest has invalid native spelling")


def _report(value: Any) -> dict[str, Any]:
    document = _exact(_capture(value), _REPORT_FIELDS, "Identity-policy analysis")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise AwsIdentityPolicyAnalysisError("Analysis schema version requires native integer one")
    for field, expected in {
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "wave_id": WAVE_ID,
    }.items():
        if type(document[field]) is not str or document[field] != expected:
            raise AwsIdentityPolicyAnalysisError("Analysis ownership metadata is unsupported")
    if (
        type(document["analysis_id"]) is not str
        or re.fullmatch(r"AIP-[0-9A-F]{32}", document["analysis_id"]) is None
    ):
        raise AwsIdentityPolicyAnalysisError("Analysis ID has invalid native spelling")
    for field in ("analysis_sha256", "source_model_sha256"):
        _digest(document[field])
    for field, expected in _FLAGS.items():
        if type(document[field]) is not bool or document[field] is not expected:
            raise AwsIdentityPolicyAnalysisError(
                "Analysis flags cannot claim authentication or authority"
            )
    for field, expected in _BOUNDS.items():
        _exact(document["bounds"], set(_BOUNDS), "Analysis bounds")
        if type(document["bounds"][field]) is not int or document["bounds"][field] != expected:
            raise AwsIdentityPolicyAnalysisError("Analysis bounds have invalid native values")
    _exact(document["effects"], set(_EFFECTS), "Analysis effects")
    if any(type(item) is not str or item != "none" for item in document["effects"].values()):
        raise AwsIdentityPolicyAnalysisError("Analysis effects must remain none")
    for item in _list(document["limitations"], len(_LIMITATIONS), "Analysis limitations"):
        _text(item, "Analysis limitation")
    summary = _exact(
        document["summary"],
        {"query_count", "policy_count", "statement_count", "matching_steps", *_DECISIONS},
        "Analysis summary",
    )
    for name, item in summary.items():
        maximum = MAX_MATCHING_STEPS if name == "matching_steps" else MAX_STATEMENTS
        _integer(item, maximum, "Summary counter")
    for issue in _list(document["source_issues"], MAX_STATEMENTS * 8, "Source issues"):
        _exact(issue, {"policy_id", "statement_index", "reason"}, "Source issue")
        _text(issue["policy_id"], "Source policy ID")
        _integer(issue["statement_index"], MAX_STATEMENTS - 1, "Source statement index")
        _text(issue["reason"], "Source issue reason")
    witnesses = 0
    for result in _list(document["results"], MAX_QUERIES, "Query results", nonempty=True):
        _exact(result, _RESULT_FIELDS, "Query result")
        _text(result["query_id"], "Result query ID")
        _digest(result["query_sha256"])
        if type(result["decision"]) is not str or result["decision"] not in _DECISIONS:
            raise AwsIdentityPolicyAnalysisError("Query decision is unsupported")
        for reason in _list(result["reasons"], MAX_VALUES, "Query reasons"):
            _text(reason, "Query reason")
        for name in ("allow_witnesses", "deny_witnesses", "unresolved_witnesses"):
            for witness in _list(result[name], MAX_WITNESSES, "Statement witnesses"):
                witnesses += 1
                if witnesses > MAX_WITNESSES:
                    raise AwsIdentityPolicyAnalysisError(
                        "Total witnesses exceed their finite bound"
                    )
                fields = _WITNESS_FIELDS | (
                    {"reasons"} if name == "unresolved_witnesses" else set()
                )
                _exact(witness, fields, "Statement witness")
                _text(witness["policy_id"], "Witness policy ID")
                _digest(witness["policy_sha256"])
                _digest(witness["statement_sha256"])
                _integer(witness["statement_index"], MAX_STATEMENTS - 1, "Witness statement index")
                if witness["statement_sid"] is not None:
                    _text(witness["statement_sid"], "Witness statement Sid")
                if name == "unresolved_witnesses":
                    for reason in _list(
                        witness["reasons"], MAX_VALUES, "Unresolved witness reasons"
                    ):
                        _text(reason, "Unresolved reason")
    expected = _derive(document["source_model"])
    if _canonical(document) != _canonical(expected):
        raise AwsIdentityPolicyAnalysisError(
            "Analysis does not exactly replay its supplied source model"
        )
    return expected


@dataclass(frozen=True, slots=True)
class AwsIdentityPolicyAnalysis:
    document_json: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "document_json", _canonical(self._read()))

    def _read(self) -> dict[str, Any]:
        try:
            text = self.document_json
        except AttributeError as exc:
            raise AwsIdentityPolicyAnalysisError("Analysis wrapper is incomplete") from exc
        return _report(_json(text))

    def to_dict(self) -> dict[str, Any]:
        return self._read()

    def to_json(self) -> str:
        return _canonical(self._read())

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> AwsIdentityPolicyAnalysis:
        return cls(_canonical(_report(document)))

    @classmethod
    def from_json(cls, document: str) -> AwsIdentityPolicyAnalysis:
        return cls(document)


def analyze_aws_identity_policy_set(model: dict[str, Any]) -> AwsIdentityPolicyAnalysis:
    return AwsIdentityPolicyAnalysis(_canonical(_derive(model)))


def analyze_aws_identity_policy_set_bytes(*, model_bytes: bytes) -> AwsIdentityPolicyAnalysis:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_DOCUMENT_BYTES:
        raise AwsIdentityPolicyAnalysisError("Model requires bounded exact native bytes")
    if not model_bytes.isascii():
        raise AwsIdentityPolicyAnalysisError("Model bytes require the ASCII JSON subset")
    return analyze_aws_identity_policy_set(_json(model_bytes.decode("ascii")))


def verify_aws_identity_policy_analysis(
    report: AwsIdentityPolicyAnalysis | dict[str, Any], *, model: dict[str, Any]
) -> AwsIdentityPolicyAnalysis:
    if type(report) is AwsIdentityPolicyAnalysis:
        observed = report.to_dict()
    elif type(report) is dict:
        observed = _report(report)
    else:
        raise AwsIdentityPolicyAnalysisError("Report requires an exact supported native family")
    expected = _derive(model)
    if _canonical(observed) != _canonical(expected):
        raise AwsIdentityPolicyAnalysisError(
            "Report does not match the separately supplied original model"
        )
    return AwsIdentityPolicyAnalysis(_canonical(expected))


__all__ = [
    "AwsIdentityPolicyAnalysis",
    "AwsIdentityPolicyAnalysisError",
    "analyze_aws_identity_policy_set",
    "analyze_aws_identity_policy_set_bytes",
    "verify_aws_identity_policy_analysis",
]
