"""Finite AWS Organizations SCP reasoning over explicitly supplied inert sources."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

PROFILE_ID = "AOE-GC-D14-S01"
CAPABILITY_ID = "army.gc.d14.s01"
VECTOR_ID = "AV-GC-D14-S01-01"
SEMANTICS_PROFILE = "aws-organizations-scp-supplied-path-subset.v1"
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_DEPTH = 24
MAX_NODES = 100_000
MAX_TEXT = 4096
MAX_PATH_LEVELS = 8
MAX_POLICIES = 128
MAX_STATEMENTS = 2048
MAX_LOCAL_ITEMS = 128
MAX_CONDITION_KEYS = 32
MAX_QUERIES = 128
MAX_MATCH_WORK = 2_000_000
MAX_WITNESSES = 2048
_DECISIONS = (
    "blocked",
    "inconclusive",
    "not_applicable",
    "not_blocked_by_supplied_scps",
)
_LIMITATIONS = (
    "All organization, attachment, principal and context facts are unauthenticated declarations.",
    "Not blocked by supplied SCPs is not effective AWS access or policy safety.",
    "Identity, resource, session, boundary and RCP policies are not evaluated.",
    "Unsupported policy syntax and unavailable context remain explicit uncertainty.",
    "No provider, credential, target, qualification, routing or deployment authority is granted.",
)


class AwsScpAnalysisError(ValueError):
    """Sources are malformed, unbounded, contradictory or falsely replayed."""


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _hash(domain: str, value: Any) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            domain.encode("ascii") + b"\n" + _canonical(value).encode("ascii")
        ).hexdigest()
    )


def _capture(value: Any) -> Any:
    """Own native JSON while charging shared containers at every occurrence."""
    active: set[int] = set()
    nodes = size = 0

    def visit(item: Any, depth: int) -> Any:
        nonlocal nodes, size
        nodes += 1
        size += 2
        if depth > MAX_DEPTH or nodes > MAX_NODES or size > MAX_JSON_BYTES:
            raise AwsScpAnalysisError("JSON structural budget exceeded")
        if type(item) is str:
            if len(item) > MAX_TEXT:
                raise AwsScpAnalysisError("JSON text budget exceeded")
            try:
                item.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise AwsScpAnalysisError("JSON text is not UTF-8") from exc
            size += 12 * len(item)
            if size > MAX_JSON_BYTES:
                raise AwsScpAnalysisError("JSON byte budget exceeded")
            return item
        if item is None or type(item) is bool:
            size += 5
            return item
        if type(item) is int:
            if not -(2**63) <= item < 2**63:
                raise AwsScpAnalysisError("JSON integer is outside signed64")
            size += 20
            return item
        if type(item) not in (dict, list):
            raise AwsScpAnalysisError("Only native JSON primitives are accepted")
        if len(item) > MAX_NODES or id(item) in active:
            raise AwsScpAnalysisError("JSON container is oversized or cyclic")
        active.add(id(item))
        try:
            if type(item) is list:
                return [visit(child, depth + 1) for child in item]
            owned = {}
            for key, child in item.items():
                if type(key) is not str:
                    raise AwsScpAnalysisError("JSON object keys require native text")
                owned[visit(key, depth + 1)] = visit(child, depth + 1)
            return owned
        finally:
            active.remove(id(item))

    owned = visit(value, 0)
    if size > MAX_JSON_BYTES:
        raise AwsScpAnalysisError("JSON byte budget exceeded")
    return owned


def _parse_bytes(raw: bytes) -> Any:
    if type(raw) is not bytes or not raw or len(raw) > MAX_JSON_BYTES:
        raise AwsScpAnalysisError("JSON requires bounded nonempty native bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AwsScpAnalysisError("JSON is not UTF-8") from exc
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
                raise AwsScpAnalysisError("JSON structural budget exceeded")
        elif character in "]}":
            depth -= 1

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, child in items:
            if key in result:
                raise AwsScpAnalysisError("Duplicate JSON object key")
            result[key] = child
        return result

    def unsupported(_: str) -> Any:
        raise AwsScpAnalysisError("JSON floats and nonfinite values are unsupported")

    def integer(value: str) -> int:
        if len(value) > 20:
            raise AwsScpAnalysisError("JSON integer is outside signed64")
        return int(value)

    try:
        value = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_float=unsupported,
            parse_constant=unsupported,
            parse_int=integer,
        )
    except (ValueError, RecursionError) as exc:
        raise AwsScpAnalysisError("Invalid bounded native JSON") from exc
    return _capture(value)


def _object(value: Any, fields: set[str], label: str) -> dict:
    if type(value) is not dict or len(value) != len(fields) or value.keys() != fields:
        raise AwsScpAnalysisError(f"{label} requires exactly its declared fields")
    return value


def _text(value: Any, label: str, *, empty: bool = False) -> str:
    if (
        type(value) is not str
        or len(value) > 512
        or (not value and not empty)
        or not value.isascii()
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise AwsScpAnalysisError(f"{label} requires bounded native ASCII text")
    return value


def _identifier(value: Any, label: str) -> str:
    text = _text(value, label)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9:._/-]*", text):
        raise AwsScpAnalysisError(f"{label} is not a supported identifier")
    return text


def _account(value: Any) -> str:
    if type(value) is not str or not re.fullmatch(r"[0-9]{12}", value):
        raise AwsScpAnalysisError("Account declarations require twelve native ASCII digits")
    return value


def _list(value: Any, label: str, *, maximum: int = MAX_LOCAL_ITEMS) -> list:
    if type(value) is not list or len(value) > maximum:
        raise AwsScpAnalysisError(f"{label} requires a bounded native list")
    return value


def _values(value: Any, label: str) -> list[str]:
    values = [value] if type(value) is str else _list(value, label)
    if not values:
        raise AwsScpAnalysisError(f"{label} cannot be empty")
    return [_text(item, label) for item in values]


def _context_key(value: Any) -> str:
    text = _text(value, "Context key")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9:/_.-]*", text):
        raise AwsScpAnalysisError("Context key is outside the supported scalar vocabulary")
    return text.lower()


def _resource_supported(value: str) -> bool:
    if value == "*":
        return True
    parts = value.split(":", 5)
    return (
        len(parts) == 6
        and parts[0] == "arn"
        and bool(parts[1])
        and bool(parts[2])
        and bool(parts[5])
        and not any("*" in part or "?" in part for part in parts[:5])
        and not (":" in parts[5] and ("*" in parts[5] or "?" in parts[5]))
        and "${" not in value
    )


def _statement(statement: Any) -> tuple[dict, tuple[str, ...]]:
    if type(statement) is not dict or "Effect" not in statement:
        raise AwsScpAnalysisError("Statements require a native object and Effect")
    if statement["Effect"] not in ("Allow", "Deny") or type(statement["Effect"]) is not str:
        raise AwsScpAnalysisError("Statement Effect requires exact Allow or Deny")
    if ("Action" in statement) == ("NotAction" in statement):
        raise AwsScpAnalysisError("Statements require exactly one action selector")
    if ("Resource" in statement) == ("NotResource" in statement):
        raise AwsScpAnalysisError("Statements require exactly one resource selector")
    if "Sid" in statement:
        _text(statement["Sid"], "Statement Sid")
    reasons = set()
    if statement.keys() - {"Sid", "Effect", "Action", "Resource", "Condition"}:
        reasons.add("unsupported_statement_fields_or_complements")
    for key in ("Action", "NotAction", "Resource", "NotResource"):
        if key in statement:
            values = _values(statement[key], key)
            if any("${" in value for value in values):
                reasons.add("unsupported_policy_variable")
            if key == "Action" and any(
                value != "*" and not re.fullmatch(r"[A-Za-z0-9_-]+:[A-Za-z0-9*?_-]+", value)
                for value in values
            ):
                reasons.add("unsupported_action_pattern")
            if key == "Resource" and any(not _resource_supported(value) for value in values):
                reasons.add("unsupported_resource_pattern")
    if statement["Effect"] == "Allow" and "Resource" in statement:
        if set(_values(statement["Resource"], "Resource")) != {"*"}:
            reasons.add("unsupported_allow_resource_subset")
    if "Condition" in statement:
        conditions = statement["Condition"]
        if type(conditions) is not dict or not conditions or len(conditions) > 8:
            raise AwsScpAnalysisError("Condition requires a bounded nonempty native object")
        for operator, keys in conditions.items():
            _text(operator, "Condition operator")
            if type(keys) is not dict or not keys or len(keys) > MAX_CONDITION_KEYS:
                raise AwsScpAnalysisError("Condition requires bounded scalar-key objects")
            seen = set()
            for key, values in keys.items():
                lowered = _context_key(key)
                if lowered in seen:
                    raise AwsScpAnalysisError("Case-colliding condition keys are ambiguous")
                seen.add(lowered)
                values = _values(values, "Condition values")
                if any("${" in value for value in values):
                    reasons.add("unsupported_policy_variable")
                if operator not in ("StringEquals", "StringLike", "Bool", "Null"):
                    reasons.add("unsupported_condition_operator")
                if operator in ("Bool", "Null") and any(
                    value not in ("true", "false") for value in values
                ):
                    raise AwsScpAnalysisError("Bool and Null values require true or false text")
    return statement, tuple(sorted(reasons))


def _validate_snapshot(snapshot: Any) -> tuple[list[tuple[dict, dict, dict]], list[dict]]:
    _object(
        snapshot,
        {"schema_version", "organization_id", "management_account_id", "scp_enabled", "path"},
        "Snapshot",
    )
    if type(snapshot["schema_version"]) is not int or snapshot["schema_version"] != 1:
        raise AwsScpAnalysisError("Snapshot schema_version requires native integer one")
    _identifier(snapshot["organization_id"], "Organization ID")
    management = _account(snapshot["management_account_id"])
    if snapshot["scp_enabled"] is not None and type(snapshot["scp_enabled"]) is not bool:
        raise AwsScpAnalysisError("SCP applicability requires native bool or null")
    path = _list(snapshot["path"], "Path", maximum=MAX_PATH_LEVELS)
    if len(path) < 2:
        raise AwsScpAnalysisError("Path requires a root and a member account")
    node_ids = set()
    documents = {}
    statements = []
    issues = []
    policy_count = 0
    for index, level in enumerate(path):
        _object(level, {"node_id", "node_type", "attachments_complete", "policies"}, "Path level")
        _identifier(level["node_id"], "Node ID")
        expected_type = "root" if index == 0 else ("account" if index == len(path) - 1 else "ou")
        if type(level["node_type"]) is not str or level["node_type"] != expected_type:
            raise AwsScpAnalysisError("Path must be one ordered root/OU/member-account chain")
        if level["node_id"] in node_ids:
            raise AwsScpAnalysisError("Path node IDs repeat")
        node_ids.add(level["node_id"])
        if type(level["attachments_complete"]) is not bool:
            raise AwsScpAnalysisError("Attachment completeness requires native bool")
        if expected_type == "account" and _account(level["node_id"]) == management:
            raise AwsScpAnalysisError("A member-account path cannot select the management account")
        policies = _list(level["policies"], "Attached policies")
        policy_count += len(policies)
        if policy_count > MAX_POLICIES:
            raise AwsScpAnalysisError("Policy attachment budget exceeded")
        attached_ids = set()
        for policy in policies:
            _object(policy, {"policy_id", "document"}, "Policy attachment")
            policy_id = _identifier(policy["policy_id"], "Policy ID")
            if policy_id in attached_ids:
                raise AwsScpAnalysisError("Duplicate policy attachment at one level")
            attached_ids.add(policy_id)
            document = policy["document"]
            if type(document) is not dict or not {"Version", "Statement"} <= document.keys():
                raise AwsScpAnalysisError("Policy requires native Version and Statement fields")
            _text(document["Version"], "Policy Version")
            if policy_id in documents and _canonical(document) != _canonical(documents[policy_id]):
                raise AwsScpAnalysisError("One policy ID has conflicting documents")
            documents[policy_id] = document
            policy_reasons = set()
            if document["Version"] != "2012-10-17":
                policy_reasons.add("unsupported_policy_version")
            if document.keys() - {"Version", "Statement"}:
                policy_reasons.add("unsupported_policy_fields")
            raw = document["Statement"]
            raw_statements = [raw] if type(raw) is dict else _list(raw, "Statements")
            if not raw_statements:
                raise AwsScpAnalysisError("Policy Statement cannot be empty")
            seen_sids = set()
            for raw_statement in raw_statements:
                statement, reasons = _statement(raw_statement)
                if "Sid" in statement:
                    if statement["Sid"] in seen_sids:
                        raise AwsScpAnalysisError("Statement Sids repeat within one policy")
                    seen_sids.add(statement["Sid"])
                statements.append((level, policy, statement))
                if len(statements) > MAX_STATEMENTS:
                    raise AwsScpAnalysisError("Statement matching budget exceeded")
                for reason in sorted(policy_reasons | set(reasons)):
                    issues.append(
                        {
                            "node_id": level["node_id"],
                            "policy_id": policy_id,
                            "statement": statement,
                            "reason": reason,
                        }
                    )
    return statements, issues


def _validate_queries(queries: Any) -> None:
    _list(queries, "Queries", maximum=MAX_QUERIES)
    seen = set()
    for query in queries:
        _object(
            query,
            {"query_id", "principal_account_id", "principal_kind", "action", "resource", "context"},
            "Query",
        )
        query_id = _identifier(query["query_id"], "Query ID")
        if query_id in seen:
            raise AwsScpAnalysisError("Query IDs repeat")
        seen.add(query_id)
        if query["principal_account_id"] is not None:
            _account(query["principal_account_id"])
        if type(query["principal_kind"]) is not str or query["principal_kind"] not in (
            "iam_user",
            "iam_role",
            "root",
            "service_linked_role",
            "unknown",
        ):
            raise AwsScpAnalysisError("Principal kind is unsupported")
        action = _text(query["action"], "Query action")
        if not re.fullmatch(r"[A-Za-z0-9_-]+:[A-Za-z0-9_-]+", action):
            raise AwsScpAnalysisError("Query action must be explicit, not a pattern")
        resource = _text(query["resource"], "Query resource")
        if not _resource_supported(resource) or (
            resource != "*" and ("*" in resource or "?" in resource)
        ):
            raise AwsScpAnalysisError("Query resource must be explicit ARN or universal star")
        context = _object(query["context"], {"values", "absent_keys"}, "Context")
        values = context["values"]
        if type(values) is not dict or len(values) > MAX_CONDITION_KEYS:
            raise AwsScpAnalysisError("Context values require a bounded scalar object")
        keys = set()
        for key, value in values.items():
            lowered = _context_key(key)
            if lowered in keys:
                raise AwsScpAnalysisError("Case-colliding context keys are ambiguous")
            keys.add(lowered)
            _text(value, "Context scalar value")
        absent = _list(context["absent_keys"], "Absent context keys", maximum=MAX_CONDITION_KEYS)
        for key in absent:
            lowered = _context_key(key)
            if lowered in keys:
                raise AwsScpAnalysisError("Context keys repeat or are both present and absent")
            keys.add(lowered)


@dataclass
class _Budget:
    work: int = 0
    witnesses: int = 0

    def spend(self, amount: int = 1) -> None:
        self.work += amount
        if self.work > MAX_MATCH_WORK:
            raise AwsScpAnalysisError("Matching work budget exceeded; no truncation is returned")

    def witness(self) -> None:
        self.witnesses += 1
        if self.witnesses > MAX_WITNESSES:
            raise AwsScpAnalysisError("Witness budget exceeded; no truncation is returned")


def _glob(pattern: str, value: str, budget: _Budget) -> bool:
    """Bounded star/question-mark matching without regex or expansion."""
    pi = vi = 0
    star = -1
    retry = 0
    while vi < len(value):
        budget.spend()
        if pi < len(pattern) and pattern[pi] == "*":
            star = pi
            pi += 1
            retry = vi
        elif pi < len(pattern) and (pattern[pi] == "?" or pattern[pi] == value[vi]):
            pi += 1
            vi += 1
        elif star >= 0:
            retry += 1
            vi = retry
            pi = star + 1
        else:
            return False
    while pi < len(pattern) and pattern[pi] == "*":
        budget.spend()
        pi += 1
    return pi == len(pattern)


def _condition(statement: dict, query: dict, budget: _Budget) -> bool | None:
    values = {key.lower(): value for key, value in query["context"]["values"].items()}
    absent = {key.lower() for key in query["context"]["absent_keys"]}
    unknown = False
    for operator, keys in sorted(statement.get("Condition", {}).items()):
        for key, raw in sorted(keys.items()):
            candidates = _values(raw, "Condition values")
            budget.spend(len(candidates) + 1)
            key = key.lower()
            if key not in values and key not in absent:
                unknown = True
                continue
            if operator == "Null":
                match = ("true" if key in absent else "false") in candidates
            elif key in absent:
                match = False
            elif operator == "StringLike":
                match = any(_glob(pattern, values[key], budget) for pattern in candidates)
            elif operator == "Bool":
                if values[key] not in ("true", "false"):
                    unknown = True
                    continue
                match = values[key] in candidates
            else:
                match = values[key] in candidates
            if not match:
                return False
    return None if unknown else True


def _resource_matches(pattern: str, value: str, budget: _Budget) -> bool | None:
    if pattern != "*" and value != "*":
        tail = pattern.split(":", 5)[5]
        value_tail = value.split(":", 5)[5]
        if ":" in value_tail and ("*" in tail or "?" in tail):
            # Only one plain trailing star has an unambiguous colon-spanning
            # meaning in this subset. Do not infer other ARN segment semantics.
            if not (tail.endswith("*") and tail.count("*") == 1 and "?" not in tail):
                budget.spend()
                return None
    return _glob(pattern, value, budget)


def _matches(statement: dict, query: dict, budget: _Budget) -> bool | None:
    budget.spend()
    if not any(
        _glob(pattern.lower(), query["action"].lower(), budget)
        for pattern in _values(statement["Action"], "Action")
    ):
        return False
    resource_matches = [
        _resource_matches(pattern, query["resource"], budget)
        for pattern in _values(statement["Resource"], "Resource")
    ]
    if not any(value is not False for value in resource_matches):
        return False
    condition = _condition(statement, query, budget)
    if condition is False:
        return False
    if condition is None or not any(value is True for value in resource_matches):
        return None
    return True


def _applicability(snapshot: dict, query: dict) -> tuple[str | None, str | None]:
    if snapshot["scp_enabled"] is False:
        return "not_applicable", "scp_declared_disabled"
    if query["principal_account_id"] == snapshot["management_account_id"]:
        return "not_applicable", "declared_management_account_exemption"
    if query["principal_kind"] == "service_linked_role":
        return "not_applicable", "declared_service_linked_role_exemption"
    if snapshot["scp_enabled"] is None:
        return "inconclusive", "scp_applicability_unavailable"
    if query["principal_account_id"] is None or query["principal_kind"] == "unknown":
        return "inconclusive", "principal_applicability_unavailable"
    if query["principal_account_id"] != snapshot["path"][-1]["node_id"]:
        return "inconclusive", "principal_outside_supplied_account_path"
    return None, None


def _build_document(snapshot: Any, queries: Any) -> dict:
    sources = _capture({"snapshot": snapshot, "queries": queries})
    snapshot, queries = sources["snapshot"], sources["queries"]
    statements, raw_issues = _validate_snapshot(snapshot)
    _validate_queries(queries)
    # Semantic and aggregate input bounds precede content hashing or matching.
    issues = {}
    unsupported = set()
    for issue in raw_issues:
        statement_sha = _hash("sunderkey.aws-scp-statement.v1", issue["statement"])
        key = (issue["node_id"], issue["policy_id"], statement_sha)
        unsupported.add(key)
        value = {
            "node_id": key[0],
            "policy_id": key[1],
            "statement_sha256": key[2],
            "reason": issue["reason"],
        }
        issues[_canonical(value)] = value
    source_issues = [issues[key] for key in sorted(issues)]
    prepared = [
        (level, policy, statement, _hash("sunderkey.aws-scp-statement.v1", statement))
        for level, policy, statement in statements
    ]
    budget = _Budget()
    results = []
    for query in sorted(queries, key=lambda item: item["query_id"]):
        decision, applicability_reason = _applicability(snapshot, query)
        reasons = set()
        allowed_levels = set()
        allows, denies, unresolved = {}, {}, {}
        incomplete = [
            level["node_id"] for level in snapshot["path"] if not level["attachments_complete"]
        ]
        if applicability_reason:
            reasons.add(applicability_reason)
        if decision is None:
            if incomplete:
                reasons.add("incomplete_policy_attachments")
            if source_issues:
                reasons.add("unsupported_source_semantics")
            for level, policy, statement, statement_sha in prepared:
                budget.spend()
                key = (level["node_id"], policy["policy_id"], statement_sha)
                witness = {
                    "node_id": key[0],
                    "policy_id": key[1],
                    "statement_sha256": key[2],
                    "effect": statement["Effect"],
                }
                witness_key = _canonical(witness)
                match = None if key in unsupported else _matches(statement, query, budget)
                if match is False:
                    continue
                selected = (
                    unresolved
                    if match is None
                    else (denies if statement["Effect"] == "Deny" else allows)
                )
                if witness_key not in selected:
                    budget.witness()
                    selected[witness_key] = witness
                if match is None:
                    reasons.add("unresolved_statement_or_context")
                elif statement["Effect"] == "Allow":
                    allowed_levels.add(level["node_id"])
            missing_allow = [
                level["node_id"]
                for level in snapshot["path"]
                if level["node_id"] not in allowed_levels
            ]
            if denies:
                decision = "blocked"
                reasons.add("matching_explicit_deny")
            elif reasons:
                decision = "inconclusive"
            elif missing_allow:
                decision = "blocked"
                reasons.add("no_matching_allow_at_every_level")
            else:
                decision = "not_blocked_by_supplied_scps"
                reasons.add("matching_allow_at_every_level_without_known_deny")
        else:
            missing_allow = []
        results.append(
            {
                "query_id": query["query_id"],
                "query_sha256": _hash("sunderkey.aws-scp-query.v1", query),
                "decision": decision,
                "reasons": sorted(reasons),
                "allow_witnesses": [allows[key] for key in sorted(allows)],
                "deny_witnesses": [denies[key] for key in sorted(denies)],
                "unresolved_witnesses": [unresolved[key] for key in sorted(unresolved)],
                "missing_allow_level_ids": missing_allow,
                "incomplete_level_ids": incomplete if decision != "not_applicable" else [],
            }
        )
    body = {
        "schema_version": 1,
        "kind": "aws_scp_analysis",
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "semantics_profile": SEMANTICS_PROFILE,
        "snapshot": snapshot,
        "queries": queries,
        "snapshot_sha256": _hash("sunderkey.aws-scp-snapshot.v1", snapshot),
        "queries_sha256": _hash("sunderkey.aws-scp-queries.v1", queries),
        "source_issues": source_issues,
        "results": results,
        "summary": {key: sum(item["decision"] == key for item in results) for key in _DECISIONS},
        "limitations": list(_LIMITATIONS),
        "effects": {
            key: "none"
            for key in ("qualification", "routing", "execution", "deployment", "target_interaction")
        },
    }
    # Output budgets apply before its canonical serialization and analysis address.
    body = _capture(body)
    digest = _hash("sunderkey.aws-scp-analysis.v1", body)
    body.update(analysis_id="ASA-" + digest[7:39].upper(), analysis_sha256=digest)
    _capture(body)
    return body


def _verified_document(raw: Any) -> dict:
    document = _capture(raw)
    if type(document) is not dict or not {"snapshot", "queries"} <= document.keys():
        raise AwsScpAnalysisError("Analysis requires embedded exact supplied inputs")
    expected = _build_document(document["snapshot"], document["queries"])
    if _canonical(document) != _canonical(expected):
        raise AwsScpAnalysisError("Analysis does not match exact source/query replay")
    return expected


@dataclass(frozen=True, slots=True)
class AwsScpAnalysis:
    """Owned canonical document; parsing and export repeat the supplied-model algorithm."""

    document_json: str

    def __post_init__(self) -> None:
        self.to_dict()

    @classmethod
    def from_dict(cls, document: dict) -> AwsScpAnalysis:
        return cls(_canonical(_verified_document(document)))

    @classmethod
    def from_json(cls, raw: bytes) -> AwsScpAnalysis:
        return cls.from_dict(_parse_bytes(raw))

    def to_dict(self) -> dict:
        text = getattr(self, "document_json", None)
        if type(text) is not str or len(text) > MAX_JSON_BYTES:
            raise AwsScpAnalysisError("Analysis requires bounded native canonical text")
        try:
            content = text.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise AwsScpAnalysisError("Analysis text is not UTF-8") from exc
        expected = _verified_document(_parse_bytes(content))
        if text != _canonical(expected):
            raise AwsScpAnalysisError("Analysis text must be exact canonical JSON")
        return expected

    def to_json(self) -> str:
        return _canonical(self.to_dict())

    @property
    def analysis_id(self) -> str:
        return self.to_dict()["analysis_id"]

    @property
    def analysis_sha256(self) -> str:
        return self.to_dict()["analysis_sha256"]


def analyze_aws_scp(snapshot: dict, queries: list) -> AwsScpAnalysis:
    """Evaluate only the supplied SCP subset, never effective AWS authorization."""
    return AwsScpAnalysis(_canonical(_build_document(snapshot, queries)))


def analyze_aws_scp_bytes(*, snapshot_bytes: bytes, queries_bytes: bytes) -> AwsScpAnalysis:
    return analyze_aws_scp(_parse_bytes(snapshot_bytes), _parse_bytes(queries_bytes))


def verify_aws_scp_analysis(
    analysis: AwsScpAnalysis | dict, *, snapshot: dict, queries: list
) -> AwsScpAnalysis:
    if type(analysis) is AwsScpAnalysis:
        document = analysis.to_dict()
    elif type(analysis) is dict:
        document = _verified_document(analysis)
    else:
        raise AwsScpAnalysisError("Expected an exact record or native analysis document")
    expected = _build_document(snapshot, queries)
    if _canonical(document) != _canonical(expected):
        raise AwsScpAnalysisError("Analysis is bound to different supplied inputs")
    return AwsScpAnalysis(_canonical(expected))
