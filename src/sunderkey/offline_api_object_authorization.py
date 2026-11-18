"""Offline object authorization projection over supplied facts and outcomes."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

PROFILE_ID = "AOE-GB-D06-S09"
CAPABILITY_ID = "api.authorization.object-level"
VECTOR_ID = "AV-GB-D06-S09-01"
WAVE_ID = "IW2-001"
DOMAIN = "sunderkey.offline-api-object-authorization.v1"
SCHEMA_VERSION = "v1"
MAX_SOURCE_BYTES = 262_144
MAX_REPORT_BYTES = 524_288
MAX_NODES = 40_000
MAX_DEPTH = 16
MAX_TEXT_BYTES = 512
MAX_SUBJECTS = 256
MAX_OBJECTS = 512
MAX_RULES = 256
MAX_OUTCOMES = 2_048
MAX_MATCH_STEPS = 262_144
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
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
    "facts_authenticated": False,
    "policy_authenticated": False,
    "access_outcomes_authenticated": False,
    "server_enforcement_observed": False,
    "finding_claimed": False,
    "positive_use_approved": False,
    "qualification_claimed": False,
}
_LIMITATIONS = [
    "Subjects, ownership, tenants, policy and access outcomes are supplied assertions.",
    "Relations are ID equalities, not resolved identities or provider semantics.",
    "Unknown or incomplete premises cannot support a consistent-result or contradiction claim.",
    "A supplied outcome contradicting a declared rule is a candidate, not a verified flaw.",
    "Object actions are modeled; property writes and function access are separate.",
    "No URL, target access, request, credential, execution or live exploit is involved.",
]
_ASSESSMENTS = {"candidate_policy_contradiction", "declared_consistent", "unknown"}
_BASES = {
    "matched_rule",
    "complete_default_deny",
    "incomplete_facts",
    "incomplete_policy",
    "missing_subject",
    "missing_object",
    "unknown_relation",
    "unknown_outcome",
    "conflicting_rules",
}


class ApiObjectAuthorizationError(ValueError):
    """Closed input, resource bound or replay validation failed."""


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields or any(type(k) is not str for k in value):
        raise ApiObjectAuthorizationError(f"{label} fields are invalid")
    return value


def _id(value: Any, label: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise ApiObjectAuthorizationError(f"{label} must be bounded native ASCII text")
    return value


def _optional_id(value: Any, label: str) -> str | None:
    return None if value is None else _id(value, label)


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ApiObjectAuthorizationError("duplicate JSON key")
        result[key] = value
    return result


def _json_integer(token: str) -> int:
    if len(token) > 20 or len(token.lstrip("-")) > 19:
        raise ApiObjectAuthorizationError("JSON integer exceeds signed64 bound")
    value = int(token)
    if not -(1 << 63) <= value < (1 << 63):
        raise ApiObjectAuthorizationError("JSON integer exceeds signed64 bound")
    return value


def _unsupported_number(_token: str) -> None:
    raise ApiObjectAuthorizationError("floating and nonfinite numbers are unsupported")


def _validate_tree(value: Any, *, maximum: int) -> None:
    stack = [(value, 1)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise ApiObjectAuthorizationError("JSON node or depth bound exceeded")
        kind = type(item)
        if kind is dict:
            if nodes + len(stack) + 2 * len(item) > MAX_NODES:
                raise ApiObjectAuthorizationError("JSON node bound exceeded")
            for key, child in item.items():
                if type(key) is not str:
                    raise ApiObjectAuthorizationError("JSON keys must be native text")
                stack.append((child, depth + 1))
                stack.append((key, depth + 1))
        elif kind is list:
            if nodes + len(stack) + len(item) > MAX_NODES:
                raise ApiObjectAuthorizationError("JSON node bound exceeded")
            stack.extend((child, depth + 1) for child in item)
        elif kind is str:
            if len(item.encode("utf-8", errors="surrogatepass")) > MAX_TEXT_BYTES or any(
                0xD800 <= ord(char) <= 0xDFFF for char in item
            ):
                raise ApiObjectAuthorizationError("JSON string is unsupported or too long")
        elif kind is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise ApiObjectAuthorizationError("JSON integer exceeds signed64 bound")
        elif kind not in (bool, type(None)):
            raise ApiObjectAuthorizationError("unsupported JSON value family")
    if len(_canonical(value).encode("ascii")) > maximum:
        raise ApiObjectAuthorizationError("canonical JSON byte bound exceeded")


def _decode(content: bytes, *, maximum: int) -> Any:
    if type(content) is not bytes or not content or len(content) > maximum:
        raise ApiObjectAuthorizationError("source must be bounded nonempty native bytes")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ApiObjectAuthorizationError("source must be UTF-8") from exc
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
                raise ApiObjectAuthorizationError("pre-decoder depth bound exceeded")
        elif char in "]}":
            nesting -= 1
            if nesting < 0:
                raise ApiObjectAuthorizationError("malformed JSON nesting")
    if nesting or quoted:
        raise ApiObjectAuthorizationError("malformed JSON nesting")
    try:
        result = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_json_integer,
            parse_float=_unsupported_number,
            parse_constant=_unsupported_number,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, ApiObjectAuthorizationError):
            raise
        raise ApiObjectAuthorizationError("malformed JSON source") from exc
    _validate_tree(result, maximum=maximum)
    return result


def _model(
    document: Any,
) -> tuple[
    bool,
    bool,
    dict[str, dict[str, Any]],
    dict[str, dict[str, Any]],
    list[dict[str, str]],
    list[dict[str, str]],
]:
    model = _exact(
        document,
        {
            "schema_version",
            "facts_complete",
            "policy_complete",
            "subjects",
            "objects",
            "policy_rules",
            "access_outcomes",
        },
        "model",
    )
    if type(model["schema_version"]) is not str or model["schema_version"] != SCHEMA_VERSION:
        raise ApiObjectAuthorizationError("unsupported model version")
    if type(model["facts_complete"]) is not bool or type(model["policy_complete"]) is not bool:
        raise ApiObjectAuthorizationError("completeness must be native Booleans")
    for name, maximum in (
        ("subjects", MAX_SUBJECTS),
        ("objects", MAX_OBJECTS),
        ("policy_rules", MAX_RULES),
        ("access_outcomes", MAX_OUTCOMES),
    ):
        values = model[name]
        if type(values) is not list or len(values) > maximum:
            raise ApiObjectAuthorizationError(f"{name} must be a bounded native array")
    subjects = {}
    for raw in model["subjects"]:
        entry = _exact(raw, {"subject_id", "tenant_id"}, "subject")
        identifier = _id(entry["subject_id"], "subject ID")
        if identifier in subjects:
            raise ApiObjectAuthorizationError("duplicate subject ID")
        subjects[identifier] = {"tenant_id": _optional_id(entry["tenant_id"], "tenant ID")}
    objects = {}
    for raw in model["objects"]:
        entry = _exact(raw, {"object_id", "owner_subject_id", "tenant_id"}, "object")
        identifier = _id(entry["object_id"], "object ID")
        if identifier in objects:
            raise ApiObjectAuthorizationError("duplicate object ID")
        objects[identifier] = {
            "owner_subject_id": _optional_id(entry["owner_subject_id"], "owner subject ID"),
            "tenant_id": _optional_id(entry["tenant_id"], "tenant ID"),
        }
    rules = []
    rule_ids = set()
    for raw in model["policy_rules"]:
        entry = _exact(
            raw,
            {"rule_id", "action", "owner_relation", "tenant_relation", "decision"},
            "policy rule",
        )
        rule_id = _id(entry["rule_id"], "rule ID")
        if rule_id in rule_ids:
            raise ApiObjectAuthorizationError("duplicate rule ID")
        rule_ids.add(rule_id)
        owner_relation = entry["owner_relation"]
        tenant_relation = entry["tenant_relation"]
        decision = entry["decision"]
        if type(owner_relation) is not str or owner_relation not in ("owner", "non_owner"):
            raise ApiObjectAuthorizationError("owner relation is unsupported")
        if type(tenant_relation) is not str or tenant_relation not in (
            "same_tenant",
            "different_tenant",
        ):
            raise ApiObjectAuthorizationError("tenant relation is unsupported")
        if type(decision) is not str or decision not in ("allow", "deny"):
            raise ApiObjectAuthorizationError("rule decision is unsupported")
        rules.append(
            {
                "rule_id": rule_id,
                "action": _id(entry["action"], "action"),
                "owner_relation": owner_relation,
                "tenant_relation": tenant_relation,
                "decision": decision,
            }
        )
    outcomes = []
    observation_ids = set()
    for raw in model["access_outcomes"]:
        entry = _exact(
            raw,
            {"observation_id", "subject_id", "object_id", "action", "outcome"},
            "access outcome",
        )
        observation_id = _id(entry["observation_id"], "observation ID")
        if observation_id in observation_ids:
            raise ApiObjectAuthorizationError("duplicate observation ID")
        observation_ids.add(observation_id)
        outcome = entry["outcome"]
        if type(outcome) is not str or outcome not in ("allowed", "denied", "unknown"):
            raise ApiObjectAuthorizationError("access outcome is unsupported")
        outcomes.append(
            {
                "observation_id": observation_id,
                "subject_id": _id(entry["subject_id"], "subject ID"),
                "object_id": _id(entry["object_id"], "object ID"),
                "action": _id(entry["action"], "action"),
                "outcome": outcome,
            }
        )
    return model["facts_complete"], model["policy_complete"], subjects, objects, rules, outcomes


def _project(
    facts_complete: bool,
    policy_complete: bool,
    subjects: dict[str, dict[str, Any]],
    objects: dict[str, dict[str, Any]],
    rules: list[dict[str, str]],
    outcomes: list[dict[str, str]],
) -> list[dict[str, Any]]:
    by_key: dict[tuple[str, str, str], list[dict[str, str]]] = {}
    for rule in rules:
        key = (rule["action"], rule["owner_relation"], rule["tenant_relation"])
        by_key.setdefault(key, []).append(rule)
    projections = []
    steps = 0
    for outcome in sorted(outcomes, key=lambda item: item["observation_id"]):
        subject_id, object_id = outcome["subject_id"], outcome["object_id"]
        subject = subjects.get(subject_id)
        object_ = objects.get(object_id)
        owner_relation = tenant_relation = None
        matching = []
        expected = "unknown"
        assessment = "unknown"
        if not facts_complete:
            basis = "incomplete_facts"
        elif not policy_complete:
            basis = "incomplete_policy"
        elif subject is None:
            basis = "missing_subject"
        elif object_ is None:
            basis = "missing_object"
        elif (
            subject["tenant_id"] is None
            or object_["tenant_id"] is None
            or (object_["owner_subject_id"] is None)
        ):
            basis = "unknown_relation"
        else:
            owner_relation = "owner" if subject_id == object_["owner_subject_id"] else "non_owner"
            tenant_relation = (
                "same_tenant"
                if subject["tenant_id"] == object_["tenant_id"]
                else "different_tenant"
            )
            key = (outcome["action"], owner_relation, tenant_relation)
            matching = sorted(by_key.get(key, []), key=lambda item: item["rule_id"])
            steps += 1 + len(matching)
            if steps > MAX_MATCH_STEPS:
                raise ApiObjectAuthorizationError("matching work bound exceeded")
            decisions = {rule["decision"] for rule in matching}
            if len(decisions) > 1:
                basis = "conflicting_rules"
            elif matching:
                expected = matching[0]["decision"]
                basis = "matched_rule"
            else:
                expected = "deny"
                basis = "complete_default_deny"
            if outcome["outcome"] == "unknown":
                assessment, basis = "unknown", "unknown_outcome"
            elif expected == "unknown":
                assessment = "unknown"
            elif (expected == "allow") == (outcome["outcome"] == "allowed"):
                assessment = "declared_consistent"
            else:
                assessment = "candidate_policy_contradiction"
        projections.append(
            {
                "observation_id": outcome["observation_id"],
                "subject_id": subject_id,
                "object_id": object_id,
                "action": outcome["action"],
                "supplied_outcome": outcome["outcome"],
                "owner_relation": owner_relation,
                "tenant_relation": tenant_relation,
                "expected_decision": expected,
                "assessment": assessment,
                "basis": basis,
                "matching_rule_ids": [rule["rule_id"] for rule in matching],
            }
        )
    return projections


@dataclass(frozen=True, slots=True)
class ApiObjectAuthorizationReport:
    """Immutable canonical report; exact source replay proves its derivation."""

    _json: str

    def __post_init__(self) -> None:
        if type(self) is not ApiObjectAuthorizationReport:
            raise ApiObjectAuthorizationError("report must be the exact report family")
        if self._json != _checked_report_json(self._json):
            raise ApiObjectAuthorizationError("canonical report JSON is required")

    def to_json(self) -> str:
        if type(self) is not ApiObjectAuthorizationReport or self._json != (
            _checked_report_json(self._json)
        ):
            raise ApiObjectAuthorizationError("canonical exact report is required")
        return self._json

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.to_json())

    @classmethod
    def from_json(cls, content: str) -> ApiObjectAuthorizationReport:
        if cls is not ApiObjectAuthorizationReport:
            raise ApiObjectAuthorizationError("report must be the exact report family")
        return cls(_checked_report_json(content))


def _checked_report_json(content: Any) -> str:
    if type(content) is not str:
        raise ApiObjectAuthorizationError("report must be native JSON text")
    try:
        raw = content.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ApiObjectAuthorizationError("report must be UTF-8 JSON text") from exc
    document = _decode(raw, maximum=MAX_REPORT_BYTES)
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
            "wave_id",
            "domain",
            "source",
            "facts_complete",
            "policy_complete",
            "projections",
            "summary",
            "effects",
            "limitations",
            "report_id",
            "report_sha256",
            *_FLAGS,
        },
        "report",
    )
    for key, expected in {
        "schema_version": SCHEMA_VERSION,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "wave_id": WAVE_ID,
        "domain": DOMAIN,
        "effects": _EFFECTS,
        "limitations": _LIMITATIONS,
        **_FLAGS,
    }.items():
        if type(item[key]) is not type(expected) or item[key] != expected:
            raise ApiObjectAuthorizationError(f"report {key} is invalid")
    source = _exact(item["source"], {"source_id", "sha256", "byte_count"}, "source")
    _id(source["source_id"], "source ID")
    if type(source["sha256"]) is not str or _DIGEST.fullmatch(source["sha256"]) is None:
        raise ApiObjectAuthorizationError("source digest is invalid")
    if type(source["byte_count"]) is not int or not 1 <= source["byte_count"] <= (MAX_SOURCE_BYTES):
        raise ApiObjectAuthorizationError("source byte count is invalid")
    if type(item["facts_complete"]) is not bool or type(item["policy_complete"]) is not bool:
        raise ApiObjectAuthorizationError("report completeness is invalid")
    projections = item["projections"]
    if type(projections) is not list or len(projections) > MAX_OUTCOMES:
        raise ApiObjectAuthorizationError("report projections are invalid")
    observed_ids = set()
    counts = {assessment: 0 for assessment in sorted(_ASSESSMENTS)}
    for raw in projections:
        projection = _exact(
            raw,
            {
                "observation_id",
                "subject_id",
                "object_id",
                "action",
                "supplied_outcome",
                "owner_relation",
                "tenant_relation",
                "expected_decision",
                "assessment",
                "basis",
                "matching_rule_ids",
            },
            "projection",
        )
        observation_id = _id(projection["observation_id"], "observation ID")
        if observation_id in observed_ids:
            raise ApiObjectAuthorizationError("duplicate projection observation ID")
        observed_ids.add(observation_id)
        for key in ("subject_id", "object_id", "action"):
            _id(projection[key], key)
        if type(projection["supplied_outcome"]) is not str or projection[
            "supplied_outcome"
        ] not in ("allowed", "denied", "unknown"):
            raise ApiObjectAuthorizationError("report outcome is invalid")
        for key, options in (
            ("owner_relation", ("owner", "non_owner")),
            ("tenant_relation", ("same_tenant", "different_tenant")),
        ):
            value = projection[key]
            if value is not None and (type(value) is not str or value not in options):
                raise ApiObjectAuthorizationError("report relation is invalid")
        if type(projection["expected_decision"]) is not str or projection[
            "expected_decision"
        ] not in ("allow", "deny", "unknown"):
            raise ApiObjectAuthorizationError("report expected decision is invalid")
        assessment = projection["assessment"]
        basis = projection["basis"]
        if (
            type(assessment) is not str
            or assessment not in _ASSESSMENTS
            or (type(basis) is not str or basis not in _BASES)
        ):
            raise ApiObjectAuthorizationError("report assessment or basis is invalid")
        counts[assessment] += 1
        names = projection["matching_rule_ids"]
        if type(names) is not list or len(names) > MAX_RULES:
            raise ApiObjectAuthorizationError("report rule references are invalid")
        checked = [_id(name, "rule ID") for name in names]
        if checked != sorted(set(checked)):
            raise ApiObjectAuthorizationError("report rule references must be sorted unique")
    summary = _exact(item["summary"], {"observation_count", *counts}, "summary")
    if any(type(value) is not int for value in summary.values()) or summary != {
        "observation_count": len(projections),
        **counts,
    }:
        raise ApiObjectAuthorizationError("report summary is invalid")
    body = {key: value for key, value in item.items() if key not in ("report_id", "report_sha256")}
    digest = _digest(_canonical({"domain": DOMAIN, "analysis": body}).encode("ascii"))
    if item["report_sha256"] != digest or item["report_id"] != "OAA-" + digest[7:39].upper():
        raise ApiObjectAuthorizationError("report address is invalid")


def analyze_api_object_authorization(
    *,
    source_content: bytes,
    source_id: str,
) -> ApiObjectAuthorizationReport:
    """Compare supplied outcomes to exact declared object-level policy facts."""
    identity = _id(source_id, "source ID")
    source = _decode(source_content, maximum=MAX_SOURCE_BYTES)
    facts_complete, policy_complete, subjects, objects, rules, outcomes = _model(source)
    projections = _project(facts_complete, policy_complete, subjects, objects, rules, outcomes)
    counts = {
        assessment: sum(p["assessment"] == assessment for p in projections)
        for assessment in sorted(_ASSESSMENTS)
    }
    document = {
        "schema_version": SCHEMA_VERSION,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "wave_id": WAVE_ID,
        "domain": DOMAIN,
        "source": {
            "source_id": identity,
            "sha256": _digest(source_content),
            "byte_count": len(source_content),
        },
        "facts_complete": facts_complete,
        "policy_complete": policy_complete,
        "projections": projections,
        "summary": {"observation_count": len(projections), **counts},
        **_FLAGS,
        "effects": _EFFECTS,
        "limitations": _LIMITATIONS,
    }
    digest = _digest(_canonical({"domain": DOMAIN, "analysis": document}).encode("ascii"))
    document["report_id"] = "OAA-" + digest[7:39].upper()
    document["report_sha256"] = digest
    _validate_tree(document, maximum=MAX_REPORT_BYTES)
    _validate_report(document)
    return ApiObjectAuthorizationReport(_canonical(document))


def analyze_supplied_api_object_authorization(
    model: dict[str, Any],
) -> ApiObjectAuthorizationReport:
    """Canonicalize an exact native source-backed component model."""
    _validate_tree(model, maximum=MAX_SOURCE_BYTES)
    item = _exact(model, {"source_id", "source"}, "component model")
    source_id = _id(item["source_id"], "source ID")
    _model(item["source"])
    return analyze_api_object_authorization(
        source_content=_canonical(item["source"]).encode("ascii"),
        source_id=source_id,
    )


def verify_api_object_authorization(
    report: ApiObjectAuthorizationReport,
    *,
    source_content: bytes,
    source_id: str,
) -> ApiObjectAuthorizationReport:
    """Rebuild a detached report from the exact supplied source bytes."""
    if type(report) is not ApiObjectAuthorizationReport:
        raise ApiObjectAuthorizationError("report must be the exact report family")
    loaded = ApiObjectAuthorizationReport.from_json(report.to_json())
    expected = analyze_api_object_authorization(source_content=source_content, source_id=source_id)
    if loaded.to_json() != expected.to_json():
        raise ApiObjectAuthorizationError("report does not replay from supplied source")
    return expected


def component_fixture() -> dict[str, Any]:
    """Return fresh inert subjects, object, policy and supplied access outcomes."""
    return {
        "schema_version": SCHEMA_VERSION,
        "facts_complete": True,
        "policy_complete": True,
        "subjects": [
            {"subject_id": "alice", "tenant_id": "tenant-a"},
            {"subject_id": "bob", "tenant_id": "tenant-b"},
        ],
        "objects": [
            {
                "object_id": "invoice-1",
                "owner_subject_id": "alice",
                "tenant_id": "tenant-a",
            }
        ],
        "policy_rules": [
            {
                "rule_id": "owner-read",
                "action": "read",
                "owner_relation": "owner",
                "tenant_relation": "same_tenant",
                "decision": "allow",
            },
            {
                "rule_id": "cross-tenant-read",
                "action": "read",
                "owner_relation": "non_owner",
                "tenant_relation": "different_tenant",
                "decision": "deny",
            },
        ],
        "access_outcomes": [
            {
                "observation_id": "obs-owner",
                "subject_id": "alice",
                "object_id": "invoice-1",
                "action": "read",
                "outcome": "allowed",
            },
            {
                "observation_id": "obs-outsider",
                "subject_id": "bob",
                "object_id": "invoice-1",
                "action": "read",
                "outcome": "allowed",
            },
        ],
    }


__all__ = [
    "ApiObjectAuthorizationError",
    "ApiObjectAuthorizationReport",
    "analyze_api_object_authorization",
    "analyze_supplied_api_object_authorization",
    "verify_api_object_authorization",
    "component_fixture",
]
