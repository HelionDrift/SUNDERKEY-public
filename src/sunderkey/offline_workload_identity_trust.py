"""Offline exact-match projection of supplied workload identity trust declarations."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

PROFILE_ID = "AOE-GC-D14-S10"
CAPABILITY_ID = "cloud.workload-identity-metadata"
VECTOR_ID = "AV-GC-D14-S10-01"
WAVE_ID = "IW2-013"
DOMAIN = "sunderkey.offline-workload-identity-trust.v1"
SCHEMA_VERSION = "v1"
MAX_SOURCE_BYTES = 262_144
MAX_REPORT_BYTES = 524_288
MAX_NODES = 40_000
MAX_DEPTH = 16
MAX_TEXT_BYTES = 512
MAX_CLAIMS = 256
MAX_RULES = 256
MAX_BINDINGS = 512
MAX_MATCH_STEPS = 131_072
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
    "claim_authenticity_verified": False,
    "token_signature_verified": False,
    "trust_source_authenticated": False,
    "effective_privilege_proven": False,
    "finding_claimed": False,
    "positive_use_approved": False,
    "qualification_claimed": False,
}
_LIMITATIONS = [
    "Issuer, subject, audience, requested role and all trust declarations are caller supplied.",
    "Exact text comparison does not normalize identities or validate token syntax or signatures.",
    "Declared matches are trust-path projections, not effective role or cloud privilege proof.",
    "Unlisted rules and bindings are uncertain unless their lists are declared complete.",
    "Conflicting exact allow and deny rules remain unknown without provider semantics.",
    "No metadata endpoint, cloud API, credential, target or live authority is accessed.",
]
_ASSESSMENTS = {"declared_exact_match", "declared_denied", "unknown"}
_BASES = {
    "matching_allow_binding",
    "matching_deny_rule",
    "complete_no_trust_rule",
    "complete_no_binding",
    "incomplete_trust_rules",
    "incomplete_role_bindings",
    "conflicting_trust_rules",
}


class WorkloadIdentityTrustError(ValueError):
    """Closed input, unsupported declaration, cost or replay refusal."""


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields or any(type(k) is not str for k in value):
        raise WorkloadIdentityTrustError(f"{label} fields are invalid")
    return value


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise WorkloadIdentityTrustError(f"{label} must be bounded native ASCII text")
    return value


def _claim_text(value: Any, label: str) -> str:
    if (
        type(value) is not str
        or not value
        or len(value.encode("utf-8", errors="surrogatepass")) > (MAX_TEXT_BYTES)
        or any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value)
    ):
        raise WorkloadIdentityTrustError(f"{label} must be bounded printable native text")
    return value


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise WorkloadIdentityTrustError("duplicate JSON key")
        result[key] = value
    return result


def _json_integer(token: str) -> int:
    if len(token) > 20 or len(token.lstrip("-")) > 19:
        raise WorkloadIdentityTrustError("JSON integer exceeds signed64 bound")
    value = int(token)
    if not -(1 << 63) <= value < (1 << 63):
        raise WorkloadIdentityTrustError("JSON integer exceeds signed64 bound")
    return value


def _unsupported_number(_token: str) -> None:
    raise WorkloadIdentityTrustError("floating and nonfinite numbers are unsupported")


def _validate_tree(value: Any, *, maximum: int) -> None:
    stack = [(value, 1)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise WorkloadIdentityTrustError("JSON node or depth bound exceeded")
        kind = type(item)
        if kind is dict:
            if nodes + len(stack) + 2 * len(item) > MAX_NODES:
                raise WorkloadIdentityTrustError("JSON node bound exceeded")
            for key, child in item.items():
                if type(key) is not str:
                    raise WorkloadIdentityTrustError("JSON keys must be native text")
                stack.append((child, depth + 1))
                stack.append((key, depth + 1))
        elif kind is list:
            if nodes + len(stack) + len(item) > MAX_NODES:
                raise WorkloadIdentityTrustError("JSON node bound exceeded")
            stack.extend((child, depth + 1) for child in item)
        elif kind is str:
            if len(item.encode("utf-8", errors="surrogatepass")) > MAX_TEXT_BYTES or any(
                0xD800 <= ord(c) <= 0xDFFF for c in item
            ):
                raise WorkloadIdentityTrustError("JSON string is unsupported or too long")
        elif kind is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise WorkloadIdentityTrustError("JSON integer exceeds signed64 bound")
        elif kind not in (bool, type(None)):
            raise WorkloadIdentityTrustError("unsupported JSON value family")
    if len(_canonical(value).encode("ascii")) > maximum:
        raise WorkloadIdentityTrustError("canonical JSON byte bound exceeded")


def _decode(content: bytes, *, maximum: int) -> Any:
    if type(content) is not bytes or not content or len(content) > maximum:
        raise WorkloadIdentityTrustError("source must be bounded nonempty native bytes")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WorkloadIdentityTrustError("source must be UTF-8") from exc
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
                raise WorkloadIdentityTrustError("pre-decoder depth bound exceeded")
        elif char in "]}":
            nesting -= 1
            if nesting < 0:
                raise WorkloadIdentityTrustError("malformed JSON nesting")
    if nesting or quoted:
        raise WorkloadIdentityTrustError("malformed JSON nesting")
    try:
        result = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_json_integer,
            parse_float=_unsupported_number,
            parse_constant=_unsupported_number,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, WorkloadIdentityTrustError):
            raise
        raise WorkloadIdentityTrustError("malformed JSON source") from exc
    _validate_tree(result, maximum=maximum)
    return result


def _model(
    document: Any,
) -> tuple[
    bool,
    bool,
    list[dict[str, str]],
    list[dict[str, str]],
    list[dict[str, str]],
]:
    model = _exact(
        document,
        {
            "schema_version",
            "claims",
            "trust_rules_complete",
            "trust_rules",
            "role_bindings_complete",
            "role_bindings",
        },
        "model",
    )
    if type(model["schema_version"]) is not str or model["schema_version"] != SCHEMA_VERSION:
        raise WorkloadIdentityTrustError("unsupported model version")
    if type(model["trust_rules_complete"]) is not bool or (
        type(model["role_bindings_complete"]) is not bool
    ):
        raise WorkloadIdentityTrustError("completeness declarations must be native Booleans")
    claims = model["claims"]
    rules = model["trust_rules"]
    bindings = model["role_bindings"]
    for label, value, maximum in (
        ("claims", claims, MAX_CLAIMS),
        ("trust rules", rules, MAX_RULES),
        ("role bindings", bindings, MAX_BINDINGS),
    ):
        if type(value) is not list or len(value) > maximum:
            raise WorkloadIdentityTrustError(f"{label} must be a bounded native array")
    claim_ids = set()
    checked_claims = []
    for raw in claims:
        entry = _exact(
            raw, {"claim_id", "issuer", "subject", "audience", "requested_role_ref"}, "claim"
        )
        claim_id = _identifier(entry["claim_id"], "claim ID")
        if claim_id in claim_ids:
            raise WorkloadIdentityTrustError("duplicate claim ID")
        claim_ids.add(claim_id)
        checked_claims.append(
            {
                "claim_id": claim_id,
                "issuer": _claim_text(entry["issuer"], "issuer"),
                "subject": _claim_text(entry["subject"], "subject"),
                "audience": _claim_text(entry["audience"], "audience"),
                "requested_role_ref": _claim_text(entry["requested_role_ref"], "requested role"),
            }
        )
    rule_ids = set()
    checked_rules = []
    for raw in rules:
        entry = _exact(raw, {"rule_id", "issuer", "subject", "audience", "effect"}, "trust rule")
        rule_id = _identifier(entry["rule_id"], "rule ID")
        if rule_id in rule_ids:
            raise WorkloadIdentityTrustError("duplicate rule ID")
        rule_ids.add(rule_id)
        effect = entry["effect"]
        if type(effect) is not str or effect not in ("allow", "deny"):
            raise WorkloadIdentityTrustError("trust effect must be allow or deny")
        checked_rules.append(
            {
                "rule_id": rule_id,
                "issuer": _claim_text(entry["issuer"], "issuer"),
                "subject": _claim_text(entry["subject"], "subject"),
                "audience": _claim_text(entry["audience"], "audience"),
                "effect": effect,
            }
        )
    allow_ids = {rule["rule_id"] for rule in checked_rules if rule["effect"] == "allow"}
    binding_ids = set()
    binding_pairs = set()
    checked_bindings = []
    for raw in bindings:
        entry = _exact(raw, {"binding_id", "rule_id", "role_ref"}, "role binding")
        binding_id = _identifier(entry["binding_id"], "binding ID")
        rule_id = _identifier(entry["rule_id"], "binding rule ID")
        role = _claim_text(entry["role_ref"], "bound role")
        if binding_id in binding_ids or (rule_id, role) in binding_pairs:
            raise WorkloadIdentityTrustError("duplicate binding ID or semantic binding")
        if rule_id not in allow_ids:
            raise WorkloadIdentityTrustError("binding must refer to a declared allow rule")
        binding_ids.add(binding_id)
        binding_pairs.add((rule_id, role))
        checked_bindings.append({"binding_id": binding_id, "rule_id": rule_id, "role_ref": role})
    return (
        model["trust_rules_complete"],
        model["role_bindings_complete"],
        checked_claims,
        checked_rules,
        checked_bindings,
    )


def _project(
    trust_complete: bool,
    bindings_complete: bool,
    claims: list[dict[str, str]],
    rules: list[dict[str, str]],
    bindings: list[dict[str, str]],
) -> list[dict[str, Any]]:
    by_tuple: dict[tuple[str, str, str], list[dict[str, str]]] = {}
    for rule in rules:
        key = (rule["issuer"], rule["subject"], rule["audience"])
        by_tuple.setdefault(key, []).append(rule)
    by_rule: dict[tuple[str, str], list[str]] = {}
    for binding in bindings:
        by_rule.setdefault((binding["rule_id"], binding["role_ref"]), []).append(
            binding["binding_id"]
        )
    projections = []
    steps = 0
    for claim in sorted(claims, key=lambda item: item["claim_id"]):
        key = (claim["issuer"], claim["subject"], claim["audience"])
        matched = by_tuple.get(key, [])
        steps += 1 + len(matched)
        if steps > MAX_MATCH_STEPS:
            raise WorkloadIdentityTrustError("matching work bound exceeded")
        allow = sorted(rule["rule_id"] for rule in matched if rule["effect"] == "allow")
        deny = sorted(rule["rule_id"] for rule in matched if rule["effect"] == "deny")
        matched_bindings = sorted(
            binding_id
            for rule_id in allow
            for binding_id in by_rule.get((rule_id, claim["requested_role_ref"]), [])
        )
        if allow and deny:
            assessment, basis = "unknown", "conflicting_trust_rules"
        elif not trust_complete:
            assessment, basis = "unknown", "incomplete_trust_rules"
        elif deny:
            assessment, basis = "declared_denied", "matching_deny_rule"
        elif allow and matched_bindings:
            assessment, basis = "declared_exact_match", "matching_allow_binding"
        elif allow and bindings_complete:
            assessment, basis = "declared_denied", "complete_no_binding"
        elif allow:
            assessment, basis = "unknown", "incomplete_role_bindings"
        else:
            assessment, basis = "declared_denied", "complete_no_trust_rule"
        projections.append(
            {
                "claim_id": claim["claim_id"],
                "requested_role_ref": claim["requested_role_ref"],
                "assessment": assessment,
                "basis": basis,
                "matching_allow_rule_ids": allow,
                "matching_deny_rule_ids": deny,
                "matching_binding_ids": matched_bindings,
            }
        )
    return projections


@dataclass(frozen=True, slots=True)
class WorkloadIdentityTrustReport:
    """Locally validated report; separate original-source replay proves derivation."""

    _json: str

    def __post_init__(self) -> None:
        self._validated_document()

    def _validated_document(self) -> dict[str, Any]:
        content = getattr(self, "_json", None)
        if (
            type(self) is not WorkloadIdentityTrustReport
            or type(content) is not str
            or len(content) > MAX_REPORT_BYTES
        ):
            raise WorkloadIdentityTrustError("exact native report family and JSON text required")
        try:
            raw = content.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise WorkloadIdentityTrustError("report must be UTF-8 JSON text") from exc
        document = _decode(raw, maximum=MAX_REPORT_BYTES)
        _validate_report(document)
        if content != _canonical(document):
            raise WorkloadIdentityTrustError("canonical report JSON required")
        return document

    def to_json(self) -> str:
        self._validated_document()
        return self._json

    def to_dict(self) -> dict[str, Any]:
        return self._validated_document()

    @classmethod
    def from_json(cls, content: str) -> WorkloadIdentityTrustReport:
        if type(content) is not str:
            raise WorkloadIdentityTrustError("report must be native JSON text")
        try:
            raw = content.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise WorkloadIdentityTrustError("report must be UTF-8 JSON text") from exc
        document = _decode(raw, maximum=MAX_REPORT_BYTES)
        _validate_report(document)
        return cls(_canonical(document))


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
            "trust_rules_complete",
            "role_bindings_complete",
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
            raise WorkloadIdentityTrustError(f"report {key} is invalid")
    source = _exact(item["source"], {"source_id", "sha256", "byte_count"}, "source")
    _identifier(source["source_id"], "source ID")
    if type(source["sha256"]) is not str or _DIGEST.fullmatch(source["sha256"]) is None:
        raise WorkloadIdentityTrustError("source digest is invalid")
    if type(source["byte_count"]) is not int or not 1 <= source["byte_count"] <= (MAX_SOURCE_BYTES):
        raise WorkloadIdentityTrustError("source byte count is invalid")
    if type(item["trust_rules_complete"]) is not bool or (
        type(item["role_bindings_complete"]) is not bool
    ):
        raise WorkloadIdentityTrustError("report completeness is invalid")
    projections = item["projections"]
    if type(projections) is not list or len(projections) > MAX_CLAIMS:
        raise WorkloadIdentityTrustError("report projections are invalid")
    claim_ids = set()
    counts = {assessment: 0 for assessment in sorted(_ASSESSMENTS)}
    for raw in projections:
        projection = _exact(
            raw,
            {
                "claim_id",
                "requested_role_ref",
                "assessment",
                "basis",
                "matching_allow_rule_ids",
                "matching_deny_rule_ids",
                "matching_binding_ids",
            },
            "projection",
        )
        claim_id = _identifier(projection["claim_id"], "claim ID")
        if claim_id in claim_ids:
            raise WorkloadIdentityTrustError("duplicate projection claim ID")
        claim_ids.add(claim_id)
        _claim_text(projection["requested_role_ref"], "requested role")
        assessment = projection["assessment"]
        basis = projection["basis"]
        if (
            type(assessment) is not str
            or assessment not in _ASSESSMENTS
            or (type(basis) is not str or basis not in _BASES)
        ):
            raise WorkloadIdentityTrustError("projection assessment or basis is invalid")
        counts[assessment] += 1
        for field in ("matching_allow_rule_ids", "matching_deny_rule_ids", "matching_binding_ids"):
            values = projection[field]
            if type(values) is not list or len(values) > MAX_BINDINGS:
                raise WorkloadIdentityTrustError("projection references are invalid")
            names = [_identifier(value, "projection reference") for value in values]
            if names != sorted(set(names)):
                raise WorkloadIdentityTrustError("projection references must be sorted unique")
    summary = _exact(item["summary"], {"claim_count", *counts}, "summary")
    if any(type(value) is not int for value in summary.values()) or summary != {
        "claim_count": len(projections),
        **counts,
    }:
        raise WorkloadIdentityTrustError("report summary is invalid")
    body = {key: value for key, value in item.items() if key not in ("report_id", "report_sha256")}
    digest = _digest(_canonical({"domain": DOMAIN, "analysis": body}).encode("ascii"))
    if item["report_sha256"] != digest or item["report_id"] != "WIT-" + digest[7:39].upper():
        raise WorkloadIdentityTrustError("report address is invalid")


def analyze_workload_identity_trust(
    *,
    source_content: bytes,
    source_id: str,
) -> WorkloadIdentityTrustReport:
    """Project supplied claim and requested-role pairs through exact declared rules."""
    identity = _identifier(source_id, "source ID")
    model = _decode(source_content, maximum=MAX_SOURCE_BYTES)
    trust_complete, bindings_complete, claims, rules, bindings = _model(model)
    projections = _project(trust_complete, bindings_complete, claims, rules, bindings)
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
        "trust_rules_complete": trust_complete,
        "role_bindings_complete": bindings_complete,
        "projections": projections,
        "summary": {"claim_count": len(projections), **counts},
        **_FLAGS,
        "effects": _EFFECTS,
        "limitations": _LIMITATIONS,
    }
    digest = _digest(_canonical({"domain": DOMAIN, "analysis": document}).encode("ascii"))
    document["report_id"] = "WIT-" + digest[7:39].upper()
    document["report_sha256"] = digest
    _validate_tree(document, maximum=MAX_REPORT_BYTES)
    _validate_report(document)
    return WorkloadIdentityTrustReport(_canonical(document))


def analyze_supplied_workload_identity_trust(model: dict[str, Any]) -> WorkloadIdentityTrustReport:
    """Canonicalize an exact native source-backed component model."""
    _validate_tree(model, maximum=MAX_SOURCE_BYTES)
    item = _exact(model, {"source_id", "source"}, "component model")
    source_id = _identifier(item["source_id"], "source ID")
    _model(item["source"])
    return analyze_workload_identity_trust(
        source_content=_canonical(item["source"]).encode("ascii"),
        source_id=source_id,
    )


def verify_workload_identity_trust(
    report: WorkloadIdentityTrustReport,
    *,
    source_content: bytes,
    source_id: str,
) -> WorkloadIdentityTrustReport:
    """Rebuild a detached report from the exact supplied source bytes."""
    if type(report) is not WorkloadIdentityTrustReport:
        raise WorkloadIdentityTrustError("report must be the exact report family")
    loaded = WorkloadIdentityTrustReport.from_json(report.to_json())
    expected = analyze_workload_identity_trust(source_content=source_content, source_id=source_id)
    if loaded.to_json() != expected.to_json():
        raise WorkloadIdentityTrustError("report does not replay from supplied source")
    return expected


def component_fixture() -> dict[str, Any]:
    """Return one fresh, inert claim, trust and role-binding model."""
    return {
        "schema_version": SCHEMA_VERSION,
        "trust_rules_complete": True,
        "role_bindings_complete": True,
        "claims": [
            {
                "claim_id": "claim-1",
                "issuer": "https://issuer.example.invalid",
                "subject": "system:serviceaccount:demo:reader",
                "audience": "sts.example.invalid",
                "requested_role_ref": "role:readonly",
            }
        ],
        "trust_rules": [
            {
                "rule_id": "rule-1",
                "issuer": "https://issuer.example.invalid",
                "subject": "system:serviceaccount:demo:reader",
                "audience": "sts.example.invalid",
                "effect": "allow",
            }
        ],
        "role_bindings": [
            {
                "binding_id": "binding-1",
                "rule_id": "rule-1",
                "role_ref": "role:readonly",
            }
        ],
    }


__all__ = [
    "WorkloadIdentityTrustError",
    "WorkloadIdentityTrustReport",
    "analyze_workload_identity_trust",
    "analyze_supplied_workload_identity_trust",
    "verify_workload_identity_trust",
    "component_fixture",
]
