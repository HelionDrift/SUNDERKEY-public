"""Bounded offline planning for authorized AI control-validation cases."""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from .json_contract_integrity import JsonContractIntegrityError, canonical_json_bytes

DOMAIN = "sunderkey.ai-validation-plan.v1"
REF_RE = re.compile(
    r"(tenantref|targetref|ownerref|reviewerref|caseref|toolref):"
    r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}\Z"
)
SHA_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
MAX_CASES = 32
MAX_TOOLS = 32
MAX_REQUESTS = 32
MAX_TOKENS = 200_000
THREATS = {
    "prompt_injection": ("ignore_untrusted_instruction", "follow_untrusted_instruction"),
    "data_leakage": ("withhold_restricted_content", "disclose_restricted_content"),
    "jailbreak": ("enforce_safety_policy", "bypass_safety_policy"),
    "tool_boundary": ("require_tool_authority", "invoke_unapproved_tool"),
    "agent_delegation": ("preserve_delegated_scope", "expand_delegated_scope"),
    "mcp_trust": ("reject_untrusted_tool_metadata", "trust_unverified_tool_metadata"),
}
STOP_RULES = ["budget_exhausted", "critical_signal", "scope_violation"]
EFFECTS = {
    "authority": "none", "model_calls": "none", "network": "none",
    "prompt_access": "none", "qualification": "none", "target_interaction": "none",
    "tool_execution": "none",
}


class AiValidationPlanError(ValueError):
    """AI validation metadata or replayed plan failed closed."""


def _canonical(value: Any) -> bytes:
    try:
        return canonical_json_bytes(value, max_bytes=1_000_000)
    except JsonContractIntegrityError as exc:
        raise AiValidationPlanError("value must be bounded exact JSON") from exc


def _sha(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys or any(
        type(key) is not str for key in value
    ):
        raise AiValidationPlanError(f"{label} fields are invalid")
    return value


def _ref(value: Any, kind: str, label: str) -> str:
    if type(value) is not str or REF_RE.fullmatch(value) is None or not value.startswith(
        kind + ":",
    ):
        raise AiValidationPlanError(f"{label} must be an opaque {kind} reference")
    return value


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or SHA_RE.fullmatch(value) is None:
        raise AiValidationPlanError(f"{label} is not a SHA-256 reference")
    return value


def _instant(value: Any, label: str) -> datetime:
    if type(value) is not str or UTC_RE.fullmatch(value) is None:
        raise AiValidationPlanError(f"{label} must be whole-second UTC")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise AiValidationPlanError(f"{label} is invalid") from exc


def _sorted_refs(value: Any, kind: str, maximum: int, label: str) -> list[str]:
    if type(value) is not list or len(value) > maximum:
        raise AiValidationPlanError(f"{label} exceeds bound")
    for item in value:
        _ref(item, kind, label)
    if value != sorted(set(value)):
        raise AiValidationPlanError(f"{label} must be sorted and unique")
    return value


def _positive(value: Any, maximum: int, label: str) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise AiValidationPlanError(f"{label} exceeds hard limit")
    return value


def _profile(value: Any, as_of: datetime) -> dict[str, Any]:
    profile = _exact(value, {
        "schema_version", "tenant_ref", "scope_sha256", "target_ref",
        "target_class", "environment", "owner_ref", "source_profile_sha256",
        "authorization_sha256", "system_revision_sha256", "redaction_policy_sha256",
        "issued_at", "expires_at", "allowed_tool_refs", "maximum_requests",
        "maximum_tokens", "stop_rules", "retention_days",
    }, "profile")
    if type(profile["schema_version"]) is not int or profile["schema_version"] != 1:
        raise AiValidationPlanError("profile version is invalid")
    for field, kind in (
        ("tenant_ref", "tenantref"), ("target_ref", "targetref"),
        ("owner_ref", "ownerref"),
    ):
        _ref(profile[field], kind, field)
    for field in (
        "scope_sha256", "source_profile_sha256", "authorization_sha256",
        "system_revision_sha256", "redaction_policy_sha256",
    ):
        _digest(profile[field], field)
    if profile["target_class"] not in ("model", "agent", "mcp_server") or (
        profile["environment"] not in ("synthetic_fixture", "declared_nonproduction")
    ):
        raise AiValidationPlanError("target class or environment is invalid")
    issued = _instant(profile["issued_at"], "issued_at")
    expires = _instant(profile["expires_at"], "expires_at")
    if not issued <= as_of < expires <= issued + timedelta(days=7):
        raise AiValidationPlanError("profile is not current or exceeds seven days")
    tools = _sorted_refs(profile["allowed_tool_refs"], "toolref", MAX_TOOLS, "tools")
    if profile["target_class"] == "model" and tools:
        raise AiValidationPlanError("model-only target cannot authorize tools")
    _positive(profile["maximum_requests"], MAX_REQUESTS, "maximum_requests")
    _positive(profile["maximum_tokens"], MAX_TOKENS, "maximum_tokens")
    if profile["stop_rules"] != STOP_RULES:
        raise AiValidationPlanError("mandatory stop rules are missing")
    if type(profile["retention_days"]) is not int or not 0 <= profile[
        "retention_days"
    ] <= 30:
        raise AiValidationPlanError("retention_days is invalid")
    return profile


def _cases(
    value: Any, profile: dict[str, Any], as_of: datetime,
) -> list[dict[str, Any]]:
    if type(value) is not list or not 1 <= len(value) <= MAX_CASES:
        raise AiValidationPlanError("case list exceeds bound or is empty")
    case_refs: list[str] = []
    total_requests = 0
    total_tokens = 0
    for index, item in enumerate(value):
        case = _exact(item, {
            "case_ref", "source_case_sha256", "threat_class", "prompt_fixture_sha256",
            "expected_behavior", "prohibited_behavior", "required_tool_refs",
            "maximum_requests", "maximum_tokens", "scoring_rubric_sha256",
            "reviewer_ref", "created_at",
        }, f"case {index}")
        case_refs.append(_ref(case["case_ref"], "caseref", "case_ref"))
        for field in (
            "source_case_sha256", "prompt_fixture_sha256", "scoring_rubric_sha256",
        ):
            _digest(case[field], field)
        threat = case["threat_class"]
        if type(threat) is not str or threat not in THREATS:
            raise AiValidationPlanError("threat class is invalid")
        if (case["expected_behavior"], case["prohibited_behavior"]) != THREATS[threat]:
            raise AiValidationPlanError("behavior pair does not match threat class")
        required = _sorted_refs(
            case["required_tool_refs"], "toolref", MAX_TOOLS, "required tools",
        )
        if not set(required).issubset(profile["allowed_tool_refs"]):
            raise AiValidationPlanError("case tools exceed target tool inventory")
        if threat in ("tool_boundary", "agent_delegation", "mcp_trust") and (
            not required or profile["target_class"] == "model"
        ):
            raise AiValidationPlanError("tool threat needs an inventoried tool")
        total_requests += _positive(
            case["maximum_requests"], MAX_REQUESTS, "case maximum_requests",
        )
        total_tokens += _positive(
            case["maximum_tokens"], MAX_TOKENS, "case maximum_tokens",
        )
        _ref(case["reviewer_ref"], "reviewerref", "reviewer_ref")
        created = _instant(case["created_at"], "case created_at")
        if created > as_of or created < _instant(profile["issued_at"], "issued_at"):
            raise AiValidationPlanError("case time is outside current profile")
    if case_refs != sorted(set(case_refs)):
        raise AiValidationPlanError("case references must be sorted and unique")
    if total_requests > profile["maximum_requests"] or total_tokens > profile[
        "maximum_tokens"
    ]:
        raise AiValidationPlanError("case budgets exceed profile ceiling")
    return value


def build_ai_validation_plan(
    profile: Any, cases: Any, *, as_of: str,
) -> dict[str, Any]:
    """Produce a non-executable review plan from opaque target and case metadata."""

    now = _instant(as_of, "as_of")
    _canonical(profile)
    _canonical(cases)
    checked_profile = _profile(profile, now)
    checked_cases = _cases(cases, checked_profile, now)
    body = {
        "schema_version": 1,
        "tenant_ref": checked_profile["tenant_ref"],
        "scope_sha256": checked_profile["scope_sha256"],
        "target_ref": checked_profile["target_ref"],
        "target_class": checked_profile["target_class"],
        "environment": checked_profile["environment"],
        "profile_sha256": _sha(checked_profile),
        "cases_sha256": _sha(checked_cases),
        "as_of": as_of,
        "case_count": len(checked_cases),
        "reserved_request_ceiling": sum(
            item["maximum_requests"] for item in checked_cases
        ),
        "reserved_token_ceiling": sum(item["maximum_tokens"] for item in checked_cases),
        "case_plan": [
            {
                "case_ref": item["case_ref"],
                "case_sha256": _sha(item),
                "threat_class": item["threat_class"],
                "reviewer_ref": item["reviewer_ref"],
            }
            for item in checked_cases
        ],
        "authorization_authenticated": False,
        "target_identity_verified": False,
        "judge_independence_verified": False,
        "prompt_custody_verified": False,
        "source_provenance": "caller_asserted_not_authenticated",
        "review_status": "metadata_ready_for_independent_review",
        "critical_verdict_rule": "independent_human_and_correlated_evidence_required",
        "qualification_effect": "none",
        "effects": dict(EFFECTS),
    }
    digest = hashlib.sha256(DOMAIN.encode() + b"\0" + _canonical(body)).hexdigest()
    return {
        **body,
        "plan_id": "AVP-" + digest[:32].upper(),
        "plan_sha256": "sha256:" + digest,
    }


def verify_ai_validation_plan(
    profile: Any, cases: Any, *, as_of: str, result: Any,
) -> dict[str, str]:
    """Reproduce the plan without granting target or provider access."""

    expected = build_ai_validation_plan(profile, cases, as_of=as_of)
    if _canonical(result) != _canonical(expected):
        raise AiValidationPlanError("AI validation plan does not reproduce")
    return {
        "status": "valid", "plan_id": expected["plan_id"],
        "plan_sha256": expected["plan_sha256"], "qualification_effect": "none",
    }
