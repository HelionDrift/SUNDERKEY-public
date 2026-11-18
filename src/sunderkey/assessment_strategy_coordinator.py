"""Deterministic, effect-free assessment strategy coordination.

The coordinator composes four already-governed planning artifacts into an
ordered proposal. It does not schedule, route, authorize, execute, resolve
credentials, contact targets, or create qualification or readiness claims.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any, ClassVar

from sunderkey.assessment_guidance import AssessmentGuidanceCard, ObjectiveKind
from sunderkey.asset_risk_scoring import AssetRiskPortfolio, EvidenceState
from sunderkey.attack_coverage_matrix import AttackCoverageMatrix, CoverageStatus
from sunderkey.impact_demonstration_policy import ImpactDemonstrationPlan, PlanStatus

SCHEMA_VERSION = 1
MAX_WORK_ITEMS = 20_000
STRATEGY_DOMAIN = "sunderkey.assessment-strategy-plan.v1"

NO_EFFECTS = MappingProxyType(
    {
        "authorization": "none",
        "credential_access": "none",
        "deployment": "none",
        "execution": "none",
        "network": "none",
        "routing": "none",
        "scheduling": "none",
        "target_contact": "none",
    }
)
NO_CLAIMS = MappingProxyType(
    {
        "competitive_parity": "not_claimed",
        "live_validation": "not_claimed",
        "production_readiness": "not_claimed",
        "qualification": "not_claimed",
    }
)

_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CONTENT_ID_RE = re.compile(r"[A-Z]{3}-[0-9A-F]{32}\Z")
_CODE_RE = re.compile(r"[a-z][a-z0-9_.]{0,95}\Z")
_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,255}\Z")
_SECRET_RE = re.compile(
    r"(?:-----BEGIN [A-Z0-9 ]*(?:PRIVATE|SECRET) KEY-----|"
    r"\b(?:authorization|cookie|password|passwd|secret|api[_-]?key|"
    r"access[_-]?token|refresh[_-]?token|client[_-]?secret)\b\s*[:=]|"
    r"\bbearer\s+[A-Za-z0-9._~+/=-]{8,}|\bAKIA[0-9A-Z]{16}\b|"
    r"\bgh[oprsu]_[A-Za-z0-9]{20,})",
    re.IGNORECASE,
)
_HOSTILE_RE = re.compile(
    r"(?:\bignore (?:all |the )?(?:previous|prior) instructions\b|"
    r"\b(?:bypass|disable|evade) (?:authorization|guardrails?|safety|scope)\b|"
    r"\b(?:run|execute|launch) (?:this |the )?(?:command|payload|shell)\b)",
    re.IGNORECASE,
)
_PAYLOAD_RE = re.compile(
    r"(?:<script\b|javascript:|powershell(?:\.exe)?\b|cmd(?:\.exe)?\s+/c\b|"
    r"\b(?:curl|wget|nc|ncat|netcat)\s+|\brm\s+-[a-z]*r[a-z]*f\b|"
    r"(?:;|&&|\|\||\|)\s*[A-Za-z0-9./\\])",
    re.IGNORECASE,
)


class AssessmentStrategyError(ValueError):
    """Raised when strategy inputs or serialized output fail closed."""


class WorkKind(StrEnum):
    ASSET_RISK = "asset_risk"
    EXPLICIT_GOAL = "explicit_goal"
    GUIDANCE_GAP = "guidance_gap"
    GUIDANCE_FRONTIER = "guidance_frontier"
    COVERAGE_GAP = "coverage_gap"
    IMPACT_EVIDENCE = "impact_evidence"


class InputKind(StrEnum):
    GUIDANCE = "assessment_guidance"
    COVERAGE = "attack_coverage_matrix"
    RISK = "asset_risk_portfolio"
    IMPACT = "impact_demonstration_plan"


def _validate_json(value: Any, label: str, *, depth: int = 0) -> None:
    if depth > 24:
        raise AssessmentStrategyError(f"{label} exceeds the nesting limit")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json(item, f"{label}[{index}]", depth=depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise AssessmentStrategyError(f"{label} contains a non-string key")
            _validate_json(item, f"{label}.{key}", depth=depth + 1)
        return
    raise AssessmentStrategyError(f"{label} contains an unsupported value")


def canonical_json(value: Any) -> str:
    """Return printable ASCII canonical JSON after content safety checks."""

    _validate_json(value, "value")
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise AssessmentStrategyError("value is not canonical JSON") from exc
    if _SECRET_RE.search(encoded):
        raise AssessmentStrategyError("secret-like material is forbidden")
    if _HOSTILE_RE.search(encoded):
        raise AssessmentStrategyError("hostile instruction material is forbidden")
    if _PAYLOAD_RE.search(encoded):
        raise AssessmentStrategyError("executable payload material is forbidden")
    return encoded


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _identity(prefix: str, kind: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": kind})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AssessmentStrategyError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _exact(raw: Any, expected: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != expected:
        raise AssessmentStrategyError(f"{label} fields do not match the contract")
    return raw


def _sequence(value: Any, label: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise AssessmentStrategyError(f"{label} must be a sequence")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise AssessmentStrategyError(f"{label} must be a SHA-256 digest")
    return value


def _content_id(value: Any, label: str, prefix: str) -> str:
    if (
        not isinstance(value, str)
        or _CONTENT_ID_RE.fullmatch(value) is None
        or not value.startswith(prefix + "-")
    ):
        raise AssessmentStrategyError(f"{label} must be a {prefix} content identity")
    return value


def _code(value: Any, label: str) -> str:
    if not isinstance(value, str) or _CODE_RE.fullmatch(value) is None:
        raise AssessmentStrategyError(f"{label} must be a canonical code")
    return value


def _reference(value: Any, label: str) -> str:
    if not isinstance(value, str) or _REF_RE.fullmatch(value) is None:
        raise AssessmentStrategyError(f"{label} must be an opaque reference")
    if _SECRET_RE.search(value) or _HOSTILE_RE.search(value) or _PAYLOAD_RE.search(value):
        raise AssessmentStrategyError(f"{label} contains prohibited material")
    return value


def _integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise AssessmentStrategyError(f"{label} must be between {minimum} and {maximum}")
    return value


def _codes(values: Sequence[Any], label: str, *, require: bool = False) -> tuple[str, ...]:
    result = tuple(sorted(_code(item, label) for item in _sequence(values, label)))
    if len(result) != len(set(result)):
        raise AssessmentStrategyError(f"{label} contains duplicate codes")
    if require and not result:
        raise AssessmentStrategyError(f"{label} must not be empty")
    return result


def _references(values: Sequence[Any], label: str) -> tuple[str, ...]:
    result = tuple(sorted(_reference(item, label) for item in _sequence(values, label)))
    if len(result) != len(set(result)):
        raise AssessmentStrategyError(f"{label} contains duplicate references")
    return result


@dataclass(frozen=True, slots=True)
class StrategyInputIdentities:
    guidance_card_id: str
    guidance_card_sha256: str
    coverage_matrix_id: str
    coverage_matrix_sha256: str
    risk_portfolio_id: str
    risk_portfolio_sha256: str
    impact_plan_id: str
    impact_plan_sha256: str

    def __post_init__(self) -> None:
        for name, prefix in (
            ("guidance_card_id", "AGC"),
            ("coverage_matrix_id", "ACM"),
            ("risk_portfolio_id", "ARP"),
            ("impact_plan_id", "IDP"),
        ):
            _content_id(getattr(self, name), name, prefix)
        for name in (
            "guidance_card_sha256",
            "coverage_matrix_sha256",
            "risk_portfolio_sha256",
            "impact_plan_sha256",
        ):
            _digest(getattr(self, name), name)

    def to_dict(self) -> dict[str, Any]:
        return {
            "coverage_matrix_id": self.coverage_matrix_id,
            "coverage_matrix_sha256": self.coverage_matrix_sha256,
            "guidance_card_id": self.guidance_card_id,
            "guidance_card_sha256": self.guidance_card_sha256,
            "impact_plan_id": self.impact_plan_id,
            "impact_plan_sha256": self.impact_plan_sha256,
            "risk_portfolio_id": self.risk_portfolio_id,
            "risk_portfolio_sha256": self.risk_portfolio_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> StrategyInputIdentities:
        return cls(**_exact(raw, set(cls.__dataclass_fields__), "strategy input identities"))


@dataclass(frozen=True, slots=True)
class InputLineage:
    input_kind: InputKind | str
    content_id: str
    content_sha256: str

    def __post_init__(self) -> None:
        try:
            kind = InputKind(self.input_kind)
        except (TypeError, ValueError) as exc:
            raise AssessmentStrategyError("input_kind is invalid") from exc
        object.__setattr__(self, "input_kind", kind)
        prefix = {
            InputKind.GUIDANCE: "AGC",
            InputKind.COVERAGE: "ACM",
            InputKind.RISK: "ARP",
            InputKind.IMPACT: "IDP",
        }[kind]
        _content_id(self.content_id, "content_id", prefix)
        _digest(self.content_sha256, "content_sha256")

    def to_dict(self) -> dict[str, Any]:
        return {
            "content_id": self.content_id,
            "content_sha256": self.content_sha256,
            "input_kind": self.input_kind.value,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> InputLineage:
        return cls(**_exact(raw, {"content_id", "content_sha256", "input_kind"}, "lineage"))


@dataclass(frozen=True, slots=True)
class StrategyWorkItem:
    order: int
    work_kind: WorkKind | str
    subject_ref: str
    source_content_ids: tuple[str, ...]
    score_components: Mapping[str, int]
    priority_score: int
    reason_codes: tuple[str, ...]
    blocked_reasons: tuple[str, ...]
    prerequisite_refs: tuple[str, ...]
    specialist_reference_ids: tuple[str, ...]
    risk_ceiling_points: int
    impact_ceiling: str
    independent_review_required: bool
    stop_conditions: tuple[str, ...]
    status: str = "proposal_only"
    work_item_id: str = field(init=False)
    work_item_sha256: str = field(init=False)

    KIND: ClassVar[str] = "sunderkey.assessment-strategy-work-item.v1"

    def __post_init__(self) -> None:
        _integer(self.order, "order", 1, MAX_WORK_ITEMS)
        try:
            kind = WorkKind(self.work_kind)
        except (TypeError, ValueError) as exc:
            raise AssessmentStrategyError("work_kind is invalid") from exc
        object.__setattr__(self, "work_kind", kind)
        _reference(self.subject_ref, "subject_ref")
        sources = tuple(sorted(self.source_content_ids))
        if not sources or len(sources) != len(set(sources)):
            raise AssessmentStrategyError("source_content_ids must be nonempty and unique")
        for value in sources:
            if _CONTENT_ID_RE.fullmatch(value) is None:
                raise AssessmentStrategyError("source_content_ids contain an invalid identity")
        object.__setattr__(self, "source_content_ids", sources)
        if not isinstance(self.score_components, Mapping) or not self.score_components:
            raise AssessmentStrategyError("score_components must be a nonempty object")
        components: dict[str, int] = {}
        for key, value in self.score_components.items():
            components[_code(key, "score component")] = _integer(
                value, "score component value", 0, 1_000_000
            )
        components = dict(sorted(components.items()))
        if self.priority_score != sum(components.values()):
            raise AssessmentStrategyError("priority_score must equal its transparent components")
        object.__setattr__(self, "score_components", MappingProxyType(components))
        object.__setattr__(
            self, "reason_codes", _codes(self.reason_codes, "reason_codes", require=True)
        )
        object.__setattr__(self, "blocked_reasons", _codes(self.blocked_reasons, "blocked_reasons"))
        object.__setattr__(
            self, "prerequisite_refs", _references(self.prerequisite_refs, "prerequisite_refs")
        )
        specialist_ids = tuple(sorted(self.specialist_reference_ids))
        if len(specialist_ids) != len(set(specialist_ids)):
            raise AssessmentStrategyError("specialist_reference_ids contains duplicates")
        for value in specialist_ids:
            _content_id(value, "specialist_reference_id", "SCR")
        object.__setattr__(self, "specialist_reference_ids", specialist_ids)
        _integer(self.risk_ceiling_points, "risk_ceiling_points", 0, 1_000_000)
        if self.impact_ceiling not in {"low", "moderate", "high"}:
            raise AssessmentStrategyError("impact_ceiling is invalid")
        if not isinstance(self.independent_review_required, bool):
            raise AssessmentStrategyError("independent_review_required must be boolean")
        object.__setattr__(
            self,
            "stop_conditions",
            _codes(self.stop_conditions, "stop_conditions", require=True),
        )
        if self.status != "proposal_only":
            raise AssessmentStrategyError("work items must remain proposal_only")
        identity, digest = _identity("SWI", self.KIND, self.body())
        object.__setattr__(self, "work_item_id", identity)
        object.__setattr__(self, "work_item_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "blocked_reasons": list(self.blocked_reasons),
            "impact_ceiling": self.impact_ceiling,
            "independent_review_required": self.independent_review_required,
            "order": self.order,
            "prerequisite_refs": list(self.prerequisite_refs),
            "priority_score": self.priority_score,
            "reason_codes": list(self.reason_codes),
            "risk_ceiling_points": self.risk_ceiling_points,
            "score_components": dict(self.score_components),
            "source_content_ids": list(self.source_content_ids),
            "specialist_reference_ids": list(self.specialist_reference_ids),
            "status": self.status,
            "stop_conditions": list(self.stop_conditions),
            "subject_ref": self.subject_ref,
            "work_kind": self.work_kind.value,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "work_item_id": self.work_item_id,
            "work_item_sha256": self.work_item_sha256,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> StrategyWorkItem:
        expected = {
            "blocked_reasons",
            "impact_ceiling",
            "independent_review_required",
            "order",
            "prerequisite_refs",
            "priority_score",
            "reason_codes",
            "risk_ceiling_points",
            "score_components",
            "source_content_ids",
            "specialist_reference_ids",
            "status",
            "stop_conditions",
            "subject_ref",
            "work_item_id",
            "work_item_sha256",
            "work_kind",
        }
        item = dict(_exact(raw, expected, "strategy work item"))
        identity = _content_id(item.pop("work_item_id"), "work_item_id", "SWI")
        digest = _digest(item.pop("work_item_sha256"), "work_item_sha256")
        for name in (
            "blocked_reasons",
            "prerequisite_refs",
            "reason_codes",
            "source_content_ids",
            "specialist_reference_ids",
            "stop_conditions",
        ):
            item[name] = tuple(_sequence(item[name], name))
        result = cls(**item)
        if result.work_item_id != identity or result.work_item_sha256 != digest:
            raise AssessmentStrategyError("work item content address is invalid")
        return result


@dataclass(frozen=True, slots=True)
class AssessmentStrategyPlan:
    tenant_ref: str
    context_ref: str
    scope_ref: str
    scope_sha256: str
    input_identities: StrategyInputIdentities
    input_lineage: tuple[InputLineage, ...]
    guidance_card: AssessmentGuidanceCard
    coverage_matrix: AttackCoverageMatrix
    risk_portfolio: AssetRiskPortfolio
    impact_plan: ImpactDemonstrationPlan
    work_items: tuple[StrategyWorkItem, ...]
    blocked_reasons: tuple[str, ...]
    independent_review_required: bool
    stop_conditions: tuple[str, ...]
    plan_id: str = field(init=False)
    plan_sha256: str = field(init=False)
    document_json: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        _reference(self.tenant_ref, "tenant_ref")
        _reference(self.context_ref, "context_ref")
        _reference(self.scope_ref, "scope_ref")
        _digest(self.scope_sha256, "scope_sha256")
        if not isinstance(self.input_identities, StrategyInputIdentities):
            raise AssessmentStrategyError("input_identities are invalid")
        _verify_inputs(
            self.input_identities,
            self.guidance_card,
            self.coverage_matrix,
            self.risk_portfolio,
            self.impact_plan,
        )
        _verify_boundaries(
            self.guidance_card,
            self.coverage_matrix,
            self.risk_portfolio,
            self.impact_plan,
        )
        if (
            self.tenant_ref != self.guidance_card.request.binding.tenant_ref
            or self.context_ref != self.guidance_card.request.binding.context_ref
            or self.scope_ref != self.guidance_card.request.binding.scope_ref
            or self.scope_sha256 != self.guidance_card.request.binding.scope_sha256
        ):
            raise AssessmentStrategyError("plan boundary does not match its inputs")
        lineage = tuple(self.input_lineage)
        expected_lineage = _lineage(self.input_identities)
        if lineage != expected_lineage:
            raise AssessmentStrategyError("input lineage is incomplete or inconsistent")
        object.__setattr__(self, "input_lineage", lineage)
        items = tuple(self.work_items)
        if not items or len(items) > MAX_WORK_ITEMS:
            raise AssessmentStrategyError("work item count is outside the supported range")
        if [item.order for item in items] != list(range(1, len(items) + 1)):
            raise AssessmentStrategyError("work item order is not contiguous")
        if len({item.work_item_id for item in items}) != len(items):
            raise AssessmentStrategyError("duplicate work item identities are forbidden")
        object.__setattr__(self, "work_items", items)
        object.__setattr__(self, "blocked_reasons", _codes(self.blocked_reasons, "blocked_reasons"))
        if not isinstance(self.independent_review_required, bool):
            raise AssessmentStrategyError("independent_review_required must be boolean")
        object.__setattr__(
            self,
            "stop_conditions",
            _codes(self.stop_conditions, "stop_conditions", require=True),
        )
        identity, digest = _identity("ASP", STRATEGY_DOMAIN, self.body())
        object.__setattr__(self, "plan_id", identity)
        object.__setattr__(self, "plan_sha256", digest)
        object.__setattr__(
            self,
            "document_json",
            canonical_json({**self.body(), "plan_id": identity, "plan_sha256": digest}),
        )

    def body(self) -> dict[str, Any]:
        return {
            "blocked_reasons": list(self.blocked_reasons),
            "claims": dict(NO_CLAIMS),
            "context_ref": self.context_ref,
            "effects": dict(NO_EFFECTS),
            "independent_review_required": self.independent_review_required,
            "input_identities": self.input_identities.to_dict(),
            "input_lineage": [item.to_dict() for item in self.input_lineage],
            "inputs": {
                "assessment_guidance": self.guidance_card.to_dict(),
                "asset_risk_portfolio": self.risk_portfolio.to_dict(),
                "attack_coverage_matrix": self.coverage_matrix.to_dict(),
                "impact_demonstration_plan": self.impact_plan.to_dict(),
            },
            "kind": STRATEGY_DOMAIN,
            "qualification_effect": "none",
            "schema_version": SCHEMA_VERSION,
            "scope_ref": self.scope_ref,
            "scope_sha256": self.scope_sha256,
            "status": "proposal_only",
            "stop_conditions": list(self.stop_conditions),
            "tenant_ref": self.tenant_ref,
            "work_items": [item.to_dict() for item in self.work_items],
        }

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @classmethod
    def from_dict(cls, raw: Any) -> AssessmentStrategyPlan:
        expected = {
            "blocked_reasons",
            "claims",
            "context_ref",
            "effects",
            "independent_review_required",
            "input_identities",
            "input_lineage",
            "inputs",
            "kind",
            "plan_id",
            "plan_sha256",
            "qualification_effect",
            "schema_version",
            "scope_ref",
            "scope_sha256",
            "status",
            "stop_conditions",
            "tenant_ref",
            "work_items",
        }
        item = dict(_exact(raw, expected, "assessment strategy plan"))
        if item.pop("schema_version") != SCHEMA_VERSION or item.pop("kind") != STRATEGY_DOMAIN:
            raise AssessmentStrategyError("plan version or kind is invalid")
        if item.pop("effects") != dict(NO_EFFECTS) or item.pop("claims") != dict(NO_CLAIMS):
            raise AssessmentStrategyError("plan boundary fields are invalid")
        if item.pop("qualification_effect") != "none" or item.pop("status") != "proposal_only":
            raise AssessmentStrategyError("plan status fields are invalid")
        identity = _content_id(item.pop("plan_id"), "plan_id", "ASP")
        digest = _digest(item.pop("plan_sha256"), "plan_sha256")
        inputs = dict(
            _exact(
                item.pop("inputs"),
                {
                    "assessment_guidance",
                    "asset_risk_portfolio",
                    "attack_coverage_matrix",
                    "impact_demonstration_plan",
                },
                "strategy inputs",
            )
        )
        result = cls(
            tenant_ref=item["tenant_ref"],
            context_ref=item["context_ref"],
            scope_ref=item["scope_ref"],
            scope_sha256=item["scope_sha256"],
            input_identities=StrategyInputIdentities.from_dict(item["input_identities"]),
            input_lineage=tuple(InputLineage.from_dict(value) for value in item["input_lineage"]),
            guidance_card=AssessmentGuidanceCard.from_dict(inputs["assessment_guidance"]),
            coverage_matrix=AttackCoverageMatrix.from_dict(inputs["attack_coverage_matrix"]),
            risk_portfolio=AssetRiskPortfolio.from_dict(inputs["asset_risk_portfolio"]),
            impact_plan=ImpactDemonstrationPlan.from_dict(inputs["impact_demonstration_plan"]),
            work_items=tuple(StrategyWorkItem.from_dict(value) for value in item["work_items"]),
            blocked_reasons=tuple(item["blocked_reasons"]),
            independent_review_required=item["independent_review_required"],
            stop_conditions=tuple(item["stop_conditions"]),
        )
        if result.plan_id != identity or result.plan_sha256 != digest:
            raise AssessmentStrategyError("plan content address is invalid")
        return result

    @classmethod
    def from_json(cls, value: str) -> AssessmentStrategyPlan:
        if not isinstance(value, str):
            raise AssessmentStrategyError("plan JSON must be text")
        try:
            raw = json.loads(value, object_pairs_hook=_strict_object)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise AssessmentStrategyError("plan JSON is invalid") from exc
        result = cls.from_dict(raw)
        if value != result.document_json:
            raise AssessmentStrategyError("plan JSON is not canonical")
        return result


def _lineage(identities: StrategyInputIdentities) -> tuple[InputLineage, ...]:
    return (
        InputLineage(
            InputKind.GUIDANCE, identities.guidance_card_id, identities.guidance_card_sha256
        ),
        InputLineage(
            InputKind.COVERAGE, identities.coverage_matrix_id, identities.coverage_matrix_sha256
        ),
        InputLineage(
            InputKind.RISK, identities.risk_portfolio_id, identities.risk_portfolio_sha256
        ),
        InputLineage(InputKind.IMPACT, identities.impact_plan_id, identities.impact_plan_sha256),
    )


def _verify_inputs(
    identities: StrategyInputIdentities,
    guidance: AssessmentGuidanceCard,
    coverage: AttackCoverageMatrix,
    risk: AssetRiskPortfolio,
    impact: ImpactDemonstrationPlan,
) -> None:
    rebuilt_guidance = AssessmentGuidanceCard.from_dict(guidance.to_dict())
    rebuilt_coverage = AttackCoverageMatrix.from_dict(coverage.to_dict())
    rebuilt_risk = AssetRiskPortfolio.from_dict(risk.to_dict())
    rebuilt_impact = ImpactDemonstrationPlan.from_dict(impact.to_dict())
    observed = StrategyInputIdentities(
        rebuilt_guidance.card_id,
        rebuilt_guidance.card_sha256,
        rebuilt_coverage.matrix_id,
        rebuilt_coverage.matrix_sha256,
        rebuilt_risk.portfolio_id,
        rebuilt_risk.portfolio_sha256,
        rebuilt_impact.plan_id,
        rebuilt_impact.plan_sha256,
    )
    if observed != identities:
        raise AssessmentStrategyError("input identity substitution or tampering detected")


def _verify_boundaries(
    guidance: AssessmentGuidanceCard,
    coverage: AttackCoverageMatrix,
    risk: AssetRiskPortfolio,
    impact: ImpactDemonstrationPlan,
) -> None:
    binding = guidance.request.binding
    expected = (binding.tenant_ref, binding.context_ref, binding.scope_sha256)
    if (coverage.tenant_ref, coverage.context_ref, coverage.scope_sha256) != expected:
        raise AssessmentStrategyError("coverage matrix crosses the strategy boundary")
    if (
        impact.request.binding.tenant_ref,
        impact.request.binding.context_ref,
        impact.request.binding.scope_sha256,
    ) != expected or impact.request.binding.scope_ref != binding.scope_ref:
        raise AssessmentStrategyError("impact plan crosses the strategy boundary")
    for item in (*risk.asset_bindings, *risk.scorecards):
        if (item.tenant_ref, item.context_ref, item.scope_sha256) != expected:
            raise AssessmentStrategyError("risk portfolio crosses the strategy boundary")


def strategy_input_identities(
    guidance: AssessmentGuidanceCard,
    coverage: AttackCoverageMatrix,
    risk: AssetRiskPortfolio,
    impact: ImpactDemonstrationPlan,
) -> StrategyInputIdentities:
    """Capture exact content identities for an explicit operator handoff."""

    return StrategyInputIdentities(
        guidance.card_id,
        guidance.card_sha256,
        coverage.matrix_id,
        coverage.matrix_sha256,
        risk.portfolio_id,
        risk.portfolio_sha256,
        impact.plan_id,
        impact.plan_sha256,
    )


_BASE_STOPS = (
    "authorization_required",
    "input_identity_change",
    "scope_binding_change",
    "target_contact_requested",
)


def build_assessment_strategy_plan(
    *,
    identities: StrategyInputIdentities,
    guidance: AssessmentGuidanceCard,
    coverage: AttackCoverageMatrix,
    risk: AssetRiskPortfolio,
    impact: ImpactDemonstrationPlan,
) -> AssessmentStrategyPlan:
    """Build one deterministic proposal without creating operational effects."""

    _verify_inputs(identities, guidance, coverage, risk, impact)
    _verify_boundaries(guidance, coverage, risk, impact)
    binding = guidance.request.binding
    constraints = guidance.request.constraints
    candidates: list[dict[str, Any]] = []

    for scorecard in risk.scorecards:
        missing = sum(code.startswith("evidence.missing_") for code in scorecard.reason_codes)
        components = {
            "asset_risk": scorecard.composite_score_bps,
            "missing_evidence": missing * 2_500,
        }
        blocked = tuple(
            sorted(
                code.replace(".", "_")
                for code in scorecard.reason_codes
                if code.startswith("evidence.")
            )
        )
        candidates.append(
            {
                "kind": WorkKind.ASSET_RISK,
                "subject": scorecard.asset_ref,
                "sources": (identities.risk_portfolio_id,),
                "components": components,
                "reasons": (
                    "asset_risk_ranked",
                    *tuple(code.replace(".", "_") for code in scorecard.reason_codes),
                ),
                "blocked": blocked
                if scorecard.evidence_state is not EvidenceState.COMPLETE
                else (),
                "prerequisites": (f"evidence:{scorecard.asset_ref.split(':', 1)[1]}",)
                if blocked
                else (),
                "specialists": (),
                "review": True,
            }
        )

    objective_weights = {
        ObjectiveKind.GOAL: 8_000,
        ObjectiveKind.GAP: 10_000,
        ObjectiveKind.FRONTIER: 9_000,
        ObjectiveKind.ENDPOINT: 7_000,
        ObjectiveKind.ROLE: 6_000,
        ObjectiveKind.ATTACK_TYPE: 6_500,
    }
    for objective in guidance.coverage_objectives:
        if objective.objective_kind not in {
            ObjectiveKind.GOAL,
            ObjectiveKind.GAP,
            ObjectiveKind.FRONTIER,
        }:
            continue
        kind = {
            ObjectiveKind.GOAL: WorkKind.EXPLICIT_GOAL,
            ObjectiveKind.GAP: WorkKind.GUIDANCE_GAP,
            ObjectiveKind.FRONTIER: WorkKind.GUIDANCE_FRONTIER,
        }[objective.objective_kind]
        candidates.append(
            {
                "kind": kind,
                "subject": objective.subject_ref,
                "sources": (identities.guidance_card_id,),
                "components": {
                    "explicit_guidance": objective_weights[objective.objective_kind],
                    "ordering_preference": max(0, 2_000 - objective.order),
                },
                "reasons": objective.reason_codes,
                "blocked": (),
                "prerequisites": (),
                "specialists": (),
                "review": guidance.independent_review_required,
            }
        )

    for row in coverage.rows:
        if row.status is CoverageStatus.REPOSITORY_COVERED:
            continue
        state_bonus = {
            CoverageStatus.PARTIAL: 1_500,
            CoverageStatus.GAP: 2_500,
            CoverageStatus.BLOCKED: 3_000,
        }[row.status]
        evidence_bonus = 2_000 if row.evidence_grade.value in {"none", "catalog_only"} else 0
        blockers = tuple(reason.value for reason in row.blocked_reasons)
        candidates.append(
            {
                "kind": WorkKind.COVERAGE_GAP,
                "subject": row.technique_reference.technique_ref,
                "sources": (identities.coverage_matrix_id,),
                "components": {
                    "coverage_gap": 6_500,
                    "evidence_deficit": evidence_bonus,
                    "status_weight": state_bonus,
                },
                "reasons": (f"coverage_{row.status.value}",),
                "blocked": blockers,
                "prerequisites": row.prerequisite_refs,
                "specialists": tuple(item.reference_id for item in row.specialist_references),
                "review": bool(blockers),
            }
        )

    impact_blockers = tuple(impact.denial_reasons)
    if impact.status is not PlanStatus.EVIDENCE_PLAN_ONLY:
        if impact.status is PlanStatus.OFF:
            impact_blockers = (*impact_blockers, "impact_mode_off")
        elif not impact_blockers:
            impact_blockers = ("impact_plan_denied",)
    candidates.append(
        {
            "kind": WorkKind.IMPACT_EVIDENCE,
            "subject": impact.request.binding.target_ref,
            "sources": (identities.impact_plan_id,),
            "components": {
                "evidence_intents": len(impact.steps) * 500,
                "impact_policy": 4_000,
            },
            "reasons": ("impact_evidence_plan",),
            "blocked": impact_blockers,
            "prerequisites": (impact.request.binding.policy_ref,),
            "specialists": (),
            "review": impact.independent_review_required or bool(impact_blockers),
        }
    )

    candidates.sort(
        key=lambda item: (
            -sum(item["components"].values()),
            item["kind"].value,
            item["subject"],
        )
    )
    work_items = tuple(
        StrategyWorkItem(
            order=index,
            work_kind=item["kind"],
            subject_ref=item["subject"],
            source_content_ids=item["sources"],
            score_components=item["components"],
            priority_score=sum(item["components"].values()),
            reason_codes=tuple(sorted(set(item["reasons"]))),
            blocked_reasons=tuple(sorted(set(item["blocked"]))),
            prerequisite_refs=tuple(item["prerequisites"]),
            specialist_reference_ids=tuple(item["specialists"]),
            risk_ceiling_points=constraints.risk_budget_points,
            impact_ceiling=constraints.impact_ceiling.value,
            independent_review_required=item["review"],
            stop_conditions=_BASE_STOPS,
        )
        for index, item in enumerate(candidates, 1)
    )
    blocked = tuple(sorted({reason for item in work_items for reason in item.blocked_reasons}))
    review_required = (
        guidance.independent_review_required
        or impact.independent_review_required
        or any(item.independent_review_required for item in work_items)
    )
    return AssessmentStrategyPlan(
        tenant_ref=binding.tenant_ref,
        context_ref=binding.context_ref,
        scope_ref=binding.scope_ref,
        scope_sha256=binding.scope_sha256,
        input_identities=identities,
        input_lineage=_lineage(identities),
        guidance_card=guidance,
        coverage_matrix=coverage,
        risk_portfolio=risk,
        impact_plan=impact,
        work_items=work_items,
        blocked_reasons=blocked,
        independent_review_required=review_required,
        stop_conditions=_BASE_STOPS,
    )


def parse_assessment_strategy_plan(raw: str | bytes | Mapping[str, Any]) -> AssessmentStrategyPlan:
    """Strictly parse and verify a canonical strategy document."""

    if isinstance(raw, bytes):
        try:
            raw = raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise AssessmentStrategyError("plan JSON must use ASCII") from exc
    if isinstance(raw, str):
        return AssessmentStrategyPlan.from_json(raw)
    return AssessmentStrategyPlan.from_dict(raw)


__all__ = [
    "NO_CLAIMS",
    "NO_EFFECTS",
    "AssessmentStrategyError",
    "AssessmentStrategyPlan",
    "InputKind",
    "InputLineage",
    "StrategyInputIdentities",
    "StrategyWorkItem",
    "WorkKind",
    "build_assessment_strategy_plan",
    "canonical_json",
    "canonical_sha256",
    "parse_assessment_strategy_plan",
    "strategy_input_identities",
]
