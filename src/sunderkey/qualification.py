"""Deterministic specialist qualification planning and coverage."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import QualificationError
from .registry import DomainCommand, ExpertProfile, ExpertRegistry, ManeuverGroup
from .routing import CapabilityCatalog, CapabilityProfileScope
from .types import MissionEnvironment, ProfileKind
from .validation import is_ascii_text

QUALIFICATION_GATE_ID_PATTERN = re.compile(
    r"qualification\.gate\.[a-z0-9]+(?:[.-][a-z0-9]+)*"
)
SCENARIO_FAMILY_ID_PATTERN = re.compile(
    r"qualification\.aoe-g[a-e]-d[0-9]{2}-s[0-9]{2}"
)
QUALIFICATION_REPORT_ID_PATTERN = re.compile(r"QCR-[0-9A-F]{32}")
QUALIFICATION_REPORT_DOMAIN = "sunderkey.qualification-coverage-report.v1"
QUALIFICATION_REPORT_SCHEMA_VERSION = 1
GATE_CATEGORIES = {
    "authority",
    "boundary",
    "collaboration",
    "evidence",
    "quality",
    "resilience",
    "safety",
    "technical",
}


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise QualificationError(
            "Could not serialize canonical qualification data"
        ) from exc


def _canonical_sha256(value: Any) -> str:
    payload = _canonical_json(value).encode("ascii")
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise QualificationError(f"{label} must be an object")
    return value


def _list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise QualificationError(f"{label} must be a list")
    return value


def _text(value: Any, label: str) -> str:
    if not is_ascii_text(value):
        raise QualificationError(f"{label} must be non-empty ASCII text")
    return value


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise QualificationError(f"{label} must be a boolean")
    return value


def _positive_integer(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise QualificationError(f"{label} must be a positive integer")
    return value


def _nonnegative_integer(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise QualificationError(
            f"{label} must be a non-negative integer"
        )
    return value


def _exact_fields(
    value: dict[str, Any],
    expected: set[str],
    label: str,
) -> None:
    unknown = set(value) - expected
    missing = expected - set(value)
    if unknown:
        names = ", ".join(sorted(unknown))
        raise QualificationError(
            f"{label} contains unsupported fields: {names}"
        )
    if missing:
        names = ", ".join(sorted(missing))
        raise QualificationError(
            f"{label} is missing required fields: {names}"
        )


def _string_tuple(
    value: Any,
    label: str,
    *,
    allow_empty: bool,
) -> tuple[str, ...]:
    items = _list(value, label)
    result = tuple(
        sorted(
            _text(item, f"{label}[{index}]")
            for index, item in enumerate(items)
        )
    )
    if not allow_empty and not result:
        raise QualificationError(f"{label} must not be empty")
    if len(result) != len(set(result)):
        raise QualificationError(f"{label} contains duplicate values")
    return result


def _load_json(path: str | Path, label: str) -> dict[str, Any]:
    resolved = Path(path).resolve()
    if not resolved.is_file():
        raise QualificationError(f"{label} file does not exist: {resolved}")
    try:
        raw = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise QualificationError(f"Could not read {label}: {resolved}") from exc
    return _mapping(raw, label)


@dataclass(frozen=True)
class QualificationGate:
    id: str
    name: str
    category: str
    evaluation_objective: str
    minimum_scenarios: int
    minimum_passing_scenarios: int
    maximum_critical_failures: int
    independent_review_required: bool

    @classmethod
    def from_dict(cls, raw: Any, index: int) -> QualificationGate:
        label = f"gates[{index}]"
        value = _mapping(raw, label)
        _exact_fields(
            value,
            {
                "id",
                "name",
                "category",
                "evaluation_objective",
                "minimum_scenarios",
                "minimum_passing_scenarios",
                "maximum_critical_failures",
                "independent_review_required",
            },
            label,
        )
        gate_id = _text(value.get("id"), f"{label}.id")
        if QUALIFICATION_GATE_ID_PATTERN.fullmatch(gate_id) is None:
            raise QualificationError(f"Invalid qualification gate ID: {gate_id}")
        category = _text(value.get("category"), f"{label}.category")
        if category not in GATE_CATEGORIES:
            options = ", ".join(sorted(GATE_CATEGORIES))
            raise QualificationError(
                f"{label}.category must be one of: {options}"
            )
        minimum_scenarios = _positive_integer(
            value.get("minimum_scenarios"),
            f"{label}.minimum_scenarios",
        )
        minimum_passing = _positive_integer(
            value.get("minimum_passing_scenarios"),
            f"{label}.minimum_passing_scenarios",
        )
        if minimum_passing > minimum_scenarios:
            raise QualificationError(
                f"{label}.minimum_passing_scenarios exceeds "
                "minimum_scenarios"
            )
        return cls(
            id=gate_id,
            name=_text(value.get("name"), f"{label}.name"),
            category=category,
            evaluation_objective=_text(
                value.get("evaluation_objective"),
                f"{label}.evaluation_objective",
            ),
            minimum_scenarios=minimum_scenarios,
            minimum_passing_scenarios=minimum_passing,
            maximum_critical_failures=_nonnegative_integer(
                value.get("maximum_critical_failures"),
                f"{label}.maximum_critical_failures",
            ),
            independent_review_required=_boolean(
                value.get("independent_review_required"),
                f"{label}.independent_review_required",
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "evaluation_objective": self.evaluation_objective,
            "minimum_scenarios": self.minimum_scenarios,
            "minimum_passing_scenarios": self.minimum_passing_scenarios,
            "maximum_critical_failures": self.maximum_critical_failures,
            "independent_review_required": self.independent_review_required,
        }


@dataclass(frozen=True)
class QualificationDecisionPolicy:
    minimum_distinct_evaluators: int
    require_independent_control_review: bool
    require_independent_assurance_review: bool
    allow_self_attestation: bool
    qualification_validity_days: int

    @classmethod
    def from_dict(cls, raw: Any) -> QualificationDecisionPolicy:
        value = _mapping(raw, "decision_policy")
        _exact_fields(
            value,
            {
                "minimum_distinct_evaluators",
                "require_independent_control_review",
                "require_independent_assurance_review",
                "allow_self_attestation",
                "qualification_validity_days",
            },
            "decision_policy",
        )
        return cls(
            minimum_distinct_evaluators=_positive_integer(
                value.get("minimum_distinct_evaluators"),
                "decision_policy.minimum_distinct_evaluators",
            ),
            require_independent_control_review=_boolean(
                value.get("require_independent_control_review"),
                "decision_policy.require_independent_control_review",
            ),
            require_independent_assurance_review=_boolean(
                value.get("require_independent_assurance_review"),
                "decision_policy.require_independent_assurance_review",
            ),
            allow_self_attestation=_boolean(
                value.get("allow_self_attestation"),
                "decision_policy.allow_self_attestation",
            ),
            qualification_validity_days=_positive_integer(
                value.get("qualification_validity_days"),
                "decision_policy.qualification_validity_days",
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "minimum_distinct_evaluators": self.minimum_distinct_evaluators,
            "require_independent_control_review": (
                self.require_independent_control_review
            ),
            "require_independent_assurance_review": (
                self.require_independent_assurance_review
            ),
            "allow_self_attestation": self.allow_self_attestation,
            "qualification_validity_days": self.qualification_validity_days,
        }


@dataclass(frozen=True)
class QualificationStandard:
    schema_version: int
    standard_id: str
    standard_version: str
    expert_catalog_id: str
    expert_catalog_version: str
    capability_catalog_id: str
    capability_catalog_version: str
    capability_catalog_sha256: str
    allowed_environments: tuple[MissionEnvironment, ...]
    decision_policy: QualificationDecisionPolicy
    gates: tuple[QualificationGate, ...]

    @property
    def gates_by_id(self) -> dict[str, QualificationGate]:
        return {gate.id: gate for gate in self.gates}

    @property
    def gate_ids(self) -> tuple[str, ...]:
        return tuple(gate.id for gate in self.gates)

    @property
    def minimum_scenarios_per_profile(self) -> int:
        return sum(gate.minimum_scenarios for gate in self.gates)

    @property
    def minimum_passing_scenarios_per_profile(self) -> int:
        return sum(gate.minimum_passing_scenarios for gate in self.gates)

    @property
    def canonical_sha256(self) -> str:
        return _canonical_sha256(self.to_dict())

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        registry: ExpertRegistry,
        catalog: CapabilityCatalog,
    ) -> QualificationStandard:
        value = _mapping(raw, "qualification standard")
        _exact_fields(
            value,
            {
                "schema_version",
                "standard_id",
                "standard_version",
                "expert_catalog_id",
                "expert_catalog_version",
                "capability_catalog_id",
                "capability_catalog_version",
                "capability_catalog_sha256",
                "allowed_environments",
                "decision_policy",
                "gates",
            },
            "qualification standard",
        )
        if value.get("schema_version") != 1:
            raise QualificationError(
                "Qualification standard schema_version must be 1"
            )
        environment_names = _string_tuple(
            value.get("allowed_environments"),
            "allowed_environments",
            allow_empty=False,
        )
        try:
            environments = tuple(
                sorted(
                    (MissionEnvironment(item) for item in environment_names),
                    key=lambda item: item.value,
                )
            )
        except ValueError as exc:
            options = ", ".join(item.value for item in MissionEnvironment)
            raise QualificationError(
                f"allowed_environments values must be one of: {options}"
            ) from exc
        gates = tuple(
            sorted(
                (
                    QualificationGate.from_dict(item, index)
                    for index, item in enumerate(
                        _list(value.get("gates"), "gates")
                    )
                ),
                key=lambda gate: gate.id,
            )
        )
        if not gates:
            raise QualificationError(
                "Qualification standard must define gates"
            )
        gate_ids = [gate.id for gate in gates]
        if len(gate_ids) != len(set(gate_ids)):
            raise QualificationError(
                "Qualification standard contains duplicate gate IDs"
            )
        standard = cls(
            schema_version=1,
            standard_id=_text(value.get("standard_id"), "standard_id"),
            standard_version=_text(
                value.get("standard_version"),
                "standard_version",
            ),
            expert_catalog_id=_text(
                value.get("expert_catalog_id"),
                "expert_catalog_id",
            ),
            expert_catalog_version=_text(
                value.get("expert_catalog_version"),
                "expert_catalog_version",
            ),
            capability_catalog_id=_text(
                value.get("capability_catalog_id"),
                "capability_catalog_id",
            ),
            capability_catalog_version=_text(
                value.get("capability_catalog_version"),
                "capability_catalog_version",
            ),
            capability_catalog_sha256=_text(
                value.get("capability_catalog_sha256"),
                "capability_catalog_sha256",
            ),
            allowed_environments=environments,
            decision_policy=QualificationDecisionPolicy.from_dict(
                value.get("decision_policy")
            ),
            gates=gates,
        )
        standard._validate_binding(registry, catalog)
        return standard

    def revalidated(
        self,
        registry: ExpertRegistry,
        catalog: CapabilityCatalog,
    ) -> QualificationStandard:
        try:
            raw = self.to_dict()
        except (AttributeError, TypeError, ValueError) as exc:
            raise QualificationError(
                "Invalid directly constructed qualification standard"
            ) from exc
        return QualificationStandard.from_dict(raw, registry, catalog)

    def _validate_binding(
        self,
        registry: ExpertRegistry,
        catalog: CapabilityCatalog,
    ) -> None:
        if catalog.profile_scope is not CapabilityProfileScope.ALL_SPECIALISTS:
            raise QualificationError(
                "Qualification standard requires an all_specialists "
                "capability catalog"
            )
        expected = (
            self.expert_catalog_id,
            self.expert_catalog_version,
            self.capability_catalog_id,
            self.capability_catalog_version,
            self.capability_catalog_sha256,
        )
        actual = (
            registry.catalog_id,
            registry.catalog_version,
            catalog.catalog_id,
            catalog.catalog_version,
            catalog.canonical_sha256,
        )
        if expected != actual:
            raise QualificationError(
                "Qualification standard binding does not match the "
                "registry and capability catalog"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "standard_id": self.standard_id,
            "standard_version": self.standard_version,
            "expert_catalog_id": self.expert_catalog_id,
            "expert_catalog_version": self.expert_catalog_version,
            "capability_catalog_id": self.capability_catalog_id,
            "capability_catalog_version": self.capability_catalog_version,
            "capability_catalog_sha256": self.capability_catalog_sha256,
            "allowed_environments": [
                environment.value for environment in self.allowed_environments
            ],
            "decision_policy": self.decision_policy.to_dict(),
            "gates": [gate.to_dict() for gate in self.gates],
        }


@dataclass(frozen=True)
class ProfileQualificationPlan:
    profile_id: str
    scenario_family_id: str
    technical_focus: str
    evaluation_objective: str
    primary_capability_ids: tuple[str, ...]
    required_gate_ids: tuple[str, ...]

    @classmethod
    def from_dict(cls, raw: Any, index: int) -> ProfileQualificationPlan:
        label = f"profile_plans[{index}]"
        value = _mapping(raw, label)
        _exact_fields(
            value,
            {
                "profile_id",
                "scenario_family_id",
                "technical_focus",
                "evaluation_objective",
                "primary_capability_ids",
                "required_gate_ids",
            },
            label,
        )
        scenario_family_id = _text(
            value.get("scenario_family_id"),
            f"{label}.scenario_family_id",
        )
        if SCENARIO_FAMILY_ID_PATTERN.fullmatch(scenario_family_id) is None:
            raise QualificationError(
                f"Invalid scenario family ID: {scenario_family_id}"
            )
        return cls(
            profile_id=_text(value.get("profile_id"), f"{label}.profile_id"),
            scenario_family_id=scenario_family_id,
            technical_focus=_text(
                value.get("technical_focus"),
                f"{label}.technical_focus",
            ),
            evaluation_objective=_text(
                value.get("evaluation_objective"),
                f"{label}.evaluation_objective",
            ),
            primary_capability_ids=_string_tuple(
                value.get("primary_capability_ids"),
                f"{label}.primary_capability_ids",
                allow_empty=False,
            ),
            required_gate_ids=_string_tuple(
                value.get("required_gate_ids"),
                f"{label}.required_gate_ids",
                allow_empty=False,
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "scenario_family_id": self.scenario_family_id,
            "technical_focus": self.technical_focus,
            "evaluation_objective": self.evaluation_objective,
            "primary_capability_ids": list(self.primary_capability_ids),
            "required_gate_ids": list(self.required_gate_ids),
        }


@dataclass(frozen=True)
class QualificationPlanCatalog:
    schema_version: int
    plan_catalog_id: str
    plan_catalog_version: str
    qualification_standard_id: str
    qualification_standard_version: str
    qualification_standard_sha256: str
    expert_catalog_id: str
    expert_catalog_version: str
    capability_catalog_id: str
    capability_catalog_version: str
    capability_catalog_sha256: str
    profile_plans: tuple[ProfileQualificationPlan, ...]

    @property
    def plans_by_profile_id(self) -> dict[str, ProfileQualificationPlan]:
        return {plan.profile_id: plan for plan in self.profile_plans}

    @property
    def canonical_sha256(self) -> str:
        return _canonical_sha256(self.to_dict())

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        registry: ExpertRegistry,
        catalog: CapabilityCatalog,
        standard: QualificationStandard,
    ) -> QualificationPlanCatalog:
        value = _mapping(raw, "qualification plan catalog")
        _exact_fields(
            value,
            {
                "schema_version",
                "plan_catalog_id",
                "plan_catalog_version",
                "qualification_standard_id",
                "qualification_standard_version",
                "qualification_standard_sha256",
                "expert_catalog_id",
                "expert_catalog_version",
                "capability_catalog_id",
                "capability_catalog_version",
                "capability_catalog_sha256",
                "profile_plans",
            },
            "qualification plan catalog",
        )
        if value.get("schema_version") != 1:
            raise QualificationError(
                "Qualification plan catalog schema_version must be 1"
            )
        plans = tuple(
            sorted(
                (
                    ProfileQualificationPlan.from_dict(item, index)
                    for index, item in enumerate(
                        _list(value.get("profile_plans"), "profile_plans")
                    )
                ),
                key=lambda plan: plan.profile_id,
            )
        )
        plan_catalog = cls(
            schema_version=1,
            plan_catalog_id=_text(
                value.get("plan_catalog_id"),
                "plan_catalog_id",
            ),
            plan_catalog_version=_text(
                value.get("plan_catalog_version"),
                "plan_catalog_version",
            ),
            qualification_standard_id=_text(
                value.get("qualification_standard_id"),
                "qualification_standard_id",
            ),
            qualification_standard_version=_text(
                value.get("qualification_standard_version"),
                "qualification_standard_version",
            ),
            qualification_standard_sha256=_text(
                value.get("qualification_standard_sha256"),
                "qualification_standard_sha256",
            ),
            expert_catalog_id=_text(
                value.get("expert_catalog_id"),
                "expert_catalog_id",
            ),
            expert_catalog_version=_text(
                value.get("expert_catalog_version"),
                "expert_catalog_version",
            ),
            capability_catalog_id=_text(
                value.get("capability_catalog_id"),
                "capability_catalog_id",
            ),
            capability_catalog_version=_text(
                value.get("capability_catalog_version"),
                "capability_catalog_version",
            ),
            capability_catalog_sha256=_text(
                value.get("capability_catalog_sha256"),
                "capability_catalog_sha256",
            ),
            profile_plans=plans,
        )
        plan_catalog._validate_relations(registry, catalog, standard)
        return plan_catalog

    def revalidated(
        self,
        registry: ExpertRegistry,
        catalog: CapabilityCatalog,
        standard: QualificationStandard,
    ) -> QualificationPlanCatalog:
        try:
            raw = self.to_dict()
        except (AttributeError, TypeError, ValueError) as exc:
            raise QualificationError(
                "Invalid directly constructed qualification plan catalog"
            ) from exc
        return QualificationPlanCatalog.from_dict(
            raw,
            registry,
            catalog,
            standard,
        )

    def _validate_relations(
        self,
        registry: ExpertRegistry,
        catalog: CapabilityCatalog,
        standard: QualificationStandard,
    ) -> None:
        expected_binding = (
            standard.standard_id,
            standard.standard_version,
            standard.canonical_sha256,
            registry.catalog_id,
            registry.catalog_version,
            catalog.catalog_id,
            catalog.catalog_version,
            catalog.canonical_sha256,
        )
        actual_binding = (
            self.qualification_standard_id,
            self.qualification_standard_version,
            self.qualification_standard_sha256,
            self.expert_catalog_id,
            self.expert_catalog_version,
            self.capability_catalog_id,
            self.capability_catalog_version,
            self.capability_catalog_sha256,
        )
        if actual_binding != expected_binding:
            raise QualificationError(
                "Qualification plan catalog binding is invalid"
            )
        specialist_ids = {
            profile.id
            for profile in registry.profiles
            if profile.kind is ProfileKind.SPECIALIST
        }
        plan_ids = [plan.profile_id for plan in self.profile_plans]
        if len(plan_ids) != len(set(plan_ids)):
            raise QualificationError(
                "Qualification plan catalog contains duplicate profiles"
            )
        if set(plan_ids) != specialist_ids:
            missing = sorted(specialist_ids - set(plan_ids))
            extra = sorted(set(plan_ids) - specialist_ids)
            details: list[str] = []
            if missing:
                details.append(f"missing profiles: {', '.join(missing)}")
            if extra:
                details.append(f"extra profiles: {', '.join(extra)}")
            raise QualificationError(
                "Qualification plans must match all specialists; "
                + "; ".join(details)
            )
        scenario_family_ids = [
            plan.scenario_family_id for plan in self.profile_plans
        ]
        if len(scenario_family_ids) != len(set(scenario_family_ids)):
            raise QualificationError(
                "Qualification plan catalog contains duplicate scenario "
                "family IDs"
            )
        assignments = catalog.assignments_by_profile_id
        required_gate_ids = standard.gate_ids
        for plan in self.profile_plans:
            profile = registry.profiles_by_id[plan.profile_id]
            assignment = assignments[plan.profile_id]
            if plan.technical_focus != profile.name:
                raise QualificationError(
                    f"Qualification plan technical focus does not match "
                    f"profile {plan.profile_id}"
                )
            if plan.primary_capability_ids != assignment.primary_capability_ids:
                raise QualificationError(
                    f"Qualification plan capabilities do not match profile "
                    f"{plan.profile_id}"
                )
            if plan.required_gate_ids != required_gate_ids:
                raise QualificationError(
                    f"Qualification plan gates do not match the standard "
                    f"for profile {plan.profile_id}"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "plan_catalog_id": self.plan_catalog_id,
            "plan_catalog_version": self.plan_catalog_version,
            "qualification_standard_id": self.qualification_standard_id,
            "qualification_standard_version": (
                self.qualification_standard_version
            ),
            "qualification_standard_sha256": (
                self.qualification_standard_sha256
            ),
            "expert_catalog_id": self.expert_catalog_id,
            "expert_catalog_version": self.expert_catalog_version,
            "capability_catalog_id": self.capability_catalog_id,
            "capability_catalog_version": self.capability_catalog_version,
            "capability_catalog_sha256": self.capability_catalog_sha256,
            "profile_plans": [
                plan.to_dict() for plan in self.profile_plans
            ],
        }


@dataclass(frozen=True)
class QualificationCoverageReport:
    report_id: str
    report_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> QualificationCoverageReport:
        value = _mapping(raw, "qualification coverage report")
        expected = {
            "schema_version",
            "report_id",
            "report_sha256",
            "status",
            "evidence_evaluation_state",
            "registry",
            "capability_catalog",
            "qualification_standard",
            "qualification_plan_catalog",
            "summary",
            "gates",
            "groups",
            "commands",
            "profiles",
            "limitations",
        }
        _exact_fields(value, expected, "qualification coverage report")
        if value.get("schema_version") != QUALIFICATION_REPORT_SCHEMA_VERSION:
            raise QualificationError(
                "Qualification coverage report schema version is invalid"
            )
        report_id = value.get("report_id")
        report_hash = value.get("report_sha256")
        if (
            not isinstance(report_id, str)
            or QUALIFICATION_REPORT_ID_PATTERN.fullmatch(report_id) is None
            or not isinstance(report_hash, str)
        ):
            raise QualificationError(
                "Qualification coverage report identity is invalid"
            )
        body = {
            key: item
            for key, item in value.items()
            if key not in {"report_id", "report_sha256"}
        }
        expected_hash = _report_hash(body)
        if report_hash != expected_hash or report_id != _report_id(expected_hash):
            raise QualificationError(
                "Qualification coverage report hash is invalid"
            )
        return cls(
            report_id=report_id,
            report_sha256=report_hash,
            document_json=_canonical_json(value),
        )

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise QualificationError(
                "Qualification coverage report document is invalid"
            )
        return value


def assess_qualification_coverage(
    registry: ExpertRegistry,
    catalog: CapabilityCatalog,
    standard: QualificationStandard,
    plans: QualificationPlanCatalog,
) -> QualificationCoverageReport:
    """Assess qualification planning without accepting evidence or decisions."""

    if not isinstance(registry, ExpertRegistry):
        raise QualificationError("registry must be an ExpertRegistry")
    if not isinstance(catalog, CapabilityCatalog):
        raise QualificationError("catalog must be a CapabilityCatalog")
    if not isinstance(standard, QualificationStandard):
        raise QualificationError(
            "standard must be a QualificationStandard"
        )
    if not isinstance(plans, QualificationPlanCatalog):
        raise QualificationError(
            "plans must be a QualificationPlanCatalog"
        )
    registry.validate()
    catalog = catalog.revalidated(registry)
    standard = standard.revalidated(registry, catalog)
    plans = plans.revalidated(registry, catalog, standard)
    specialists = tuple(
        sorted(
            (
                profile
                for profile in registry.profiles
                if profile.kind is ProfileKind.SPECIALIST
            ),
            key=lambda profile: profile.id,
        )
    )
    profile_records = tuple(
        _profile_record(
            profile,
            plans.plans_by_profile_id[profile.id],
            standard,
        )
        for profile in specialists
    )
    profiles_by_id = {
        str(record["profile_id"]): record for record in profile_records
    }
    command_records = tuple(
        _command_record(command, profiles_by_id, standard)
        for command in sorted(registry.commands, key=lambda item: item.id)
    )
    commands_by_id = {
        str(record["command_id"]): record for record in command_records
    }
    group_records = tuple(
        _group_record(group, commands_by_id)
        for group in sorted(registry.groups, key=lambda item: item.id)
    )
    status_counts = Counter(profile.status for profile in specialists)
    review_reasons = _standard_review_reasons(standard)
    if review_reasons:
        status = "qualification_standard_review_required"
    elif status_counts["defined"]:
        status = "qualification_execution_pending"
    elif status_counts["retired"]:
        status = "registry_review_required"
    else:
        status = "registry_qualification_complete"
    body = {
        "schema_version": QUALIFICATION_REPORT_SCHEMA_VERSION,
        "status": status,
        "evidence_evaluation_state": "not_performed",
        "registry": {
            "id": registry.catalog_id,
            "version": registry.catalog_version,
            "sha256": _canonical_sha256(registry.to_dict()),
        },
        "capability_catalog": {
            "id": catalog.catalog_id,
            "version": catalog.catalog_version,
            "sha256": catalog.canonical_sha256,
        },
        "qualification_standard": {
            "id": standard.standard_id,
            "version": standard.standard_version,
            "sha256": standard.canonical_sha256,
            "review_reasons": list(review_reasons),
        },
        "qualification_plan_catalog": {
            "id": plans.plan_catalog_id,
            "version": plans.plan_catalog_version,
            "sha256": plans.canonical_sha256,
        },
        "summary": {
            "group_count": len(group_records),
            "command_count": len(command_records),
            "specialist_count": len(specialists),
            "planned_specialist_count": len(plans.profile_plans),
            "gate_count": len(standard.gates),
            "planned_gate_assessment_count": (
                len(specialists) * len(standard.gates)
            ),
            "minimum_scenario_count": (
                len(specialists) * standard.minimum_scenarios_per_profile
            ),
            "minimum_passing_scenario_count": (
                len(specialists)
                * standard.minimum_passing_scenarios_per_profile
            ),
            "qualified_specialist_count": status_counts["qualified"],
            "defined_specialist_count": status_counts["defined"],
            "retired_specialist_count": status_counts["retired"],
            "commands_with_no_qualified_specialist": sum(
                int(record["priority_band"] == "priority_0_no_qualified")
                for record in command_records
            ),
            "commands_with_partial_qualification": sum(
                int(record["priority_band"] == "priority_1_partial")
                for record in command_records
            ),
            "commands_fully_qualified": sum(
                int(record["priority_band"] == "complete")
                for record in command_records
            ),
        },
        "gates": [
            {
                **gate.to_dict(),
                "planned_profile_count": len(specialists),
                "planned_scenario_count": (
                    len(specialists) * gate.minimum_scenarios
                ),
                "minimum_passing_scenario_count": (
                    len(specialists) * gate.minimum_passing_scenarios
                ),
            }
            for gate in standard.gates
        ],
        "groups": list(group_records),
        "commands": list(command_records),
        "profiles": list(profile_records),
        "limitations": [
            (
                "This report validates qualification plans. It does not "
                "ingest, verify, or claim qualification evidence."
            ),
            (
                "Registry status remains the current qualification source. "
                "This report cannot change that status."
            ),
            (
                "Qualification planning does not activate a profile, grant "
                "authority, dispatch work, connect to a tool, or execute an "
                "action."
            ),
            (
                "The authority and signed evidence contract for future "
                "qualification decisions remains a separate architecture "
                "decision."
            ),
        ],
    }
    report_hash = _report_hash(body)
    return QualificationCoverageReport.from_dict(
        {
            **body,
            "report_id": _report_id(report_hash),
            "report_sha256": report_hash,
        }
    )


def _profile_record(
    profile: ExpertProfile,
    plan: ProfileQualificationPlan,
    standard: QualificationStandard,
) -> dict[str, Any]:
    if profile.status == "retired":
        state = "retired"
    elif profile.status == "qualified":
        state = "registry_qualified_plan_present"
    else:
        state = "qualification_execution_pending"
    return {
        "profile_id": profile.id,
        "name": profile.name,
        "group_id": profile.group_id,
        "command_id": profile.command_id,
        "registry_status": profile.status,
        "qualification_state": state,
        "scenario_family_id": plan.scenario_family_id,
        "technical_focus": plan.technical_focus,
        "evaluation_objective": plan.evaluation_objective,
        "primary_capability_ids": list(plan.primary_capability_ids),
        "required_gate_ids": list(plan.required_gate_ids),
        "planned_gate_assessment_count": len(plan.required_gate_ids),
        "minimum_scenario_count": standard.minimum_scenarios_per_profile,
        "minimum_passing_scenario_count": (
            standard.minimum_passing_scenarios_per_profile
        ),
    }


def _command_record(
    command: DomainCommand,
    profiles_by_id: dict[str, dict[str, Any]],
    standard: QualificationStandard,
) -> dict[str, Any]:
    records = tuple(
        profiles_by_id[profile_id]
        for profile_id in command.specialist_profile_ids
    )
    qualified = tuple(
        str(record["profile_id"])
        for record in records
        if record["registry_status"] == "qualified"
    )
    pending = tuple(
        str(record["profile_id"])
        for record in records
        if record["qualification_state"] == "qualification_execution_pending"
    )
    if not qualified:
        priority_band = "priority_0_no_qualified"
    elif len(qualified) < len(records):
        priority_band = "priority_1_partial"
    else:
        priority_band = "complete"
    return {
        "command_id": command.id,
        "name": command.name,
        "group_id": command.group_id,
        "priority_band": priority_band,
        "specialist_count": len(records),
        "planned_specialist_count": len(records),
        "qualified_specialist_count": len(qualified),
        "pending_qualification_count": len(pending),
        "planned_gate_assessment_count": len(records) * len(standard.gates),
        "minimum_scenario_count": (
            len(records) * standard.minimum_scenarios_per_profile
        ),
        "qualified_specialist_ids": list(qualified),
        "pending_qualification_ids": list(pending),
    }


def _group_record(
    group: ManeuverGroup,
    commands_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    records = tuple(
        commands_by_id[command_id] for command_id in group.command_ids
    )
    return {
        "group_id": group.id,
        "name": group.name,
        "command_count": len(records),
        "priority_0_command_count": sum(
            int(record["priority_band"] == "priority_0_no_qualified")
            for record in records
        ),
        "specialist_count": sum(
            int(record["specialist_count"]) for record in records
        ),
        "planned_specialist_count": sum(
            int(record["planned_specialist_count"]) for record in records
        ),
        "qualified_specialist_count": sum(
            int(record["qualified_specialist_count"]) for record in records
        ),
        "pending_qualification_count": sum(
            int(record["pending_qualification_count"]) for record in records
        ),
        "planned_gate_assessment_count": sum(
            int(record["planned_gate_assessment_count"])
            for record in records
        ),
        "minimum_scenario_count": sum(
            int(record["minimum_scenario_count"]) for record in records
        ),
    }


def _standard_review_reasons(
    standard: QualificationStandard,
) -> tuple[str, ...]:
    reasons: list[str] = []
    if MissionEnvironment.PRODUCTION in standard.allowed_environments:
        reasons.append("production_environment_allowed")
    if standard.decision_policy.minimum_distinct_evaluators < 2:
        reasons.append("fewer_than_two_evaluators")
    if not standard.decision_policy.require_independent_control_review:
        reasons.append("independent_control_review_not_required")
    if not standard.decision_policy.require_independent_assurance_review:
        reasons.append("independent_assurance_review_not_required")
    if standard.decision_policy.allow_self_attestation:
        reasons.append("self_attestation_allowed")
    if any(gate.maximum_critical_failures > 0 for gate in standard.gates):
        reasons.append("critical_failures_allowed")
    if any(not gate.independent_review_required for gate in standard.gates):
        reasons.append("gate_without_independent_review")
    return tuple(reasons)


def _report_hash(body: dict[str, Any]) -> str:
    return _canonical_sha256(
        {
            "domain": QUALIFICATION_REPORT_DOMAIN,
            "report": body,
        }
    )


def _report_id(report_hash: str) -> str:
    return "QCR-" + report_hash.removeprefix("sha256:")[:32].upper()


def load_qualification_standard(
    path: str | Path,
    registry: ExpertRegistry,
    catalog: CapabilityCatalog,
) -> QualificationStandard:
    return QualificationStandard.from_dict(
        _load_json(path, "qualification standard"),
        registry,
        catalog,
    )


def load_qualification_plan_catalog(
    path: str | Path,
    registry: ExpertRegistry,
    catalog: CapabilityCatalog,
    standard: QualificationStandard,
) -> QualificationPlanCatalog:
    return QualificationPlanCatalog.from_dict(
        _load_json(path, "qualification plan catalog"),
        registry,
        catalog,
        standard,
    )
