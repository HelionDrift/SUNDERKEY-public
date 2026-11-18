"""Advisory-only evaluation of synthetic qualification observations."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import QualificationError
from .qualification import (
    QualificationPlanCatalog,
    QualificationStandard,
    _boolean,
    _canonical_json,
    _canonical_sha256,
    _exact_fields,
    _list,
    _load_json,
    _mapping,
    _positive_integer,
    _text,
)
from .registry import ExpertRegistry
from .routing import CapabilityCatalog
from .types import MissionEnvironment

SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
CASE_ID_PATTERN = re.compile(r"QCASE-[A-Z0-9-]{8,96}")
REPORT_ID_PATTERN = re.compile(r"QER-[0-9A-F]{32}")
REPORT_DOMAIN = "sunderkey.qualification-evaluation-report.v1"
REPORT_SCHEMA_VERSION = 1


def _sha256(value: Any, label: str) -> str:
    digest = _text(value, label)
    if SHA256_PATTERN.fullmatch(digest) is None:
        raise QualificationError(f"{label} must be a SHA-256 digest")
    return digest


@dataclass(frozen=True)
class QualificationCandidateBinding:
    candidate_id: str
    candidate_version: str
    candidate_artifact_sha256: str

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        label: str = "candidate",
    ) -> QualificationCandidateBinding:
        value = _mapping(raw, label)
        _exact_fields(
            value,
            {
                "candidate_id",
                "candidate_version",
                "candidate_artifact_sha256",
            },
            label,
        )
        return cls(
            candidate_id=_text(
                value.get("candidate_id"),
                f"{label}.candidate_id",
            ),
            candidate_version=_text(
                value.get("candidate_version"),
                f"{label}.candidate_version",
            ),
            candidate_artifact_sha256=_sha256(
                value.get("candidate_artifact_sha256"),
                f"{label}.candidate_artifact_sha256",
            ),
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "candidate_id": self.candidate_id,
            "candidate_version": self.candidate_version,
            "candidate_artifact_sha256": self.candidate_artifact_sha256,
        }


@dataclass(frozen=True)
class QualificationScenarioCase:
    case_id: str
    gate_id: str
    ordinal: int
    environment: MissionEnvironment
    scenario_sha256: str
    expected_result_sha256: str
    critical_failure_definition_sha256: str

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        index: int,
    ) -> QualificationScenarioCase:
        label = f"cases[{index}]"
        value = _mapping(raw, label)
        _exact_fields(
            value,
            {
                "case_id",
                "gate_id",
                "ordinal",
                "environment",
                "scenario_sha256",
                "expected_result_sha256",
                "critical_failure_definition_sha256",
            },
            label,
        )
        case_id = _text(value.get("case_id"), f"{label}.case_id")
        if CASE_ID_PATTERN.fullmatch(case_id) is None:
            raise QualificationError(f"Invalid qualification case ID: {case_id}")
        environment_name = _text(
            value.get("environment"),
            f"{label}.environment",
        )
        try:
            environment = MissionEnvironment(environment_name)
        except ValueError as exc:
            options = ", ".join(item.value for item in MissionEnvironment)
            raise QualificationError(
                f"{label}.environment must be one of: {options}"
            ) from exc
        return cls(
            case_id=case_id,
            gate_id=_text(value.get("gate_id"), f"{label}.gate_id"),
            ordinal=_positive_integer(
                value.get("ordinal"),
                f"{label}.ordinal",
            ),
            environment=environment,
            scenario_sha256=_sha256(
                value.get("scenario_sha256"),
                f"{label}.scenario_sha256",
            ),
            expected_result_sha256=_sha256(
                value.get("expected_result_sha256"),
                f"{label}.expected_result_sha256",
            ),
            critical_failure_definition_sha256=_sha256(
                value.get("critical_failure_definition_sha256"),
                f"{label}.critical_failure_definition_sha256",
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "gate_id": self.gate_id,
            "ordinal": self.ordinal,
            "environment": self.environment.value,
            "scenario_sha256": self.scenario_sha256,
            "expected_result_sha256": self.expected_result_sha256,
            "critical_failure_definition_sha256": (
                self.critical_failure_definition_sha256
            ),
        }


@dataclass(frozen=True)
class QualificationEvaluationSuite:
    schema_version: int
    suite_id: str
    suite_version: str
    suite_mode: str
    advisory_only: bool
    expert_catalog_id: str
    expert_catalog_version: str
    capability_catalog_id: str
    capability_catalog_version: str
    capability_catalog_sha256: str
    qualification_standard_id: str
    qualification_standard_version: str
    qualification_standard_sha256: str
    qualification_plan_catalog_id: str
    qualification_plan_catalog_version: str
    qualification_plan_catalog_sha256: str
    profile_id: str
    scenario_family_id: str
    candidate: QualificationCandidateBinding
    cases: tuple[QualificationScenarioCase, ...]

    @property
    def canonical_sha256(self) -> str:
        return _canonical_sha256(self.to_dict())

    @property
    def cases_by_id(self) -> dict[str, QualificationScenarioCase]:
        return {case.case_id: case for case in self.cases}

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        registry: ExpertRegistry,
        catalog: CapabilityCatalog,
        standard: QualificationStandard,
        plans: QualificationPlanCatalog,
    ) -> QualificationEvaluationSuite:
        value = _mapping(raw, "qualification evaluation suite")
        _exact_fields(
            value,
            {
                "schema_version",
                "suite_id",
                "suite_version",
                "suite_mode",
                "advisory_only",
                "expert_catalog_id",
                "expert_catalog_version",
                "capability_catalog_id",
                "capability_catalog_version",
                "capability_catalog_sha256",
                "qualification_standard_id",
                "qualification_standard_version",
                "qualification_standard_sha256",
                "qualification_plan_catalog_id",
                "qualification_plan_catalog_version",
                "qualification_plan_catalog_sha256",
                "profile_id",
                "scenario_family_id",
                "candidate",
                "cases",
            },
            "qualification evaluation suite",
        )
        if value.get("schema_version") != 1:
            raise QualificationError(
                "Qualification evaluation suite schema_version must be 1"
            )
        suite_mode = _text(value.get("suite_mode"), "suite_mode")
        if suite_mode != "synthetic":
            raise QualificationError(
                "Qualification evaluation suite mode must be synthetic"
            )
        advisory_only = _boolean(
            value.get("advisory_only"),
            "advisory_only",
        )
        if not advisory_only:
            raise QualificationError(
                "Qualification evaluation suite must be advisory_only"
            )
        cases = tuple(
            sorted(
                (
                    QualificationScenarioCase.from_dict(item, index)
                    for index, item in enumerate(
                        _list(value.get("cases"), "cases")
                    )
                ),
                key=lambda case: (case.gate_id, case.ordinal, case.case_id),
            )
        )
        suite = cls(
            schema_version=1,
            suite_id=_text(value.get("suite_id"), "suite_id"),
            suite_version=_text(
                value.get("suite_version"),
                "suite_version",
            ),
            suite_mode=suite_mode,
            advisory_only=advisory_only,
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
            capability_catalog_sha256=_sha256(
                value.get("capability_catalog_sha256"),
                "capability_catalog_sha256",
            ),
            qualification_standard_id=_text(
                value.get("qualification_standard_id"),
                "qualification_standard_id",
            ),
            qualification_standard_version=_text(
                value.get("qualification_standard_version"),
                "qualification_standard_version",
            ),
            qualification_standard_sha256=_sha256(
                value.get("qualification_standard_sha256"),
                "qualification_standard_sha256",
            ),
            qualification_plan_catalog_id=_text(
                value.get("qualification_plan_catalog_id"),
                "qualification_plan_catalog_id",
            ),
            qualification_plan_catalog_version=_text(
                value.get("qualification_plan_catalog_version"),
                "qualification_plan_catalog_version",
            ),
            qualification_plan_catalog_sha256=_sha256(
                value.get("qualification_plan_catalog_sha256"),
                "qualification_plan_catalog_sha256",
            ),
            profile_id=_text(value.get("profile_id"), "profile_id"),
            scenario_family_id=_text(
                value.get("scenario_family_id"),
                "scenario_family_id",
            ),
            candidate=QualificationCandidateBinding.from_dict(
                value.get("candidate")
            ),
            cases=cases,
        )
        suite._validate_relations(registry, catalog, standard, plans)
        return suite

    def revalidated(
        self,
        registry: ExpertRegistry,
        catalog: CapabilityCatalog,
        standard: QualificationStandard,
        plans: QualificationPlanCatalog,
    ) -> QualificationEvaluationSuite:
        try:
            raw = self.to_dict()
        except (AttributeError, TypeError, ValueError) as exc:
            raise QualificationError(
                "Invalid directly constructed qualification suite"
            ) from exc
        return QualificationEvaluationSuite.from_dict(
            raw,
            registry,
            catalog,
            standard,
            plans,
        )

    def _validate_relations(
        self,
        registry: ExpertRegistry,
        catalog: CapabilityCatalog,
        standard: QualificationStandard,
        plans: QualificationPlanCatalog,
    ) -> None:
        expected_binding = (
            registry.catalog_id,
            registry.catalog_version,
            catalog.catalog_id,
            catalog.catalog_version,
            catalog.canonical_sha256,
            standard.standard_id,
            standard.standard_version,
            standard.canonical_sha256,
            plans.plan_catalog_id,
            plans.plan_catalog_version,
            plans.canonical_sha256,
        )
        actual_binding = (
            self.expert_catalog_id,
            self.expert_catalog_version,
            self.capability_catalog_id,
            self.capability_catalog_version,
            self.capability_catalog_sha256,
            self.qualification_standard_id,
            self.qualification_standard_version,
            self.qualification_standard_sha256,
            self.qualification_plan_catalog_id,
            self.qualification_plan_catalog_version,
            self.qualification_plan_catalog_sha256,
        )
        if actual_binding != expected_binding:
            raise QualificationError(
                "Qualification evaluation suite binding is invalid"
            )
        plan = plans.plans_by_profile_id.get(self.profile_id)
        if plan is None:
            raise QualificationError(
                "Qualification evaluation suite profile is not planned"
            )
        if self.scenario_family_id != plan.scenario_family_id:
            raise QualificationError(
                "Qualification evaluation suite scenario family does not "
                "match the profile plan"
            )
        if not self.cases:
            raise QualificationError(
                "Qualification evaluation suite must define cases"
            )
        case_ids = [case.case_id for case in self.cases]
        if len(case_ids) != len(set(case_ids)):
            raise QualificationError(
                "Qualification evaluation suite contains duplicate case IDs"
            )
        cases_by_gate: dict[str, list[QualificationScenarioCase]] = {
            gate_id: [] for gate_id in standard.gate_ids
        }
        for case in self.cases:
            if case.gate_id not in cases_by_gate:
                raise QualificationError(
                    f"Qualification case references unknown gate: "
                    f"{case.gate_id}"
                )
            if case.environment not in standard.allowed_environments:
                raise QualificationError(
                    f"Qualification case environment is not allowed: "
                    f"{case.case_id}"
                )
            cases_by_gate[case.gate_id].append(case)
        for gate in standard.gates:
            gate_cases = cases_by_gate[gate.id]
            if len(gate_cases) < gate.minimum_scenarios:
                raise QualificationError(
                    f"Qualification suite has too few scenarios for gate "
                    f"{gate.id}"
                )
            ordinals = sorted(case.ordinal for case in gate_cases)
            if ordinals != list(range(1, len(gate_cases) + 1)):
                raise QualificationError(
                    f"Qualification suite ordinals are not contiguous for "
                    f"gate {gate.id}"
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "suite_id": self.suite_id,
            "suite_version": self.suite_version,
            "suite_mode": self.suite_mode,
            "advisory_only": self.advisory_only,
            "expert_catalog_id": self.expert_catalog_id,
            "expert_catalog_version": self.expert_catalog_version,
            "capability_catalog_id": self.capability_catalog_id,
            "capability_catalog_version": self.capability_catalog_version,
            "capability_catalog_sha256": self.capability_catalog_sha256,
            "qualification_standard_id": self.qualification_standard_id,
            "qualification_standard_version": (
                self.qualification_standard_version
            ),
            "qualification_standard_sha256": (
                self.qualification_standard_sha256
            ),
            "qualification_plan_catalog_id": (
                self.qualification_plan_catalog_id
            ),
            "qualification_plan_catalog_version": (
                self.qualification_plan_catalog_version
            ),
            "qualification_plan_catalog_sha256": (
                self.qualification_plan_catalog_sha256
            ),
            "profile_id": self.profile_id,
            "scenario_family_id": self.scenario_family_id,
            "candidate": self.candidate.to_dict(),
            "cases": [case.to_dict() for case in self.cases],
        }


@dataclass(frozen=True)
class QualificationCaseObservation:
    case_id: str
    outcome: str
    critical_failure: bool
    result_sha256: str
    evidence_manifest_sha256: str

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        index: int,
    ) -> QualificationCaseObservation:
        label = f"observations[{index}]"
        value = _mapping(raw, label)
        _exact_fields(
            value,
            {
                "case_id",
                "outcome",
                "critical_failure",
                "result_sha256",
                "evidence_manifest_sha256",
            },
            label,
        )
        case_id = _text(value.get("case_id"), f"{label}.case_id")
        if CASE_ID_PATTERN.fullmatch(case_id) is None:
            raise QualificationError(f"Invalid qualification case ID: {case_id}")
        outcome = _text(value.get("outcome"), f"{label}.outcome")
        if outcome not in {"pass", "fail"}:
            raise QualificationError(
                f"{label}.outcome must be pass or fail"
            )
        critical_failure = _boolean(
            value.get("critical_failure"),
            f"{label}.critical_failure",
        )
        if outcome == "pass" and critical_failure:
            raise QualificationError(
                f"{label} cannot pass with a critical failure"
            )
        return cls(
            case_id=case_id,
            outcome=outcome,
            critical_failure=critical_failure,
            result_sha256=_sha256(
                value.get("result_sha256"),
                f"{label}.result_sha256",
            ),
            evidence_manifest_sha256=_sha256(
                value.get("evidence_manifest_sha256"),
                f"{label}.evidence_manifest_sha256",
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "outcome": self.outcome,
            "critical_failure": self.critical_failure,
            "result_sha256": self.result_sha256,
            "evidence_manifest_sha256": self.evidence_manifest_sha256,
        }


@dataclass(frozen=True)
class QualificationObservationSet:
    schema_version: int
    observation_set_id: str
    observation_set_version: str
    advisory_only: bool
    suite_id: str
    suite_version: str
    suite_sha256: str
    profile_id: str
    candidate: QualificationCandidateBinding
    observations: tuple[QualificationCaseObservation, ...]

    @property
    def observations_by_case_id(
        self,
    ) -> dict[str, QualificationCaseObservation]:
        return {
            observation.case_id: observation
            for observation in self.observations
        }

    @property
    def canonical_sha256(self) -> str:
        return _canonical_sha256(self.to_dict())

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        suite: QualificationEvaluationSuite,
    ) -> QualificationObservationSet:
        value = _mapping(raw, "qualification observation set")
        _exact_fields(
            value,
            {
                "schema_version",
                "observation_set_id",
                "observation_set_version",
                "advisory_only",
                "suite_id",
                "suite_version",
                "suite_sha256",
                "profile_id",
                "candidate",
                "observations",
            },
            "qualification observation set",
        )
        if value.get("schema_version") != 1:
            raise QualificationError(
                "Qualification observation set schema_version must be 1"
            )
        advisory_only = _boolean(
            value.get("advisory_only"),
            "advisory_only",
        )
        if not advisory_only:
            raise QualificationError(
                "Qualification observation set must be advisory_only"
            )
        observations = tuple(
            sorted(
                (
                    QualificationCaseObservation.from_dict(item, index)
                    for index, item in enumerate(
                        _list(value.get("observations"), "observations")
                    )
                ),
                key=lambda observation: observation.case_id,
            )
        )
        observation_set = cls(
            schema_version=1,
            observation_set_id=_text(
                value.get("observation_set_id"),
                "observation_set_id",
            ),
            observation_set_version=_text(
                value.get("observation_set_version"),
                "observation_set_version",
            ),
            advisory_only=advisory_only,
            suite_id=_text(value.get("suite_id"), "suite_id"),
            suite_version=_text(
                value.get("suite_version"),
                "suite_version",
            ),
            suite_sha256=_sha256(
                value.get("suite_sha256"),
                "suite_sha256",
            ),
            profile_id=_text(value.get("profile_id"), "profile_id"),
            candidate=QualificationCandidateBinding.from_dict(
                value.get("candidate")
            ),
            observations=observations,
        )
        observation_set._validate_binding(suite)
        return observation_set

    def revalidated(
        self,
        suite: QualificationEvaluationSuite,
    ) -> QualificationObservationSet:
        try:
            raw = self.to_dict()
        except (AttributeError, TypeError, ValueError) as exc:
            raise QualificationError(
                "Invalid directly constructed qualification observations"
            ) from exc
        return QualificationObservationSet.from_dict(raw, suite)

    def _validate_binding(self, suite: QualificationEvaluationSuite) -> None:
        expected = (
            suite.suite_id,
            suite.suite_version,
            suite.canonical_sha256,
            suite.profile_id,
            suite.candidate,
        )
        actual = (
            self.suite_id,
            self.suite_version,
            self.suite_sha256,
            self.profile_id,
            self.candidate,
        )
        if actual != expected:
            raise QualificationError(
                "Qualification observation set binding is invalid"
            )
        observation_ids = [item.case_id for item in self.observations]
        if len(observation_ids) != len(set(observation_ids)):
            raise QualificationError(
                "Qualification observation set contains duplicate cases"
            )
        expected_case_ids = set(suite.cases_by_id)
        if set(observation_ids) != expected_case_ids:
            missing = sorted(expected_case_ids - set(observation_ids))
            extra = sorted(set(observation_ids) - expected_case_ids)
            details: list[str] = []
            if missing:
                details.append(f"missing cases: {', '.join(missing)}")
            if extra:
                details.append(f"extra cases: {', '.join(extra)}")
            raise QualificationError(
                "Qualification observations must match every suite case; "
                + "; ".join(details)
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "observation_set_id": self.observation_set_id,
            "observation_set_version": self.observation_set_version,
            "advisory_only": self.advisory_only,
            "suite_id": self.suite_id,
            "suite_version": self.suite_version,
            "suite_sha256": self.suite_sha256,
            "profile_id": self.profile_id,
            "candidate": self.candidate.to_dict(),
            "observations": [
                observation.to_dict() for observation in self.observations
            ],
        }


@dataclass(frozen=True)
class QualificationEvaluationReport:
    report_id: str
    report_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> QualificationEvaluationReport:
        value = _mapping(raw, "qualification evaluation report")
        expected = {
            "schema_version",
            "report_id",
            "report_sha256",
            "status",
            "advisory_only",
            "qualification_effect",
            "independent_review_evaluation_state",
            "suite",
            "observation_set",
            "profile",
            "candidate",
            "summary",
            "gates",
            "limitations",
        }
        _exact_fields(value, expected, "qualification evaluation report")
        if value.get("schema_version") != REPORT_SCHEMA_VERSION:
            raise QualificationError(
                "Qualification evaluation report schema version is invalid"
            )
        report_id = value.get("report_id")
        report_hash = value.get("report_sha256")
        if (
            not isinstance(report_id, str)
            or REPORT_ID_PATTERN.fullmatch(report_id) is None
            or not isinstance(report_hash, str)
        ):
            raise QualificationError(
                "Qualification evaluation report identity is invalid"
            )
        body = {
            key: item
            for key, item in value.items()
            if key not in {"report_id", "report_sha256"}
        }
        expected_hash = _report_hash(body)
        if report_hash != expected_hash or report_id != _report_id(expected_hash):
            raise QualificationError(
                "Qualification evaluation report hash is invalid"
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
                "Qualification evaluation report document is invalid"
            )
        return value


def evaluate_qualification_observations(
    registry: ExpertRegistry,
    catalog: CapabilityCatalog,
    standard: QualificationStandard,
    plans: QualificationPlanCatalog,
    suite: QualificationEvaluationSuite,
    observations: QualificationObservationSet,
) -> QualificationEvaluationReport:
    """Evaluate unsigned synthetic observations without qualification effect."""

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
    if not isinstance(suite, QualificationEvaluationSuite):
        raise QualificationError(
            "suite must be a QualificationEvaluationSuite"
        )
    if not isinstance(observations, QualificationObservationSet):
        raise QualificationError(
            "observations must be a QualificationObservationSet"
        )
    registry.validate()
    catalog = catalog.revalidated(registry)
    standard = standard.revalidated(registry, catalog)
    plans = plans.revalidated(registry, catalog, standard)
    suite = suite.revalidated(registry, catalog, standard, plans)
    observations = observations.revalidated(suite)
    observation_by_case = observations.observations_by_case_id
    gate_records: list[dict[str, Any]] = []
    for gate in standard.gates:
        gate_cases = tuple(
            case for case in suite.cases if case.gate_id == gate.id
        )
        gate_observations = tuple(
            observation_by_case[case.case_id] for case in gate_cases
        )
        passed_count = sum(
            observation.outcome == "pass"
            for observation in gate_observations
        )
        critical_count = sum(
            observation.critical_failure
            for observation in gate_observations
        )
        threshold_met = (
            passed_count >= gate.minimum_passing_scenarios
            and critical_count <= gate.maximum_critical_failures
        )
        gate_records.append(
            {
                "gate_id": gate.id,
                "name": gate.name,
                "case_count": len(gate_cases),
                "passed_count": passed_count,
                "failed_count": len(gate_cases) - passed_count,
                "critical_failure_count": critical_count,
                "minimum_passing_scenarios": (
                    gate.minimum_passing_scenarios
                ),
                "maximum_critical_failures": (
                    gate.maximum_critical_failures
                ),
                "advisory_threshold_status": (
                    "met" if threshold_met else "not_met"
                ),
            }
        )
    thresholds_met = all(
        record["advisory_threshold_status"] == "met"
        for record in gate_records
    )
    profile = registry.profiles_by_id[suite.profile_id]
    passed_total = sum(
        observation.outcome == "pass"
        for observation in observations.observations
    )
    critical_total = sum(
        observation.critical_failure
        for observation in observations.observations
    )
    body = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "status": (
            "advisory_thresholds_met"
            if thresholds_met
            else "advisory_thresholds_not_met"
        ),
        "advisory_only": True,
        "qualification_effect": "none",
        "independent_review_evaluation_state": "not_performed",
        "suite": {
            "id": suite.suite_id,
            "version": suite.suite_version,
            "sha256": suite.canonical_sha256,
            "mode": suite.suite_mode,
        },
        "observation_set": {
            "id": observations.observation_set_id,
            "version": observations.observation_set_version,
            "sha256": observations.canonical_sha256,
        },
        "profile": {
            "id": profile.id,
            "name": profile.name,
            "registry_status": profile.status,
            "scenario_family_id": suite.scenario_family_id,
        },
        "candidate": suite.candidate.to_dict(),
        "summary": {
            "gate_count": len(gate_records),
            "gates_meeting_advisory_thresholds": sum(
                record["advisory_threshold_status"] == "met"
                for record in gate_records
            ),
            "gates_not_meeting_advisory_thresholds": sum(
                record["advisory_threshold_status"] == "not_met"
                for record in gate_records
            ),
            "case_count": len(suite.cases),
            "passed_count": passed_total,
            "failed_count": len(suite.cases) - passed_total,
            "critical_failure_count": critical_total,
        },
        "gates": gate_records,
        "limitations": [
            (
                "This report evaluates unsigned local observations against "
                "planned numerical thresholds only."
            ),
            (
                "Candidate identity, scenario content, expected results, "
                "results, and evidence manifests are content hashes, not "
                "verified attestations."
            ),
            (
                "Independent evaluator, Control, and Assurance review are "
                "not performed by this command."
            ),
            (
                "Meeting advisory thresholds does not qualify a profile, "
                "change registry status, alter routing eligibility, or "
                "authorize execution."
            ),
        ],
    }
    report_hash = _report_hash(body)
    return QualificationEvaluationReport.from_dict(
        {
            **body,
            "report_id": _report_id(report_hash),
            "report_sha256": report_hash,
        }
    )


def _report_hash(body: dict[str, Any]) -> str:
    return _canonical_sha256(
        {
            "domain": REPORT_DOMAIN,
            "report": body,
        }
    )


def _report_id(report_hash: str) -> str:
    return "QER-" + report_hash.removeprefix("sha256:")[:32].upper()


def load_qualification_evaluation_suite(
    path: str | Path,
    registry: ExpertRegistry,
    catalog: CapabilityCatalog,
    standard: QualificationStandard,
    plans: QualificationPlanCatalog,
) -> QualificationEvaluationSuite:
    return QualificationEvaluationSuite.from_dict(
        _load_json(path, "qualification evaluation suite"),
        registry,
        catalog,
        standard,
        plans,
    )


def load_qualification_observation_set(
    path: str | Path,
    suite: QualificationEvaluationSuite,
) -> QualificationObservationSet:
    return QualificationObservationSet.from_dict(
        _load_json(path, "qualification observation set"),
        suite,
    )
